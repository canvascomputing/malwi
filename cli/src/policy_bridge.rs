//! Bridge between the policy engine and the CLI tracing system.
//!
//! Loads policies, derives hook configurations, and evaluates trace events.

use malwi_policy::{
    Category, EnforcementMode, HookSpecKind, Operation, PolicyDecision, PolicyEngine,
    PolicyHookSpec, Runtime, SectionKey,
};
use malwi_protocol::{HookConfig, HookType, NetworkInfo, TraceEvent};

#[cfg(test)]
use crate::default_policy::DEFAULT_SECURITY_YAML;

/// Resolve an `includes:` name to a YAML string using the embedded policy templates.
fn include_resolver(name: &str) -> Option<String> {
    crate::auto_policy::embedded_policy(name)
}

/// Active policy loaded and ready for evaluation.
pub struct ActivePolicy {
    engine: PolicyEngine,
    /// Cache: (hook_type discriminant, function_name) → function-level disposition.
    /// Only caches results for functions without arg-filter constraints.
    fn_cache: std::cell::RefCell<std::collections::HashMap<(u8, String), CachedDisposition>>,
}

/// Compact representation of a cached function-level disposition.
#[derive(Clone)]
enum CachedDisposition {
    Display,
    Suppress,
    Warn { rule: String, section: String },
    Block { rule: String, section: String },
    Review { rule: String, section: String },
}

/// The disposition of a trace event after policy evaluation.
#[derive(Debug)]
#[allow(dead_code)]
pub enum EventDisposition {
    /// Matched a deny rule with Log mode — display the event.
    Display,
    /// Matched a deny rule with Warn mode.
    Warn { rule: String, section: String },
    /// Matched a deny rule with Block mode.
    Block { rule: String, section: String },
    /// Matched a deny rule with Review mode.
    Review { rule: String, section: String },
    /// No deny match (allowed by policy) — nothing to show.
    Suppress,
}

#[allow(dead_code)]
impl EventDisposition {
    /// Whether this event should be shown to the user.
    pub fn should_display(&self) -> bool {
        !matches!(self, EventDisposition::Suppress)
    }

    /// Whether this event requires review mode interaction.
    pub fn requires_review(&self) -> bool {
        matches!(self, EventDisposition::Review { .. })
    }

    /// Whether this event should be blocked.
    pub fn is_blocked(&self) -> bool {
        matches!(self, EventDisposition::Block { .. })
    }

    fn to_cached(&self) -> CachedDisposition {
        match self {
            EventDisposition::Display => CachedDisposition::Display,
            EventDisposition::Suppress => CachedDisposition::Suppress,
            EventDisposition::Warn { rule, section } => CachedDisposition::Warn {
                rule: rule.clone(),
                section: section.clone(),
            },
            EventDisposition::Block { rule, section } => CachedDisposition::Block {
                rule: rule.clone(),
                section: section.clone(),
            },
            EventDisposition::Review { rule, section } => CachedDisposition::Review {
                rule: rule.clone(),
                section: section.clone(),
            },
        }
    }
}

impl CachedDisposition {
    fn to_disposition(&self) -> EventDisposition {
        match self {
            CachedDisposition::Display => EventDisposition::Display,
            CachedDisposition::Suppress => EventDisposition::Suppress,
            CachedDisposition::Warn { rule, section } => EventDisposition::Warn {
                rule: rule.clone(),
                section: section.clone(),
            },
            CachedDisposition::Block { rule, section } => EventDisposition::Block {
                rule: rule.clone(),
                section: section.clone(),
            },
            CachedDisposition::Review { rule, section } => EventDisposition::Review {
                rule: rule.clone(),
                section: section.clone(),
            },
        }
    }
}

impl ActivePolicy {
    /// Load a policy from a YAML file, resolving `includes:` directives.
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let yaml = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read policy file '{}': {}", path, e))?;
        let engine = PolicyEngine::from_yaml_with_includes(&yaml, &include_resolver)
            .map_err(|e| anyhow::anyhow!("Failed to parse policy file '{}': {}", path, e))?;
        Ok(Self {
            engine,
            fn_cache: Default::default(),
        })
    }

    /// Load a policy from a YAML string, resolving `includes:` directives.
    pub fn from_yaml(yaml: &str) -> anyhow::Result<Self> {
        let engine = PolicyEngine::from_yaml_with_includes(yaml, &include_resolver)
            .map_err(|e| anyhow::anyhow!("Failed to parse policy YAML: {}", e))?;
        Ok(Self {
            engine,
            fn_cache: Default::default(),
        })
    }

    /// Load the built-in default security policy.
    #[cfg(test)]
    pub fn default_security() -> anyhow::Result<Self> {
        let engine = PolicyEngine::from_yaml(DEFAULT_SECURITY_YAML)
            .map_err(|e| anyhow::anyhow!("Failed to parse default security policy: {}", e))?;
        Ok(Self {
            engine,
            fn_cache: Default::default(),
        })
    }

    /// Derive hook configurations from policy rules.
    /// Each policy rule (allow or deny) needs an agent-side hook so we can intercept the call.
    pub fn derive_hook_configs(&self, capture_stack: bool) -> Vec<HookConfig> {
        let specs = self.engine.extract_hook_specs();
        let mut configs = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for spec in &specs {
            let config = hook_spec_to_config(spec, capture_stack);
            // Deduplicate by (hook_type, symbol) — same function may appear in allow + deny
            let key = (format!("{:?}", config.hook_type), config.symbol.clone());
            if seen.insert(key) {
                configs.push(config);
            }
        }

        configs
    }

    /// Evaluate a trace event against the policy.
    ///
    /// Performs three levels of evaluation:
    /// 1. Function-level: matches against python, node, etc.
    /// 2. Network info: uses structured `NetworkInfo` if available, otherwise
    ///    falls back to text-based extraction from argument display strings.
    ///
    /// Returns the strictest disposition (most restrictive wins).
    pub fn evaluate_trace(&self, event: &TraceEvent) -> EventDisposition {
        let func = &event.function;

        // Cache lookup for function-level disposition (skip Exec/EnvVar — names vary per call)
        let cache_key = if !matches!(event.hook_type, HookType::Exec | HookType::EnvVar) {
            let key = (hook_type_discriminant(&event.hook_type), func.to_string());
            if let Some(cached) = self.fn_cache.borrow().get(&key) {
                let disp = cached.to_disposition();
                // If blocked, return immediately; otherwise continue to network eval
                if disp.is_blocked() {
                    return disp;
                }
                // Have cached function-level result — skip to network eval
                return self.evaluate_network_phase(event, disp);
            }
            Some(key)
        } else {
            None
        };

        let args: Vec<&str> = event
            .arguments
            .iter()
            .filter_map(|a| a.display.as_deref())
            .collect();

        let decision = match event.hook_type {
            HookType::Python => self.engine.evaluate_function(Runtime::Python, func, &args),
            HookType::Nodejs => self.engine.evaluate_function(Runtime::Node, func, &args),
            HookType::Native => self.engine.evaluate_native_function(func, &args),
            HookType::Exec => {
                // Unwrap shell wrappers: sh -c "curl ..." → evaluate as "curl ..."
                let full_cmd = unwrap_shell_exec_args(func, &args).unwrap_or_else(|| {
                    // Build full command string: "cmd arg1 arg2" (skip argv[0])
                    let cmd_args: Vec<&str> = args.get(1..).unwrap_or(&[]).to_vec();
                    if cmd_args.is_empty() {
                        func.to_string()
                    } else {
                        format!("{} {}", func, cmd_args.join(" "))
                    }
                });
                self.engine.evaluate_execution(&full_cmd)
            }
            HookType::DirectSyscall => {
                let syscall_name = func.strip_prefix("syscall:").unwrap_or(func);
                self.engine.evaluate_syscall(syscall_name)
            }
            HookType::EnvVar => self.engine.evaluate_envvar(func),
        };

        let disp = decision_to_disposition(decision);

        // Cache the function-level result
        if let Some(key) = cache_key {
            self.fn_cache.borrow_mut().insert(key, disp.to_cached());
        }

        // If the function itself is already blocked, no need to check further
        if disp.is_blocked() {
            return disp;
        }

        let disp = self.evaluate_network_phase(event, disp);
        let disp = self.evaluate_file_phase(event, disp);
        self.evaluate_command_phase(event, disp)
    }

    /// Evaluate networking policy (URL, domain, endpoint, protocol) against a trace event.
    /// Takes the function-level disposition and returns the strictest combined result.
    fn evaluate_network_phase(
        &self,
        event: &TraceEvent,
        mut disp: EventDisposition,
    ) -> EventDisposition {
        // Prefer structured NetworkInfo when available (populated agent-side).
        // Falls back to text-based extraction for events without it.
        if let Some(ref net) = event.network_info {
            if let Some(net_disp) = self.evaluate_network_info(net) {
                disp = pick_stricter(disp, net_disp);
            }
        } else {
            // Fallback: text-based extraction from argument display strings
            let args: Vec<&str> = event
                .arguments
                .iter()
                .filter_map(|a| a.display.as_deref())
                .collect();
            if let Some(http_disp) = self.evaluate_http_from_args(&args) {
                disp = pick_stricter(disp, http_disp);
                if disp.is_blocked() {
                    return disp;
                }
            }
            if let Some(net_disp) = self.evaluate_networking_from_args(&args) {
                disp = pick_stricter(disp, net_disp);
            }
        }

        disp
    }

    /// Evaluate structured networking metadata against all networking policy sections.
    ///
    /// Checks HTTP URL rules, domain, endpoint, and protocol policies using
    /// the structured fields from `NetworkInfo` — no text parsing needed.
    fn evaluate_network_info(&self, info: &NetworkInfo) -> Option<EventDisposition> {
        let mut strictest: Option<EventDisposition> = None;

        // HTTP URL rules (network section, URL patterns)
        if let Some(ref url) = info.url {
            if url.contains("://") {
                if let Some(parsed) = ParsedUrl::parse(url) {
                    let full_url = parsed.full_url();
                    let no_scheme_url = parsed.url_without_scheme();
                    let decision = self.engine.evaluate_http_url(&full_url, &no_scheme_url);
                    let disp = decision_to_disposition(decision);
                    if disp.should_display() {
                        strictest = Some(pick_stricter_opt(strictest, disp));
                    }
                }
            }
        }

        // network domains
        if let Some(ref host) = info.host {
            let decision = self.engine.evaluate_domain(host);
            let disp = decision_to_disposition(decision);
            if disp.should_display() {
                strictest = Some(pick_stricter_opt(strictest, disp));
            }
        }

        // network endpoints
        if let (Some(ref host), Some(port)) = (&info.host, info.port) {
            let decision = self.engine.evaluate_endpoint(host, port);
            let disp = decision_to_disposition(decision);
            if disp.should_display() {
                strictest = Some(pick_stricter_opt(strictest, disp));
            }
        }

        // network protocols
        if let Some(ref protocol) = info.protocol {
            let decision = self.engine.evaluate_protocol(protocol.as_str());
            let disp = decision_to_disposition(decision);
            if disp.should_display() {
                strictest = Some(pick_stricter_opt(strictest, disp));
            }
        }

        strictest
    }

    /// Extract URL from arguments and evaluate against network URL rules.
    fn evaluate_http_from_args(&self, args: &[&str]) -> Option<EventDisposition> {
        for arg in args {
            if let Some(url) = extract_url_from_arg(arg) {
                if let Some(parsed) = ParsedUrl::parse(&url) {
                    let full_url = parsed.full_url();
                    let no_scheme_url = parsed.url_without_scheme();
                    let decision = self.engine.evaluate_http_url(&full_url, &no_scheme_url);
                    let disp = decision_to_disposition(decision);
                    if disp.should_display() {
                        return Some(disp);
                    }
                }
            }
        }
        None
    }

    /// Extract HTTP metadata (URL, domain, protocol) from argument strings
    /// and evaluate against networking policy sections.
    fn evaluate_networking_from_args(&self, args: &[&str]) -> Option<EventDisposition> {
        let mut strictest: Option<EventDisposition> = None;

        for arg in args {
            if let Some(url) = extract_url_from_arg(arg) {
                if let Some(parsed) = ParsedUrl::parse(&url) {
                    // Evaluate domain
                    let domain_decision = self.engine.evaluate_domain(&parsed.host);
                    let domain_disp = decision_to_disposition(domain_decision);
                    strictest = Some(pick_stricter_opt(strictest, domain_disp));

                    // Evaluate protocol
                    let proto_decision = self.engine.evaluate_protocol(&parsed.scheme);
                    let proto_disp = decision_to_disposition(proto_decision);
                    strictest = Some(pick_stricter_opt(strictest, proto_disp));

                    // Evaluate endpoint (host:port)
                    if let Some(port) = parsed.port {
                        let ep_decision = self.engine.evaluate_endpoint(&parsed.host, port);
                        let ep_disp = decision_to_disposition(ep_decision);
                        strictest = Some(pick_stricter_opt(strictest, ep_disp));
                    }
                }
            }
        }

        // Only return if we found a non-Suppress result
        strictest.filter(|d| d.should_display())
    }

    /// Evaluate file access against the `files:` policy section.
    ///
    /// Two paths:
    /// - Exec events: check command arguments for file paths
    /// - Native open/openat: extract the path from the call arguments
    fn evaluate_file_phase(&self, event: &TraceEvent, disp: EventDisposition) -> EventDisposition {
        match event.hook_type {
            HookType::Exec => self.evaluate_file_args_from_exec(event, disp),
            HookType::Native => self.evaluate_file_from_native(event, disp),
            _ => disp,
        }
    }

    /// Check command arguments for file paths (covers SIP-protected binaries).
    fn evaluate_file_args_from_exec(
        &self,
        event: &TraceEvent,
        disp: EventDisposition,
    ) -> EventDisposition {
        let args: Vec<&str> = event
            .arguments
            .iter()
            .filter_map(|a| a.display.as_deref())
            .collect();

        let mut strictest = disp;
        for arg in args.iter().skip(1) {
            // skip argv[0]
            if arg.starts_with('-') || arg.is_empty() {
                continue;
            }
            let normalized = normalize_path(arg);
            let decision = self.engine.evaluate_file(&normalized, Operation::Read);
            let file_disp = decision_to_disposition(decision);
            if file_disp.should_display() {
                strictest = pick_stricter(strictest, file_disp);
                if strictest.is_blocked() {
                    return strictest;
                }
            }
        }
        strictest
    }

    /// Extract path from open()/openat() args and evaluate against files: policy.
    fn evaluate_file_from_native(
        &self,
        event: &TraceEvent,
        disp: EventDisposition,
    ) -> EventDisposition {
        let func = &event.function;
        let args: Vec<&str> = event
            .arguments
            .iter()
            .filter_map(|a| a.display.as_deref())
            .collect();

        // Extract file path based on function
        let path_str = match func.as_str() {
            "open" | "_open" => args.first().and_then(|a| strip_quotes(a)),
            "openat" | "_openat" => args.get(1).and_then(|a| strip_quotes(a)),
            _ => return disp,
        };

        if let Some(path) = path_str {
            let normalized = normalize_path(path);
            let operation = detect_operation_from_flags(&args, func);
            let decision = self.engine.evaluate_file(&normalized, operation);
            let file_disp = decision_to_disposition(decision);
            if file_disp.should_display() {
                return pick_stricter(disp, file_disp);
            }
        }
        disp
    }

    /// Collect file deny/warn/log patterns from the `files:` policy section.
    fn file_deny_patterns(&self) -> Vec<&str> {
        let key = SectionKey::global(Category::Files);
        self.engine
            .policy()
            .get_section(&key)
            .map(|s| {
                s.deny_rules
                    .iter()
                    .map(|r| r.pattern.original())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Collect command deny/warn/log patterns from the `commands:` policy section.
    fn command_deny_patterns(&self) -> Vec<&str> {
        let key = SectionKey::global(Category::Execution);
        self.engine
            .policy()
            .get_section(&key)
            .map(|s| {
                s.deny_rules
                    .iter()
                    .map(|r| r.pattern.original())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Run the deterministic command triage layer on exec events.
    ///
    /// If suspicious, escalates the disposition to at least Warn.
    fn evaluate_command_phase(
        &self,
        event: &TraceEvent,
        disp: EventDisposition,
    ) -> EventDisposition {
        if event.hook_type != HookType::Exec || disp.is_blocked() {
            return disp;
        }
        let args: Vec<&str> = event
            .arguments
            .iter()
            .filter_map(|a| a.display.as_deref())
            .collect();
        let file_patterns = self.file_deny_patterns();
        let cmd_patterns = self.command_deny_patterns();
        match crate::command_analysis::analyze_command(
            &event.function,
            &args,
            &file_patterns,
            &cmd_patterns,
        ) {
            Some(analysis) => pick_stricter(
                disp,
                EventDisposition::Warn {
                    rule: analysis.reason,
                    section: "analysis".to_string(),
                },
            ),
            None => disp,
        }
    }

    /// Check if the policy has any sections with review or block mode.
    /// Used to determine if review mode should be enabled in the agent.
    pub fn has_blocking_sections(&self) -> bool {
        self.engine
            .policy()
            .iter_sections()
            .any(|(_, section)| section.mode.is_blocking())
    }
}

/// Parsed URL components for policy evaluation.
struct ParsedUrl {
    scheme: String,
    host: String,
    port: Option<u16>,
    /// Path component of the URL (everything after the authority, including leading /).
    /// Empty string if no path is present.
    path: String,
}

impl ParsedUrl {
    /// Parse a URL string into components.
    /// Handles http://, https://, ws://, wss:// schemes.
    fn parse(url: &str) -> Option<Self> {
        let (scheme, rest) = url.split_once("://")?;
        let scheme = scheme.to_lowercase();
        if !matches!(scheme.as_str(), "http" | "https" | "ws" | "wss") {
            return None;
        }

        // Split authority from path at first /
        let (authority, path) = if let Some(slash_pos) = rest.find('/') {
            (&rest[..slash_pos], &rest[slash_pos..])
        } else {
            (rest, "")
        };

        // Strip userinfo@ if present
        let authority = authority
            .rsplit_once('@')
            .map(|(_, h)| h)
            .unwrap_or(authority);

        let (host, explicit_port) = if authority.starts_with('[') {
            // IPv6: [::1]:port
            let bracket_end = authority.find(']')?;
            let host = &authority[1..bracket_end];
            let port = authority[bracket_end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse().ok());
            (host.to_string(), port)
        } else if let Some((h, p)) = authority.rsplit_once(':') {
            // host:port (only if p is numeric — avoids splitting IPv6 without brackets)
            if let Ok(port) = p.parse::<u16>() {
                (h.to_string(), Some(port))
            } else {
                (authority.to_string(), None)
            }
        } else {
            (authority.to_string(), None)
        };

        if host.is_empty() {
            return None;
        }

        // Default port based on scheme
        let port = explicit_port.or(match scheme.as_str() {
            "http" | "ws" => Some(80),
            "https" | "wss" => Some(443),
            _ => None,
        });

        Some(ParsedUrl {
            scheme,
            host,
            port,
            path: path.to_string(),
        })
    }

    /// Reconstruct the full URL for pattern matching.
    /// Format: "{scheme}://{host}[:{port}]{path}"
    /// Port is included only if it was explicitly specified (non-default).
    fn full_url(&self) -> String {
        let default_port = match self.scheme.as_str() {
            "http" | "ws" => Some(80),
            "https" | "wss" => Some(443),
            _ => None,
        };
        let port_suffix = match self.port {
            Some(p) if Some(p) != default_port => format!(":{}", p),
            _ => String::new(),
        };
        format!(
            "{}://{}{}{}",
            self.scheme, self.host, port_suffix, self.path
        )
    }

    /// Return the URL without scheme for matching patterns that omit the scheme.
    /// Format: "{host}[:{port}]{path}"
    fn url_without_scheme(&self) -> String {
        let default_port = match self.scheme.as_str() {
            "http" | "ws" => Some(80),
            "https" | "wss" => Some(443),
            _ => None,
        };
        let port_suffix = match self.port {
            Some(p) if Some(p) != default_port => format!(":{}", p),
            _ => String::new(),
        };
        format!("{}{}{}", self.host, port_suffix, self.path)
    }
}

/// Extract a URL from a formatted argument display string.
///
/// Handles formats produced by the Python/Node.js formatters:
/// - `url='https://example.com/path'`
/// - `url=https://example.com/path`
/// - `'https://example.com/path'`
/// - `https://example.com/path`
/// - `uri='wss://example.com'`
fn extract_url_from_arg(arg: &str) -> Option<String> {
    // Try "url=..." or "uri=..." prefix
    let value = if let Some(rest) = arg
        .strip_prefix("url=")
        .or_else(|| arg.strip_prefix("uri="))
    {
        rest
    } else {
        arg
    };

    // Strip trailing truncation marker "..." before stripping quotes,
    // since the formatter may produce: url='https://long-url'...
    let value = value.strip_suffix("...").unwrap_or(value);

    // Strip surrounding quotes
    let value = value.trim_matches('\'').trim_matches('"');

    // Must look like a URL
    if value.contains("://") {
        Some(value.to_string())
    } else {
        None
    }
}

/// Normalize a file path by collapsing `.` and `..` segments.
/// Prevents traversal bypasses like `/tmp/../../home/.ssh/id_rsa`.
pub(crate) fn normalize_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    let joined = parts.join("/");
    if path.starts_with('/') {
        format!("/{}", joined)
    } else {
        joined
    }
}

/// Remove surrounding double quotes from a formatted display string.
fn strip_quotes(s: &str) -> Option<&str> {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or(Some(s))
}

/// Determine Read vs Write operation from open() flags argument.
fn detect_operation_from_flags(args: &[&str], func: &str) -> Operation {
    let flags_str = match func {
        "open" | "_open" => args.get(1),
        "openat" | "_openat" => args.get(2),
        _ => None,
    };
    if let Some(flags) = flags_str {
        if flags.contains("O_WRONLY") || flags.contains("O_RDWR") || flags.contains("O_CREAT") {
            return Operation::Write;
        }
    }
    Operation::Read
}

/// Severity ranking for dispositions (higher = stricter).
fn disposition_severity(d: &EventDisposition) -> u8 {
    match d {
        EventDisposition::Suppress => 0,
        EventDisposition::Display => 1,
        EventDisposition::Warn { .. } => 2,
        EventDisposition::Review { .. } => 3,
        EventDisposition::Block { .. } => 4,
    }
}

/// Return the stricter of two dispositions.
fn pick_stricter(a: EventDisposition, b: EventDisposition) -> EventDisposition {
    if disposition_severity(&b) > disposition_severity(&a) {
        b
    } else {
        a
    }
}

/// Return the stricter of an optional and a new disposition.
fn pick_stricter_opt(current: Option<EventDisposition>, new: EventDisposition) -> EventDisposition {
    match current {
        Some(c) => pick_stricter(c, new),
        None => new,
    }
}

/// Compact discriminant for HookType used as cache key.
fn hook_type_discriminant(ht: &HookType) -> u8 {
    match ht {
        HookType::Native => 0,
        HookType::Python => 1,
        HookType::Nodejs => 2,
        HookType::Exec => 3,
        HookType::DirectSyscall => 4,
        HookType::EnvVar => 5,
    }
}

/// Convert a PolicyDecision to an EventDisposition.
fn decision_to_disposition(decision: PolicyDecision) -> EventDisposition {
    if decision.is_allowed() {
        return EventDisposition::Suppress;
    }

    // Denied — disposition depends on enforcement mode
    let rule = decision
        .matched_rule
        .unwrap_or_else(|| "(implicit)".to_string());
    let section = decision.section;

    match decision.mode {
        EnforcementMode::Block => EventDisposition::Block { rule, section },
        EnforcementMode::Review => EventDisposition::Review { rule, section },
        EnforcementMode::Warn => EventDisposition::Warn { rule, section },
        EnforcementMode::Log => EventDisposition::Display,
        EnforcementMode::Noop => EventDisposition::Suppress,
    }
}

/// Unwrap shell wrappers in exec event arguments for policy evaluation.
/// Given func="sh" and args=["sh", "-c", "curl -s https://evil.com"],
/// returns Some("curl -s https://evil.com") with basename applied to the command.
fn unwrap_shell_exec_args(func: &str, args: &[&str]) -> Option<String> {
    const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh"];

    let shell_basename = std::path::Path::new(func).file_name()?.to_str()?;
    if !SHELLS.contains(&shell_basename) {
        return None;
    }
    let c_idx = args.iter().position(|a| *a == "-c")?;
    let cmd_str = args.get(c_idx + 1)?;
    if cmd_str.is_empty() {
        return None;
    }
    // Replace the command path with its basename, keep the rest
    let first_space = cmd_str.find(char::is_whitespace);
    let cmd_path = match first_space {
        Some(idx) => &cmd_str[..idx],
        None => cmd_str,
    };
    let cmd_basename = std::path::Path::new(cmd_path).file_name()?.to_str()?;
    match first_space {
        Some(idx) => Some(format!("{}{}", cmd_basename, &cmd_str[idx..])),
        None => Some(cmd_basename.to_string()),
    }
}

/// Extract the command name from an exec pattern for agent-side filtering.
///
/// The exec filter only checks command basenames, so multi-word patterns
/// like "curl wikipedia.org" or "curl *" need to be reduced to just the
/// command name "curl". The CLI's evaluate_execution() handles full
/// command string matching with specificity.
fn exec_filter_name(pattern: &str) -> String {
    pattern
        .split_whitespace()
        .next()
        .unwrap_or(pattern)
        .to_string()
}

/// Convert a PolicyHookSpec to a HookConfig for the agent.
fn hook_spec_to_config(spec: &PolicyHookSpec, capture_stack: bool) -> HookConfig {
    match spec.kind {
        HookSpecKind::Syscall => {
            return HookConfig {
                hook_type: HookType::DirectSyscall,
                symbol: spec.pattern.clone(),
                arg_count: None,
                capture_return: false,
                capture_stack: false,
            };
        }
        HookSpecKind::EnvVar => {
            return HookConfig {
                hook_type: HookType::EnvVar,
                symbol: spec.pattern.clone(),
                arg_count: None,
                capture_return: false,
                capture_stack: false,
            };
        }
        _ => {}
    }
    if spec.kind == HookSpecKind::Command {
        HookConfig {
            hook_type: HookType::Exec,
            symbol: exec_filter_name(&spec.pattern),

            arg_count: None,
            capture_return: false,
            capture_stack,
        }
    } else {
        match spec.runtime {
            Some(Runtime::Python) => HookConfig {
                hook_type: HookType::Python,
                symbol: spec.pattern.clone(),

                arg_count: None,
                capture_return: true,
                capture_stack,
            },
            Some(Runtime::Node) => HookConfig {
                hook_type: HookType::Nodejs,
                symbol: spec.pattern.clone(),

                arg_count: None,
                capture_return: true,
                capture_stack,
            },
            None => HookConfig {
                hook_type: HookType::Native,
                symbol: spec.pattern.clone(),

                arg_count: Some(6),
                capture_return: true,
                capture_stack,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use malwi_protocol::{Argument, EventType, Protocol};

    fn make_trace_event(hook_type: HookType, function: &str, args: &[&str]) -> TraceEvent {
        TraceEvent {
            hook_type,
            event_type: EventType::Enter,
            function: function.to_string(),
            arguments: args
                .iter()
                .map(|s| Argument {
                    raw_value: 0,
                    display: Some(s.to_string()),
                })
                .collect(),
            native_stack: vec![],
            runtime_stack: None,
            network_info: None,
            source_file: None,
            source_line: None,
        }
    }

    fn make_trace_event_with_net(
        hook_type: HookType,
        function: &str,
        args: &[&str],
        net: NetworkInfo,
    ) -> TraceEvent {
        let mut event = make_trace_event(hook_type, function, args);
        event.network_info = Some(net);
        event
    }

    /// Make a TraceEvent that looks like an exec event (as produced by child_info_to_trace_event).
    /// argv[0] = cmd_name (same as function), argv[1..] = args
    fn make_exec_event(cmd: &str, args: &[&str]) -> TraceEvent {
        let mut all_args: Vec<&str> = vec![cmd];
        all_args.extend_from_slice(args);
        make_trace_event(HookType::Exec, cmd, &all_args)
    }

    #[test]
    fn test_default_security_loads() {
        let policy = ActivePolicy::default_security().unwrap();
        // Should derive some hook configs
        let configs = policy.derive_hook_configs(false);
        assert!(!configs.is_empty());
    }

    #[test]
    fn test_default_security_warns_python_getpass() {
        let policy = ActivePolicy::default_security().unwrap();

        let event = make_trace_event(HookType::Python, "getpass.getpass", &[]);
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "getpass.getpass should be warned");
    }

    #[test]
    fn test_default_security_logs_nodejs_dns() {
        let policy = ActivePolicy::default_security().unwrap();

        let event = make_trace_event(HookType::Nodejs, "dns.lookup", &["example.com"]);
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "dns.lookup should be logged");
    }

    #[test]
    fn test_default_security_denies_native_getpass() {
        let policy = ActivePolicy::default_security().unwrap();

        let event = make_trace_event(HookType::Native, "getpass", &[]);
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display());
    }

    #[test]
    fn test_default_security_allows_unlisted_native() {
        let policy = ActivePolicy::default_security().unwrap();

        let event = make_trace_event(HookType::Native, "printf", &["hello"]);
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display());
    }

    #[test]
    fn test_default_security_denies_curl_exec() {
        let policy = ActivePolicy::default_security().unwrap();

        let event = make_exec_event("curl", &["https://evil.com"]);
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display());
    }

    #[test]
    fn test_default_security_allows_unlisted_exec() {
        let policy = ActivePolicy::default_security().unwrap();

        let event = make_exec_event("ls", &["-la"]);
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display());
    }

    #[test]
    fn test_hook_derivation_covers_all_categories() {
        let policy = ActivePolicy::default_security().unwrap();
        let configs = policy.derive_hook_configs(false);

        let has_native = configs
            .iter()
            .any(|c| matches!(c.hook_type, HookType::Native));
        let has_python = configs
            .iter()
            .any(|c| matches!(c.hook_type, HookType::Python));
        let has_nodejs = configs
            .iter()
            .any(|c| matches!(c.hook_type, HookType::Nodejs));
        let has_exec = configs
            .iter()
            .any(|c| matches!(c.hook_type, HookType::Exec));

        assert!(has_native, "Should have native hooks");
        assert!(has_python, "Should have Python hooks");
        assert!(has_nodejs, "Should have Node.js hooks");
        assert!(has_exec, "Should have exec hooks");
    }

    #[test]
    fn test_hook_deduplication() {
        let policy = ActivePolicy::default_security().unwrap();
        let configs = policy.derive_hook_configs(false);

        // Check no duplicate (type, symbol) pairs
        let mut seen = std::collections::HashSet::new();
        for config in &configs {
            let key = (format!("{:?}", config.hook_type), config.symbol.clone());
            assert!(
                seen.insert(key),
                "Duplicate hook: {:?} {}",
                config.hook_type,
                config.symbol
            );
        }
    }

    #[test]
    fn test_disposition_block() {
        let policy = ActivePolicy::from_file("/dev/null").unwrap_or_else(|_| {
            // Use inline YAML
            let engine =
                PolicyEngine::from_yaml("version: 1\npython:\n  deny:\n    - eval\n").unwrap();
            ActivePolicy {
                engine,
                fn_cache: Default::default(),
            }
        });

        let event = make_trace_event(HookType::Python, "eval", &[]);
        let disp = policy.evaluate_trace(&event);
        assert!(disp.is_blocked()); // Default mode is Block
    }

    #[test]
    fn test_disposition_suppress() {
        let policy = ActivePolicy::default_security().unwrap();

        // Unlisted function — not in any warn/log list, so it's suppressed
        let event = make_trace_event(HookType::Python, "json.loads", &["{}"]);
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display());
    }

    #[test]
    fn test_shell_unwrapped_curl_logged() {
        // Shell unwrapping now happens in child_info_to_trace_event (agent_server).
        // By the time evaluate_trace sees it, function="curl" and args=["curl", "-s", "https://evil.com"].
        let policy = ActivePolicy::default_security().unwrap();

        let event = make_exec_event("curl", &["-s", "https://evil.com"]);
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "unwrapped curl should be logged");
    }

    #[test]
    fn test_shell_unwrapped_allowed_command() {
        let policy = ActivePolicy::default_security().unwrap();

        let event = make_exec_event("ls", &["-la", "/tmp"]);
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "unwrapped ls should be allowed");
    }

    // =====================================================================
    // Tests for two-pass execution through evaluate_trace with exec events
    // =====================================================================

    #[test]
    fn test_evaluate_exec_allow_specific_deny_general() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
commands:
  allow:
    - "curl example.com"
  deny:
    - curl
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // "curl example.com" should be allowed (specific allow overrides general deny)
        let event = make_exec_event("curl", &["example.com"]);
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "curl example.com should be allowed");

        // "curl evil.com" should be denied (no specific allow, general deny matches)
        let event = make_exec_event("curl", &["evil.com"]);
        let disp = policy.evaluate_trace(&event);
        assert!(disp.is_blocked(), "curl evil.com should be blocked");

        // bare "curl" should be denied
        let event = make_exec_event("curl", &[]);
        let disp = policy.evaluate_trace(&event);
        assert!(disp.is_blocked(), "bare curl should be blocked");
    }

    #[test]
    fn test_evaluate_exec_shell_unwrapped_allow_specific() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
commands:
  allow:
    - "curl example.com"
  deny:
    - curl
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // After shell unwrapping, "sh -c 'curl example.com'" becomes exec event:
        // function="curl", args=["curl", "example.com"]
        let event = make_exec_event("curl", &["example.com"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            !disp.should_display(),
            "unwrapped 'curl example.com' should be allowed"
        );

        // "sh -c 'curl evil.com'" → function="curl", args=["curl", "evil.com"]
        let event = make_exec_event("curl", &["evil.com"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "unwrapped 'curl evil.com' should be blocked"
        );
    }

    // =====================================================================
    // Tests for URL extraction from formatted arguments
    // =====================================================================

    #[test]
    fn test_extract_url_from_formatted_arg() {
        // Python formatter style: url='https://example.com/path'
        assert_eq!(
            extract_url_from_arg("url='https://example.com/path'"),
            Some("https://example.com/path".to_string())
        );

        // Without quotes
        assert_eq!(
            extract_url_from_arg("url=https://example.com/path"),
            Some("https://example.com/path".to_string())
        );

        // Bare URL
        assert_eq!(
            extract_url_from_arg("'https://example.com'"),
            Some("https://example.com".to_string())
        );

        // WebSocket URI
        assert_eq!(
            extract_url_from_arg("uri='wss://ws.example.com'"),
            Some("wss://ws.example.com".to_string())
        );

        // Truncated URL (with ...)
        assert_eq!(
            extract_url_from_arg("url='https://example.com/very/long/path'..."),
            Some("https://example.com/very/long/path".to_string())
        );

        // Not a URL
        assert_eq!(extract_url_from_arg("method=GET"), None);
        assert_eq!(extract_url_from_arg("42"), None);
    }

    #[test]
    fn test_parsed_url_basic() {
        let url = ParsedUrl::parse("https://example.com/path").unwrap();
        assert_eq!(url.scheme, "https");
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, Some(443));
        assert_eq!(url.path, "/path");

        let url = ParsedUrl::parse("http://api.example.com:8080/data").unwrap();
        assert_eq!(url.scheme, "http");
        assert_eq!(url.host, "api.example.com");
        assert_eq!(url.port, Some(8080));
        assert_eq!(url.path, "/data");
    }

    #[test]
    fn test_parsed_url_websocket() {
        let url = ParsedUrl::parse("ws://localhost:3000").unwrap();
        assert_eq!(url.scheme, "ws");
        assert_eq!(url.host, "localhost");
        assert_eq!(url.port, Some(3000));
        assert_eq!(url.path, "");

        let url = ParsedUrl::parse("wss://ws.example.com").unwrap();
        assert_eq!(url.scheme, "wss");
        assert_eq!(url.host, "ws.example.com");
        assert_eq!(url.port, Some(443));
    }

    #[test]
    fn test_parsed_url_path_preserved() {
        let url = ParsedUrl::parse("https://api.example.com/v1/users/123").unwrap();
        assert_eq!(url.path, "/v1/users/123");

        let url = ParsedUrl::parse("https://example.com").unwrap();
        assert_eq!(url.path, "");

        let url = ParsedUrl::parse("https://example.com/").unwrap();
        assert_eq!(url.path, "/");
    }

    #[test]
    fn test_parsed_url_full_url() {
        let url = ParsedUrl::parse("https://example.com/path").unwrap();
        assert_eq!(url.full_url(), "https://example.com/path");

        let url = ParsedUrl::parse("http://api.example.com:8080/data").unwrap();
        assert_eq!(url.full_url(), "http://api.example.com:8080/data");

        // Default port should not be included
        let url = ParsedUrl::parse("https://example.com:443/test").unwrap();
        assert_eq!(url.full_url(), "https://example.com/test");

        let url = ParsedUrl::parse("http://example.com:80/test").unwrap();
        assert_eq!(url.full_url(), "http://example.com/test");
    }

    #[test]
    fn test_parsed_url_without_scheme() {
        let url = ParsedUrl::parse("https://example.com/path").unwrap();
        assert_eq!(url.url_without_scheme(), "example.com/path");

        let url = ParsedUrl::parse("http://api.example.com:8080/data").unwrap();
        assert_eq!(url.url_without_scheme(), "api.example.com:8080/data");
    }

    #[test]
    fn test_parsed_url_no_scheme() {
        assert!(ParsedUrl::parse("example.com").is_none());
        assert!(ParsedUrl::parse("ftp://example.com").is_none());
    }

    // =====================================================================
    // Tests for networking policy evaluation from trace events
    // =====================================================================

    #[test]
    fn test_domain_policy_denies_via_url_arg() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
network:
  deny:
    - "*.evil.com"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // Python requests.get with URL to evil domain
        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://malware.evil.com/payload'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "evil.com domain should be flagged");

        // Safe domain should be suppressed
        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://api.example.com/data'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "example.com should be allowed");
    }

    #[test]
    fn test_protocol_policy_denies_http() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
network:
  protocols: [https]
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // HTTP (not in allowed list) — should be denied
        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='http://example.com/insecure'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "http should be denied when only https allowed"
        );

        // HTTPS — should be allowed
        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://example.com/secure'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "https should be allowed");
    }

    #[test]
    fn test_endpoint_policy_denies_port() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
network:
  deny:
    - "*:22"
    - "*:25"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // Port 22 should be denied
        let event = make_trace_event(
            HookType::Nodejs,
            "http.request",
            &["url='http://example.com:22/ssh-tunnel'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "port 22 should be denied");

        // Port 443 should be allowed
        let event = make_trace_event(
            HookType::Nodejs,
            "http.request",
            &["url='https://example.com/safe'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "port 443 should be allowed");
    }

    #[test]
    fn test_function_deny_and_domain_deny_both_trigger() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
python:
  deny:
    - "requests.get"
network:
  deny:
    - "*.evil.com"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // Both function and domain denied — should be blocked
        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://malware.evil.com'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.is_blocked(), "function deny should win (blocked)");
    }

    #[test]
    fn test_function_allowed_but_domain_denied() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
network:
  deny:
    - "*.evil.com"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // Function is allowed (no function rules), but domain is denied
        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://malware.evil.com'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "domain deny should still trigger");
    }

    #[test]
    fn test_no_url_in_args_skips_networking() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
network:
  deny:
    - "*.evil.com"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // Event with no URL in args — networking check skipped
        let event = make_trace_event(HookType::Python, "json.loads", &["'{\"key\": \"value\"}'"]);
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "no URL = no networking check");
    }

    #[test]
    fn test_nodejs_bare_url_extraction() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
network:
  deny:
    - "*.evil.com"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // Node.js may pass URLs as bare string args without url= prefix
        let event = make_trace_event(
            HookType::Nodejs,
            "https.request",
            &["'https://download.evil.com/malware'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "bare URL should be extracted");
    }

    #[test]
    fn test_disposition_severity_ordering() {
        assert!(
            disposition_severity(&EventDisposition::Suppress)
                < disposition_severity(&EventDisposition::Display)
        );
        assert!(
            disposition_severity(&EventDisposition::Display)
                < disposition_severity(&EventDisposition::Warn {
                    rule: String::new(),
                    section: String::new()
                })
        );
        assert!(
            disposition_severity(&EventDisposition::Warn {
                rule: String::new(),
                section: String::new()
            }) < disposition_severity(&EventDisposition::Block {
                rule: String::new(),
                section: String::new()
            })
        );
    }

    // =====================================================================
    // Tests for HTTP URL policy evaluation via evaluate_trace()
    // =====================================================================

    #[test]
    fn test_http_url_policy_denies_evil_domain() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
network:
  deny:
    - "*.evil.com/**"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://malware.evil.com/payload'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "evil.com URL should be denied by http section"
        );
    }

    #[test]
    fn test_http_url_policy_allows_safe_url() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
network:
  deny:
    - "*.evil.com/**"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://api.example.com/data'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "safe URL should be allowed");
    }

    #[test]
    fn test_http_url_policy_path_deny() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
network:
  deny:
    - "**/admin/**"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://example.com/admin/users'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "/admin/ path should be denied");

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://example.com/api/data'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "/api/ path should be allowed");
    }

    #[test]
    fn test_http_url_policy_deny_http_scheme() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
network:
  deny:
    - "http://**"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='http://example.com/insecure'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "http:// should be denied");

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://example.com/secure'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "https:// should be allowed");
    }

    #[test]
    fn test_http_url_policy_allow_with_implicit_deny() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
network:
  allow:
    - "pypi.org/**"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // Allowed URL — should be suppressed
        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://pypi.org/simple/requests/'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "pypi.org should be allowed");

        // Disallowed URL — implicit deny (allow rules present)
        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://evil.com/malware'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "non-pypi URL should be denied");

        // Node.js event to same disallowed URL — also denied (global section)
        let event = make_trace_event(
            HookType::Nodejs,
            "http.request",
            &["url='https://evil.com/malware'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "global network section affects all runtimes"
        );
    }

    #[test]
    fn test_network_url_and_domain_patterns_both_evaluated() {
        // In the network section, URL patterns (with /) and domain patterns (bare)
        // both auto-classify and evaluate independently.
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
network:
  deny:
    - "*.evil.com/**"
    - "*.bad.com"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // evil.com caught by URL pattern (has /)
        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://x.evil.com/path'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "evil.com should be denied by URL pattern"
        );

        // bad.com caught by domain pattern (bare hostname)
        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://x.bad.com/path'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "bad.com should be denied by domain pattern"
        );
    }

    // =====================================================================
    // Tests for structured NetworkInfo evaluation
    // =====================================================================

    #[test]
    fn test_network_info_domain_deny() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
network:
  deny:
    - "*.evil.com"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let net = NetworkInfo {
            url: Some("https://malware.evil.com/payload".to_string()),
            host: Some("malware.evil.com".to_string()),
            port: Some(443),
            protocol: Some(Protocol::Https),
        };
        let event = make_trace_event_with_net(
            HookType::Python,
            "requests.get",
            &["url='https://malware.evil.com/payload'"],
            net,
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "evil.com domain via NetworkInfo should be flagged"
        );
    }

    #[test]
    fn test_network_info_endpoint_deny() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
network:
  deny:
    - "*:22"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // Port 22 via raw socket — NetworkInfo has host+port but no URL
        let net = NetworkInfo {
            host: Some("10.0.0.1".to_string()),
            port: Some(22),
            protocol: Some(Protocol::Tcp),
            ..Default::default()
        };
        let event = make_trace_event_with_net(
            HookType::Python,
            "socket.connect",
            &["address=('10.0.0.1', 22)"],
            net,
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "port 22 via socket.connect should be denied"
        );

        // Port 80 should be allowed
        let net = NetworkInfo {
            host: Some("example.com".to_string()),
            port: Some(80),
            protocol: Some(Protocol::Tcp),
            ..Default::default()
        };
        let event = make_trace_event_with_net(
            HookType::Python,
            "socket.connect",
            &["address=('example.com', 80)"],
            net,
        );
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "port 80 should be allowed");
    }

    #[test]
    fn test_network_info_protocol_deny() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
network:
  protocols: [https]
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // HTTP via NetworkInfo — should be denied
        let net = NetworkInfo {
            url: Some("http://example.com/insecure".to_string()),
            host: Some("example.com".to_string()),
            port: Some(80),
            protocol: Some(Protocol::Http),
        };
        let event = make_trace_event_with_net(
            HookType::Python,
            "requests.get",
            &["url='http://example.com/insecure'"],
            net,
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "http protocol should be denied when only https allowed"
        );
    }

    #[test]
    fn test_network_info_http_url_deny() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
network:
  deny:
    - "*.evil.com/**"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let net = NetworkInfo {
            url: Some("https://x.evil.com/payload".to_string()),
            host: Some("x.evil.com".to_string()),
            port: Some(443),
            protocol: Some(Protocol::Https),
        };
        let event = make_trace_event_with_net(HookType::Python, "requests.get", &[], net);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "evil.com URL via NetworkInfo should be denied by network section"
        );
    }

    #[test]
    fn test_network_info_socket_no_url_still_evaluates_endpoint() {
        // This is the key test: raw socket.connect with no URL should still
        // be evaluated against endpoint policies via NetworkInfo.
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
network:
  deny:
    - "*:6379"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // socket.connect to Redis port — no URL, just host+port
        let net = NetworkInfo {
            host: Some("redis.internal".to_string()),
            port: Some(6379),
            protocol: Some(Protocol::Tcp),
            ..Default::default()
        };
        let event = make_trace_event_with_net(
            HookType::Python,
            "socket.connect",
            &["address=('redis.internal', 6379)"],
            net,
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "port 6379 via socket.connect should be denied"
        );
    }

    #[test]
    fn test_fallback_to_text_extraction_when_no_network_info() {
        // When network_info is None, should still work via text extraction
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
network:
  deny:
    - "*.evil.com"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // Event without network_info — should use text extraction fallback
        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://malware.evil.com/payload'"],
        );
        assert!(event.network_info.is_none());
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "text fallback should still work");
    }

    // =====================================================================
    // Tests for exec_filter_name extraction
    // =====================================================================

    #[test]
    fn test_exec_filter_name_extraction() {
        assert_eq!(exec_filter_name("curl"), "curl");
        assert_eq!(exec_filter_name("curl wikipedia.org"), "curl");
        assert_eq!(exec_filter_name("curl *"), "curl");
        assert_eq!(exec_filter_name("pip install *"), "pip");
        assert_eq!(exec_filter_name("*"), "*");
        assert_eq!(exec_filter_name("*sudo*"), "*sudo*");
        assert_eq!(exec_filter_name("git push --force"), "git");
    }

    #[test]
    fn test_exec_hook_specs_use_command_name_only() {
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
commands:
  allow:
    - "curl wikipedia.org"
  deny:
    - "curl *"
"#,
        )
        .unwrap();
        let configs = policy.derive_hook_configs(false);
        let exec_configs: Vec<_> = configs
            .iter()
            .filter(|c| matches!(c.hook_type, HookType::Exec))
            .collect();
        // Both patterns should produce a single "curl" filter (deduped)
        assert_eq!(
            exec_configs.len(),
            1,
            "should deduplicate to single 'curl' filter"
        );
        assert_eq!(exec_configs[0].symbol, "curl");
    }

    // =====================================================================
    // Tests for EnvVar evaluation
    // =====================================================================

    #[test]
    fn test_default_security_warns_envvar_secret() {
        let policy = ActivePolicy::default_security().unwrap();

        let event = make_trace_event(HookType::EnvVar, "AWS_SECRET_ACCESS_KEY", &[]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "AWS_SECRET_ACCESS_KEY should be warned"
        );
    }

    #[test]
    fn test_default_security_warns_envvar_token() {
        let policy = ActivePolicy::default_security().unwrap();

        let event = make_trace_event(HookType::EnvVar, "GITHUB_TOKEN", &[]);
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "GITHUB_TOKEN should be warned");
    }

    #[test]
    fn test_default_security_allows_unlisted_envvar() {
        let policy = ActivePolicy::default_security().unwrap();

        let event = make_trace_event(HookType::EnvVar, "HOME", &[]);
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "HOME should not be warned");
    }

    #[test]
    fn test_envvar_hook_config_emitted() {
        let policy = ActivePolicy::default_security().unwrap();
        let configs = policy.derive_hook_configs(false);
        let has_envvar = configs
            .iter()
            .any(|c| matches!(c.hook_type, HookType::EnvVar));
        assert!(
            has_envvar,
            "Should have EnvVar hook config from default policy"
        );
    }

    // =====================================================================
    // Tests for file access evaluation (defense-in-depth)
    // =====================================================================

    #[test]
    fn test_exec_cat_ssh_key_blocked_by_files() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
commands:
  allow:
    - cat
files:
  deny:
    - "*/.ssh/**"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // cat ~/.ssh/id_rsa — command allowed, but file denied
        let event = make_exec_event("cat", &["~/.ssh/id_rsa"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "cat ~/.ssh/id_rsa should be blocked by files: deny"
        );
    }

    #[test]
    fn test_exec_cat_safe_file_allowed() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
commands:
  allow:
    - cat
files:
  deny:
    - "*/.ssh/**"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // cat /tmp/ok.txt — command allowed, file not denied
        let event = make_exec_event("cat", &["/tmp/ok.txt"]);
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "cat /tmp/ok.txt should be allowed");
    }

    #[test]
    fn test_native_open_ssh_key_blocked() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
files:
  deny:
    - "*/.ssh/**"
    - "*id_rsa*"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // Native open() with quoted path (as formatted by agent)
        let event = make_trace_event(
            HookType::Native,
            "open",
            &["\"/Users/mav/.ssh/id_rsa\"", "O_RDONLY"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "open(\"/Users/mav/.ssh/id_rsa\") should be blocked by files: deny"
        );
    }

    #[test]
    fn test_native_openat_denied_file() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
files:
  deny:
    - "*.pem"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // Native openat() — path is second arg (after dirfd)
        let event = make_trace_event(
            HookType::Native,
            "openat",
            &["-100", "\"/tmp/server.pem\"", "O_RDONLY"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "openat(-100, \"/tmp/server.pem\") should be blocked by files: deny"
        );
    }

    #[test]
    fn test_native_open_safe_file_suppressed() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
files:
  deny:
    - "*/.ssh/**"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let event = make_trace_event(HookType::Native, "open", &["\"/tmp/ok.txt\"", "O_RDONLY"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            !disp.should_display(),
            "open(\"/tmp/ok.txt\") should be suppressed"
        );
    }

    #[test]
    fn test_normalize_path_collapses_dotdot() {
        assert_eq!(
            normalize_path("/tmp/../../home/.ssh/id_rsa"),
            "/home/.ssh/id_rsa"
        );
    }

    #[test]
    fn test_normalize_path_preserves_absolute() {
        assert_eq!(
            normalize_path("/Users/mav/.ssh/id_rsa"),
            "/Users/mav/.ssh/id_rsa"
        );
    }

    #[test]
    fn test_normalize_path_relative() {
        assert_eq!(normalize_path("foo/./bar/../baz"), "foo/baz");
    }

    #[test]
    fn test_detect_operation_write() {
        let args = vec!["\"/tmp/out\"", "O_WRONLY|O_CREAT"];
        assert!(matches!(
            detect_operation_from_flags(&args, "open"),
            Operation::Write
        ));
    }

    #[test]
    fn test_detect_operation_read() {
        let args = vec!["\"/tmp/in\"", "O_RDONLY"];
        assert!(matches!(
            detect_operation_from_flags(&args, "open"),
            Operation::Read
        ));
    }

    #[test]
    fn test_strip_quotes_removes_double_quotes() {
        assert_eq!(strip_quotes("\"/tmp/file\""), Some("/tmp/file"));
    }

    #[test]
    fn test_strip_quotes_passes_through_unquoted() {
        assert_eq!(strip_quotes("/tmp/file"), Some("/tmp/file"));
    }

    #[test]
    fn test_exec_skips_flags_in_file_check() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
commands:
  allow:
    - cat
files:
  deny:
    - "*/.ssh/**"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // cat -n /tmp/ok.txt — flags should be skipped
        let event = make_exec_event("cat", &["-n", "/tmp/ok.txt"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            !disp.should_display(),
            "cat -n /tmp/ok.txt should be allowed (flags skipped)"
        );
    }

    #[test]
    fn test_exec_dotdot_traversal_blocked() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
commands:
  allow:
    - cat
files:
  deny:
    - "*/.ssh/**"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // Path traversal: /tmp/../../home/user/.ssh/id_rsa → /home/user/.ssh/id_rsa
        let event = make_exec_event("cat", &["/tmp/../../home/user/.ssh/id_rsa"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "path traversal to .ssh should be blocked"
        );
    }

    #[test]
    fn test_file_phase_skips_non_exec_non_native() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
files:
  deny:
    - "*/.ssh/**"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        // Python event — file phase should be a no-op
        let event = make_trace_event(HookType::Python, "open", &["~/.ssh/id_rsa"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            !disp.should_display(),
            "Python open() should not be checked by file phase (no python: rules)"
        );
    }

    // =====================================================================
    // Tests for command analysis integration
    // =====================================================================

    #[test]
    fn test_command_analysis_ln_sensitive_warns() {
        // `ln` is allowed by commands, but targeting ~/.ssh triggers analysis warning
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
commands:
  allow:
    - ln
files:
  warn:
    - "*/.ssh/**"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let event = make_exec_event("ln", &["-s", "~/.ssh", "/tmp/x"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "ln -s ~/.ssh /tmp/x should be warned by command analysis"
        );
    }

    #[test]
    fn test_command_analysis_blocked_stays_blocked() {
        // If curl is already blocked by commands: deny, analysis doesn't downgrade
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
commands:
  deny:
    - curl
files:
  warn:
    - "*/.ssh/**"
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let event = make_exec_event("curl", &["file:///etc/passwd"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "blocked curl should stay blocked even with suspicious args"
        );
    }

    #[test]
    fn test_command_analysis_curl_file_protocol_warns() {
        // curl is in the log list; file:// protocol triggers analysis warning
        let engine = PolicyEngine::from_yaml(
            r#"
version: 1
commands:
  log:
    - curl
"#,
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let event = make_exec_event("curl", &["file:///etc/passwd"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            matches!(disp, EventDisposition::Warn { .. }),
            "curl file:///etc/passwd should be warned by analysis"
        );
    }
}
