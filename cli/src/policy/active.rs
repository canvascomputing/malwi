//! Core policy evaluation bridge.
//!
//! Contains the `ActivePolicy` struct, `EventDisposition` type, and the
//! top-level `evaluate_trace()` dispatch that runs four sequential phases:
//!
//! ```text
//! evaluate_trace                  (orchestrator: runs all 4 phases in order)
//! +-- evaluate_function_phase     (phase 1: function-level, cached for Python/Node/Native)
//! |   +-- compute_function_decision  (raw engine dispatch)
//! +-- evaluate_network_phase      (phase 2: network eval, in network.rs)
//! +-- evaluate_file_phase         (phase 3: file path checks, in files.rs)
//! +-- evaluate_command_phase      (phase 4: command triage, in commands.rs)
//! ```
//!
//! Phase-specific evaluation methods (network, files, commands) are in sibling modules.

use crate::policy::{Category, EnforcementMode, PolicyDecision, PolicyEngine, Runtime, SectionKey};
use malwi_intercept::{HookConfig, HookType, TraceEvent};

// ── Types ──────────────────────────────────────────────────────

/// The disposition of a trace event after policy evaluation.
#[derive(Debug, Clone, PartialEq)]
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
    /// Matched a hide rule — silently non-existent, no display, no event.
    Hide,
}

#[allow(dead_code)]
impl EventDisposition {
    /// Whether this event should be shown to the user.
    pub fn should_display(&self) -> bool {
        !matches!(self, EventDisposition::Suppress | EventDisposition::Hide)
    }

    /// Whether this event requires review mode interaction.
    pub fn requires_review(&self) -> bool {
        matches!(self, EventDisposition::Review { .. })
    }

    /// Whether this event should be blocked.
    pub fn is_blocked(&self) -> bool {
        matches!(self, EventDisposition::Block { .. })
    }
}

/// Active policy loaded and ready for evaluation.
pub struct ActivePolicy {
    pub(super) engine: PolicyEngine,
    /// Cache: (hook_type discriminant, function_name) → function-level disposition only.
    /// Arg-dependent phases (network, file, command) always run regardless of cache hits.
    pub(super) fn_cache:
        std::cell::RefCell<std::collections::HashMap<(u8, String), EventDisposition>>,
    /// Whether the policy has any network allow rules (Http, Domains, or Endpoints).
    /// Computed once at construction time since the policy is immutable after load.
    has_network_allow: bool,
    /// Whether the policy has any commands allow rules (implicit deny for unlisted).
    /// When true, a wildcard `*` exec filter is emitted so the agent intercepts
    /// all spawned commands, letting the CLI evaluate them against the allowlist.
    has_commands_allow: bool,
}

// ── Construction ───────────────────────────────────────────────

impl ActivePolicy {
    /// Create an ActivePolicy from a PolicyEngine, computing cached fields.
    pub(super) fn new(engine: PolicyEngine) -> Self {
        let has_network_allow = compute_has_network_allow(&engine);
        let has_commands_allow = compute_has_commands_allow(&engine);
        Self {
            engine,
            fn_cache: Default::default(),
            has_network_allow,
            has_commands_allow,
        }
    }

    /// Load a policy from a YAML file, resolving `includes:` directives.
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let yaml = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read policy file '{}': {}", path, e))?;
        let engine = PolicyEngine::from_yaml_with_includes(&yaml, &include_resolver)
            .map_err(|e| anyhow::anyhow!("Failed to parse policy file '{}': {}", path, e))?;
        Ok(Self::new(engine))
    }

    /// Load a policy from a YAML string, resolving `includes:` directives.
    #[cfg(test)]
    pub fn from_yaml(yaml: &str) -> anyhow::Result<Self> {
        let engine = PolicyEngine::from_yaml_with_includes(yaml, &include_resolver)
            .map_err(|e| anyhow::anyhow!("Failed to parse policy YAML: {}", e))?;
        Ok(Self::new(engine))
    }

    /// Load the built-in default security policy.
    #[cfg(test)]
    pub fn default_security() -> anyhow::Result<Self> {
        let engine = PolicyEngine::from_yaml(&super::templates::DEFAULT_SECURITY_YAML)
            .map_err(|e| anyhow::anyhow!("Failed to parse default security policy: {}", e))?;
        Ok(Self::new(engine))
    }
}

/// Resolve an `includes:` name to a YAML string using the embedded policy templates.
fn include_resolver(name: &str) -> Option<String> {
    super::templates::embedded_policy(name)
}

/// Check if a policy engine has any network allow rules (unified Network section).
/// Called once at construction time; result is cached on `ActivePolicy`.
///
/// `Category::Protocols` is intentionally excluded: a protocol-only allowlist
/// (e.g. `protocols: [https]`) constrains *how* connections are made, not *where*
/// they go. Passthrough exists to let URL/domain allow rules work; a protocol
/// allowlist alone doesn't express "allow specific hosts" and shouldn't unlock
/// native socket passthrough.
fn compute_has_network_allow(engine: &PolicyEngine) -> bool {
    let policy = engine.policy();
    let key = SectionKey::global(Category::Network);
    if let Some(section) = policy.get_section(&key) {
        return section.has_allow_rules();
    }
    false
}

/// Check if a policy engine has any commands allow rules (Execution category).
/// When commands: allow exists, unlisted commands are implicitly denied,
/// so we need a wildcard exec filter to intercept all spawned commands.
fn compute_has_commands_allow(engine: &PolicyEngine) -> bool {
    let policy = engine.policy();
    let key = SectionKey::global(Category::Execution);
    if let Some(section) = policy.get_section(&key) {
        return section.has_allow_rules();
    }
    false
}

// ── Public Queries ─────────────────────────────────────────────

impl ActivePolicy {
    /// Check if the policy has any sections with review or block mode.
    /// Used to determine if review mode should be enabled in the agent.
    pub fn has_blocking_sections(&self) -> bool {
        self.engine
            .policy()
            .iter_sections()
            .any(|(_, section)| section.mode.is_blocking())
    }
}

// ── Hook Derivation ────────────────────────────────────────────

/// Type alias for the dedup set used during hook config derivation.
type SeenSet = std::collections::HashSet<(String, String)>;

/// Map a policy runtime to the corresponding agent HookType.
fn runtime_to_hook_type(runtime: Option<Runtime>) -> HookType {
    match runtime {
        None => HookType::Native,
        Some(Runtime::Python) => HookType::Python,
        Some(Runtime::Node) => HookType::Nodejs,
    }
}

/// Insert a HookConfig if not already seen (dedup by hook_type + symbol).
fn emit_config(config: HookConfig, configs: &mut Vec<HookConfig>, seen: &mut SeenSet) {
    let key = (format!("{:?}", config.hook_type), config.symbol.clone());
    if seen.insert(key) {
        configs.push(config);
    }
}

/// Emit a function hook for a given runtime and symbol pattern.
fn emit_function_hook(
    runtime: Option<Runtime>,
    symbol: &str,
    capture_stack: bool,
    configs: &mut Vec<HookConfig>,
    seen: &mut SeenSet,
) {
    let hook_type = runtime_to_hook_type(runtime);
    let is_native = matches!(hook_type, HookType::Native);
    emit_config(
        HookConfig {
            hook_type,
            symbol: symbol.to_string(),
            arg_count: if is_native { Some(6) } else { None },
            capture_return: true,
            capture_stack,
        },
        configs,
        seen,
    );
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

/// Emit an exec filter hook for a command pattern.
fn emit_exec_hook(
    pattern: &str,
    capture_stack: bool,
    configs: &mut Vec<HookConfig>,
    seen: &mut SeenSet,
) {
    let symbol = exec_filter_name(pattern);
    emit_config(
        HookConfig {
            hook_type: HookType::Exec,
            symbol,
            arg_count: None,
            capture_return: false,
            capture_stack,
        },
        configs,
        seen,
    );
}

/// Emit an EnvVar hook config.
fn emit_envvar_hook(symbol: &str, configs: &mut Vec<HookConfig>, seen: &mut SeenSet) {
    emit_config(
        HookConfig {
            hook_type: HookType::EnvVar,
            symbol: symbol.to_string(),
            arg_count: None,
            capture_return: false,
            capture_stack: false,
        },
        configs,
        seen,
    );
}

impl ActivePolicy {
    /// Derive hook configurations from policy rules.
    ///
    /// Iterates compiled policy sections directly — each category emits the
    /// appropriate HookConfig entries for the agent. No intermediate types.
    ///
    /// When the policy has `network: allow:` rules, also auto-adds known HTTP
    /// functions from the taxonomy so the network phase can evaluate their URLs.
    pub fn derive_hook_configs(&self, capture_stack: bool) -> Vec<HookConfig> {
        let mut configs = Vec::new();
        let mut seen = SeenSet::new();

        for (key, section) in self.engine.policy().iter_sections() {
            if section.mode == EnforcementMode::Noop {
                continue;
            }

            match key.category {
                Category::Functions => {
                    // Emit hook for each allow + deny rule pattern
                    for rule in section.allow_rules.iter().chain(&section.deny_rules) {
                        emit_function_hook(
                            key.runtime,
                            rule.pattern.original(),
                            capture_stack,
                            &mut configs,
                            &mut seen,
                        );
                    }
                }
                Category::Execution => {
                    for rule in section.allow_rules.iter().chain(&section.deny_rules) {
                        emit_exec_hook(
                            rule.pattern.original(),
                            capture_stack,
                            &mut configs,
                            &mut seen,
                        );
                    }
                }
                Category::Files => {
                    // Native file syscalls
                    for sym in super::templates::file_functions_native() {
                        emit_function_hook(None, sym, capture_stack, &mut configs, &mut seen);
                    }
                    // Python file functions — only bare names (no dots).
                    // Module-qualified names like "builtins.open" trigger eager C hook
                    // resolution in the agent, which can interfere with Python startup.
                    for func in super::templates::file_functions_python() {
                        if !func.contains('.') {
                            emit_function_hook(
                                Some(Runtime::Python),
                                func,
                                capture_stack,
                                &mut configs,
                                &mut seen,
                            );
                        }
                    }
                    // Node.js fs module (prefix → wildcard)
                    let node_pattern =
                        format!("{}*", super::templates::taxonomy::NODEJS_FILE_PREFIX);
                    emit_function_hook(
                        Some(Runtime::Node),
                        &node_pattern,
                        capture_stack,
                        &mut configs,
                        &mut seen,
                    );
                    // Hide rules → native stat/lstat/access hooks for review mode
                    if section.has_hide_rules() {
                        let mut hide_syms = vec!["stat", "lstat", "access"];
                        #[cfg(target_os = "macos")]
                        hide_syms.extend_from_slice(&["stat$INODE64", "lstat$INODE64"]);
                        for sym in &hide_syms {
                            emit_function_hook(None, sym, capture_stack, &mut configs, &mut seen);
                        }
                    }
                }
                Category::EnvVars => {
                    // Wildcard to enable envvar monitoring
                    emit_envvar_hook("*", &mut configs, &mut seen);
                    // Block-mode deny patterns for agent-side blocking.
                    // Warn/Log modes only observe (CLI displays warning but value is accessible).
                    for rule in &section.deny_rules {
                        if rule.mode == EnforcementMode::Block {
                            emit_envvar_hook(rule.pattern.original(), &mut configs, &mut seen);
                        }
                    }
                    // Allow patterns — agent-side bypass for deny checks.
                    // Encoded with "!" prefix convention.
                    for rule in &section.allow_rules {
                        let symbol = format!("!{}", rule.pattern.original());
                        emit_envvar_hook(&symbol, &mut configs, &mut seen);
                    }
                    // Hide rules → native getenv hooks for review mode
                    if section.has_hide_rules() {
                        emit_function_hook(None, "getenv", capture_stack, &mut configs, &mut seen);
                        #[cfg(target_os = "linux")]
                        emit_function_hook(
                            None,
                            "secure_getenv",
                            capture_stack,
                            &mut configs,
                            &mut seen,
                        );
                    }
                }
                // Network categories don't need hooks — evaluated against NetworkInfo
                _ => continue,
            }
        }

        // Auto-add wildcard exec filter when commands: allow exists.
        // Unlisted commands need to be intercepted so the CLI can evaluate
        // them against the allowlist and block them (implicit deny).
        if self.has_commands_allow {
            emit_exec_hook("*", capture_stack, &mut configs, &mut seen);
        }

        // Auto-add network function hooks when network: allow exists.
        // These functions aren't in any deny/warn list, but the network phase
        // needs to see them fire to evaluate URLs/hosts against the allowlist.
        if self.has_network_allow {
            for func in super::templates::network_functions_python() {
                emit_function_hook(
                    Some(Runtime::Python),
                    func,
                    capture_stack,
                    &mut configs,
                    &mut seen,
                );
            }
            for func in super::templates::network_functions_nodejs() {
                emit_function_hook(
                    Some(Runtime::Node),
                    func,
                    capture_stack,
                    &mut configs,
                    &mut seen,
                );
            }
        }

        configs
    }
}

// ── Evaluation Pipeline ────────────────────────────────────────

impl ActivePolicy {
    /// Evaluate a trace event against the full policy pipeline.
    ///
    /// Four sequential phases:
    /// 1. Function-level — is this function allowed/denied? (cached for Python/Node/Native)
    /// 2. Network — URL, domain, endpoint, protocol checks (from NetworkInfo or args)
    /// 3. File — file path extraction and evaluation against files: rules
    /// 4. Command — deterministic command triage (Exec/Bash only)
    ///
    /// Returns the strictest disposition across all phases.
    pub fn evaluate_trace(&self, event: &TraceEvent) -> EventDisposition {
        // Phase 1: Function-level (cached for Python/Node/Native)
        let mut disp = self.evaluate_function_phase(event);

        // Native `connect`/`socket` are low-level plumbing. When the policy
        // has network destination rules (like `network: allow: [pypi.org]`),
        // don't block on the symbol name — let the network phase decide based
        // on the actual destination.
        let deferred_to_network = disp.is_blocked()
            && self.has_network_allow
            && matches!(event.hook_type, HookType::Native)
            && is_networking_symbol(&event.function);
        if deferred_to_network {
            disp = EventDisposition::Display;
        }

        // Phase 2: Network evaluation
        let mut disp = self.evaluate_network_phase(event, disp);

        // We deferred to the network phase, but it blocked because domain
        // allow rules didn't match. If we only have a raw IP (no domain or
        // URL), that's expected — domain rules *can't* match a bare IP.
        // Don't block in that case; the event simply has no domain context.
        if deferred_to_network && disp.is_blocked() {
            if let Some(ref net) = event.network_info {
                if !has_hostname_context(net) {
                    disp = EventDisposition::Display;
                }
            }
        }

        // Phase 2.5: Envvar cross-evaluation for native getenv/secure_getenv.
        // When a native hook fires for getenv, extract the envvar name from arg0
        // and evaluate it against the envvars: section (which may produce Hide).
        let disp = if matches!(event.hook_type, HookType::Native) {
            let func = event.function.as_str();
            if func == "getenv" || func == "secure_getenv" {
                if let Some(name) = event.arguments.first().and_then(|a| a.display.as_deref()) {
                    let envvar_decision = self.engine.evaluate_envvar(name);
                    let envvar_disp = decision_to_disposition(envvar_decision);
                    pick_stricter(disp, envvar_disp)
                } else {
                    disp
                }
            } else {
                disp
            }
        } else {
            disp
        };

        // Phase 3: File access evaluation
        let disp = self.evaluate_file_phase(event, disp);

        // Phase 4: Command triage (no-op for non-Exec/Bash)
        self.evaluate_command_phase(event, disp)
    }

    /// Phase 1: Evaluate function name against policy rules.
    ///
    /// Caches results for Python/Node/Native (deterministic per function name).
    /// Exec/Bash/EnvVar are not cached — their names vary per call.
    fn evaluate_function_phase(&self, event: &TraceEvent) -> EventDisposition {
        let func = &event.function;

        // Cache lookup (Python/Node/Native only)
        if !matches!(
            event.hook_type,
            HookType::Exec | HookType::Bash | HookType::EnvVar
        ) {
            let key = (hook_type_discriminant(&event.hook_type), func.to_string());
            if let Some(cached) = self.fn_cache.borrow().get(&key) {
                return cached.clone();
            }
            let disp = self.compute_function_decision(event);
            self.fn_cache.borrow_mut().insert(key, disp.clone());
            return disp;
        }

        self.compute_function_decision(event)
    }

    /// Dispatch to the appropriate engine evaluation method based on hook type.
    /// Returns the raw function-level disposition (no caching, no phase chaining).
    fn compute_function_decision(&self, event: &TraceEvent) -> EventDisposition {
        let func = &event.function;
        let args: Vec<&str> = event
            .arguments
            .iter()
            .filter_map(|a| a.display.as_deref())
            .collect();

        let decision = match event.hook_type {
            HookType::Python => self.engine.evaluate_function(Runtime::Python, func, &args),
            HookType::Nodejs => self.engine.evaluate_function(Runtime::Node, func, &args),
            HookType::Native => self.engine.evaluate_native_function(func, &args),
            HookType::Exec | HookType::Bash => {
                let full_cmd = unwrap_shell_exec_args(func, &args).unwrap_or_else(|| {
                    let cmd_args: Vec<&str> = args.get(1..).unwrap_or(&[]).to_vec();
                    if cmd_args.is_empty() {
                        func.to_string()
                    } else {
                        format!("{} {}", func, cmd_args.join(" "))
                    }
                });
                self.engine.evaluate_execution(&full_cmd)
            }
            HookType::EnvVar => self.engine.evaluate_envvar(func),
        };

        decision_to_disposition(decision)
    }
}

/// Check if a native function name is a networking symbol.
/// Uses `networking_symbols.yaml` via the group macro accessor as single source of truth.
fn is_networking_symbol(name: &str) -> bool {
    super::templates::networking_symbols()
        .iter()
        .any(|s| s == name)
}

/// Check if NetworkInfo has hostname context (URL or domain).
/// IP-only events can't match hostname-based allow rules, so blocking them
/// based on "no allow match" would be incorrect.
pub(super) fn has_hostname_context(info: &malwi_intercept::NetworkInfo) -> bool {
    info.url.is_some() || info.domain.is_some()
}

// ── Disposition Utilities ──────────────────────────────────────

/// Convert a PolicyDecision to an EventDisposition.
pub(super) fn decision_to_disposition(decision: PolicyDecision) -> EventDisposition {
    if decision.is_allowed() {
        return EventDisposition::Suppress;
    }

    if decision.is_hidden() {
        return EventDisposition::Hide;
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
        EnforcementMode::Hide => EventDisposition::Hide,
    }
}

/// Severity ranking for dispositions (higher = stricter).
pub(super) fn disposition_severity(d: &EventDisposition) -> u8 {
    match d {
        EventDisposition::Suppress => 0,
        EventDisposition::Display => 1,
        EventDisposition::Warn { .. } => 2,
        EventDisposition::Review { .. } => 3,
        EventDisposition::Block { .. } => 4,
        EventDisposition::Hide => 5,
    }
}

/// Return the stricter of two dispositions.
pub(super) fn pick_stricter(a: EventDisposition, b: EventDisposition) -> EventDisposition {
    if disposition_severity(&b) > disposition_severity(&a) {
        b
    } else {
        a
    }
}

/// Return the stricter of an optional and a new disposition.
pub(super) fn pick_stricter_opt(
    current: Option<EventDisposition>,
    new: EventDisposition,
) -> EventDisposition {
    match current {
        Some(c) => pick_stricter(c, new),
        None => new,
    }
}

// ── Shell Utilities ────────────────────────────────────────────

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

// ── Internal Utilities ─────────────────────────────────────────

/// Compact discriminant for HookType used as cache key.
fn hook_type_discriminant(ht: &HookType) -> u8 {
    match ht {
        HookType::Native => 0,
        HookType::Python => 1,
        HookType::Nodejs => 2,
        HookType::Exec => 3,
        HookType::EnvVar => 4,
        HookType::Bash => 5,
    }
}

// ── Test Helpers + Tests ───────────────────────────────────────

#[cfg(test)]
pub(super) mod test_helpers {
    use malwi_intercept::{Argument, EventType, HookType, NetworkInfo, TraceEvent};

    pub fn make_trace_event(hook_type: HookType, function: &str, args: &[&str]) -> TraceEvent {
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
            ..Default::default()
        }
    }

    pub fn make_trace_event_with_net(
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
    pub fn make_exec_event(cmd: &str, args: &[&str]) -> TraceEvent {
        let mut all_args: Vec<&str> = vec![cmd];
        all_args.extend_from_slice(args);
        make_trace_event(HookType::Exec, cmd, &all_args)
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use super::*;
    use crate::policy::PolicyEngine;
    use malwi_intercept::HookType;

    #[test]
    fn test_default_security_loads() {
        let policy = ActivePolicy::default_security().unwrap();
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
        let engine = PolicyEngine::from_yaml("version: 1\npython:\n  deny:\n    - eval\n").unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(HookType::Python, "eval", &[]);
        let disp = policy.evaluate_trace(&event);
        assert!(disp.is_blocked());
    }

    #[test]
    fn test_disposition_suppress() {
        let policy = ActivePolicy::default_security().unwrap();

        let event = make_trace_event(HookType::Python, "json.loads", &["{}"]);
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display());
    }

    #[test]
    fn test_shell_unwrapped_curl_logged() {
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
        let policy = ActivePolicy::new(engine);

        let event = make_exec_event("curl", &["example.com"]);
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "curl example.com should be allowed");

        let event = make_exec_event("curl", &["evil.com"]);
        let disp = policy.evaluate_trace(&event);
        assert!(disp.is_blocked(), "curl evil.com should be blocked");

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
        let policy = ActivePolicy::new(engine);

        let event = make_exec_event("curl", &["example.com"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            !disp.should_display(),
            "unwrapped 'curl example.com' should be allowed"
        );

        let event = make_exec_event("curl", &["evil.com"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "unwrapped 'curl evil.com' should be blocked"
        );
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
        // "curl" from allow+deny (deduplicated) + "*" from has_commands_allow
        assert!(
            exec_configs.iter().any(|c| c.symbol == "curl"),
            "should have 'curl' filter"
        );
        assert!(
            exec_configs.iter().any(|c| c.symbol == "*"),
            "should have wildcard filter from commands allow"
        );
    }

    #[test]
    fn test_commands_allowlist_emits_wildcard_exec_filter() {
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
commands:
  allow:
    - "git clone *"
    - "pip install *"
"#,
        )
        .unwrap();
        let configs = policy.derive_hook_configs(false);
        let exec_configs: Vec<_> = configs
            .iter()
            .filter(|c| matches!(c.hook_type, HookType::Exec))
            .collect();
        assert!(
            exec_configs.iter().any(|c| c.symbol == "*"),
            "commands allow should emit wildcard exec filter"
        );
    }

    #[test]
    fn test_commands_deny_only_no_wildcard_exec_filter() {
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
commands:
  deny:
    - curl
    - wget
"#,
        )
        .unwrap();
        let configs = policy.derive_hook_configs(false);
        let exec_configs: Vec<_> = configs
            .iter()
            .filter(|c| matches!(c.hook_type, HookType::Exec))
            .collect();
        assert!(
            !exec_configs.iter().any(|c| c.symbol == "*"),
            "commands deny-only should NOT emit wildcard exec filter"
        );
    }

    #[test]
    fn test_commands_allowlist_blocks_unlisted_command() {
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
commands:
  allow:
    - "git clone *"
    - "pip install *"
"#,
        )
        .unwrap();

        // Unlisted command should be blocked (implicit deny)
        let event = make_exec_event("curl", &["https://evil.com"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "unlisted command 'curl' should be blocked by commands allowlist"
        );

        // Allowed command should pass
        let event = make_exec_event("git", &["clone", "https://github.com/example/repo.git"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            !disp.is_blocked(),
            "'git clone' should be allowed by commands allowlist"
        );
    }

    // =====================================================================
    // pypi-install: network passthrough tests (ActivePolicy level)
    // =====================================================================

    fn pypi_install_policy() -> ActivePolicy {
        ActivePolicy::from_yaml(
            &crate::policy::templates::embedded_policy("pypi-install")
                .expect("pypi-install policy must exist"),
        )
        .expect("pypi-install policy must parse")
    }

    #[test]
    fn test_pypi_install_native_socket_not_blocked() {
        let policy = pypi_install_policy();

        // Native socket() should NOT be blocked — the policy has network allow rules
        // for pypi.org, so native networking symbols pass through to network phase.
        let event = make_trace_event(HookType::Native, "socket", &[]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            !disp.is_blocked(),
            "native socket should not be blocked when policy has network allow rules"
        );
    }

    #[test]
    fn test_pypi_install_native_connect_not_blocked() {
        let policy = pypi_install_policy();

        let event = make_trace_event(HookType::Native, "connect", &[]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            !disp.is_blocked(),
            "native connect should not be blocked when policy has network allow rules"
        );
    }

    #[test]
    fn test_pypi_install_native_getpass_warned() {
        let policy = pypi_install_policy();

        // Non-networking symbols should be warned
        let event = make_trace_event(HookType::Native, "getpass", &[]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            matches!(disp, EventDisposition::Warn { .. }),
            "native getpass should be warned (not a networking symbol)"
        );
    }

    #[test]
    fn test_pypi_install_python_socket_pypi_allowed() {
        let policy = pypi_install_policy();

        // Python socket.create_connection to pypi.org should be allowed
        let net = malwi_intercept::NetworkInfo {
            domain: Some("pypi.org".to_string()),
            port: Some(443),
            ..Default::default()
        };
        let event = make_trace_event_with_net(
            HookType::Python,
            "socket.create_connection",
            &["address=('pypi.org', 443)"],
            net,
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            !disp.is_blocked(),
            "socket.create_connection to pypi.org should be allowed"
        );
    }

    #[test]
    fn test_pypi_install_python_socket_evil_blocked() {
        let policy = pypi_install_policy();

        // Python socket.create_connection to evil.com should be blocked
        let net = malwi_intercept::NetworkInfo {
            domain: Some("evil.com".to_string()),
            port: Some(443),
            ..Default::default()
        };
        let event = make_trace_event_with_net(
            HookType::Python,
            "socket.create_connection",
            &["address=('evil.com', 443)"],
            net,
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "socket.create_connection to evil.com should be blocked"
        );
    }

    #[test]
    fn test_no_network_allow_still_blocks_native_socket() {
        // Policy denies socket but has NO network allow rules —
        // native socket should remain blocked (no passthrough).
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
symbols:
  deny:
    - socket
    - connect
network:
  deny:
    - "*.evil.com"
"#,
        )
        .unwrap();

        let event = make_trace_event(HookType::Native, "socket", &[]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "native socket should be blocked when no network allow rules exist"
        );
    }

    // =====================================================================
    // Tests for derive_hook_configs() — covers hook derivation from sections
    // =====================================================================

    #[test]
    fn test_derive_configs_basic() {
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
python:
  deny:
    - eval
    - exec
nodejs:
  deny:
    - "child_process.exec"
symbols:
  deny:
    - socket
commands:
  deny:
    - curl
"#,
        )
        .unwrap();

        let configs = policy.derive_hook_configs(false);

        let py = configs
            .iter()
            .filter(|c| matches!(c.hook_type, HookType::Python))
            .count();
        assert_eq!(py, 2);

        let node = configs
            .iter()
            .filter(|c| matches!(c.hook_type, HookType::Nodejs))
            .count();
        assert_eq!(node, 1);

        assert!(configs
            .iter()
            .any(|c| matches!(c.hook_type, HookType::Native) && c.symbol == "socket"));

        assert!(configs
            .iter()
            .any(|c| matches!(c.hook_type, HookType::Exec) && c.symbol == "curl"));
    }

    #[test]
    fn test_derive_configs_skips_non_hookable() {
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
network:
  deny:
    - "*.onion"
  protocols: [tcp, https]
python:
  deny:
    - eval
"#,
        )
        .unwrap();

        let configs = policy.derive_hook_configs(false);

        // Only python should produce configs (network categories have no hooks)
        assert!(configs
            .iter()
            .any(|c| matches!(c.hook_type, HookType::Python) && c.symbol == "eval"));
        // No native, exec, or envvar hooks
        assert!(!configs
            .iter()
            .any(|c| matches!(c.hook_type, HookType::Native)));
        assert!(!configs
            .iter()
            .any(|c| matches!(c.hook_type, HookType::Exec)));
    }

    #[test]
    fn test_derive_configs_files_emits_native_and_runtime_hooks() {
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
files:
  deny:
    - "/etc/*"
"#,
        )
        .unwrap();

        let configs = policy.derive_hook_configs(false);
        let file_native = crate::policy::templates::file_functions_native();
        let file_py = crate::policy::templates::file_functions_python();

        // All native file syscalls should be present
        for sym in file_native {
            assert!(
                configs
                    .iter()
                    .any(|c| matches!(c.hook_type, HookType::Native) && c.symbol == *sym),
                "missing native file hook: {}",
                sym
            );
        }
        // Bare Python file funcs (no dots) should be present
        for func in file_py.iter().filter(|f| !f.contains('.')) {
            assert!(
                configs
                    .iter()
                    .any(|c| matches!(c.hook_type, HookType::Python) && c.symbol == *func),
                "missing python file hook: {}",
                func
            );
        }
        // Node.js fs wildcard
        let node_prefix = crate::policy::templates::taxonomy::NODEJS_FILE_PREFIX;
        assert!(configs
            .iter()
            .any(|c| matches!(c.hook_type, HookType::Nodejs) && c.symbol.starts_with(node_prefix)));
    }

    #[test]
    fn test_derive_configs_includes_allow_and_deny() {
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
python:
  allow:
    - "json.*"
  deny:
    - eval
"#,
        )
        .unwrap();

        let configs = policy.derive_hook_configs(false);
        let py_symbols: Vec<&str> = configs
            .iter()
            .filter(|c| matches!(c.hook_type, HookType::Python))
            .map(|c| c.symbol.as_str())
            .collect();
        assert!(py_symbols.contains(&"json.*"));
        assert!(py_symbols.contains(&"eval"));
    }

    #[test]
    fn test_derive_configs_skips_noop() {
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
python:
  noop:
    - eval
nodejs:
  deny:
    - eval
"#,
        )
        .unwrap();

        let configs = policy.derive_hook_configs(false);
        // Only Node.js should produce configs (Python is noop)
        assert!(!configs
            .iter()
            .any(|c| matches!(c.hook_type, HookType::Python)));
        assert!(configs
            .iter()
            .any(|c| matches!(c.hook_type, HookType::Nodejs) && c.symbol == "eval"));
    }

    #[test]
    fn test_derive_configs_envvars() {
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
envvars:
  warn:
    - "*SECRET*"
    - "AWS_*"
"#,
        )
        .unwrap();

        let configs = policy.derive_hook_configs(false);
        let envvar_configs: Vec<_> = configs
            .iter()
            .filter(|c| matches!(c.hook_type, HookType::EnvVar))
            .collect();
        // Warn mode: only wildcard (no individual deny patterns)
        assert_eq!(envvar_configs.len(), 1);
        assert_eq!(envvar_configs[0].symbol, "*");
    }

    #[test]
    fn test_derive_configs_skips_noop_envvars() {
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
envvars:
  noop:
    - "*"
"#,
        )
        .unwrap();

        let configs = policy.derive_hook_configs(false);
        let envvar_configs: Vec<_> = configs
            .iter()
            .filter(|c| matches!(c.hook_type, HookType::EnvVar))
            .collect();
        assert!(envvar_configs.is_empty());
    }

    #[test]
    fn test_derive_configs_envvars_block_mode_emits_deny_patterns() {
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
envvars:
  deny:
    - "*SECRET*"
    - "AWS_*"
"#,
        )
        .unwrap();

        let configs = policy.derive_hook_configs(false);
        let envvar_configs: Vec<_> = configs
            .iter()
            .filter(|c| matches!(c.hook_type, HookType::EnvVar))
            .collect();
        // Block mode (default for deny:) — wildcard + 2 deny patterns
        assert_eq!(envvar_configs.len(), 3);
        let symbols: Vec<&str> = envvar_configs.iter().map(|c| c.symbol.as_str()).collect();
        assert!(symbols.contains(&"*"));
        assert!(symbols.contains(&"*SECRET*"));
        assert!(symbols.contains(&"AWS_*"));
    }

    #[test]
    fn test_derive_configs_envvars_warn_mode_no_deny_patterns() {
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
envvars:
  warn:
    - "*SECRET*"
    - "AWS_*"
"#,
        )
        .unwrap();

        let configs = policy.derive_hook_configs(false);
        let envvar_configs: Vec<_> = configs
            .iter()
            .filter(|c| matches!(c.hook_type, HookType::EnvVar))
            .collect();
        // Only wildcard — no individual deny patterns (warn mode doesn't block)
        assert_eq!(envvar_configs.len(), 1);
        assert_eq!(envvar_configs[0].symbol, "*");
    }
}
