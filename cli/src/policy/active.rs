//! Core policy evaluation bridge.
//!
//! Contains the `ActivePolicy` struct, `EventDisposition` type, and the
//! top-level `evaluate_trace()` dispatch. Phase-specific evaluation methods
//! (network, files, commands) are in sibling modules.

use malwi_policy::{
    EnforcementMode, HookSpecKind, PolicyDecision, PolicyEngine, PolicyHookSpec, Runtime,
};
use malwi_protocol::{HookConfig, HookType, TraceEvent};

/// Resolve an `includes:` name to a YAML string using the embedded policy templates.
fn include_resolver(name: &str) -> Option<String> {
    super::templates::embedded_policy(name)
}

/// Active policy loaded and ready for evaluation.
pub struct ActivePolicy {
    pub(super) engine: PolicyEngine,
    /// Cache: (hook_type discriminant, function_name) → function-level disposition.
    /// Only caches results for functions without arg-filter constraints.
    pub(super) fn_cache: std::cell::RefCell<std::collections::HashMap<(u8, String), CachedDisposition>>,
}

/// Compact representation of a cached function-level disposition.
#[derive(Clone)]
pub(super) enum CachedDisposition {
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

    pub(super) fn to_cached(&self) -> CachedDisposition {
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
    pub(super) fn to_disposition(&self) -> EventDisposition {
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
        let engine = PolicyEngine::from_yaml(super::templates::DEFAULT_SECURITY_YAML)
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

    /// Check if the policy has any sections with review or block mode.
    /// Used to determine if review mode should be enabled in the agent.
    pub fn has_blocking_sections(&self) -> bool {
        self.engine
            .policy()
            .iter_sections()
            .any(|(_, section)| section.mode.is_blocking())
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
pub(super) fn decision_to_disposition(decision: PolicyDecision) -> EventDisposition {
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

// ---------------------------------------------------------------------------
// Test helpers (shared with sibling test modules)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(super) mod test_helpers {
    use malwi_protocol::{Argument, EventType, HookType, NetworkInfo, TraceEvent};

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
            native_stack: vec![],
            runtime_stack: None,
            network_info: None,
            source_file: None,
            source_line: None,
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
    use malwi_policy::PolicyEngine;
    use malwi_protocol::HookType;

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        assert_eq!(
            exec_configs.len(),
            1,
            "should deduplicate to single 'curl' filter"
        );
        assert_eq!(exec_configs[0].symbol, "curl");
    }
}
