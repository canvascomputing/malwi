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

use crate::policy::{Category, EnforcementMode, PolicyEngine, Runtime, SectionKey};
use malwi_intercept::{HookConfig, HookType, TraceEvent};

/// Maximum argument count for native function hooks (covers most libc signatures).
const NATIVE_HOOK_ARG_COUNT: usize = 6;

// ── Types ──────────────────────────────────────────────────────

/// The disposition of a trace event after policy evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum EventDisposition {
    /// Matched a deny rule with Log mode — display the event.
    Display,
    /// Matched a deny rule with Warn mode.
    Warn { rule: String, section: String },
    /// Matched a deny rule with Block mode.
    Block { rule: String, section: String },
    /// No deny match (allowed by policy) — nothing to show.
    Suppress,
    /// Matched a hide rule — silently non-existent, no display, no event.
    Hide,
}

impl EventDisposition {
    /// Whether this event should be shown to the user.
    pub fn should_display(&self) -> bool {
        !matches!(self, EventDisposition::Suppress | EventDisposition::Hide)
    }

    /// Whether this event should be blocked.
    pub fn is_blocked(&self) -> bool {
        matches!(self, EventDisposition::Block { .. })
    }
}

/// Active policy loaded and ready for evaluation.
pub struct ActivePolicy {
    /// Compiled engine — used for hook derivation.
    pub(super) engine: PolicyEngine,
    /// Resolved policy — used for evaluation (shared with agent) and agent config delivery.
    pub(super) resolved: malwi_policy::Policy,
    /// Whether the policy has any network allow rules.
    has_network_allow: bool,
    /// Whether the policy has any network rules at all.
    has_network_rules: bool,
    /// Whether the policy has any commands allow rules.
    has_commands_allow: bool,
}

// ── Construction ───────────────────────────────────────────────

impl ActivePolicy {
    /// Create an ActivePolicy from a PolicyEngine, computing cached fields.
    pub(super) fn new(engine: PolicyEngine) -> Self {
        let has_network_allow = compute_has_network_allow(&engine);
        let has_network_rules = compute_has_network_rules(&engine);
        let has_commands_allow = compute_has_commands_allow(&engine);
        let resolved = malwi_policy::prioritize_and_resolve(engine.policy());
        Self {
            engine,
            resolved,
            has_network_allow,
            has_network_rules,
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
        let engine = PolicyEngine::from_yaml(&malwi_policy::templates::DEFAULT_SECURITY_YAML)
            .map_err(|e| anyhow::anyhow!("Failed to parse default security policy: {}", e))?;
        Ok(Self::new(engine))
    }
}

/// Resolve an `includes:` name to a YAML string using the embedded policy templates.
fn include_resolver(name: &str) -> Option<String> {
    malwi_policy::templates::embedded_policy(name)
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

/// Check if a policy engine has any network rules at all (deny, allow, warn, or protocols).
/// Broader than `compute_has_network_allow` — includes deny-only and protocol-only policies.
/// Used to decide whether to auto-emit native networking symbol hooks.
fn compute_has_network_rules(engine: &PolicyEngine) -> bool {
    let policy = engine.policy();
    let net_key = SectionKey::global(Category::Network);
    let proto_key = SectionKey::global(Category::Protocols);
    let has_net = policy
        .get_section(&net_key)
        .map_or(false, |s| !s.is_empty());
    let has_proto = policy
        .get_section(&proto_key)
        .map_or(false, |s| !s.is_empty());
    has_net || has_proto
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
    /// Convert this policy to an `AgentConfig` for file-based delivery.
    ///
    /// Extracts hooks (via `derive_hook_configs`) and flattens compiled policy
    /// sections into glob pattern lists that the agent can evaluate locally.
    /// Convert this policy to an `AgentConfig` for file-based delivery.
    ///
    /// Uses the resolved policy (pre-sorted rules with full network pattern
    /// fidelity) paired with derived hook configs.
    pub fn to_agent_config(&self, capture_stack: bool) -> malwi_policy::AgentConfig {
        let hooks = self.derive_hook_configs(capture_stack);
        malwi_policy::AgentConfig {
            hooks,
            policy: self.resolved.clone(),
        }
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
            arg_count: if is_native {
                Some(NATIVE_HOOK_ARG_COUNT)
            } else {
                None
            },
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
                    // Native file syscalls — only when section has blocking/hide rules.
                    // Warn/log-only sections use runtime hooks to avoid frida-gum
                    // interference with V8/libc++ during Node.js startup.
                    if section.has_blocking_rules() {
                        for sym in malwi_policy::templates::file_functions_native() {
                            emit_function_hook(None, sym, capture_stack, &mut configs, &mut seen);
                        }
                    }
                    // Python file functions — only bare names (no dots).
                    // Module-qualified names like "builtins.open" trigger eager C hook
                    // resolution in the agent, which can interfere with Python startup.
                    for func in malwi_policy::templates::file_functions_python() {
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
                        format!("{}*", malwi_policy::templates::taxonomy::NODEJS_FILE_PREFIX);
                    emit_function_hook(
                        Some(Runtime::Node),
                        &node_pattern,
                        capture_stack,
                        &mut configs,
                        &mut seen,
                    );
                    // Hide rules → native stat/lstat/access hooks for agent-side hide enforcement
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
                    // Hide rules → native getenv hooks for agent-side hide enforcement
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
            for func in malwi_policy::templates::network_functions_python() {
                emit_function_hook(
                    Some(Runtime::Python),
                    func,
                    capture_stack,
                    &mut configs,
                    &mut seen,
                );
            }
            for func in malwi_policy::templates::network_functions_nodejs() {
                emit_function_hook(
                    Some(Runtime::Node),
                    func,
                    capture_stack,
                    &mut configs,
                    &mut seen,
                );
            }
        }

        // Auto-add native networking symbol hooks when any network rules exist.
        // These produce NetworkInfo (domain, IP, port) that the network phase
        // evaluates against deny/allow patterns. SeenSet prevents duplicates
        // when symbols are already hooked from the symbols: section.
        if self.has_network_rules {
            for sym in malwi_policy::templates::networking_symbols() {
                emit_function_hook(None, sym, capture_stack, &mut configs, &mut seen);
            }
        }

        configs
    }
}

// ── Evaluation Pipeline ────────────────────────────────────────

impl ActivePolicy {
    /// Evaluate a trace event against the policy.
    ///
    /// Delegates core evaluation to `Policy::check_event()` (the unified
    /// evaluator shared with the agent), then applies CLI-only enrichment:
    /// - Network extraction from command args (Exec/Bash without NetworkInfo)
    /// - Command analysis escalation (7-engine triage)
    pub fn evaluate_trace(&self, event: &TraceEvent) -> EventDisposition {
        // Unified evaluator — same code the agent runs
        let outcome = self.resolved.check_event(event);
        let mut disp = outcome_to_disposition(outcome);

        // CLI-only: network enrichment for Exec/Bash events without NetworkInfo.
        // The agent populates NetworkInfo for native hooks (connect, etc.), but
        // Exec/Bash events may lack it when the child runs without agent injection
        // (macOS SIP). Extract URLs/hosts from command args and re-evaluate.
        if !disp.is_blocked() {
            disp = self.enrich_network_from_args(event, disp);
        }

        // CLI-only: command analysis escalation (7-engine triage).
        // Deterministic heuristic layer that escalates suspicious commands to Warn.
        self.escalate_suspicious_command(event, disp)
    }
}

// ── Disposition Utilities ──────────────────────────────────────

/// Convert a malwi_policy Outcome to an EventDisposition.
fn outcome_to_disposition(outcome: malwi_policy::Outcome) -> EventDisposition {
    match outcome {
        malwi_policy::Outcome::Trace => EventDisposition::Display,
        malwi_policy::Outcome::Block { rule, section } => EventDisposition::Block { rule, section },
        malwi_policy::Outcome::Warn { rule, section } => EventDisposition::Warn { rule, section },
        malwi_policy::Outcome::Suppress => EventDisposition::Suppress,
        malwi_policy::Outcome::Hide => EventDisposition::Hide,
    }
}

/// Severity ranking for dispositions (higher = stricter).
pub(super) fn disposition_severity(d: &EventDisposition) -> u8 {
    match d {
        EventDisposition::Suppress => 0,
        EventDisposition::Display => 1,
        EventDisposition::Warn { .. } => 2,
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
            &malwi_policy::templates::embedded_policy("pypi-install")
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
    fn test_network_deny_defers_native_symbols_to_network_phase() {
        // Policy denies socket + connect at symbol level, with network: deny rules.
        // All networking symbols defer to the network phase.
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

        // socket() deferred → network phase has nothing to match → Display (not blocked)
        let event = make_trace_event(HookType::Native, "socket", &[]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            !disp.is_blocked(),
            "socket() should be deferred, not blocked (network phase has no info)"
        );

        // connect() to evil.com → deferred, network phase blocks
        let net = malwi_intercept::NetworkInfo {
            domain: Some("x.evil.com".to_string()),
            port: Some(443),
            ..Default::default()
        };
        let event = make_trace_event_with_net(HookType::Native, "connect", &[], net);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "connect to evil.com should be blocked by network deny"
        );

        // connect() to safe.com → deferred, network phase doesn't deny → Display
        let net = malwi_intercept::NetworkInfo {
            domain: Some("safe.com".to_string()),
            port: Some(443),
            ..Default::default()
        };
        let event = make_trace_event_with_net(HookType::Native, "connect", &[], net);
        let disp = policy.evaluate_trace(&event);
        assert!(
            !disp.is_blocked(),
            "connect to safe.com should not be blocked"
        );
    }

    #[test]
    fn test_no_network_rules_still_blocks_native_socket() {
        // Policy denies socket but has NO network rules at all —
        // no deferral, symbol-level block stands.
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
symbols:
  deny:
    - socket
    - connect
"#,
        )
        .unwrap();

        let event = make_trace_event(HookType::Native, "socket", &[]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "native socket should be blocked when no network rules exist"
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

        // Python hooks from python: deny
        assert!(configs
            .iter()
            .any(|c| matches!(c.hook_type, HookType::Python) && c.symbol == "eval"));
        // Native networking hooks auto-emitted from network rules
        assert!(configs
            .iter()
            .any(|c| matches!(c.hook_type, HookType::Native) && c.symbol == "connect"));
        // No exec or envvar hooks (no commands or envvars sections)
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
        let file_native = malwi_policy::templates::file_functions_native();
        let file_py = malwi_policy::templates::file_functions_python();

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
        let node_prefix = malwi_policy::templates::taxonomy::NODEJS_FILE_PREFIX;
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

    // =====================================================================
    // has_network_rules construction tests
    // =====================================================================

    #[test]
    fn test_has_network_rules_deny_only() {
        let policy =
            ActivePolicy::from_yaml("version: 1\nnetwork:\n  deny:\n    - \"*.evil.com\"\n")
                .unwrap();
        assert!(
            policy.has_network_rules,
            "deny-only should set has_network_rules"
        );
        assert!(
            !policy.has_network_allow,
            "deny-only should not set has_network_allow"
        );
    }

    #[test]
    fn test_has_network_rules_allow_only() {
        let policy =
            ActivePolicy::from_yaml("version: 1\nnetwork:\n  allow:\n    - \"pypi.org/**\"\n")
                .unwrap();
        assert!(policy.has_network_rules);
        assert!(policy.has_network_allow);
    }

    #[test]
    fn test_has_network_rules_warn_only() {
        let policy =
            ActivePolicy::from_yaml("version: 1\nnetwork:\n  warn:\n    - \"*.sketchy.io\"\n")
                .unwrap();
        assert!(
            policy.has_network_rules,
            "warn-only should set has_network_rules"
        );
        assert!(!policy.has_network_allow);
    }

    #[test]
    fn test_has_network_rules_protocols_only() {
        let policy =
            ActivePolicy::from_yaml("version: 1\nnetwork:\n  protocols: [https]\n").unwrap();
        assert!(
            policy.has_network_rules,
            "protocols should set has_network_rules"
        );
        assert!(!policy.has_network_allow);
    }

    #[test]
    fn test_has_network_rules_empty() {
        let policy = ActivePolicy::from_yaml("version: 1\n").unwrap();
        assert!(!policy.has_network_rules);
        assert!(!policy.has_network_allow);
    }

    // =====================================================================
    // Native networking hook auto-generation tests
    // =====================================================================

    #[test]
    fn test_network_deny_auto_generates_native_hooks() {
        let policy =
            ActivePolicy::from_yaml("version: 1\nnetwork:\n  deny:\n    - \"*.evil.com\"\n")
                .unwrap();
        let configs = policy.derive_hook_configs(false);
        let has_connect = configs
            .iter()
            .any(|c| matches!(c.hook_type, HookType::Native) && c.symbol == "connect");
        let has_getaddrinfo = configs
            .iter()
            .any(|c| matches!(c.hook_type, HookType::Native) && c.symbol == "getaddrinfo");
        let has_sendto = configs
            .iter()
            .any(|c| matches!(c.hook_type, HookType::Native) && c.symbol == "sendto");
        assert!(has_connect, "network deny should auto-add connect hook");
        assert!(
            has_getaddrinfo,
            "network deny should auto-add getaddrinfo hook"
        );
        assert!(has_sendto, "network deny should auto-add sendto hook");
    }

    #[test]
    fn test_network_allow_auto_generates_native_hooks() {
        let policy =
            ActivePolicy::from_yaml("version: 1\nnetwork:\n  allow:\n    - \"pypi.org/**\"\n")
                .unwrap();
        let configs = policy.derive_hook_configs(false);
        let has_connect = configs
            .iter()
            .any(|c| matches!(c.hook_type, HookType::Native) && c.symbol == "connect");
        assert!(has_connect, "network allow should auto-add connect hook");
    }

    #[test]
    fn test_network_rules_native_hooks_dedup() {
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
symbols:
  deny:
    - connect
network:
  deny:
    - "*"
"#,
        )
        .unwrap();
        let configs = policy.derive_hook_configs(false);
        let connect_count = configs
            .iter()
            .filter(|c| matches!(c.hook_type, HookType::Native) && c.symbol == "connect")
            .count();
        assert_eq!(connect_count, 1, "connect should appear only once (dedup)");
    }

    #[test]
    fn test_no_network_rules_no_native_hooks() {
        let policy =
            ActivePolicy::from_yaml("version: 1\nfiles:\n  deny:\n    - \"/etc/passwd\"\n")
                .unwrap();
        let configs = policy.derive_hook_configs(false);
        let networking_syms: Vec<&str> = malwi_policy::templates::networking_symbols()
            .iter()
            .map(|s: &String| s.as_str())
            .collect();
        let has_net_native = configs.iter().any(|c| {
            matches!(c.hook_type, HookType::Native) && networking_syms.contains(&c.symbol.as_str())
        });
        assert!(
            !has_net_native,
            "no network rules should not emit native networking hooks"
        );
    }

    // =====================================================================
    // Deferred-to-network with deny-only tests
    // =====================================================================

    #[test]
    fn test_deferred_deny_only_blocks_evil_connect() {
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
symbols:
  deny:
    - connect
network:
  deny:
    - "*.evil.com"
"#,
        )
        .unwrap();

        let net = malwi_intercept::NetworkInfo {
            domain: Some("x.evil.com".to_string()),
            port: Some(443),
            ..Default::default()
        };
        let event = make_trace_event_with_net(HookType::Native, "connect", &[], net);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "connect to evil.com should be blocked via network phase"
        );
    }

    #[test]
    fn test_deferred_deny_only_allows_safe_connect() {
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
symbols:
  deny:
    - connect
network:
  deny:
    - "*.evil.com"
"#,
        )
        .unwrap();

        let net = malwi_intercept::NetworkInfo {
            domain: Some("safe.com".to_string()),
            port: Some(443),
            ..Default::default()
        };
        let event = make_trace_event_with_net(HookType::Native, "connect", &[], net);
        let disp = policy.evaluate_trace(&event);
        assert!(
            !disp.is_blocked(),
            "connect to safe.com should not be blocked with deny-only"
        );
    }

    #[test]
    fn test_deferred_allow_blocks_unlisted_connect() {
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
symbols:
  deny:
    - connect
network:
  allow:
    - "pypi.org/**"
"#,
        )
        .unwrap();

        let net = malwi_intercept::NetworkInfo {
            domain: Some("evil.com".to_string()),
            port: Some(443),
            ..Default::default()
        };
        let event = make_trace_event_with_net(HookType::Native, "connect", &[], net);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "connect to evil.com should be blocked by implicit deny"
        );
    }

    #[test]
    fn test_deferred_allow_ip_only_not_blocked() {
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
symbols:
  deny:
    - connect
network:
  allow:
    - "pypi.org/**"
"#,
        )
        .unwrap();

        let net = malwi_intercept::NetworkInfo {
            ip: Some("93.184.216.34".to_string()),
            port: Some(443),
            ..Default::default()
        };
        let event = make_trace_event_with_net(HookType::Native, "connect", &[], net);
        let disp = policy.evaluate_trace(&event);
        assert!(
            !disp.is_blocked(),
            "IP-only connect should not be blocked (no domain context)"
        );
    }

    #[test]
    fn test_no_deferral_without_network_rules() {
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
symbols:
  deny:
    - connect
"#,
        )
        .unwrap();

        let event = make_trace_event(HookType::Native, "connect", &[]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "connect should be blocked without network rules (no deferral)"
        );
    }

    #[test]
    fn test_deferred_deny_port_blocks_bare_ip() {
        // Port-based deny should still work on bare IP (no hostname needed)
        let policy = ActivePolicy::from_yaml(
            r#"
version: 1
symbols:
  deny:
    - connect
network:
  deny:
    - "*:22"
"#,
        )
        .unwrap();

        let net = malwi_intercept::NetworkInfo {
            ip: Some("1.2.3.4".to_string()),
            port: Some(22),
            ..Default::default()
        };
        let event = make_trace_event_with_net(HookType::Native, "connect", &[], net);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "port 22 should be blocked by port deny rule"
        );
    }
}
