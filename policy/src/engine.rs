use crate::compiled::{
    Category, CompiledPolicy, CompiledRule, Constraint, ConstraintKind, EnforcementMode, Operation,
    Runtime, SectionKey,
};
use crate::compiler::compile_policy_yaml;
use crate::error::Result;
use crate::pattern::CompiledPattern;

/// Policy evaluation engine.
pub struct PolicyEngine {
    policy: CompiledPolicy,
}

/// Result of a policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// The action to take.
    pub action: PolicyAction,
    /// The rule that matched (if any).
    pub matched_rule: Option<String>,
    /// The section that was evaluated.
    pub section: String,
    /// The enforcement mode of the section.
    pub mode: EnforcementMode,
}

impl PolicyDecision {
    /// Get the enforcement mode for this decision.
    pub fn section_mode(&self) -> EnforcementMode {
        self.mode
    }

    /// Check if this decision allows the action.
    pub fn is_allowed(&self) -> bool {
        matches!(self.action, PolicyAction::Allow)
    }

    /// Check if this decision denies the action.
    pub fn is_denied(&self) -> bool {
        matches!(self.action, PolicyAction::Deny)
    }
}

/// The action resulting from policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// Allow the operation.
    Allow,
    /// Deny the operation (actual enforcement depends on section mode).
    Deny,
}

/// Context for evaluating a function call.
pub struct EvalContext<'a> {
    pub runtime: Option<Runtime>,
    pub name: &'a str,
    pub arguments: &'a [&'a str],
    pub operation: Option<Operation>,
}

impl PolicyEngine {
    /// Create a new policy engine from a compiled policy.
    pub fn new(policy: CompiledPolicy) -> Self {
        Self { policy }
    }

    /// Create a new policy engine from YAML.
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let policy = compile_policy_yaml(yaml)?;
        Ok(Self::new(policy))
    }

    /// Create a new policy engine from YAML, resolving `includes:` directives.
    ///
    /// The `resolver` maps include names (e.g. "base") to YAML strings.
    pub fn from_yaml_with_includes(
        yaml: &str,
        resolver: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self> {
        let policy =
            crate::compiler::compile_policy_yaml_with_includes(yaml, resolver)?;
        Ok(Self::new(policy))
    }

    /// Get the underlying policy.
    pub fn policy(&self) -> &CompiledPolicy {
        &self.policy
    }

    /// Evaluate a function call.
    pub fn evaluate_function(
        &self,
        runtime: Runtime,
        name: &str,
        arguments: &[&str],
    ) -> PolicyDecision {
        let key = SectionKey::for_runtime(runtime, Category::Functions);
        self.evaluate_with_key(&key, name, arguments, None)
    }

    /// Evaluate a file operation (global `files` section).
    pub fn evaluate_file(&self, path: &str, operation: Operation) -> PolicyDecision {
        let key = SectionKey::global(Category::Files);
        self.evaluate_with_key(&key, path, &[], Some(operation))
    }

    /// Evaluate a domain name.
    pub fn evaluate_domain(&self, domain: &str) -> PolicyDecision {
        let key = SectionKey::global(Category::Domains);
        self.evaluate_with_key(&key, domain, &[], None)
    }

    /// Evaluate a network endpoint (host:port format).
    pub fn evaluate_endpoint(&self, host: &str, port: u16) -> PolicyDecision {
        let key = SectionKey::global(Category::Endpoints);
        let endpoint = format!("{}:{}", host, port);
        self.evaluate_with_key(&key, &endpoint, &[], None)
    }

    /// Evaluate a protocol.
    pub fn evaluate_protocol(&self, protocol: &str) -> PolicyDecision {
        let key = SectionKey::global(Category::Protocols);
        let section_name = "network".to_string();

        if let Some(section) = self.policy.get_section(&key) {
            // For protocol lists, check if in allowed values
            if !section.allowed_values.is_empty() {
                let is_allowed = section
                    .allowed_values
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(protocol));

                return PolicyDecision {
                    action: if is_allowed {
                        PolicyAction::Allow
                    } else {
                        PolicyAction::Deny
                    },
                    matched_rule: if is_allowed {
                        Some(protocol.to_string())
                    } else {
                        None
                    },
                    section: section_name,
                    mode: section.mode,
                };
            }
        }

        // No protocol restrictions
        PolicyDecision {
            action: PolicyAction::Allow,
            matched_rule: None,
            section: section_name,
            mode: EnforcementMode::default(),
        }
    }

    /// Evaluate an HTTP URL against the global `network` section's URL patterns.
    ///
    /// The `full_url` should be the complete URL string (e.g., "https://example.com/path").
    /// The `no_scheme_url` should be the URL without scheme (e.g., "example.com/path") for
    /// matching patterns that omit the scheme.
    pub fn evaluate_http_url(&self, full_url: &str, no_scheme_url: &str) -> PolicyDecision {
        let key = SectionKey::global(Category::Http);
        self.evaluate_http_url_against_section(&key, full_url, no_scheme_url)
    }

    /// Evaluate a URL against a specific http section.
    /// Tries matching the full URL first, then the URL without scheme.
    fn evaluate_http_url_against_section(
        &self,
        key: &SectionKey,
        full_url: &str,
        no_scheme_url: &str,
    ) -> PolicyDecision {
        let section_name = format_section_name(key);

        let section = match self.policy.get_section(key) {
            Some(s) => s,
            None => {
                return PolicyDecision {
                    action: PolicyAction::Allow,
                    matched_rule: None,
                    section: section_name,
                    mode: EnforcementMode::default(),
                };
            }
        };

        if section.mode == EnforcementMode::Noop {
            return PolicyDecision {
                action: PolicyAction::Allow,
                matched_rule: None,
                section: section_name,
                mode: section.mode,
            };
        }

        if section.is_empty() {
            return PolicyDecision {
                action: PolicyAction::Allow,
                matched_rule: None,
                section: section_name,
                mode: section.mode,
            };
        }

        // Find the most specific matching rule from each side
        let best_deny = find_best_url_match(&section.deny_rules, full_url, no_scheme_url);
        let best_allow = find_best_url_match(&section.allow_rules, full_url, no_scheme_url);

        match (best_allow, best_deny) {
            (Some(allow), Some(deny)) => {
                // Both matched — most specific wins, deny on tie
                if pattern_specificity(&allow.pattern) > pattern_specificity(&deny.pattern) {
                    return PolicyDecision {
                        action: PolicyAction::Allow,
                        matched_rule: Some(allow.pattern.original().to_string()),
                        section: section_name,
                        mode: allow.mode,
                    };
                } else {
                    return PolicyDecision {
                        action: PolicyAction::Deny,
                        matched_rule: Some(deny.pattern.original().to_string()),
                        section: section_name,
                        mode: deny.mode,
                    };
                }
            }
            (Some(allow), None) => {
                return PolicyDecision {
                    action: PolicyAction::Allow,
                    matched_rule: Some(allow.pattern.original().to_string()),
                    section: section_name,
                    mode: allow.mode,
                };
            }
            (None, Some(deny)) => {
                return PolicyDecision {
                    action: PolicyAction::Deny,
                    matched_rule: Some(deny.pattern.original().to_string()),
                    section: section_name,
                    mode: deny.mode,
                };
            }
            (None, None) => {}
        }

        // No rules matched
        let action = if section.has_allow_rules() {
            PolicyAction::Deny
        } else {
            PolicyAction::Allow
        };

        PolicyDecision {
            action,
            matched_rule: None,
            section: section_name,
            mode: section.mode,
        }
    }

    #[allow(dead_code)]
    fn decision_severity(d: &PolicyDecision) -> u8 {
        match (d.action, d.mode) {
            (PolicyAction::Allow, _) => 0,
            (PolicyAction::Deny, EnforcementMode::Noop) => 0,
            (PolicyAction::Deny, EnforcementMode::Log) => 1,
            (PolicyAction::Deny, EnforcementMode::Warn) => 2,
            (PolicyAction::Deny, EnforcementMode::Review) => 3,
            (PolicyAction::Deny, EnforcementMode::Block) => 4,
        }
    }

    /// Evaluate a native/C function call (no runtime prefix).
    /// Uses the global `symbols:` section (SectionKey { runtime: None, category: Functions }).
    pub fn evaluate_native_function(&self, name: &str, arguments: &[&str]) -> PolicyDecision {
        let key = SectionKey::global(Category::Functions);
        self.evaluate_with_key(&key, name, arguments, None)
    }

    /// Evaluate command execution with two-pass matching.
    ///
    /// Pass 1: match rules against the full command string (e.g. "curl example.com").
    /// Pass 2: if no explicit rule matched, match against just the command name (first word).
    /// This lets `allow: ["curl example.com"]` override `deny: [curl]` for that specific invocation.
    pub fn evaluate_execution(&self, command: &str) -> PolicyDecision {
        let key = SectionKey::global(Category::Execution);

        // Pass 1: match against full command string
        let full_result = self.evaluate_with_key(&key, command, &[], None);
        if full_result.matched_rule.is_some() {
            return full_result;
        }

        // Pass 2: match against command name only (first word)
        let cmd_name = command.split_whitespace().next().unwrap_or(command);
        if cmd_name != command {
            let name_result = self.evaluate_with_key(&key, cmd_name, &[], None);
            if name_result.matched_rule.is_some() {
                return name_result;
            }
        }

        // Fallback: implicit result from pass 1
        full_result
    }

    /// Evaluate environment variable access (global `envvars` section).
    pub fn evaluate_envvar(&self, name: &str) -> PolicyDecision {
        let key = SectionKey::global(Category::EnvVars);
        self.evaluate_with_key(&key, name, &[], None)
    }

    /// Evaluate a direct syscall name (global `syscalls` section).
    pub fn evaluate_syscall(&self, name: &str) -> PolicyDecision {
        let key = SectionKey::global(Category::Syscalls);
        self.evaluate_with_key(&key, name, &[], None)
    }

    /// Check if the policy has a non-noop `syscalls` section.
    /// Used to determine whether the syscall monitor should be enabled.
    pub fn has_syscalls_section(&self) -> bool {
        let key = SectionKey::global(Category::Syscalls);
        self.policy
            .get_section(&key)
            .map(|s| s.mode != EnforcementMode::Noop && !s.is_empty())
            .unwrap_or(false)
    }

    /// Core evaluation logic.
    fn evaluate_with_key(
        &self,
        key: &SectionKey,
        name: &str,
        arguments: &[&str],
        operation: Option<Operation>,
    ) -> PolicyDecision {
        let section_name = format_section_name(key);

        // Get the section, or return allow if no policy for this section
        let section = match self.policy.get_section(key) {
            Some(s) => s,
            None => {
                return PolicyDecision {
                    action: PolicyAction::Allow,
                    matched_rule: None,
                    section: section_name,
                    mode: EnforcementMode::default(),
                };
            }
        };

        // Noop mode: skip all evaluation
        if section.mode == EnforcementMode::Noop {
            return PolicyDecision {
                action: PolicyAction::Allow,
                matched_rule: None,
                section: section_name,
                mode: section.mode,
            };
        }

        // Empty section: allow everything
        if section.is_empty() {
            return PolicyDecision {
                action: PolicyAction::Allow,
                matched_rule: None,
                section: section_name,
                mode: section.mode,
            };
        }

        // Find the most specific matching rule from each side
        let best_deny = find_best_match(&section.deny_rules, name, arguments, operation);
        let best_allow = find_best_match(&section.allow_rules, name, arguments, operation);

        match (best_allow, best_deny) {
            (Some(allow), Some(deny)) => {
                // Both matched — most specific wins, deny on tie
                if pattern_specificity(&allow.pattern) > pattern_specificity(&deny.pattern) {
                    return PolicyDecision {
                        action: PolicyAction::Allow,
                        matched_rule: Some(allow.pattern.original().to_string()),
                        section: section_name,
                        mode: allow.mode,
                    };
                } else {
                    return PolicyDecision {
                        action: PolicyAction::Deny,
                        matched_rule: Some(deny.pattern.original().to_string()),
                        section: section_name,
                        mode: deny.mode,
                    };
                }
            }
            (Some(allow), None) => {
                return PolicyDecision {
                    action: PolicyAction::Allow,
                    matched_rule: Some(allow.pattern.original().to_string()),
                    section: section_name,
                    mode: allow.mode,
                };
            }
            (None, Some(deny)) => {
                return PolicyDecision {
                    action: PolicyAction::Deny,
                    matched_rule: Some(deny.pattern.original().to_string()),
                    section: section_name,
                    mode: deny.mode,
                };
            }
            (None, None) => {}
        }

        // No rules matched - determine implicit action
        let action = if section.has_allow_rules() {
            // Has allow rules but none matched = implicit deny
            PolicyAction::Deny
        } else {
            // Only has deny rules (and none matched) = implicit allow
            PolicyAction::Allow
        };

        PolicyDecision {
            action,
            matched_rule: None,
            section: section_name,
            mode: section.mode,
        }
    }
}

/// The kind of hook a policy spec represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookSpecKind {
    /// A regular function hook (native, Python, Node.js).
    Function,
    /// An execution/command hook (exec filter).
    Command,
    /// A direct syscall detection hook.
    Syscall,
    /// An environment variable access hook.
    EnvVar,
}

/// A hook specification derived from a policy rule.
#[derive(Debug, Clone)]
pub struct PolicyHookSpec {
    /// Runtime for this hook (None = native).
    pub runtime: Option<Runtime>,
    /// Pattern string for the function/command to hook.
    pub pattern: String,
    /// Kind of hook.
    pub kind: HookSpecKind,
}

impl PolicyEngine {
    /// Extract hook specifications from all policy rules.
    /// Both allow and deny rules produce hooks (must intercept a call to decide on it).
    /// Skips categories that don't map to hooks (files, domains, endpoints, protocols).
    pub fn extract_hook_specs(&self) -> Vec<PolicyHookSpec> {
        let mut specs = Vec::new();

        for (key, section) in self.policy.iter_sections() {
            // Skip noop sections
            if section.mode == EnforcementMode::Noop {
                continue;
            }

            match key.category {
                Category::Functions | Category::Execution => {
                    let kind = if key.category == Category::Execution {
                        HookSpecKind::Command
                    } else {
                        HookSpecKind::Function
                    };
                    Self::collect_specs_from_rules(
                        &section.allow_rules,
                        key.runtime,
                        kind,
                        &mut specs,
                    );
                    Self::collect_specs_from_rules(
                        &section.deny_rules,
                        key.runtime,
                        kind,
                        &mut specs,
                    );
                }
                Category::Syscalls => {
                    specs.push(PolicyHookSpec {
                        runtime: None,
                        pattern: "*".to_string(),
                        kind: HookSpecKind::Syscall,
                    });
                }
                Category::Files => {
                    // Hook open/openat to monitor file access.
                    // CLI-side evaluate_trace() extracts paths and checks against files: policy.
                    for sym in &["open", "openat"] {
                        specs.push(PolicyHookSpec {
                            runtime: None,
                            pattern: sym.to_string(),
                            kind: HookSpecKind::Function,
                        });
                    }
                }
                Category::EnvVars => {
                    // Emit a wildcard spec to signal envvar monitoring enablement,
                    // plus individual deny patterns for agent-side blocking.
                    // Only Block-mode rules get sent as deny patterns — Warn/Log
                    // modes only observe (CLI displays warning but value is accessible).
                    specs.push(PolicyHookSpec {
                        runtime: None,
                        pattern: "*".to_string(),
                        kind: HookSpecKind::EnvVar,
                    });
                    for rule in &section.deny_rules {
                        if rule.mode == EnforcementMode::Block {
                            specs.push(PolicyHookSpec {
                                runtime: None,
                                pattern: rule.pattern.original().to_string(),
                                kind: HookSpecKind::EnvVar,
                            });
                        }
                    }
                }
                _ => continue,
            }
        }

        specs
    }

    fn collect_specs_from_rules(
        rules: &[CompiledRule],
        runtime: Option<Runtime>,
        kind: HookSpecKind,
        specs: &mut Vec<PolicyHookSpec>,
    ) {
        for rule in rules {
            specs.push(PolicyHookSpec {
                runtime,
                pattern: rule.pattern.original().to_string(),
                kind,
            });
        }
    }
}

/// Compute a specificity score for a pattern (higher = more specific).
/// Exact patterns score highest (len * 2), globs score by literal character count.
fn pattern_specificity(pattern: &CompiledPattern) -> usize {
    match pattern {
        CompiledPattern::Exact(s) => s.len() * 2,
        CompiledPattern::Glob { original, .. } => {
            original.chars().filter(|c| *c != '*' && *c != '?').count()
        }
        CompiledPattern::Regex { original, .. } => {
            let body = original.strip_prefix("regex:").unwrap_or(original);
            body.chars()
                .filter(|c| {
                    !matches!(
                        c,
                        '^' | '$'
                            | '.'
                            | '+'
                            | '('
                            | ')'
                            | '['
                            | ']'
                            | '{'
                            | '}'
                            | '|'
                            | '\\'
                            | '?'
                            | '*'
                    )
                })
                .count()
        }
    }
}

/// Find the most specific matching rule. On specificity tie, first rule wins.
fn find_best_match<'a>(
    rules: &'a [CompiledRule],
    name: &str,
    arguments: &[&str],
    operation: Option<Operation>,
) -> Option<&'a CompiledRule> {
    let mut best: Option<&CompiledRule> = None;
    let mut best_spec = 0;
    for rule in rules {
        if rule_matches(rule, name, arguments, operation) {
            let spec = pattern_specificity(&rule.pattern);
            if best.is_none() || spec > best_spec {
                best = Some(rule);
                best_spec = spec;
            }
        }
    }
    best
}

/// Find the most specific URL-matching rule. Checks both full URL and schemeless URL.
fn find_best_url_match<'a>(
    rules: &'a [CompiledRule],
    full_url: &str,
    no_scheme_url: &str,
) -> Option<&'a CompiledRule> {
    let mut best: Option<&CompiledRule> = None;
    let mut best_spec = 0;
    for rule in rules {
        if rule.pattern.matches(full_url) || rule.pattern.matches(no_scheme_url) {
            let spec = pattern_specificity(&rule.pattern);
            if best.is_none() || spec > best_spec {
                best = Some(rule);
                best_spec = spec;
            }
        }
    }
    best
}

/// Check if a rule matches the given context.
fn rule_matches(
    rule: &CompiledRule,
    name: &str,
    arguments: &[&str],
    operation: Option<Operation>,
) -> bool {
    // First check if the pattern matches the name
    if !rule.pattern.matches(name) {
        return false;
    }

    // If no constraints, pattern match is sufficient
    if rule.constraints.is_empty() {
        return true;
    }

    // Check constraints
    check_constraints(&rule.constraints, arguments, operation)
}

/// Check if any constraint is satisfied.
fn check_constraints(
    constraints: &[Constraint],
    arguments: &[&str],
    operation: Option<Operation>,
) -> bool {
    // If there are constraints, at least one must match
    for constraint in constraints {
        match &constraint.kind {
            ConstraintKind::AnyArgument => {
                // Check if any argument matches the pattern
                if arguments.iter().any(|arg| constraint.pattern.matches(arg)) {
                    return true;
                }
            }
            ConstraintKind::ArgumentIndex(idx) => {
                // Check if the specific argument matches
                if let Some(arg) = arguments.get(*idx) {
                    if constraint.pattern.matches(arg) {
                        return true;
                    }
                }
            }
            ConstraintKind::Operation(allowed_ops) => {
                // Check if the operation is in the allowed list
                if let Some(op) = operation {
                    if allowed_ops.contains(&op) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

fn format_section_name(key: &SectionKey) -> String {
    let category = match key.category {
        Category::Functions => "symbols",
        Category::Files => "files",
        Category::EnvVars => "envvars",
        Category::Http | Category::Endpoints | Category::Domains | Category::Protocols => "network",
        Category::Execution => "commands",
        Category::Syscalls => "syscalls",
    };

    match key.runtime {
        Some(Runtime::Python) => "python".to_string(),
        Some(Runtime::Node) => "nodejs".to_string(),
        None => category.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_from_yaml(yaml: &str) -> PolicyEngine {
        PolicyEngine::from_yaml(yaml).unwrap()
    }

    #[test]
    fn test_basic_deny() {
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  deny:
    - eval
"#,
        );

        let decision = engine.evaluate_function(Runtime::Python, "eval", &[]);
        assert_eq!(decision.action, PolicyAction::Deny);
        assert_eq!(decision.matched_rule, Some("eval".to_string()));
    }

    #[test]
    fn test_basic_allow() {
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  allow:
    - json.loads
"#,
        );

        let decision = engine.evaluate_function(Runtime::Python, "json.loads", &[]);
        assert_eq!(decision.action, PolicyAction::Allow);
    }

    #[test]
    fn test_implicit_deny_with_allow_rules() {
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  allow:
    - json.loads
    - json.dumps
"#,
        );

        // Unlisted function should be denied
        let decision = engine.evaluate_function(Runtime::Python, "eval", &[]);
        assert_eq!(decision.action, PolicyAction::Deny);
    }

    #[test]
    fn test_implicit_allow_with_only_deny_rules() {
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  deny:
    - eval
    - exec
"#,
        );

        // Unlisted function should be allowed
        let decision = engine.evaluate_function(Runtime::Python, "json.loads", &[]);
        assert_eq!(decision.action, PolicyAction::Allow);
    }

    #[test]
    fn test_deny_takes_precedence() {
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  allow:
    - "*"
  deny:
    - eval
"#,
        );

        // eval should be denied even though "*" matches
        let decision = engine.evaluate_function(Runtime::Python, "eval", &[]);
        assert_eq!(decision.action, PolicyAction::Deny);

        // Other functions allowed
        let decision = engine.evaluate_function(Runtime::Python, "print", &[]);
        assert_eq!(decision.action, PolicyAction::Allow);
    }

    #[test]
    fn test_most_specific_deny_wins() {
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  deny:
    - "os.*"
    - os.system
"#,
        );

        let decision = engine.evaluate_function(Runtime::Python, "os.system", &[]);
        // os.system (exact, spec=18) beats os.* (glob, spec=3)
        assert_eq!(decision.matched_rule, Some("os.system".to_string()));
    }

    #[test]
    fn test_most_specific_allow_wins() {
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  allow:
    - "json.*"
    - json.loads
"#,
        );

        let decision = engine.evaluate_function(Runtime::Python, "json.loads", &[]);
        // json.loads (exact, spec=20) beats json.* (glob, spec=5)
        assert_eq!(decision.matched_rule, Some("json.loads".to_string()));
    }

    #[test]
    fn test_constraint_allow() {
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  allow:
    - "requests.get": ["https://api.example.com/*"]
"#,
        );

        // Allowed URL
        let decision = engine.evaluate_function(
            Runtime::Python,
            "requests.get",
            &["https://api.example.com/users"],
        );
        assert_eq!(decision.action, PolicyAction::Allow);

        // Disallowed URL (no matching constraint)
        let decision = engine.evaluate_function(
            Runtime::Python,
            "requests.get",
            &["https://evil.com/malware"],
        );
        assert_eq!(decision.action, PolicyAction::Deny);
    }

    #[test]
    fn test_constraint_deny() {
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  deny:
    - "subprocess.run": ["*sudo*"]
"#,
        );

        // Command with sudo - blocked
        let decision =
            engine.evaluate_function(Runtime::Python, "subprocess.run", &["sudo rm -rf /"]);
        assert_eq!(decision.action, PolicyAction::Deny);

        // Safe command - allowed (deny rule doesn't match due to constraint)
        let decision = engine.evaluate_function(Runtime::Python, "subprocess.run", &["ls -la"]);
        assert_eq!(decision.action, PolicyAction::Allow);
    }

    #[test]
    fn test_file_operation_constraint() {
        let engine = engine_from_yaml(
            r#"
version: 1
files:
  allow:
    - "/tmp/*": [read]
    - "/app/data/*": [read, edit]
"#,
        );

        // Read /tmp - allowed
        let decision = engine.evaluate_file("/tmp/test.txt", Operation::Read);
        assert_eq!(decision.action, PolicyAction::Allow);

        // Write /tmp - denied
        let decision = engine.evaluate_file("/tmp/test.txt", Operation::Edit);
        assert_eq!(decision.action, PolicyAction::Deny);

        // Edit /app/data - allowed
        let decision = engine.evaluate_file("/app/data/file.json", Operation::Edit);
        assert_eq!(decision.action, PolicyAction::Allow);
    }

    #[test]
    fn test_mode_default_block() {
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  deny:
    - eval
"#,
        );

        let decision = engine.evaluate_function(Runtime::Python, "eval", &[]);
        assert_eq!(decision.section_mode(), EnforcementMode::Block);
    }

    #[test]
    fn test_mode_log() {
        let engine = engine_from_yaml(
            r#"
version: 1
files:
  log:
    - "/etc/*"
"#,
        );

        let decision = engine.evaluate_file("/etc/passwd", Operation::Read);
        assert_eq!(decision.action, PolicyAction::Deny);
        assert_eq!(decision.section_mode(), EnforcementMode::Log);
    }

    #[test]
    fn test_mode_noop() {
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  noop:
    - "*"
"#,
        );

        // Even with deny *, noop mode allows
        let decision = engine.evaluate_function(Runtime::Python, "eval", &[]);
        assert_eq!(decision.action, PolicyAction::Allow);
    }

    #[test]
    fn test_runtime_isolation() {
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  deny:
    - eval
nodejs:
  allow:
    - eval
"#,
        );

        // Python eval denied
        let d1 = engine.evaluate_function(Runtime::Python, "eval", &[]);
        assert_eq!(d1.action, PolicyAction::Deny);

        // Node eval allowed
        let d2 = engine.evaluate_function(Runtime::Node, "eval", &[]);
        assert_eq!(d2.action, PolicyAction::Allow);
    }

    #[test]
    fn test_domain_evaluation() {
        let engine = engine_from_yaml(
            r#"
version: 1
network:
  deny:
    - "*.onion"
"#,
        );

        let d1 = engine.evaluate_domain("hidden.onion");
        assert_eq!(d1.action, PolicyAction::Deny);

        let d2 = engine.evaluate_domain("example.com");
        assert_eq!(d2.action, PolicyAction::Allow);
    }

    #[test]
    fn test_endpoint_evaluation() {
        let engine = engine_from_yaml(
            r#"
version: 1
network:
  deny:
    - "*:22"
"#,
        );

        let d1 = engine.evaluate_endpoint("example.com", 22);
        assert_eq!(d1.action, PolicyAction::Deny);

        let d2 = engine.evaluate_endpoint("example.com", 443);
        assert_eq!(d2.action, PolicyAction::Allow);
    }

    #[test]
    fn test_protocol_evaluation() {
        let engine = engine_from_yaml(
            r#"
version: 1
network:
  protocols: [tcp, https]
"#,
        );

        let d1 = engine.evaluate_protocol("tcp");
        assert_eq!(d1.action, PolicyAction::Allow);

        let d2 = engine.evaluate_protocol("HTTPS");
        assert_eq!(d2.action, PolicyAction::Allow);

        let d3 = engine.evaluate_protocol("ftp");
        assert_eq!(d3.action, PolicyAction::Deny);
    }

    #[test]
    fn test_execution_evaluation() {
        let engine = engine_from_yaml(
            r#"
version: 1
commands:
  allow:
    - "pip install *"
    - "git *"
  deny:
    - curl
    - wget
"#,
        );

        let d1 = engine.evaluate_execution("pip install requests");
        assert_eq!(d1.action, PolicyAction::Allow);

        let d2 = engine.evaluate_execution("curl http://evil.com");
        assert_eq!(d2.action, PolicyAction::Deny);

        let d3 = engine.evaluate_execution("ls -la");
        assert_eq!(d3.action, PolicyAction::Deny); // Not in allow list
    }

    #[test]
    fn test_empty_policy() {
        let engine = engine_from_yaml("version: 1\n");

        let decision = engine.evaluate_function(Runtime::Python, "anything", &[]);
        assert_eq!(decision.action, PolicyAction::Allow);
    }

    #[test]
    fn test_case_sensitivity_functions() {
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  deny:
    - Eval
"#,
        );

        // Case-sensitive
        let d1 = engine.evaluate_function(Runtime::Python, "Eval", &[]);
        assert_eq!(d1.action, PolicyAction::Deny);

        let d2 = engine.evaluate_function(Runtime::Python, "eval", &[]);
        assert_eq!(d2.action, PolicyAction::Allow);
    }

    #[test]
    fn test_case_insensitivity_domains() {
        let engine = engine_from_yaml(
            r#"
version: 1
network:
  deny:
    - "*.ONION"
"#,
        );

        // Should be case-insensitive
        let d1 = engine.evaluate_domain("test.onion");
        let d2 = engine.evaluate_domain("TEST.ONION");
        assert_eq!(d1.action, d2.action);
    }

    #[test]
    fn test_special_characters() {
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  deny:
    - __import__
    - os.path.join
"#,
        );

        let d1 = engine.evaluate_function(Runtime::Python, "__import__", &[]);
        assert_eq!(d1.action, PolicyAction::Deny);

        let d2 = engine.evaluate_function(Runtime::Python, "os.path.join", &[]);
        assert_eq!(d2.action, PolicyAction::Deny);
    }

    #[test]
    fn test_multiple_constraints_any_match() {
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  allow:
    - "requests.*": ["https://api1.com/*", "https://api2.com/*"]
"#,
        );

        // Either URL works
        let d1 = engine.evaluate_function(Runtime::Python, "requests.get", &["https://api1.com/x"]);
        let d2 = engine.evaluate_function(Runtime::Python, "requests.get", &["https://api2.com/y"]);
        assert_eq!(d1.action, PolicyAction::Allow);
        assert_eq!(d2.action, PolicyAction::Allow);

        // Other URLs blocked
        let d3 = engine.evaluate_function(Runtime::Python, "requests.get", &["https://other.com"]);
        assert_eq!(d3.action, PolicyAction::Deny);
    }

    #[test]
    fn test_empty_arguments() {
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  allow:
    - "print": ["*"]
"#,
        );

        // No arguments - constraint doesn't match
        let decision = engine.evaluate_function(Runtime::Python, "print", &[]);
        // With allow rules and constraint not satisfied, should deny
        assert_eq!(decision.action, PolicyAction::Deny);
    }

    // =====================================================================
    // Tests for new direct list format (implicit allow)
    // =====================================================================

    #[test]
    fn test_eval_direct_list_allows_listed() {
        let engine = engine_from_yaml(
            r#"
version: 1
nodejs:
  - JSON.parse
  - JSON.stringify
"#,
        );

        let d1 = engine.evaluate_function(Runtime::Node, "JSON.parse", &[]);
        assert_eq!(d1.action, PolicyAction::Allow);

        let d2 = engine.evaluate_function(Runtime::Node, "JSON.stringify", &[]);
        assert_eq!(d2.action, PolicyAction::Allow);
    }

    #[test]
    fn test_eval_direct_list_denies_unlisted() {
        let engine = engine_from_yaml(
            r#"
version: 1
nodejs:
  - JSON.parse
"#,
        );

        // eval not in list, should be implicitly denied
        let d = engine.evaluate_function(Runtime::Node, "eval", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_eval_direct_list_with_constraints() {
        let engine = engine_from_yaml(
            r#"
version: 1
nodejs:
  - "axios.*": ["https://api.example.com/*"]
  - JSON.parse
"#,
        );

        // axios with allowed URL
        let d1 = engine.evaluate_function(
            Runtime::Node,
            "axios.get",
            &["https://api.example.com/users"],
        );
        assert_eq!(d1.action, PolicyAction::Allow);

        // axios with disallowed URL
        let d2 = engine.evaluate_function(Runtime::Node, "axios.get", &["https://evil.com"]);
        assert_eq!(d2.action, PolicyAction::Deny);

        // JSON.parse (no constraints)
        let d3 = engine.evaluate_function(Runtime::Node, "JSON.parse", &[]);
        assert_eq!(d3.action, PolicyAction::Allow);
    }

    #[test]
    fn test_eval_direct_list_glob_pattern() {
        let engine = engine_from_yaml(
            r#"
version: 1
nodejs:
  - "console.*"
"#,
        );

        let d1 = engine.evaluate_function(Runtime::Node, "console.log", &[]);
        assert_eq!(d1.action, PolicyAction::Allow);

        let d2 = engine.evaluate_function(Runtime::Node, "console.error", &[]);
        assert_eq!(d2.action, PolicyAction::Allow);

        let d3 = engine.evaluate_function(Runtime::Node, "process.exit", &[]);
        assert_eq!(d3.action, PolicyAction::Deny);
    }

    #[test]
    fn test_eval_endpoints_network() {
        let engine = engine_from_yaml(
            r#"
version: 1
network:
  allow:
    - "127.0.0.1:*"
    - "*:443"
"#,
        );

        // localhost any port
        let d1 = engine.evaluate_endpoint("127.0.0.1", 8080);
        assert_eq!(d1.action, PolicyAction::Allow);

        // any host port 443
        let d2 = engine.evaluate_endpoint("example.com", 443);
        assert_eq!(d2.action, PolicyAction::Allow);

        // disallowed
        let d3 = engine.evaluate_endpoint("example.com", 80);
        assert_eq!(d3.action, PolicyAction::Deny);
    }

    #[test]
    fn test_backward_compat_explicit_allow_deny() {
        // Old format should still work
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  allow:
    - json.loads
  deny:
    - eval
"#,
        );

        assert_eq!(
            engine
                .evaluate_function(Runtime::Python, "json.loads", &[])
                .action,
            PolicyAction::Allow
        );
        assert_eq!(
            engine
                .evaluate_function(Runtime::Python, "eval", &[])
                .action,
            PolicyAction::Deny
        );
    }

    #[test]
    fn test_mixed_new_and_old_format() {
        // Mix of old (explicit allow/deny) and new (direct list) formats
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  allow:
    - json.loads
  deny:
    - eval
nodejs:
  - JSON.parse
  - JSON.stringify
"#,
        );

        // Old format (Python)
        assert_eq!(
            engine
                .evaluate_function(Runtime::Python, "json.loads", &[])
                .action,
            PolicyAction::Allow
        );
        assert_eq!(
            engine
                .evaluate_function(Runtime::Python, "eval", &[])
                .action,
            PolicyAction::Deny
        );

        // New format (Node)
        assert_eq!(
            engine
                .evaluate_function(Runtime::Node, "JSON.parse", &[])
                .action,
            PolicyAction::Allow
        );
        assert_eq!(
            engine.evaluate_function(Runtime::Node, "eval", &[]).action,
            PolicyAction::Deny
        );
    }

    // =====================================================================
    // Tests for two-pass execution evaluation
    // =====================================================================

    #[test]
    fn test_execution_two_pass_allow_specific_overrides_deny_general() {
        let engine = engine_from_yaml(
            r#"
version: 1
commands:
  allow:
    - "curl example.com"
  deny:
    - curl
"#,
        );

        // "curl example.com" matches allow rule in pass 1 → allowed
        let d1 = engine.evaluate_execution("curl example.com");
        assert_eq!(d1.action, PolicyAction::Allow);
        assert_eq!(d1.matched_rule, Some("curl example.com".to_string()));

        // "curl evil.com" has no explicit match in pass 1, pass 2 matches deny "curl"
        let d2 = engine.evaluate_execution("curl evil.com");
        assert_eq!(d2.action, PolicyAction::Deny);
        assert_eq!(d2.matched_rule, Some("curl".to_string()));

        // bare "curl" matches deny in pass 1
        let d3 = engine.evaluate_execution("curl");
        assert_eq!(d3.action, PolicyAction::Deny);
        assert_eq!(d3.matched_rule, Some("curl".to_string()));
    }

    #[test]
    fn test_execution_two_pass_deny_with_args() {
        let engine = engine_from_yaml(
            r#"
version: 1
commands:
  deny:
    - "curl -k *"
    - wget
"#,
        );

        // "curl -k https://evil.com" matches deny "curl -k *" in pass 1
        let d1 = engine.evaluate_execution("curl -k https://evil.com");
        assert_eq!(d1.action, PolicyAction::Deny);
        assert_eq!(d1.matched_rule, Some("curl -k *".to_string()));

        // "curl https://good.com" has no match in pass 1 or pass 2 → implicit allow
        let d2 = engine.evaluate_execution("curl https://good.com");
        assert_eq!(d2.action, PolicyAction::Allow);

        // "wget" matches deny in pass 1
        let d3 = engine.evaluate_execution("wget");
        assert_eq!(d3.action, PolicyAction::Deny);
    }

    #[test]
    fn test_execution_two_pass_glob_deny_matches_full_command() {
        let engine = engine_from_yaml(
            r#"
version: 1
commands:
  deny:
    - "curl *evil*"
"#,
        );

        // Full command with "evil" in it → denied in pass 1
        let d1 = engine.evaluate_execution("curl https://evil.com/malware");
        assert_eq!(d1.action, PolicyAction::Deny);

        // Full command without "evil" → no match pass 1 or 2 → implicit allow
        let d2 = engine.evaluate_execution("curl https://good.com");
        assert_eq!(d2.action, PolicyAction::Allow);
    }

    #[test]
    fn test_execution_two_pass_no_args_single_pass() {
        // When command has no args, pass 1 and pass 2 would be identical,
        // so pass 2 is skipped
        let engine = engine_from_yaml(
            r#"
version: 1
commands:
  deny:
    - curl
"#,
        );

        let d = engine.evaluate_execution("curl");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.matched_rule, Some("curl".to_string()));
    }

    #[test]
    fn test_execution_two_pass_deny_first_in_each_pass() {
        let engine = engine_from_yaml(
            r#"
version: 1
commands:
  allow:
    - "git push"
    - git
  deny:
    - "git push --force"
    - rm
"#,
        );

        // "git push --force" matches deny in pass 1
        let d1 = engine.evaluate_execution("git push --force");
        assert_eq!(d1.action, PolicyAction::Deny);

        // "git push" matches allow in pass 1
        let d2 = engine.evaluate_execution("git push");
        assert_eq!(d2.action, PolicyAction::Allow);

        // "git status" → no match pass 1; pass 2 "git" matches allow
        let d3 = engine.evaluate_execution("git status");
        assert_eq!(d3.action, PolicyAction::Allow);
        assert_eq!(d3.matched_rule, Some("git".to_string()));

        // "rm -rf /" → no match pass 1; pass 2 "rm" matches deny
        let d4 = engine.evaluate_execution("rm -rf /");
        assert_eq!(d4.action, PolicyAction::Deny);
    }

    // =====================================================================
    // Tests for evaluate_native_function()
    // =====================================================================

    #[test]
    fn test_native_function_deny() {
        let engine = engine_from_yaml(
            r#"
version: 1
symbols:
  deny:
    - socket
    - connect
"#,
        );

        let d1 = engine.evaluate_native_function("socket", &[]);
        assert_eq!(d1.action, PolicyAction::Deny);

        let d2 = engine.evaluate_native_function("connect", &["127.0.0.1:80"]);
        assert_eq!(d2.action, PolicyAction::Deny);

        // Unlisted native function should be allowed
        let d3 = engine.evaluate_native_function("printf", &[]);
        assert_eq!(d3.action, PolicyAction::Allow);
    }

    #[test]
    fn test_native_function_isolation_from_runtime() {
        let engine = engine_from_yaml(
            r#"
version: 1
symbols:
  deny:
    - socket
python:
  deny:
    - eval
"#,
        );

        // Native socket denied
        let d1 = engine.evaluate_native_function("socket", &[]);
        assert_eq!(d1.action, PolicyAction::Deny);

        // Native eval NOT denied (not in global functions section)
        let d2 = engine.evaluate_native_function("eval", &[]);
        assert_eq!(d2.action, PolicyAction::Allow);

        // Python eval IS denied
        let d3 = engine.evaluate_function(Runtime::Python, "eval", &[]);
        assert_eq!(d3.action, PolicyAction::Deny);
    }

    #[test]
    fn test_native_function_no_section() {
        // No global functions section → everything allowed
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  deny:
    - eval
"#,
        );

        let d = engine.evaluate_native_function("socket", &[]);
        assert_eq!(d.action, PolicyAction::Allow);
    }

    // =====================================================================
    // Tests for extract_hook_specs()
    // =====================================================================

    #[test]
    fn test_extract_hook_specs_basic() {
        let engine = engine_from_yaml(
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
        );

        let specs = engine.extract_hook_specs();

        // Should have specs for all rules
        let py_specs: Vec<_> = specs
            .iter()
            .filter(|s| s.runtime == Some(Runtime::Python))
            .collect();
        assert_eq!(py_specs.len(), 2);

        let node_specs: Vec<_> = specs
            .iter()
            .filter(|s| s.runtime == Some(Runtime::Node))
            .collect();
        assert_eq!(node_specs.len(), 1);

        let native_specs: Vec<_> = specs
            .iter()
            .filter(|s| s.runtime.is_none() && s.kind == HookSpecKind::Function)
            .collect();
        assert_eq!(native_specs.len(), 1);
        assert_eq!(native_specs[0].pattern, "socket");

        let exec_specs: Vec<_> = specs
            .iter()
            .filter(|s| s.kind == HookSpecKind::Command)
            .collect();
        assert_eq!(exec_specs.len(), 1);
        assert_eq!(exec_specs[0].pattern, "curl");
    }

    #[test]
    fn test_extract_hook_specs_skips_non_hookable() {
        let engine = engine_from_yaml(
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
        );

        let specs = engine.extract_hook_specs();

        // Only python should produce specs
        // domains, protocols should be skipped
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].pattern, "eval");
    }

    #[test]
    fn test_extract_hook_specs_files_emits_open_openat() {
        let engine = engine_from_yaml(
            r#"
version: 1
files:
  deny:
    - "/etc/*"
"#,
        );

        let specs = engine.extract_hook_specs();

        // files: section should emit open and openat native function specs
        assert_eq!(specs.len(), 2);
        let patterns: Vec<&str> = specs.iter().map(|s| s.pattern.as_str()).collect();
        assert!(patterns.contains(&"open"));
        assert!(patterns.contains(&"openat"));
        assert!(specs.iter().all(|s| s.runtime.is_none()));
        assert!(specs.iter().all(|s| s.kind == HookSpecKind::Function));
    }

    #[test]
    fn test_extract_hook_specs_includes_allow_and_deny() {
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  allow:
    - "json.*"
  deny:
    - eval
"#,
        );

        let specs = engine.extract_hook_specs();
        // Should include both the allow and deny rules
        assert_eq!(specs.len(), 2);
        let patterns: Vec<&str> = specs.iter().map(|s| s.pattern.as_str()).collect();
        assert!(patterns.contains(&"json.*"));
        assert!(patterns.contains(&"eval"));
    }

    #[test]
    fn test_extract_hook_specs_skips_noop() {
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  noop:
    - eval
nodejs:
  deny:
    - eval
"#,
        );

        let specs = engine.extract_hook_specs();
        // Only node should produce specs (python is noop)
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].runtime, Some(Runtime::Node));
    }

    // =====================================================================
    // Tests for evaluate_http_url()
    // =====================================================================

    #[test]
    fn test_http_url_deny_pattern() {
        let engine = engine_from_yaml(
            r#"
version: 1
network:
  deny:
    - "*.evil.com/**"
"#,
        );

        let d = engine.evaluate_http_url(
            "https://malware.evil.com/payload",
            "malware.evil.com/payload",
        );
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url("https://example.com/safe", "example.com/safe");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_http_url_allow_pattern() {
        let engine = engine_from_yaml(
            r#"
version: 1
network:
  allow:
    - "https://api.example.com/v1/**"
    - "https://api.example.com/health"
"#,
        );

        // Allowed URL
        let d = engine.evaluate_http_url(
            "https://api.example.com/v1/users",
            "api.example.com/v1/users",
        );
        assert_eq!(d.action, PolicyAction::Allow);

        // Not in allow list → implicit deny
        let d =
            engine.evaluate_http_url("https://api.example.com/v2/data", "api.example.com/v2/data");
        assert_eq!(d.action, PolicyAction::Deny);

        // Exact match allowed
        let d =
            engine.evaluate_http_url("https://api.example.com/health", "api.example.com/health");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_http_url_path_matching() {
        let engine = engine_from_yaml(
            r#"
version: 1
network:
  deny:
    - "**/admin/**"
    - "**/.env"
"#,
        );

        let d =
            engine.evaluate_http_url("https://example.com/admin/users", "example.com/admin/users");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url("https://example.com/.env", "example.com/.env");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url("https://example.com/api/data", "example.com/api/data");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_http_url_scheme_specific() {
        let engine = engine_from_yaml(
            r#"
version: 1
network:
  deny:
    - "http://**"
"#,
        );

        // HTTP denied
        let d = engine.evaluate_http_url("http://example.com/path", "example.com/path");
        assert_eq!(d.action, PolicyAction::Deny);

        // HTTPS allowed
        let d = engine.evaluate_http_url("https://example.com/path", "example.com/path");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_http_url_schemeless_pattern_matches_any_scheme() {
        let engine = engine_from_yaml(
            r#"
version: 1
network:
  deny:
    - "*.evil.com/**"
"#,
        );

        // Pattern without scheme should match via no_scheme_url
        let d = engine.evaluate_http_url("https://malware.evil.com/path", "malware.evil.com/path");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url("http://malware.evil.com/path", "malware.evil.com/path");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_http_url_no_section_allows_all() {
        let engine = engine_from_yaml("version: 1\n");

        let d = engine.evaluate_http_url("https://anything.com/path", "anything.com/path");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_http_url_single_star_doesnt_cross_slash() {
        let engine = engine_from_yaml(
            r#"
version: 1
network:
  allow:
    - "https://api.example.com/v1/*"
"#,
        );

        // Single path segment — allowed
        let d = engine.evaluate_http_url(
            "https://api.example.com/v1/users",
            "api.example.com/v1/users",
        );
        assert_eq!(d.action, PolicyAction::Allow);

        // Multiple path segments — single * doesn't cross /
        let d = engine.evaluate_http_url(
            "https://api.example.com/v1/users/123",
            "api.example.com/v1/users/123",
        );
        assert_eq!(d.action, PolicyAction::Deny); // Implicit deny (allow rules present but no match)
    }

    #[test]
    fn test_http_url_with_port() {
        let engine = engine_from_yaml(
            r#"
version: 1
network:
  deny:
    - "*.example.com:8080/**"
"#,
        );

        let d = engine.evaluate_http_url(
            "http://api.example.com:8080/data",
            "api.example.com:8080/data",
        );
        assert_eq!(d.action, PolicyAction::Deny);

        // Default port (80) — no :8080 in URL
        let d = engine.evaluate_http_url("http://api.example.com/data", "api.example.com/data");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_http_url_warn_key() {
        let engine = engine_from_yaml(
            r#"
version: 1
network:
  warn:
    - "http://**"
"#,
        );

        let d = engine.evaluate_http_url("http://example.com/insecure", "example.com/insecure");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.mode, EnforcementMode::Warn);
    }

    // =====================================================================
    // Tests for evaluate_syscall()
    // =====================================================================

    #[test]
    fn test_syscall_deny_all() {
        let engine = engine_from_yaml(
            r#"
version: 1
syscalls:
  deny:
    - "*"
"#,
        );

        let d = engine.evaluate_syscall("socket");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_syscall("connect");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_syscall_specific_deny() {
        let engine = engine_from_yaml(
            r#"
version: 1
syscalls:
  deny:
    - socket
    - connect
"#,
        );

        let d = engine.evaluate_syscall("socket");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_syscall("connect");
        assert_eq!(d.action, PolicyAction::Deny);

        // Unlisted syscall should be allowed
        let d = engine.evaluate_syscall("read");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_syscall_noop() {
        let engine = engine_from_yaml(
            r#"
version: 1
syscalls:
  noop:
    - "*"
"#,
        );

        // Noop mode — everything allowed
        let d = engine.evaluate_syscall("socket");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_has_syscalls_section() {
        // With syscalls section
        let engine = engine_from_yaml(
            r#"
version: 1
syscalls:
  deny:
    - "*"
"#,
        );
        assert!(engine.has_syscalls_section());

        // Without syscalls section
        let engine = engine_from_yaml("version: 1\n");
        assert!(!engine.has_syscalls_section());

        // With noop syscalls section
        let engine = engine_from_yaml(
            r#"
version: 1
syscalls:
  noop:
    - "*"
"#,
        );
        assert!(!engine.has_syscalls_section());
    }

    #[test]
    fn test_syscall_warn_mode() {
        let engine = engine_from_yaml(
            r#"
version: 1
syscalls:
  warn:
    - "*"
"#,
        );

        let d = engine.evaluate_syscall("execve");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.mode, EnforcementMode::Warn);
    }

    #[test]
    fn test_extract_hook_specs_includes_syscalls() {
        let engine = engine_from_yaml(
            r#"
version: 1
python:
  deny:
    - eval
syscalls:
  deny:
    - "*"
"#,
        );

        let specs = engine.extract_hook_specs();
        let syscall_specs: Vec<_> = specs
            .iter()
            .filter(|s| s.kind == HookSpecKind::Syscall)
            .collect();
        assert_eq!(syscall_specs.len(), 1);
        assert_eq!(syscall_specs[0].pattern, "*");
    }

    #[test]
    fn test_extract_hook_specs_skips_noop_syscalls() {
        let engine = engine_from_yaml(
            r#"
version: 1
syscalls:
  noop:
    - "*"
"#,
        );

        let specs = engine.extract_hook_specs();
        let syscall_specs: Vec<_> = specs
            .iter()
            .filter(|s| s.kind == HookSpecKind::Syscall)
            .collect();
        assert!(syscall_specs.is_empty());
    }

    #[test]
    fn test_extract_hook_specs_includes_envvars() {
        let engine = engine_from_yaml(
            r#"
version: 1
envvars:
  warn:
    - "*SECRET*"
    - "AWS_*"
"#,
        );

        let specs = engine.extract_hook_specs();
        let envvar_specs: Vec<_> = specs
            .iter()
            .filter(|s| s.kind == HookSpecKind::EnvVar)
            .collect();
        assert_eq!(envvar_specs.len(), 1);
        assert_eq!(envvar_specs[0].pattern, "*");
    }

    #[test]
    fn test_extract_hook_specs_skips_noop_envvars() {
        let engine = engine_from_yaml(
            r#"
version: 1
envvars:
  noop:
    - "*"
"#,
        );

        let specs = engine.extract_hook_specs();
        let envvar_specs: Vec<_> = specs
            .iter()
            .filter(|s| s.kind == HookSpecKind::EnvVar)
            .collect();
        assert!(envvar_specs.is_empty());
    }

    #[test]
    fn test_extract_hook_specs_envvars_block_mode_emits_deny_patterns() {
        let engine = engine_from_yaml(
            r#"
version: 1
envvars:
  deny:
    - "*SECRET*"
    - "AWS_*"
"#,
        );

        let specs = engine.extract_hook_specs();
        let envvar_specs: Vec<_> = specs
            .iter()
            .filter(|s| s.kind == HookSpecKind::EnvVar)
            .collect();
        // Block mode (default for deny:) — wildcard + 2 deny patterns
        assert_eq!(envvar_specs.len(), 3);
        assert_eq!(envvar_specs[0].pattern, "*");
        let patterns: Vec<&str> = envvar_specs.iter().map(|s| s.pattern.as_str()).collect();
        assert!(patterns.contains(&"*SECRET*"));
        assert!(patterns.contains(&"AWS_*"));
    }

    #[test]
    fn test_extract_hook_specs_envvars_warn_mode_no_deny_patterns() {
        // Warn mode should NOT emit individual deny patterns (only wildcard for monitoring)
        let engine = engine_from_yaml(
            r#"
version: 1
envvars:
  warn:
    - "*SECRET*"
    - "AWS_*"
"#,
        );

        let specs = engine.extract_hook_specs();
        let envvar_specs: Vec<_> = specs
            .iter()
            .filter(|s| s.kind == HookSpecKind::EnvVar)
            .collect();
        // Only wildcard — no individual deny patterns (warn mode doesn't block)
        assert_eq!(envvar_specs.len(), 1);
        assert_eq!(envvar_specs[0].pattern, "*");
    }

    #[test]
    fn test_evaluate_envvar() {
        let engine = engine_from_yaml(
            r#"
version: 1
envvars:
  warn:
    - "*SECRET*"
    - "AWS_*"
"#,
        );

        let d = engine.evaluate_envvar("AWS_SECRET_ACCESS_KEY");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.mode, EnforcementMode::Warn);

        let d = engine.evaluate_envvar("HOME");
        assert_eq!(d.action, PolicyAction::Allow);
    }
}
