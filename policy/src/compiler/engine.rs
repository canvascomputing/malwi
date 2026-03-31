use super::compile::compile_policy_yaml;
use super::compiled::{
    Category, CompiledNetworkRule, CompiledPolicy, CompiledRule, Constraint, ConstraintKind,
    EnforcementMode, Runtime, SectionKey,
};
use super::error::Result;
use super::pattern::CompiledPattern;

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

    /// Check if this decision hides the target (silent non-existence).
    pub fn is_hidden(&self) -> bool {
        matches!(self.action, PolicyAction::Hide)
    }
}

/// The action resulting from policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// Allow the operation.
    Allow,
    /// Deny the operation (actual enforcement depends on section mode).
    Deny,
    /// Hide — silently pretend the target is non-existent.
    Hide,
}

/// Context for evaluating a function call.
pub struct EvalContext<'a> {
    pub runtime: Option<Runtime>,
    pub name: &'a str,
    pub arguments: &'a [&'a str],
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
        let policy = super::compile::compile_policy_yaml_with_includes(yaml, resolver)?;
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
        self.evaluate_with_key(&key, name, arguments)
    }

    /// Evaluate a file access (global `files` section).
    pub fn evaluate_file(&self, path: &str) -> PolicyDecision {
        let key = SectionKey::global(Category::Files);
        self.evaluate_with_key(&key, path, &[])
    }

    /// Evaluate a domain name against network patterns.
    /// Convenience wrapper around `evaluate_network`.
    pub fn evaluate_domain(&self, domain: &str) -> PolicyDecision {
        self.evaluate_network(None, None, Some(domain), None)
    }

    /// Evaluate a network endpoint (host:port format).
    /// Convenience wrapper around `evaluate_network`.
    pub fn evaluate_endpoint(&self, host: &str, port: u16) -> PolicyDecision {
        let endpoint = format!("{}:{}", host, port);
        self.evaluate_network(None, None, Some(host), Some(&endpoint))
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

    /// Evaluate an HTTP URL against network patterns.
    /// Convenience wrapper around `evaluate_network`.
    pub fn evaluate_http_url(&self, full_url: &str, no_scheme_url: &str) -> PolicyDecision {
        self.evaluate_network(Some(full_url), Some(no_scheme_url), None, None)
    }

    /// Unified network pattern evaluation.
    ///
    /// Tries every pattern against all available representations in a single pass.
    /// No pattern classification needed — each `CompiledNetworkRule` has matchers
    /// for URL, domain, and endpoint pre-compiled.
    ///
    /// When no URL is provided but a domain is, a synthetic `"domain/"` is also
    /// tried against URL matchers (handles URL-style allow patterns like `"pypi.org/**"`
    /// for socket events that only have a hostname).
    pub fn evaluate_network(
        &self,
        full_url: Option<&str>,
        no_scheme_url: Option<&str>,
        domain: Option<&str>,
        endpoint: Option<&str>,
    ) -> PolicyDecision {
        let key = SectionKey::global(Category::Network);
        let section_name = "network".to_string();

        let section = match self.policy.get_section(&key) {
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

        // Synthetic URL for socket events: "domain/" allows URL patterns to
        // match domain-only events (e.g., "pypi.org/**" matches socket to pypi.org).
        let synthetic_url = if full_url.is_none() {
            domain.map(|d| format!("{}/", d))
        } else {
            None
        };

        let best_deny = find_best_network_match(
            &section.network_deny_rules,
            full_url,
            no_scheme_url,
            synthetic_url.as_deref(),
            domain,
            endpoint,
        );
        let best_allow = find_best_network_match(
            &section.network_allow_rules,
            full_url,
            no_scheme_url,
            synthetic_url.as_deref(),
            domain,
            endpoint,
        );

        match (best_allow, best_deny) {
            (Some((allow, allow_spec)), Some((deny, deny_spec))) => {
                // Both matched — most specific wins, deny on tie
                if allow_spec > deny_spec {
                    PolicyDecision {
                        action: PolicyAction::Allow,
                        matched_rule: Some(allow.url_pattern.original().to_string()),
                        section: section_name,
                        mode: allow.mode,
                    }
                } else {
                    PolicyDecision {
                        action: PolicyAction::Deny,
                        matched_rule: Some(deny.url_pattern.original().to_string()),
                        section: section_name,
                        mode: deny.mode,
                    }
                }
            }
            (Some((allow, _)), None) => PolicyDecision {
                action: PolicyAction::Allow,
                matched_rule: Some(allow.url_pattern.original().to_string()),
                section: section_name,
                mode: allow.mode,
            },
            (None, Some((deny, _))) => PolicyDecision {
                action: PolicyAction::Deny,
                matched_rule: Some(deny.url_pattern.original().to_string()),
                section: section_name,
                mode: deny.mode,
            },
            (None, None) => {
                // No rules matched — implicit action depends on allow rules.
                // IP-only events (no domain, no URL) shouldn't be implicitly
                // denied by hostname/URL allow rules — there's no hostname
                // context to evaluate against.
                let has_hostname_context = full_url.is_some() || domain.is_some();
                let action = if section.has_allow_rules() && has_hostname_context {
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
        }
    }

    /// Evaluate a native/C function call (no runtime prefix).
    /// Uses the global `symbols:` section (SectionKey { runtime: None, category: Functions }).
    pub fn evaluate_native_function(&self, name: &str, arguments: &[&str]) -> PolicyDecision {
        let key = SectionKey::global(Category::Functions);
        self.evaluate_with_key(&key, name, arguments)
    }

    /// Evaluate command execution with two-pass matching.
    ///
    /// Pass 1: match rules against the full command string (e.g. "curl example.com").
    /// Pass 2: if no explicit rule matched, match against just the command name (first word).
    /// This lets `allow: ["curl example.com"]` override `deny: [curl]` for that specific invocation.
    pub fn evaluate_execution(&self, command: &str) -> PolicyDecision {
        // Collapse whitespace (including newlines from -c scripts) so
        // patterns like "python -c *" match multiline content.
        let normalized: String = command.split_whitespace().collect::<Vec<_>>().join(" ");
        let key = SectionKey::global(Category::Execution);

        // Pass 1: match against full command string
        let full_result = self.evaluate_with_key(&key, &normalized, &[]);
        if full_result.matched_rule.is_some() {
            return full_result;
        }

        // Pass 2: match against command name only (first word)
        let cmd_name = normalized.split_once(' ').map(|(name, _)| name);
        if let Some(cmd_name) = cmd_name {
            let name_result = self.evaluate_with_key(&key, cmd_name, &[]);
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
        self.evaluate_with_key(&key, name, &[])
    }

    /// Core evaluation logic.
    fn evaluate_with_key(
        &self,
        key: &SectionKey,
        name: &str,
        arguments: &[&str],
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

        // Hide rules — checked first, before allow/deny
        if let Some(hide) = find_best_match(&section.hide_rules, name, arguments) {
            return PolicyDecision {
                action: PolicyAction::Hide,
                matched_rule: Some(hide.pattern.original().to_string()),
                section: section_name,
                mode: EnforcementMode::Hide,
            };
        }

        // Find the most specific matching rule from each side
        let best_deny = find_best_match(&section.deny_rules, name, arguments);
        let best_allow = find_best_match(&section.allow_rules, name, arguments);

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
        let action = if section.has_allow_rules() && !section.has_deny_rules() {
            // Pure allowlist — implicit deny for unlisted items
            PolicyAction::Deny
        } else {
            // Deny-only or mixed allow+deny — implicit allow for unlisted items
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

/// Compute a specificity score for a pattern (higher = more specific).
/// Exact patterns score highest (len * 2), globs score by literal character count.
fn pattern_specificity(pattern: &CompiledPattern) -> usize {
    match pattern {
        // Double so an exact match always outscores a glob of the same length
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
) -> Option<&'a CompiledRule> {
    let mut best: Option<&CompiledRule> = None;
    let mut best_spec = 0;
    for rule in rules {
        if rule_matches(rule, name, arguments) {
            let spec = pattern_specificity(&rule.pattern);
            if best.is_none() || spec > best_spec {
                best = Some(rule);
                best_spec = spec;
            }
        }
    }
    best
}

/// Find the most specific network rule that matches any of the available representations.
///
/// Returns the best-matching rule and the specificity of its match. The specificity
/// is taken from whichever matcher hit (url, domain, or endpoint), choosing the
/// highest specificity across all representations for each rule.
fn find_best_network_match<'a>(
    rules: &'a [CompiledNetworkRule],
    full_url: Option<&str>,
    no_scheme_url: Option<&str>,
    synthetic_url: Option<&str>,
    domain: Option<&str>,
    endpoint: Option<&str>,
) -> Option<(&'a CompiledNetworkRule, usize)> {
    let mut best: Option<(&CompiledNetworkRule, usize)> = None;

    for rule in rules {
        let mut rule_spec = None;

        // Try URL matchers
        if let Some(url) = full_url {
            if rule.url_pattern.matches(url) {
                let s = pattern_specificity(&rule.url_pattern);
                rule_spec = Some(rule_spec.map_or(s, |prev: usize| prev.max(s)));
            }
        }
        if let Some(url) = no_scheme_url {
            if rule.url_pattern.matches(url) {
                let s = pattern_specificity(&rule.url_pattern);
                rule_spec = Some(rule_spec.map_or(s, |prev: usize| prev.max(s)));
            }
        }
        // Synthetic URL: "domain/" for socket events without a URL
        if let Some(url) = synthetic_url {
            if rule.url_pattern.matches(url) {
                let s = pattern_specificity(&rule.url_pattern);
                rule_spec = Some(rule_spec.map_or(s, |prev: usize| prev.max(s)));
            }
        }

        // Try domain matcher
        if let Some(d) = domain {
            if rule.domain_pattern.matches(d) {
                let s = pattern_specificity(&rule.domain_pattern);
                rule_spec = Some(rule_spec.map_or(s, |prev: usize| prev.max(s)));
            }
        }

        // Try endpoint matcher
        if let Some(ep) = endpoint {
            if rule.endpoint_pattern.matches(ep) {
                let s = pattern_specificity(&rule.endpoint_pattern);
                rule_spec = Some(rule_spec.map_or(s, |prev: usize| prev.max(s)));
            }
        }

        if let Some(spec) = rule_spec {
            if best.is_none() || spec > best.unwrap().1 {
                best = Some((rule, spec));
            }
        }
    }

    best
}

/// Check if a rule matches the given context.
fn rule_matches(rule: &CompiledRule, name: &str, arguments: &[&str]) -> bool {
    // First check if the pattern matches the name
    if !rule.pattern.matches(name) {
        return false;
    }

    // If no constraints, pattern match is sufficient
    if rule.constraints.is_empty() {
        return true;
    }

    // Check constraints
    check_constraints(&rule.constraints, arguments)
}

/// Check if any constraint is satisfied.
fn check_constraints(constraints: &[Constraint], arguments: &[&str]) -> bool {
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
        }
    }

    false
}

fn format_section_name(key: &SectionKey) -> String {
    let category = match key.category {
        Category::Functions => "symbols",
        Category::Files => "files",
        Category::EnvVars => "envvars",
        Category::Network | Category::Protocols => "network",
        Category::Execution => "commands",
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
    fn test_deny_rule_blocks_matching_function() {
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
    fn test_allow_rule_permits_matching_function() {
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
    fn test_file_allow_deny() {
        let engine = engine_from_yaml(
            r#"
version: 1
files:
  allow:
    - "/tmp/*"
    - "/app/data/*"
  deny:
    - "/etc/*"
"#,
        );

        // /tmp allowed
        let decision = engine.evaluate_file("/tmp/test.txt");
        assert_eq!(decision.action, PolicyAction::Allow);

        // /app/data allowed
        let decision = engine.evaluate_file("/app/data/file.json");
        assert_eq!(decision.action, PolicyAction::Allow);

        // /etc denied
        let decision = engine.evaluate_file("/etc/passwd");
        assert_eq!(decision.action, PolicyAction::Deny);
    }

    #[test]
    fn test_default_mode_uses_block_enforcement() {
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
    fn test_log_key_denies_with_log_enforcement() {
        let engine = engine_from_yaml(
            r#"
version: 1
files:
  log:
    - "/etc/*"
"#,
        );

        let decision = engine.evaluate_file("/etc/passwd");
        assert_eq!(decision.action, PolicyAction::Deny);
        assert_eq!(decision.section_mode(), EnforcementMode::Log);
    }

    #[test]
    fn test_noop_mode_allows_everything() {
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
    fn test_python_deny_does_not_affect_nodejs_allow() {
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
    fn test_deny_network_blocks_matching_domain() {
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
    fn test_deny_network_blocks_matching_endpoint() {
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
    fn test_protocol_allowlist_blocks_unlisted_protocol() {
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
    fn test_deny_commands_blocks_matching_execution() {
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
        assert_eq!(d3.action, PolicyAction::Allow); // Mixed allow+deny: implicit allow for unlisted
    }

    #[test]
    fn test_empty_policy_allows_any_function() {
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
    fn test_pattern_with_special_chars_matches_literally() {
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
    fn test_unconstrained_deny_matches_with_empty_args() {
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

    #[test]
    fn test_evaluate_execution_multiline_c_flag_matches_star() {
        let engine = engine_from_yaml(
            r#"
version: 1
commands:
  allow:
    - "python -c *"
    - "node -e *"
    - "bash -c *"
"#,
        );

        // Python multiline -c script
        let d = engine.evaluate_execution("python -c import sys\nprint('hello')");
        assert_eq!(d.action, PolicyAction::Allow);
        assert_eq!(d.matched_rule, Some("python -c *".to_string()));

        // Node.js multiline -e script
        let d2 = engine.evaluate_execution("node -e const x = 1;\nconsole.log(x)");
        assert_eq!(d2.action, PolicyAction::Allow);
        assert_eq!(d2.matched_rule, Some("node -e *".to_string()));

        // Bash multiline -c script
        let d3 = engine.evaluate_execution("bash -c echo hello\necho world");
        assert_eq!(d3.action, PolicyAction::Allow);
        assert_eq!(d3.matched_rule, Some("bash -c *".to_string()));

        // Tabs and multiple spaces also normalized
        let d4 = engine.evaluate_execution("python -c import\t\tsys\n  print('x')");
        assert_eq!(d4.action, PolicyAction::Allow);
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
