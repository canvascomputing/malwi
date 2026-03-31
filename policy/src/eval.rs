//! Policy evaluator — the single evaluation engine for malwi.
//!
//! Used by both the agent (in-process enforcement) and CLI (display rendering).
//! Simple sections use pre-sorted rules (first match wins). The network section
//! uses multi-representation matching with runtime specificity.

use crate::decision::{combine_outcomes, Outcome};
use crate::glob::{matches_glob, matches_glob_ci};
use crate::resolved::{Decision, NetworkRule, NetworkRuleSet, Policy, RuleSet};
use crate::util::{extract_file_path, is_networking_symbol, matches_network_host, to_tilde_path};
use malwi_protocol::event::{HookType, NetworkInfo, TraceEvent};

// ── RuleSet Evaluation (simple sections) ─────────────────────────

impl RuleSet {
    /// Match a name against sorted rules. First match wins.
    pub fn match_name(&self, name: &str) -> Outcome {
        for rule in &self.rules {
            if rule.runtime_filter.is_none() && matches_glob(&rule.pattern, name) {
                return rule.decision.to_outcome(&rule.label);
            }
        }
        self.default_decision.to_outcome_default()
    }

    /// Match a name with hook type context. Rules with runtime_filter are only
    /// checked when the hook type matches.
    pub fn match_name_for_hook(&self, name: &str, hook_type: &HookType) -> Outcome {
        for rule in &self.rules {
            if let Some(ref filter) = rule.runtime_filter {
                if filter != hook_type {
                    continue;
                }
            }
            if matches_glob(&rule.pattern, name) {
                return rule.decision.to_outcome(&rule.label);
            }
        }
        self.default_decision.to_outcome_default()
    }

    /// Case-insensitive match (for network hostnames/URLs).
    pub fn match_name_ci(&self, name: &str) -> Outcome {
        let lower = name.to_lowercase();
        for rule in &self.rules {
            if rule.runtime_filter.is_none() && matches_glob_ci(&rule.pattern, &lower) {
                return rule.decision.to_outcome(&rule.label);
            }
        }
        self.default_decision.to_outcome_default()
    }
}

impl Decision {
    /// Convert to an Outcome using the matched rule's label.
    fn to_outcome(&self, label: &str) -> Outcome {
        match self {
            Decision::Suppress => Outcome::Suppress,
            Decision::Trace => Outcome::Trace,
            Decision::Warn { section } => Outcome::Warn {
                rule: label.to_string(),
                section: section.clone(),
            },
            Decision::Block { section } => Outcome::Block {
                rule: label.to_string(),
                section: section.clone(),
            },
            Decision::Hide => Outcome::Hide,
        }
    }

    /// Convert to an Outcome for the default (no rule matched).
    fn to_outcome_default(&self) -> Outcome {
        match self {
            Decision::Block { section } => Outcome::Block {
                rule: "(implicit deny)".to_string(),
                section: section.clone(),
            },
            Decision::Suppress => Outcome::Suppress,
            Decision::Trace => Outcome::Trace,
            Decision::Warn { section } => Outcome::Warn {
                rule: "(implicit)".to_string(),
                section: section.clone(),
            },
            Decision::Hide => Outcome::Hide,
        }
    }
}

// ── NetworkRuleSet Evaluation ────────────────────────────────────

/// Compute specificity score for a glob pattern.
/// Higher = more specific. Counts non-wildcard characters.
/// Exact matches (no wildcards) score double to always beat globs.
pub fn pattern_score(pattern: &str) -> usize {
    if !pattern.contains('*') && !pattern.contains('?') {
        // Exact match — double score to always beat globs of same length
        pattern.len() * 2
    } else {
        pattern.chars().filter(|c| *c != '*' && *c != '?').count()
    }
}

/// Find the highest-specificity matching rule across all representations.
///
/// Each rule has 3 matchers (URL, domain, endpoint). Each is tried against
/// the corresponding event representation. The rule's score is the highest
/// specificity from any matcher that hit.
fn best_matching_rule<'a>(
    rules: &'a [NetworkRule],
    full_url: Option<&str>,
    no_scheme_url: Option<&str>,
    domain: Option<&str>,
    endpoint: Option<&str>,
    synthetic_url: Option<&str>,
) -> Option<(&'a NetworkRule, usize)> {
    let mut best: Option<(&NetworkRule, usize)> = None;

    for rule in rules {
        let mut rule_score: Option<usize> = None;

        // URL matcher — try full URL, schemeless URL, then synthetic URL
        for url in [full_url, no_scheme_url, synthetic_url]
            .into_iter()
            .flatten()
        {
            if matches_glob_ci(&rule.url_pattern, url) {
                let s = pattern_score(&rule.url_pattern);
                rule_score = Some(rule_score.map_or(s, |prev: usize| prev.max(s)));
            }
        }

        // Domain matcher (case-insensitive)
        if let Some(d) = domain {
            if matches_glob_ci(&rule.domain_pattern, d) {
                let s = pattern_score(&rule.domain_pattern);
                rule_score = Some(rule_score.map_or(s, |prev: usize| prev.max(s)));
            }
        }

        // Endpoint matcher
        if let Some(ep) = endpoint {
            if matches_glob(&rule.endpoint_pattern, ep) {
                let s = pattern_score(&rule.endpoint_pattern);
                rule_score = Some(rule_score.map_or(s, |prev: usize| prev.max(s)));
            }
        }

        if let Some(score) = rule_score {
            if best.is_none() || score > best.unwrap().1 {
                best = Some((rule, score));
            }
        }
    }

    best
}

impl NetworkRuleSet {
    /// Match network info against rules using multi-representation matching.
    pub fn match_connection(&self, info: &NetworkInfo) -> Outcome {
        let has_hostname_context = info.domain.is_some() || info.url.is_some();

        // Protocol check (orthogonal constraint)
        if let Some(ref proto) = info.protocol {
            if let Some(outcome) = self.check_protocol(proto.as_str()) {
                return outcome;
            }
        }

        // Build representations
        let full_url = info.url.as_deref().filter(|u| u.contains("://"));
        let domain = info.domain.as_deref();
        let endpoint = match (&info.domain, &info.ip, info.port) {
            (Some(host), _, Some(port)) => Some(format!("{}:{}", host, port)),
            (None, Some(ip), Some(port)) => Some(format!("{}:{}", ip, port)),
            _ => None,
        };

        // Schemeless URL for matching patterns without scheme prefix
        // (e.g., "pypi.org/**" should match "https://pypi.org/simple/")
        let no_scheme_url = full_url.and_then(|u| u.split_once("://").map(|(_, rest)| rest));

        // Synthetic URL for socket events without full URL:
        // "domain/" lets URL patterns like "pypi.org/**" match
        let synthetic_url = if full_url.is_none() {
            domain.map(|d| format!("{}/", d))
        } else {
            None
        };

        // Find best deny and best allow
        let best_deny = best_matching_rule(
            &self.deny_rules,
            full_url,
            no_scheme_url,
            domain,
            endpoint.as_deref(),
            synthetic_url.as_deref(),
        );
        let best_allow = best_matching_rule(
            &self.allow_rules,
            full_url,
            no_scheme_url,
            domain,
            endpoint.as_deref(),
            synthetic_url.as_deref(),
        );

        // Check hide rules (highest priority)
        let best_hide = best_matching_rule(
            &self.hide_rules,
            full_url,
            no_scheme_url,
            domain,
            endpoint.as_deref(),
            synthetic_url.as_deref(),
        );
        if let Some((rule, _)) = best_hide {
            return rule.decision.to_outcome(&rule.label);
        }

        // Resolve allow vs deny by specificity
        match (best_allow, best_deny) {
            (Some((allow, allow_score)), Some((deny, deny_score))) => {
                if allow_score > deny_score {
                    allow.decision.to_outcome(&allow.label)
                } else {
                    deny.decision.to_outcome(&deny.label)
                }
            }
            (Some((allow, _)), None) => allow.decision.to_outcome(&allow.label),
            (None, Some((deny, _))) => deny.decision.to_outcome(&deny.label),
            (None, None) => {
                // No rules matched — implicit action
                // IP-only events shouldn't be implicitly denied by hostname rules
                if self.has_allow_rules && has_hostname_context {
                    Outcome::Block {
                        rule: "(implicit deny)".into(),
                        section: "network".into(),
                    }
                } else {
                    Outcome::Suppress
                }
            }
        }
    }

    /// Check if a protocol is allowed.
    /// Returns Some(Block) if the protocol is denied, None if allowed or no restriction.
    fn check_protocol(&self, protocol: &str) -> Option<Outcome> {
        if self.allowed_protocols.is_empty() {
            return None; // No protocol restrictions
        }
        let is_allowed = self
            .allowed_protocols
            .iter()
            .any(|p| p.eq_ignore_ascii_case(protocol));
        if is_allowed {
            None // Protocol allowed, continue to pattern matching
        } else {
            Some(Outcome::Block {
                rule: format!("protocol {} not in allowed list", protocol),
                section: "network".into(),
            })
        }
    }
}

// ── Multi-Phase Evaluation ───────────────────────────────────────

impl Policy {
    /// Evaluate a trace event against all applicable policy sections.
    ///
    /// Core entry point — same code runs in agent and CLI.
    pub fn check_event(&self, event: &TraceEvent) -> Outcome {
        let mut outcomes: Vec<Outcome> = Vec::new();

        // Network deferral: native networking symbols are deferred from
        // functions phase to network phase when network rules exist.
        let defer_to_network = self.network.is_active()
            && matches!(event.hook_type, HookType::Native)
            && is_networking_symbol(&event.function);

        // Phase 1: Function-level (runtime-aware matching)
        if self.functions.is_active() && !defer_to_network {
            outcomes.push(
                self.functions
                    .match_name_for_hook(&event.function, &event.hook_type),
            );
        }

        // Phase 2: Network (from NetworkInfo)
        if self.network.is_active() {
            if let Some(ref net) = event.network_info {
                outcomes.push(self.network.match_connection(net));
            }
        }

        // Phase 3: EnvVar
        if self.envvars.is_active() {
            if matches!(event.hook_type, HookType::EnvVar) {
                outcomes.push(self.envvars.match_name(&event.function));
            }
            // Cross-evaluation: native getenv → envvars section
            if matches!(event.hook_type, HookType::Native)
                && (event.function == "getenv" || event.function == "secure_getenv")
            {
                if let Some(name) = event.arguments.first().and_then(|a| a.display.as_deref()) {
                    outcomes.push(self.envvars.match_name(name));
                }
            }
        }

        // Phase 4: File (extract path from first arg)
        if self.files.is_active() {
            if let Some(path) = extract_file_path(event) {
                let outcome = self.files.match_name(&path);
                let outcome = if matches!(outcome, Outcome::Suppress) {
                    if let Some(tilde) = to_tilde_path(&path) {
                        let tilde_outcome = self.files.match_name(&tilde);
                        if !matches!(tilde_outcome, Outcome::Suppress) {
                            tilde_outcome
                        } else {
                            outcome
                        }
                    } else {
                        outcome
                    }
                } else {
                    outcome
                };
                outcomes.push(outcome);
            }
        }

        // Phase 5: Command (Exec/Bash only) — two-pass matching.
        // Pass 1: match full command string (function + args).
        // Pass 2: if no explicit match, try command name only.
        if self.commands.is_active() && matches!(event.hook_type, HookType::Exec | HookType::Bash) {
            let full_cmd = build_full_command(event);
            outcomes.push(self.match_command(&full_cmd));
        }

        // No phases produced an outcome:
        // - Network deferral (socket without destination) → Trace (display, let network decide later)
        // - No policy rules at all → Trace (display everything)
        // - Policy has rules but none applicable to this event → Suppress
        if outcomes.is_empty() {
            return if defer_to_network || !self.has_rules() {
                Outcome::Trace
            } else {
                Outcome::Suppress
            };
        }

        // Separate displayable outcomes from suppressions.
        // If any phase explicitly wants to display/block/warn, that wins.
        // Suppress (no match in section) only wins if ALL phases suppress.
        let mut has_suppress = false;
        let mut displayable: Vec<Outcome> = Vec::new();
        for o in outcomes {
            match o {
                Outcome::Suppress => has_suppress = true,
                other => displayable.push(other),
            }
        }

        if displayable.is_empty() {
            // All phases suppressed → Suppress
            if has_suppress {
                return Outcome::Suppress;
            }
            return Outcome::Trace;
        }

        // Combine displayable outcomes (strictest wins)
        combine_outcomes(displayable)
    }

    /// Evaluate a single envvar name (for getenv hide/block hooks).
    pub fn check_envvar(&self, name: &str) -> Outcome {
        if !self.envvars.is_active() {
            return Outcome::Trace;
        }
        self.envvars.match_name(name)
    }

    /// Evaluate a single file path (for stat/access hide hooks).
    pub fn check_file(&self, path: &str) -> Outcome {
        if !self.files.is_active() {
            return Outcome::Trace;
        }
        let outcome = self.files.match_name(path);
        if matches!(outcome, Outcome::Suppress) {
            if let Some(tilde) = to_tilde_path(path) {
                let tilde_outcome = self.files.match_name(&tilde);
                if !matches!(tilde_outcome, Outcome::Suppress) {
                    return tilde_outcome;
                }
            }
        }
        outcome
    }

    /// Evaluate a network host (for connect hooks).
    pub fn check_network_host(&self, host: &str) -> Outcome {
        if !self.network.is_active() {
            return Outcome::Trace;
        }
        // Simple case: match host against network rules as a domain
        let info = NetworkInfo {
            domain: Some(host.to_string()),
            ..Default::default()
        };
        self.network.match_connection(&info)
    }

    /// Two-pass command matching: full command string first, then command name only.
    fn match_command(&self, full_cmd: &str) -> Outcome {
        // Collapse whitespace (including newlines from -c scripts)
        let normalized: String = full_cmd.split_whitespace().collect::<Vec<_>>().join(" ");

        // Pass 1: match against full command string
        for rule in &self.commands.rules {
            if matches_glob(&rule.pattern, &normalized) {
                return rule.decision.to_outcome(&rule.label);
            }
        }

        // Pass 2: match against command name only (first word)
        if let Some(cmd_name) = normalized.split_once(' ').map(|(name, _)| name) {
            for rule in &self.commands.rules {
                if matches_glob(&rule.pattern, cmd_name) {
                    return rule.decision.to_outcome(&rule.label);
                }
            }
        }

        // No match — use default
        self.commands.default_decision.to_outcome_default()
    }

    /// Extract file deny/warn patterns for command analysis triage.
    pub fn file_deny_patterns(&self) -> Vec<&str> {
        self.files
            .rules
            .iter()
            .filter(|r| matches!(r.decision, Decision::Block { .. } | Decision::Warn { .. }))
            .map(|r| r.pattern.as_str())
            .collect()
    }

    /// Extract command deny/warn patterns for command analysis triage.
    pub fn command_deny_patterns(&self) -> Vec<&str> {
        self.commands
            .rules
            .iter()
            .filter(|r| matches!(r.decision, Decision::Block { .. } | Decision::Warn { .. }))
            .map(|r| r.pattern.as_str())
            .collect()
    }
}

// ── Command Utilities ─────────────────────────────────────────────

/// Build the full command string from an exec/bash trace event.
/// Handles shell unwrapping: `sh -c "curl evil.com"` → `"curl evil.com"`.
fn build_full_command(event: &TraceEvent) -> String {
    let func = &event.function;
    let args: Vec<&str> = event
        .arguments
        .iter()
        .filter_map(|a| a.display.as_deref())
        .collect();

    // Try shell unwrapping first
    if let Some(unwrapped) = unwrap_shell_exec_args(func, &args) {
        return unwrapped;
    }

    // Build "cmd arg1 arg2 ..." from function + args (skip argv[0])
    let cmd_args: Vec<&str> = args.get(1..).unwrap_or(&[]).to_vec();
    if cmd_args.is_empty() {
        func.to_string()
    } else {
        format!("{} {}", func, cmd_args.join(" "))
    }
}

/// Unwrap shell wrappers: `sh -c "curl -s evil.com"` → `"curl -s evil.com"`.
/// Replaces the command path with its basename, keeps the rest.
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

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolved::{NetworkRule, NetworkRuleSet, Rule, RuleSet};
    use malwi_protocol::event::{Argument, EventType, HookType, NetworkInfo, TraceEvent};

    fn make_event(hook_type: HookType, function: &str) -> TraceEvent {
        TraceEvent {
            hook_type,
            function: function.into(),
            event_type: EventType::Enter,
            ..Default::default()
        }
    }

    fn make_event_with_args(hook_type: HookType, function: &str, args: &[&str]) -> TraceEvent {
        TraceEvent {
            hook_type,
            function: function.into(),
            event_type: EventType::Enter,
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

    fn make_network_event(function: &str, domain: &str) -> TraceEvent {
        TraceEvent {
            hook_type: HookType::Native,
            function: function.into(),
            event_type: EventType::Enter,
            network_info: Some(NetworkInfo {
                domain: Some(domain.into()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Build a RuleSet from allow/deny patterns, sorted by specificity.
    fn ruleset_from_patterns(allow: &[&str], deny: &[&str], section: &str) -> RuleSet {
        let mut scored: Vec<(Rule, usize)> = Vec::new();

        for p in deny {
            let spec = pattern_score(p);
            scored.push((
                Rule {
                    pattern: p.to_string(),
                    decision: Decision::Block {
                        section: section.into(),
                    },
                    label: p.to_string(),
                    runtime_filter: None,
                },
                spec,
            ));
        }

        for p in allow {
            let spec = pattern_score(p);
            scored.push((
                Rule {
                    pattern: p.to_string(),
                    decision: Decision::Suppress,
                    label: p.to_string(),
                    runtime_filter: None,
                },
                spec,
            ));
        }

        scored.sort_by(|a, b| {
            b.1.cmp(&a.1).then_with(|| {
                let a_is_allow = matches!(a.0.decision, Decision::Suppress);
                let b_is_allow = matches!(b.0.decision, Decision::Suppress);
                a_is_allow.cmp(&b_is_allow)
            })
        });

        let default_decision = if !allow.is_empty() {
            Decision::Block {
                section: section.into(),
            }
        } else {
            Decision::Suppress
        };

        RuleSet {
            rules: scored.into_iter().map(|(r, _)| r).collect(),
            default_decision,
        }
    }

    fn network_ruleset_from_patterns(allow: &[&str], deny: &[&str]) -> NetworkRuleSet {
        let make_rules = |patterns: &[&str], decision: Decision| -> Vec<NetworkRule> {
            patterns
                .iter()
                .map(|p| NetworkRule {
                    url_pattern: p.to_string(),
                    domain_pattern: p.to_string(),
                    endpoint_pattern: p.to_string(),
                    decision: decision.clone(),
                    label: p.to_string(),
                })
                .collect()
        };

        NetworkRuleSet {
            allow_rules: make_rules(allow, Decision::Suppress),
            deny_rules: make_rules(
                deny,
                Decision::Block {
                    section: "network".into(),
                },
            ),
            hide_rules: Vec::new(),
            allowed_protocols: Vec::new(),
            has_allow_rules: !allow.is_empty(),
        }
    }

    fn policy_with_functions(ruleset: RuleSet) -> Policy {
        Policy {
            functions: ruleset,
            ..Policy::empty()
        }
    }

    fn policy_with_network(network: NetworkRuleSet) -> Policy {
        Policy {
            network,
            ..Policy::empty()
        }
    }

    // ── Core evaluator tests ─────────────────────────────────────

    #[test]
    fn test_empty_policy_traces() {
        let policy = Policy::empty();
        assert_eq!(
            policy.check_event(&make_event(HookType::Native, "connect")),
            Outcome::Trace
        );
    }

    #[test]
    fn test_function_deny_blocks() {
        let policy = policy_with_functions(ruleset_from_patterns(&[], &["eval"], "functions"));
        assert!(matches!(
            policy.check_event(&make_event(HookType::Python, "eval")),
            Outcome::Block { .. }
        ));
        assert_eq!(
            policy.check_event(&make_event(HookType::Python, "json.loads")),
            Outcome::Suppress
        );
    }

    #[test]
    fn test_function_allow_suppresses() {
        let policy = policy_with_functions(ruleset_from_patterns(&["json.*"], &["*"], "functions"));
        assert_eq!(
            policy.check_event(&make_event(HookType::Python, "json.loads")),
            Outcome::Suppress
        );
        assert!(matches!(
            policy.check_event(&make_event(HookType::Python, "eval")),
            Outcome::Block { .. }
        ));
    }

    // ── Divergence fix tests ─────────────────────────────────────

    #[test]
    fn test_broad_allow_specific_deny_blocks() {
        let policy = policy_with_functions(ruleset_from_patterns(&["*"], &["eval"], "functions"));
        assert!(
            matches!(
                policy.check_event(&make_event(HookType::Python, "eval")),
                Outcome::Block { .. }
            ),
            "deny eval must beat allow * via specificity"
        );
        assert_eq!(
            policy.check_event(&make_event(HookType::Python, "json.loads")),
            Outcome::Suppress
        );
    }

    #[test]
    fn test_module_allow_specific_deny_blocks() {
        let policy = policy_with_functions(ruleset_from_patterns(
            &["fs.*"],
            &["fs.writeFile"],
            "functions",
        ));
        assert!(matches!(
            policy.check_event(&make_event(HookType::Nodejs, "fs.writeFile")),
            Outcome::Block { .. }
        ));
        assert_eq!(
            policy.check_event(&make_event(HookType::Nodejs, "fs.readFileSync")),
            Outcome::Suppress
        );
    }

    // ── Network tests ────────────────────────────────────────────

    #[test]
    fn test_network_deny_blocks_domain() {
        let policy = policy_with_network(network_ruleset_from_patterns(&[], &["*.evil.com"]));
        assert!(matches!(
            policy.check_event(&make_network_event("connect", "malware.evil.com")),
            Outcome::Block { .. }
        ));
        assert_eq!(
            policy.check_event(&make_network_event("connect", "pypi.org")),
            Outcome::Suppress
        );
    }

    #[test]
    fn test_network_case_insensitive() {
        let policy = policy_with_network(network_ruleset_from_patterns(&["*.PyPI.org"], &["*"]));
        assert_eq!(
            policy.check_event(&make_network_event("connect", "files.pypi.org")),
            Outcome::Suppress
        );
    }

    // ── Command tests ────────────────────────────────────────────

    #[test]
    fn test_command_deny() {
        let policy = Policy {
            commands: ruleset_from_patterns(&[], &["curl", "wget"], "commands"),
            ..Policy::empty()
        };
        assert!(matches!(
            policy.check_event(&make_event(HookType::Exec, "curl")),
            Outcome::Block { .. }
        ));
        assert_eq!(
            policy.check_event(&make_event(HookType::Exec, "ls")),
            Outcome::Suppress
        );
    }

    // ── EnvVar tests ─────────────────────────────────────────────

    #[test]
    fn test_envvar_hide() {
        let policy = Policy {
            envvars: RuleSet {
                rules: vec![Rule {
                    pattern: "MALWI_*".into(),
                    decision: Decision::Hide,
                    label: "MALWI_*".into(),
                    runtime_filter: None,
                }],
                default_decision: Decision::Suppress,
            },
            ..Policy::empty()
        };
        assert_eq!(
            policy.check_event(&make_event(HookType::EnvVar, "MALWI_URL")),
            Outcome::Hide
        );
        assert_eq!(
            policy.check_event(&make_event(HookType::EnvVar, "HOME")),
            Outcome::Suppress
        );
    }

    #[test]
    fn test_getenv_cross_evaluation() {
        let policy = Policy {
            envvars: RuleSet {
                rules: vec![Rule {
                    pattern: "SECRET_KEY".into(),
                    decision: Decision::Hide,
                    label: "SECRET_KEY".into(),
                    runtime_filter: None,
                }],
                default_decision: Decision::Suppress,
            },
            ..Policy::empty()
        };
        assert_eq!(
            policy.check_event(&make_event_with_args(
                HookType::Native,
                "getenv",
                &["SECRET_KEY"]
            )),
            Outcome::Hide
        );
        assert_eq!(
            policy.check_event(&make_event_with_args(HookType::Native, "getenv", &["HOME"])),
            Outcome::Suppress
        );
    }

    // ── File tests ───────────────────────────────────────────────

    #[test]
    fn test_file_deny() {
        let policy = Policy {
            files: ruleset_from_patterns(&[], &["*.pem"], "files"),
            ..Policy::empty()
        };
        assert!(matches!(
            policy.check_event(&make_event_with_args(
                HookType::Native,
                "open",
                &["/etc/ssl/cert.pem"]
            )),
            Outcome::Block { .. }
        ));
    }

    #[test]
    fn test_file_tilde_matches_absolute() {
        let policy = Policy {
            files: ruleset_from_patterns(&[], &["~/.ssh/**"], "files"),
            ..Policy::empty()
        };
        let home = std::env::var("HOME").unwrap();
        let ssh_path = format!("{home}/.ssh/id_rsa");
        assert!(matches!(
            policy.check_event(&make_event_with_args(
                HookType::Native,
                "open",
                &[&ssh_path]
            )),
            Outcome::Block { .. }
        ));
    }

    // ── Network deferral ─────────────────────────────────────────

    #[test]
    fn test_network_deferral_socket_not_blocked() {
        let policy = Policy {
            functions: ruleset_from_patterns(&[], &["socket", "connect"], "functions"),
            network: network_ruleset_from_patterns(&[], &["*"]),
            ..Policy::empty()
        };
        // socket() with no NetworkInfo → deferred, not blocked
        assert_eq!(
            policy.check_event(&make_event(HookType::Native, "socket")),
            Outcome::Trace
        );
        // connect() with domain → network phase blocks
        assert!(matches!(
            policy.check_event(&make_network_event("connect", "evil.com")),
            Outcome::Block { .. }
        ));
    }

    // ── Cross-phase strictness ───────────────────────────────────

    #[test]
    fn test_stricter_wins_across_sections() {
        let policy = Policy {
            functions: RuleSet {
                rules: vec![Rule {
                    pattern: "connect".into(),
                    decision: Decision::Warn {
                        section: "functions".into(),
                    },
                    label: "connect".into(),
                    runtime_filter: None,
                }],
                default_decision: Decision::Suppress,
            },
            network: network_ruleset_from_patterns(&[], &["*.evil.com"]),
            ..Policy::empty()
        };
        let mut event = make_event(HookType::Native, "connect");
        event.network_info = Some(NetworkInfo {
            domain: Some("x.evil.com".into()),
            ..Default::default()
        });
        assert!(matches!(policy.check_event(&event), Outcome::Block { .. }));
    }

    // ── Deny-only suppression ────────────────────────────────────

    #[test]
    fn test_deny_only_no_trace_noise() {
        let policy = Policy {
            functions: ruleset_from_patterns(&[], &["os.system", "subprocess.*"], "functions"),
            files: ruleset_from_patterns(&[], &["~/.ssh/**", "*.pem"], "files"),
            envvars: ruleset_from_patterns(&[], &["SECRET_*"], "envvars"),
            ..Policy::empty()
        };
        assert_eq!(
            policy.check_event(&make_event_with_args(
                HookType::Native,
                "open",
                &["/tmp/pip-xyz/setup.py"]
            )),
            Outcome::Suppress
        );
        assert_eq!(
            policy.check_event(&make_event(HookType::EnvVar, "BUILD_ID")),
            Outcome::Suppress
        );
        assert!(matches!(
            policy.check_event(&make_event(HookType::EnvVar, "SECRET_KEY")),
            Outcome::Block { .. }
        ));
    }

    // ── Pattern score tests ──────────────────────────────────────

    #[test]
    fn test_pattern_score() {
        assert_eq!(pattern_score("eval"), 8); // exact: 4*2
        assert_eq!(pattern_score("*"), 0); // pure wildcard
        assert_eq!(pattern_score("fs.*"), 3); // glob: 'f','s','.' = 3 non-wildcard
        assert_eq!(pattern_score("fs.writeFile"), 24); // exact: 12*2
        assert_eq!(pattern_score("*.evil.com"), 9); // glob: ".evil.com" = 9
    }
}
