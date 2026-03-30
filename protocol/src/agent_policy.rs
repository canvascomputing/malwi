//! Agent-side policy evaluation using glob patterns.
//!
//! This module provides in-process policy evaluation for the agent. Instead of
//! sending events to the CLI for review decisions, the agent evaluates policy
//! rules locally using compiled glob patterns. This eliminates the TCP
//! round-trip for every hook event and removes the fail-open timeout risk.
//!
//! The evaluation order per event:
//! 1. Check hide patterns → if match, `Hide`
//! 2. Check allow patterns → if match, `Suppress`
//! 3. Check deny patterns → if match, `Block { rule }`
//! 4. Check warn patterns → if match, `Warn { rule }`
//! 5. Check log patterns → if match, `Trace` (display normally)
//! 6. Implicit deny (if allow patterns exist) → `Block`
//! 7. No match → `Suppress` if monitoring-only section, else `Trace`

use crate::agent_config::{AgentPolicySections, PolicySection};
use crate::event::{HookType, TraceEvent};
use crate::glob::matches_glob;

/// Result of agent-side policy evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentDecision {
    /// Display to user (no policy match).
    Trace,
    /// Agent blocked the call (returned -1/EACCES).
    Block { rule: String, section: String },
    /// Agent allowed but flagged.
    Warn { rule: String, section: String },
    /// Make target silently non-existent (NULL/ENOENT), don't display.
    Hide,
    /// Don't display, don't block (allowed by policy).
    Suppress,
}

impl AgentDecision {
    /// Whether the call should be allowed to proceed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Trace | Self::Warn { .. } | Self::Suppress)
    }

    /// Whether the event should be sent to the CLI for display.
    pub fn should_send(&self) -> bool {
        matches!(self, Self::Trace | Self::Block { .. } | Self::Warn { .. })
    }
}

/// Agent-side policy evaluator compiled from `AgentConfig`.
pub struct AgentPolicy {
    network: SectionRules,
    commands: SectionRules,
    files: SectionRules,
    envvars: SectionRules,
    functions: SectionRules,
}

/// Compiled rules for a single policy section.
struct SectionRules {
    allow: Vec<String>,
    deny: Vec<String>,
    warn: Vec<String>,
    log: Vec<String>,
    hide: Vec<String>,
}

impl SectionRules {
    fn from_section(section: &PolicySection) -> Self {
        Self {
            allow: section.allow.clone(),
            deny: section.deny.clone(),
            warn: section.warn.clone(),
            log: section.log.clone(),
            hide: section.hide.clone(),
        }
    }

    /// Core evaluation cascade shared by all matching modes.
    ///
    /// Evaluation order: hide → allow → deny → warn → log → implicit deny → default.
    /// When `allow` patterns exist, anything not explicitly allowed is implicitly denied.
    /// When no allow/deny patterns exist (monitoring-only), unmatched events are suppressed.
    fn evaluate_with(&self, section: &str, matches: impl Fn(&str, &str) -> bool) -> AgentDecision {
        for pattern in &self.hide {
            if matches(pattern, section) {
                return AgentDecision::Hide;
            }
        }

        for pattern in &self.allow {
            if matches(pattern, section) {
                return AgentDecision::Suppress;
            }
        }

        for pattern in &self.deny {
            if matches(pattern, section) {
                return AgentDecision::Block {
                    rule: pattern.clone(),
                    section: section.to_string(),
                };
            }
        }

        for pattern in &self.warn {
            if matches(pattern, section) {
                return AgentDecision::Warn {
                    rule: pattern.clone(),
                    section: section.to_string(),
                };
            }
        }

        for pattern in &self.log {
            if matches(pattern, section) {
                return AgentDecision::Trace;
            }
        }

        if !self.allow.is_empty() {
            return AgentDecision::Block {
                rule: "(implicit deny)".to_string(),
                section: section.to_string(),
            };
        }

        // No match, no allow rules — suppress. Trace only comes from explicit
        // log pattern matches. This is the blocklist model: deny-only sections
        // block matching events and stay quiet about everything else.
        AgentDecision::Suppress
    }

    /// Evaluate a name against this section's rules (case-sensitive).
    fn evaluate(&self, name: &str, section: &str) -> AgentDecision {
        self.evaluate_with(section, |pattern, _| matches_glob(pattern, name))
    }

    /// Evaluate using case-insensitive matching (for network hostnames/URLs).
    fn evaluate_ci(&self, name: &str, section: &str) -> AgentDecision {
        let lower = name.to_lowercase();
        self.evaluate_with(section, |pattern, _| {
            matches_glob(&pattern.to_lowercase(), &lower)
        })
    }

    /// Evaluate a hostname against network rules, handling URL-like patterns.
    ///
    /// Network patterns may be URL-like (e.g. `pypi.org/**`). When matching a
    /// bare hostname, we also try the domain prefix (everything before the first `/`).
    fn evaluate_network_host(&self, hostname: &str) -> AgentDecision {
        let lower = hostname.to_lowercase();
        self.evaluate_with("network", |pattern, _| {
            matches_network_host(&pattern.to_lowercase(), &lower)
        })
    }

    fn is_empty(&self) -> bool {
        self.allow.is_empty()
            && self.deny.is_empty()
            && self.warn.is_empty()
            && self.log.is_empty()
            && self.hide.is_empty()
    }
}

impl AgentPolicy {
    /// Create a new policy evaluator from agent config sections.
    pub fn new(sections: &AgentPolicySections) -> Self {
        Self {
            network: SectionRules::from_section(&sections.network),
            commands: SectionRules::from_section(&sections.commands),
            files: SectionRules::from_section(&sections.files),
            envvars: SectionRules::from_section(&sections.envvars),
            functions: SectionRules::from_section(&sections.functions),
        }
    }

    /// Create an empty policy (everything is traced, nothing blocked).
    pub fn empty() -> Self {
        Self {
            network: SectionRules::from_section(&PolicySection::default()),
            commands: SectionRules::from_section(&PolicySection::default()),
            files: SectionRules::from_section(&PolicySection::default()),
            envvars: SectionRules::from_section(&PolicySection::default()),
            functions: SectionRules::from_section(&PolicySection::default()),
        }
    }

    /// Check if this policy has any rules at all.
    pub fn has_rules(&self) -> bool {
        !self.network.is_empty()
            || !self.commands.is_empty()
            || !self.files.is_empty()
            || !self.envvars.is_empty()
            || !self.functions.is_empty()
    }

    /// Evaluate a trace event against all applicable policy sections.
    ///
    /// Runs all applicable phases and combines results. Within each phase,
    /// the section evaluation determines allow/deny/warn/hide. Across phases,
    /// the strictest (most restrictive) result wins — except that `Suppress`
    /// (explicit allow) always overrides the default `Trace`.
    pub fn evaluate(&self, event: &TraceEvent) -> AgentDecision {
        let mut decisions: Vec<AgentDecision> = Vec::new();

        // When network rules exist, native networking symbols (socket, connect,
        // sendto, etc.) are deferred from the functions phase to the network
        // phase. This prevents socket() (which has no destination info yet) from
        // being blocked by a functions deny-all, while letting connect() be
        // blocked by the network phase using actual destination info.
        let defer_to_network = !self.network.is_empty()
            && matches!(event.hook_type, HookType::Native)
            && is_networking_symbol(&event.function);

        // Phase 1: Function-level evaluation (skipped for deferred symbols)
        // Use the hook type as the section name for function-level rules,
        // matching CLI's behavior (e.g. "python", "nodejs", "native").
        if !self.functions.is_empty() && !defer_to_network {
            let section = match event.hook_type {
                HookType::Python => "python",
                HookType::Nodejs => "nodejs",
                HookType::Native => "native",
                HookType::Bash => "bash",
                HookType::Exec => "commands",
                HookType::EnvVar => "envvars",
            };
            decisions.push(self.functions.evaluate(&event.function, section));
        }

        // Phase 2: Network evaluation (from NetworkInfo)
        if !self.network.is_empty() {
            if let Some(ref net) = event.network_info {
                let has_hostname_context = net.domain.is_some() || net.url.is_some();

                // Try domain (case-insensitive, with domain-prefix extraction
                // for URL-like patterns like "pypi.org/**")
                if let Some(ref domain) = net.domain {
                    decisions.push(self.network.evaluate_network_host(domain));
                }
                // Try URL (full match against URL patterns)
                if let Some(ref url) = net.url {
                    decisions.push(self.network.evaluate_ci(url, "network"));
                }
                // Try IP — but skip when network has allow-only rules and
                // no hostname context. Domain allow rules can't match bare IPs;
                // the IP is likely from a previously-allowed DNS resolution.
                // This matches CLI's ActivePolicy behavior.
                if let Some(ref ip) = net.ip {
                    let skip_ip = !has_hostname_context
                        && !self.network.allow.is_empty()
                        && self.network.deny.is_empty();
                    if !skip_ip {
                        decisions.push(self.network.evaluate(ip, "network"));
                    }
                }
            }
        }

        // Phase 3: File evaluation (extract path from args for file-related hooks)
        if !self.files.is_empty() {
            if let Some(path) = extract_file_path(event) {
                let decision = self.files.evaluate(&path, "files");
                // If absolute path didn't match, try tilde form (~/...) since
                // policy patterns commonly use tilde notation.
                let decision = if matches!(decision, AgentDecision::Suppress) {
                    if let Some(tilde) = to_tilde_path(&path) {
                        let tilde_decision = self.files.evaluate(&tilde, "files");
                        if !matches!(tilde_decision, AgentDecision::Suppress) {
                            tilde_decision
                        } else {
                            decision
                        }
                    } else {
                        decision
                    }
                } else {
                    decision
                };
                decisions.push(decision);
            }
        }

        // Phase 4: Command evaluation (Exec/Bash hooks)
        if !self.commands.is_empty() && matches!(event.hook_type, HookType::Exec | HookType::Bash) {
            decisions.push(self.commands.evaluate(&event.function, "commands"));
        }

        // Phase 5: EnvVar evaluation
        if !self.envvars.is_empty() && matches!(event.hook_type, HookType::EnvVar) {
            decisions.push(self.envvars.evaluate(&event.function, "envvars"));
        }

        // Cross-evaluation: native getenv → envvar section
        if !self.envvars.is_empty()
            && matches!(event.hook_type, HookType::Native)
            && (event.function == "getenv" || event.function == "secure_getenv")
        {
            if let Some(name) = event.arguments.first().and_then(|a| a.display.as_deref()) {
                decisions.push(self.envvars.evaluate(name, "envvars"));
            }
        }

        // No phases matched → default Trace
        if decisions.is_empty() {
            return AgentDecision::Trace;
        }

        // Combine: strictest non-Trace decision wins.
        // If all phases say Trace, result is Trace.
        // Suppress < Warn < Block < Hide in strictness.
        let mut result = decisions[0].clone();
        for d in &decisions[1..] {
            result = pick_stricter(result, d.clone());
        }
        result
    }

    /// Evaluate just the envvar section (for getenv hooks that need hide/block).
    pub fn evaluate_envvar(&self, name: &str) -> AgentDecision {
        if self.envvars.is_empty() {
            return AgentDecision::Trace;
        }
        self.envvars.evaluate(name, "envvars")
    }

    /// Evaluate just the file section (for stat/access hooks that need hide).
    pub fn evaluate_file(&self, path: &str) -> AgentDecision {
        if self.files.is_empty() {
            return AgentDecision::Trace;
        }
        let decision = self.files.evaluate(path, "files");
        // Try tilde form if absolute path didn't match
        if matches!(decision, AgentDecision::Suppress) {
            if let Some(tilde) = to_tilde_path(path) {
                let tilde_decision = self.files.evaluate(&tilde, "files");
                if !matches!(tilde_decision, AgentDecision::Suppress) {
                    return tilde_decision;
                }
            }
        }
        decision
    }

    /// Evaluate just the network section (for connect hooks).
    pub fn evaluate_network_host(&self, host: &str) -> AgentDecision {
        if self.network.is_empty() {
            return AgentDecision::Trace;
        }
        self.network.evaluate_ci(host, "network")
    }
}

/// Match a hostname against a network pattern, handling URL-like patterns.
///
/// Tries exact glob match first. If that fails and the pattern contains `/`,
/// extracts the domain prefix (everything before the first `/`) and matches
/// against that. This way `pypi.org/**` matches hostname `pypi.org`.
fn matches_network_host(pattern: &str, hostname: &str) -> bool {
    // Direct glob match
    if matches_glob(pattern, hostname) {
        return true;
    }
    // Try domain prefix of URL-like patterns (e.g. "pypi.org/**" → "pypi.org")
    if let Some(slash_pos) = pattern.find('/') {
        let domain_part = &pattern[..slash_pos];
        if matches_glob(domain_part, hostname) {
            return true;
        }
    }
    false
}

/// Networking native symbols that should be deferred to the network phase
/// when network policy rules exist. Matches `networking_symbols.yaml`.
const NETWORKING_SYMBOLS: &[&str] = &[
    "socket",
    "connect",
    "sendto",
    "send",
    "bind",
    "listen",
    "accept",
    "accept4",
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname2",
];

/// Check if a native function name is a networking symbol.
fn is_networking_symbol(name: &str) -> bool {
    NETWORKING_SYMBOLS.contains(&name)
}

/// Extract a file path from a trace event's arguments (first string arg).
/// Strips surrounding quotes from native hook argument formatting.
fn extract_file_path(event: &TraceEvent) -> Option<String> {
    event
        .arguments
        .first()
        .and_then(|a| a.display.as_deref())
        .map(|s| s.trim_matches('"').trim_matches('\'').to_string())
}

/// Convert an absolute path to tilde notation (e.g. /Users/mav/.ssh → ~/.ssh).
/// Returns None if HOME is not set or the path is not under HOME.
fn to_tilde_path(path: &str) -> Option<String> {
    use std::sync::OnceLock;
    static HOME: OnceLock<Option<String>> = OnceLock::new();
    let home = HOME.get_or_init(|| std::env::var("HOME").ok());
    let home = home.as_deref()?;
    path.strip_prefix(home).map(|rest| format!("~{rest}"))
}

/// Severity ranking for decisions (higher = more specific/stricter).
/// `Trace` is the default (no policy match), so it's lowest.
/// `Suppress` is an explicit policy match (allow), so it ranks above `Trace`.
fn decision_severity(d: &AgentDecision) -> u8 {
    match d {
        AgentDecision::Trace => 0,
        AgentDecision::Suppress => 1,
        AgentDecision::Warn { .. } => 2,
        AgentDecision::Block { .. } => 3,
        AgentDecision::Hide => 4,
    }
}

/// Return the stricter of two decisions.
fn pick_stricter(a: AgentDecision, b: AgentDecision) -> AgentDecision {
    if decision_severity(&b) > decision_severity(&a) {
        b
    } else {
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_config::AgentPolicySections;
    use crate::event::{Argument, EventType, NetworkInfo};

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

    #[test]
    fn test_empty_policy_traces_everything() {
        let policy = AgentPolicy::empty();
        let event = make_event(HookType::Native, "connect");
        assert_eq!(policy.evaluate(&event), AgentDecision::Trace);
    }

    #[test]
    fn test_function_deny_blocks() {
        let sections = AgentPolicySections {
            functions: PolicySection {
                deny: vec!["eval".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = AgentPolicy::new(&sections);

        let event = make_event(HookType::Python, "eval");
        assert!(matches!(
            policy.evaluate(&event),
            AgentDecision::Block { .. }
        ));

        let event2 = make_event(HookType::Python, "json.loads");
        assert_eq!(policy.evaluate(&event2), AgentDecision::Suppress);
    }

    #[test]
    fn test_function_allow_suppresses() {
        let sections = AgentPolicySections {
            functions: PolicySection {
                allow: vec!["json.*".into()],
                deny: vec!["*".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = AgentPolicy::new(&sections);

        let event = make_event(HookType::Python, "json.loads");
        assert_eq!(policy.evaluate(&event), AgentDecision::Suppress);

        let event2 = make_event(HookType::Python, "eval");
        assert!(matches!(
            policy.evaluate(&event2),
            AgentDecision::Block { .. }
        ));
    }

    #[test]
    fn test_network_deny_blocks_domain() {
        let sections = AgentPolicySections {
            network: PolicySection {
                deny: vec!["*.evil.com".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = AgentPolicy::new(&sections);

        let event = make_network_event("connect", "malware.evil.com");
        assert!(matches!(
            policy.evaluate(&event),
            AgentDecision::Block { .. }
        ));

        let event2 = make_network_event("connect", "pypi.org");
        assert_eq!(policy.evaluate(&event2), AgentDecision::Suppress);
    }

    #[test]
    fn test_network_case_insensitive() {
        let sections = AgentPolicySections {
            network: PolicySection {
                allow: vec!["*.PyPI.org".into()],
                deny: vec!["*".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = AgentPolicy::new(&sections);

        let event = make_network_event("connect", "files.pypi.org");
        assert_eq!(policy.evaluate(&event), AgentDecision::Suppress);
    }

    #[test]
    fn test_command_deny() {
        let sections = AgentPolicySections {
            commands: PolicySection {
                deny: vec!["curl".into(), "wget".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = AgentPolicy::new(&sections);

        let event = make_event(HookType::Exec, "curl");
        assert!(matches!(
            policy.evaluate(&event),
            AgentDecision::Block { .. }
        ));

        let event2 = make_event(HookType::Exec, "ls");
        assert_eq!(policy.evaluate(&event2), AgentDecision::Suppress);
    }

    #[test]
    fn test_envvar_hide() {
        let sections = AgentPolicySections {
            envvars: PolicySection {
                hide: vec!["MALWI_*".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = AgentPolicy::new(&sections);

        let event = make_event(HookType::EnvVar, "MALWI_URL");
        assert_eq!(policy.evaluate(&event), AgentDecision::Hide);

        let event2 = make_event(HookType::EnvVar, "HOME");
        assert_eq!(policy.evaluate(&event2), AgentDecision::Suppress);
    }

    #[test]
    fn test_getenv_cross_evaluation() {
        let sections = AgentPolicySections {
            envvars: PolicySection {
                hide: vec!["SECRET_KEY".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = AgentPolicy::new(&sections);

        // Native getenv("SECRET_KEY") should trigger envvar hide
        let event = make_event_with_args(HookType::Native, "getenv", &["SECRET_KEY"]);
        assert_eq!(policy.evaluate(&event), AgentDecision::Hide);

        // Native getenv("HOME") — suppressed (hide-only section has no display rules)
        let event2 = make_event_with_args(HookType::Native, "getenv", &["HOME"]);
        assert_eq!(policy.evaluate(&event2), AgentDecision::Suppress);
    }

    #[test]
    fn test_file_warn() {
        let sections = AgentPolicySections {
            files: PolicySection {
                warn: vec!["*.pem".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = AgentPolicy::new(&sections);

        let event = make_event_with_args(HookType::Native, "open", &["/etc/ssl/cert.pem"]);
        assert!(matches!(
            policy.evaluate(&event),
            AgentDecision::Warn { .. }
        ));
    }

    #[test]
    fn test_hide_beats_deny() {
        let sections = AgentPolicySections {
            envvars: PolicySection {
                deny: vec!["*".into()],
                hide: vec!["SECRET".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = AgentPolicy::new(&sections);

        // Hide is stricter than block
        let event = make_event(HookType::EnvVar, "SECRET");
        assert_eq!(policy.evaluate(&event), AgentDecision::Hide);

        // Other vars get blocked
        let event2 = make_event(HookType::EnvVar, "OTHER");
        assert!(matches!(
            policy.evaluate(&event2),
            AgentDecision::Block { .. }
        ));
    }

    #[test]
    fn test_warn_pattern() {
        let sections = AgentPolicySections {
            functions: PolicySection {
                warn: vec!["dlopen".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = AgentPolicy::new(&sections);

        let event = make_event(HookType::Native, "dlopen");
        assert!(matches!(
            policy.evaluate(&event),
            AgentDecision::Warn { .. }
        ));
    }

    #[test]
    fn test_stricter_wins_across_sections() {
        let sections = AgentPolicySections {
            functions: PolicySection {
                warn: vec!["connect".into()],
                ..Default::default()
            },
            network: PolicySection {
                deny: vec!["*.evil.com".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = AgentPolicy::new(&sections);

        // Network block should win over function warn
        let mut event = make_event(HookType::Native, "connect");
        event.network_info = Some(NetworkInfo {
            domain: Some("x.evil.com".into()),
            ..Default::default()
        });
        assert!(matches!(
            policy.evaluate(&event),
            AgentDecision::Block { .. }
        ));
    }

    #[test]
    fn test_network_deferral_socket_not_blocked() {
        // When network deny rules exist, socket() should be deferred
        // (not blocked by functions phase) because it has no destination info.
        let sections = AgentPolicySections {
            functions: PolicySection {
                deny: vec!["socket".into(), "connect".into()],
                ..Default::default()
            },
            network: PolicySection {
                deny: vec!["*".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = AgentPolicy::new(&sections);

        // socket() with no NetworkInfo → deferred, not blocked
        let event = make_event(HookType::Native, "socket");
        assert_eq!(policy.evaluate(&event), AgentDecision::Trace);

        // connect() with domain → network phase blocks
        let mut connect_event = make_event(HookType::Native, "connect");
        connect_event.network_info = Some(NetworkInfo {
            domain: Some("evil.com".into()),
            ..Default::default()
        });
        assert!(matches!(
            policy.evaluate(&connect_event),
            AgentDecision::Block { .. }
        ));
    }

    #[test]
    fn test_file_deny_suppresses_unmatched() {
        let sections = AgentPolicySections {
            files: PolicySection {
                deny: vec!["*.pem".into(), "~/.ssh/**".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = AgentPolicy::new(&sections);

        // Unmatched file path → Suppress (not Trace)
        let event = make_event_with_args(HookType::Native, "open", &["/tmp/foo.txt"]);
        assert_eq!(policy.evaluate(&event), AgentDecision::Suppress);
    }

    #[test]
    fn test_file_deny_blocks_matching() {
        let sections = AgentPolicySections {
            files: PolicySection {
                deny: vec!["*.pem".into(), "~/.ssh/**".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = AgentPolicy::new(&sections);

        let event = make_event_with_args(HookType::Native, "open", &["/etc/ssl/cert.pem"]);
        assert!(matches!(
            policy.evaluate(&event),
            AgentDecision::Block { .. }
        ));
    }

    #[test]
    fn test_file_deny_tilde_matches_absolute_path() {
        // Tilde patterns like ~/.ssh/** must match absolute paths like /Users/x/.ssh/id_rsa
        let sections = AgentPolicySections {
            files: PolicySection {
                deny: vec!["~/.ssh/**".into(), "~/.aws/**".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = AgentPolicy::new(&sections);

        let home = std::env::var("HOME").unwrap();
        let ssh_path = format!("{home}/.ssh/id_rsa");
        let event = make_event_with_args(HookType::Native, "open", &[&ssh_path]);
        assert!(
            matches!(policy.evaluate(&event), AgentDecision::Block { .. }),
            "Absolute path {ssh_path} should match tilde pattern ~/.ssh/**"
        );

        let aws_path = format!("{home}/.aws/credentials");
        let event2 = make_event_with_args(HookType::Native, "open", &[&aws_path]);
        assert!(
            matches!(policy.evaluate(&event2), AgentDecision::Block { .. }),
            "Absolute path {aws_path} should match tilde pattern ~/.aws/**"
        );
    }

    #[test]
    fn test_file_deny_quoted_path_stripped() {
        // Native open hook formats paths with surrounding quotes — must be stripped
        let sections = AgentPolicySections {
            files: PolicySection {
                deny: vec!["*.pem".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = AgentPolicy::new(&sections);

        let event = make_event_with_args(HookType::Native, "open", &["\"/etc/ssl/cert.pem\""]);
        assert!(
            matches!(policy.evaluate(&event), AgentDecision::Block { .. }),
            "Quoted path should match after stripping quotes"
        );
    }

    #[test]
    fn test_log_produces_trace() {
        // Explicit log patterns are the only way to get Trace
        let sections = AgentPolicySections {
            functions: PolicySection {
                deny: vec!["eval".into()],
                log: vec!["open".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = AgentPolicy::new(&sections);

        // log match → Trace
        let event = make_event(HookType::Native, "open");
        assert_eq!(policy.evaluate(&event), AgentDecision::Trace);

        // deny match → Block
        let event2 = make_event(HookType::Python, "eval");
        assert!(matches!(
            policy.evaluate(&event2),
            AgentDecision::Block { .. }
        ));

        // no match → Suppress
        let event3 = make_event(HookType::Native, "read");
        assert_eq!(policy.evaluate(&event3), AgentDecision::Suppress);
    }

    #[test]
    fn test_deny_only_no_trace_noise() {
        // Reproduce pip install scenario: functions deny + files deny,
        // native open("/tmp/foo") should be fully suppressed.
        let sections = AgentPolicySections {
            functions: PolicySection {
                deny: vec!["os.system".into(), "subprocess.*".into()],
                ..Default::default()
            },
            files: PolicySection {
                deny: vec!["~/.ssh/**".into(), "*.pem".into()],
                ..Default::default()
            },
            envvars: PolicySection {
                deny: vec!["SECRET_*".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = AgentPolicy::new(&sections);

        // Native open to harmless file → Suppress (not Trace)
        let event = make_event_with_args(HookType::Native, "open", &["/tmp/pip-xyz/setup.py"]);
        assert_eq!(policy.evaluate(&event), AgentDecision::Suppress);

        // Envvar read of harmless var → Suppress
        let event2 = make_event(HookType::EnvVar, "BUILD_ID");
        assert_eq!(policy.evaluate(&event2), AgentDecision::Suppress);

        // Envvar read of denied var → Block
        let event3 = make_event(HookType::EnvVar, "SECRET_KEY");
        assert!(matches!(
            policy.evaluate(&event3),
            AgentDecision::Block { .. }
        ));
    }
}
