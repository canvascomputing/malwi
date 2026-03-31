//! Policy types — the final, ready-to-evaluate policy representation.
//!
//! Two kinds of sections:
//! - `RuleSet`: pre-sorted rules where first match = correct answer (functions, commands, files, envvars)
//! - `NetworkRuleSet`: multi-representation matching with runtime specificity (network)

/// What to do when a rule matches.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Allowed, don't display.
    Suppress,
    /// Allowed, display to user (log mode).
    Trace,
    /// Allowed, display as warning.
    Warn { section: String },
    /// Blocked, display as denied.
    Block { section: String },
    /// Blocked, return fake value (NULL/ENOENT), no display.
    Hide,
}

/// A single rule with a glob pattern and its decision.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Glob pattern to match against.
    pub pattern: String,
    /// What to do when this rule matches.
    pub decision: Decision,
    /// Original rule text for display in block/warn messages.
    pub label: String,
    /// Optional runtime restriction. When set, this rule only matches events
    /// from the specified hook type (e.g., Python-only or Node.js-only rules).
    pub runtime_filter: Option<malwi_protocol::event::HookType>,
}

/// A set of rules sorted by specificity. First match = correct answer.
///
/// Used for simple 1:1 matching sections (functions, commands, files, envvars).
/// The compiler sorts rules by specificity at compile time, so the evaluator
/// just scans top-to-bottom.
#[derive(Debug, Clone)]
pub struct RuleSet {
    /// Rules in priority order. First matching rule wins.
    pub rules: Vec<Rule>,
    /// Decision when no rule matches.
    /// `Block` when allow rules exist (implicit deny), `Suppress` otherwise.
    pub default_decision: Decision,
}

impl RuleSet {
    /// Create an empty rule set (no rules, default suppress).
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            default_decision: Decision::Suppress,
        }
    }

    /// Whether this rule set has any rules.
    pub fn is_active(&self) -> bool {
        !self.rules.is_empty()
    }
}

/// A network rule with 3 matchers for multi-representation matching.
///
/// Each source pattern (e.g. `"evil.com"`, `"*.evil.com/**"`, `"*:22"`)
/// compiles into three matchers so that evaluation can try each against
/// every available event representation (URL, domain, endpoint).
#[derive(Debug, Clone)]
pub struct NetworkRule {
    /// For matching against URLs (full URL and schemeless URL).
    pub url_pattern: String,
    /// For matching against domain names (case-insensitive).
    pub domain_pattern: String,
    /// For matching against endpoint strings (host:port).
    pub endpoint_pattern: String,
    /// What to do when this rule matches.
    pub decision: Decision,
    /// Original rule text for display in block/warn messages.
    pub label: String,
}

/// Network rules requiring runtime specificity computation.
///
/// Unlike `RuleSet`, network rules can't be pre-sorted because specificity
/// depends on which representations are available per event (URL vs domain
/// vs endpoint). The evaluator computes specificity at match time.
#[derive(Debug, Clone)]
pub struct NetworkRuleSet {
    pub allow_rules: Vec<NetworkRule>,
    pub deny_rules: Vec<NetworkRule>,
    pub hide_rules: Vec<NetworkRule>,
    /// Allowed protocols (empty = all allowed).
    pub allowed_protocols: Vec<String>,
    /// Whether allow rules exist (for implicit deny logic).
    pub has_allow_rules: bool,
}

impl NetworkRuleSet {
    /// Create an empty network rule set.
    pub fn empty() -> Self {
        Self {
            allow_rules: Vec::new(),
            deny_rules: Vec::new(),
            hide_rules: Vec::new(),
            allowed_protocols: Vec::new(),
            has_allow_rules: false,
        }
    }

    /// Whether this rule set has any rules.
    pub fn is_active(&self) -> bool {
        !self.allow_rules.is_empty()
            || !self.deny_rules.is_empty()
            || !self.hide_rules.is_empty()
            || !self.allowed_protocols.is_empty()
    }
}

/// The complete, ready-to-evaluate policy.
///
/// Used by both the agent (in-process enforcement) and CLI (display rendering).
/// Simple sections use pre-sorted rules (first match wins). The network
/// section uses multi-representation matching with runtime specificity.
#[derive(Debug, Clone)]
pub struct Policy {
    pub commands: RuleSet,
    pub files: RuleSet,
    pub envvars: RuleSet,
    pub functions: RuleSet,
    pub network: NetworkRuleSet,
}

impl Policy {
    /// Create an empty policy (no rules, everything traced).
    pub fn empty() -> Self {
        Self {
            commands: RuleSet::empty(),
            files: RuleSet::empty(),
            envvars: RuleSet::empty(),
            functions: RuleSet::empty(),
            network: NetworkRuleSet::empty(),
        }
    }

    /// Whether this policy has any rules at all.
    pub fn has_rules(&self) -> bool {
        self.commands.is_active()
            || self.files.is_active()
            || self.envvars.is_active()
            || self.functions.is_active()
            || self.network.is_active()
    }
}
