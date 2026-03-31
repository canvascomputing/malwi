//! Agent configuration: hooks + policy delivered to the agent process.
//!
//! The CLI compiles policy rules into a `Policy`, serializes it along with
//! hook configs to a YAML file, and passes the path via `MALWI_CONFIG`.
//! The agent reads it at init time for hook installation and policy evaluation.

use malwi_protocol::event::{HookConfig, HookType};
use malwi_protocol::yaml::{self, YamlValue};

use crate::resolved::{Decision, NetworkRule, NetworkRuleSet, Policy, Rule, RuleSet};

/// Agent configuration: hooks to install + policy for local evaluation.
#[derive(Debug, Clone, Default)]
pub struct AgentConfig {
    /// Hooks to install in the target process.
    pub hooks: Vec<HookConfig>,
    /// Policy for agent-side evaluation (same evaluator as CLI).
    pub policy: Policy,
}

impl Default for Policy {
    fn default() -> Self {
        Self::empty()
    }
}

// ── AgentConfig Serialization ────────────────────────────────────

impl AgentConfig {
    /// Serialize to YAML string.
    pub fn to_yaml(&self) -> String {
        let mut pairs: Vec<(String, YamlValue)> = Vec::new();

        pairs.push(("version".into(), YamlValue::Integer(2)));

        // Hooks
        if !self.hooks.is_empty() {
            let hook_items: Vec<YamlValue> = self
                .hooks
                .iter()
                .map(|h| {
                    let mut hm: Vec<(String, YamlValue)> = Vec::new();
                    hm.push((
                        "hook_type".into(),
                        YamlValue::String(hook_type_str(&h.hook_type)),
                    ));
                    hm.push(("symbol".into(), YamlValue::String(h.symbol.clone())));
                    if let Some(ac) = h.arg_count {
                        hm.push(("arg_count".into(), YamlValue::Integer(ac as i64)));
                    }
                    if h.capture_return {
                        hm.push(("capture_return".into(), YamlValue::String("true".into())));
                    }
                    if h.capture_stack {
                        hm.push(("capture_stack".into(), YamlValue::String("true".into())));
                    }
                    YamlValue::Mapping(hm)
                })
                .collect();
            pairs.push(("hooks".into(), YamlValue::Sequence(hook_items)));
        }

        // Policy
        if self.policy.has_rules() {
            pairs.push(("policy".into(), self.policy.to_yaml()));
        }

        yaml::write(&YamlValue::Mapping(pairs))
    }

    /// Parse from YAML string.
    pub fn from_yaml(input: &str) -> Result<Self, yaml::YamlError> {
        let root = yaml::parse(input)?;

        let mut config = AgentConfig::default();

        // Parse hooks
        if let Some(hooks_val) = root.get("hooks") {
            if let Some(items) = hooks_val.as_seq() {
                for item in items {
                    if let Some(hook) = parse_hook_config(item) {
                        config.hooks.push(hook);
                    }
                }
            }
        }

        // Parse policy
        if let Some(policy_val) = root.get("policy") {
            config.policy = Policy::from_yaml(policy_val);
        }

        Ok(config)
    }
}

// ── Policy Serialization ─────────────────────────────────────────

impl Policy {
    /// Serialize to YAML value.
    pub fn to_yaml(&self) -> YamlValue {
        let mut pairs: Vec<(String, YamlValue)> = Vec::new();

        if self.network.is_active() {
            pairs.push(("network".into(), self.network.to_yaml()));
        }
        if self.commands.is_active() {
            pairs.push(("commands".into(), self.commands.to_yaml()));
        }
        if self.files.is_active() {
            pairs.push(("files".into(), self.files.to_yaml()));
        }
        if self.envvars.is_active() {
            pairs.push(("envvars".into(), self.envvars.to_yaml()));
        }
        if self.functions.is_active() {
            pairs.push(("functions".into(), self.functions.to_yaml()));
        }

        YamlValue::Mapping(pairs)
    }

    /// Deserialize from a YAML value.
    pub fn from_yaml(val: &YamlValue) -> Self {
        Self {
            network: val
                .get("network")
                .map(NetworkRuleSet::from_yaml)
                .unwrap_or_else(NetworkRuleSet::empty),
            commands: val
                .get("commands")
                .map(RuleSet::from_yaml)
                .unwrap_or_else(RuleSet::empty),
            files: val
                .get("files")
                .map(RuleSet::from_yaml)
                .unwrap_or_else(RuleSet::empty),
            envvars: val
                .get("envvars")
                .map(RuleSet::from_yaml)
                .unwrap_or_else(RuleSet::empty),
            functions: val
                .get("functions")
                .map(RuleSet::from_yaml)
                .unwrap_or_else(RuleSet::empty),
        }
    }
}

// ── RuleSet Serialization ────────────────────────────────────────

impl RuleSet {
    fn to_yaml(&self) -> YamlValue {
        let mut pairs: Vec<(String, YamlValue)> = Vec::new();
        let rule_items: Vec<YamlValue> = self.rules.iter().map(|r| r.to_yaml()).collect();
        if !rule_items.is_empty() {
            pairs.push(("rules".into(), YamlValue::Sequence(rule_items)));
        }
        pairs.push(("default".into(), self.default_decision.to_yaml()));
        YamlValue::Mapping(pairs)
    }

    fn from_yaml(val: &YamlValue) -> Self {
        let rules = val
            .get("rules")
            .and_then(|v| v.as_seq())
            .map(|items| items.iter().filter_map(Rule::from_yaml).collect())
            .unwrap_or_default();
        let default_decision = val
            .get("default")
            .map(Decision::from_yaml)
            .unwrap_or(Decision::Suppress);
        Self {
            rules,
            default_decision,
        }
    }
}

impl Rule {
    fn to_yaml(&self) -> YamlValue {
        let mut pairs: Vec<(String, YamlValue)> = Vec::new();
        pairs.push(("p".into(), YamlValue::String(self.pattern.clone())));
        pairs.push(("d".into(), self.decision.to_yaml()));
        if !self.label.is_empty() {
            pairs.push(("l".into(), YamlValue::String(self.label.clone())));
        }
        YamlValue::Mapping(pairs)
    }

    fn from_yaml(val: &YamlValue) -> Option<Self> {
        let pattern = val.get("p")?.as_str()?.to_string();
        let decision = Decision::from_yaml(val.get("d")?);
        let label = val
            .get("l")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        Some(Self {
            pattern,
            decision,
            label,
            runtime_filter: None, // agent config doesn't carry runtime context
        })
    }
}

// ── NetworkRuleSet Serialization ─────────────────────────────────

impl NetworkRuleSet {
    fn to_yaml(&self) -> YamlValue {
        let mut pairs: Vec<(String, YamlValue)> = Vec::new();

        let serialize_rules = |rules: &[NetworkRule]| -> YamlValue {
            YamlValue::Sequence(rules.iter().map(|r| r.to_yaml()).collect())
        };

        if !self.allow_rules.is_empty() {
            pairs.push(("allow".into(), serialize_rules(&self.allow_rules)));
        }
        if !self.deny_rules.is_empty() {
            pairs.push(("deny".into(), serialize_rules(&self.deny_rules)));
        }
        if !self.hide_rules.is_empty() {
            pairs.push(("hide".into(), serialize_rules(&self.hide_rules)));
        }
        if !self.allowed_protocols.is_empty() {
            pairs.push((
                "protocols".into(),
                YamlValue::Sequence(
                    self.allowed_protocols
                        .iter()
                        .map(|s| YamlValue::String(s.clone()))
                        .collect(),
                ),
            ));
        }

        YamlValue::Mapping(pairs)
    }

    fn from_yaml(val: &YamlValue) -> Self {
        let parse_rules = |key: &str| -> Vec<NetworkRule> {
            val.get(key)
                .and_then(|v| v.as_seq())
                .map(|items| items.iter().filter_map(NetworkRule::from_yaml).collect())
                .unwrap_or_default()
        };

        let allow_rules = parse_rules("allow");
        let has_allow_rules = !allow_rules.is_empty();

        Self {
            allow_rules,
            deny_rules: parse_rules("deny"),
            hide_rules: parse_rules("hide"),
            allowed_protocols: val
                .get("protocols")
                .map(|v| v.string_list())
                .unwrap_or_default(),
            has_allow_rules,
        }
    }
}

impl NetworkRule {
    fn to_yaml(&self) -> YamlValue {
        let mut pairs: Vec<(String, YamlValue)> = Vec::new();
        pairs.push(("u".into(), YamlValue::String(self.url_pattern.clone())));
        pairs.push(("h".into(), YamlValue::String(self.domain_pattern.clone())));
        pairs.push(("e".into(), YamlValue::String(self.endpoint_pattern.clone())));
        pairs.push(("d".into(), self.decision.to_yaml()));
        if !self.label.is_empty() {
            pairs.push(("l".into(), YamlValue::String(self.label.clone())));
        }
        YamlValue::Mapping(pairs)
    }

    fn from_yaml(val: &YamlValue) -> Option<Self> {
        let url_pattern = val.get("u")?.as_str()?.to_string();
        let domain_pattern = val.get("h")?.as_str()?.to_string();
        let endpoint_pattern = val.get("e")?.as_str()?.to_string();
        let decision = Decision::from_yaml(val.get("d")?);
        let label = val
            .get("l")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        Some(Self {
            url_pattern,
            domain_pattern,
            endpoint_pattern,
            decision,
            label,
        })
    }
}

impl Decision {
    fn to_yaml(&self) -> YamlValue {
        match self {
            Decision::Suppress => YamlValue::String("s".into()),
            Decision::Trace => YamlValue::String("t".into()),
            Decision::Warn { section } => {
                YamlValue::Mapping(vec![("w".into(), YamlValue::String(section.clone()))])
            }
            Decision::Block { section } => {
                YamlValue::Mapping(vec![("b".into(), YamlValue::String(section.clone()))])
            }
            Decision::Hide => YamlValue::String("h".into()),
        }
    }

    fn from_yaml(val: &YamlValue) -> Self {
        if let Some(s) = val.as_str() {
            return match s {
                "s" => Decision::Suppress,
                "t" => Decision::Trace,
                "h" => Decision::Hide,
                _ => Decision::Suppress,
            };
        }
        if let Some(section) = val.get("w").and_then(|v| v.as_str()) {
            return Decision::Warn {
                section: section.to_string(),
            };
        }
        if let Some(section) = val.get("b").and_then(|v| v.as_str()) {
            return Decision::Block {
                section: section.to_string(),
            };
        }
        Decision::Suppress
    }
}

// ── Helpers ──────────────────────────────────────────────────────

fn hook_type_str(ht: &HookType) -> String {
    match ht {
        HookType::Native => "Native".into(),
        HookType::Python => "Python".into(),
        HookType::Nodejs => "Nodejs".into(),
        HookType::Exec => "Exec".into(),
        HookType::EnvVar => "EnvVar".into(),
        HookType::Bash => "Bash".into(),
    }
}

fn parse_hook_type(s: &str) -> HookType {
    match s {
        "Native" => HookType::Native,
        "Python" => HookType::Python,
        "Nodejs" => HookType::Nodejs,
        "Exec" => HookType::Exec,
        "EnvVar" => HookType::EnvVar,
        "Bash" => HookType::Bash,
        _ => HookType::Native,
    }
}

fn parse_hook_config(val: &YamlValue) -> Option<HookConfig> {
    let ht = val.get("hook_type")?.as_str()?;
    let symbol = val.get("symbol")?.as_str()?;

    Some(HookConfig {
        hook_type: parse_hook_type(ht),
        symbol: symbol.to_string(),
        arg_count: val
            .get("arg_count")
            .and_then(|v| v.as_int())
            .map(|n| n as usize),
        capture_return: val
            .get("capture_return")
            .and_then(|v| v.as_str())
            .map(|s| s == "true")
            .unwrap_or(false),
        capture_stack: val
            .get("capture_stack")
            .and_then(|v| v.as_str())
            .map(|s| s == "true")
            .unwrap_or(false),
    })
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_config_roundtrip() {
        let config = AgentConfig {
            hooks: vec![
                HookConfig {
                    hook_type: HookType::Native,
                    symbol: "connect".into(),
                    arg_count: Some(6),
                    capture_return: true,
                    capture_stack: false,
                },
                HookConfig {
                    hook_type: HookType::Python,
                    symbol: "urllib.request.urlopen".into(),
                    arg_count: None,
                    capture_return: false,
                    capture_stack: true,
                },
            ],
            policy: Policy {
                functions: RuleSet {
                    rules: vec![Rule {
                        pattern: "eval".into(),
                        decision: Decision::Block {
                            section: "functions".into(),
                        },
                        label: "eval".into(),
                        runtime_filter: None,
                    }],
                    default_decision: Decision::Suppress,
                },
                network: NetworkRuleSet {
                    allow_rules: vec![NetworkRule {
                        url_pattern: "*.pypi.org/**".into(),
                        domain_pattern: "*.pypi.org".into(),
                        endpoint_pattern: "*.pypi.org:*".into(),
                        decision: Decision::Suppress,
                        label: "*.pypi.org".into(),
                    }],
                    deny_rules: vec![],
                    hide_rules: vec![],
                    allowed_protocols: vec!["https".into()],
                    has_allow_rules: true,
                },
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
            },
        };

        let yaml = config.to_yaml();
        let parsed = AgentConfig::from_yaml(&yaml).unwrap();

        // Hooks
        assert_eq!(parsed.hooks.len(), 2);
        assert_eq!(parsed.hooks[0].symbol, "connect");
        assert_eq!(parsed.hooks[0].hook_type, HookType::Native);
        assert_eq!(parsed.hooks[0].arg_count, Some(6));
        assert!(parsed.hooks[0].capture_return);

        assert_eq!(parsed.hooks[1].symbol, "urllib.request.urlopen");
        assert!(parsed.hooks[1].capture_stack);

        // Policy
        assert_eq!(parsed.policy.functions.rules.len(), 1);
        assert_eq!(parsed.policy.functions.rules[0].pattern, "eval");

        assert_eq!(parsed.policy.network.allow_rules.len(), 1);
        assert_eq!(
            parsed.policy.network.allow_rules[0].domain_pattern,
            "*.pypi.org"
        );
        assert_eq!(parsed.policy.network.allowed_protocols, vec!["https"]);

        assert_eq!(parsed.policy.envvars.rules.len(), 1);
        assert!(matches!(
            parsed.policy.envvars.rules[0].decision,
            Decision::Hide
        ));
    }

    #[test]
    fn test_agent_config_empty() {
        let config = AgentConfig::default();
        let yaml = config.to_yaml();
        let parsed = AgentConfig::from_yaml(&yaml).unwrap();
        assert!(parsed.hooks.is_empty());
        assert!(!parsed.policy.has_rules());
    }
}
