//! Agent configuration delivered via file before spawn.
//!
//! The CLI compiles policy rules into an `AgentConfig`, writes it as YAML to a
//! temp file, and passes the path via `MALWI_CONFIG` env var. The agent reads
//! it at init time and uses it for both hook installation and local policy
//! evaluation — no TCP handshake needed.

use crate::event::HookConfig;
use crate::yaml::{self, YamlValue};

/// Agent configuration: hooks to install + policy rules for local evaluation.
#[derive(Debug, Clone, Default)]
pub struct AgentConfig {
    /// Hooks to install in the target process.
    pub hooks: Vec<HookConfig>,
    /// Policy sections for agent-side evaluation.
    pub policy: AgentPolicySections,
}

/// Policy sections for agent-side evaluation.
/// Each section contains glob pattern lists for allow/deny/warn/hide.
#[derive(Debug, Clone, Default)]
pub struct AgentPolicySections {
    pub network: PolicySection,
    pub commands: PolicySection,
    pub files: PolicySection,
    pub envvars: PolicySection,
    pub functions: PolicySection,
}

/// A single policy section with glob pattern lists.
#[derive(Debug, Clone, Default)]
pub struct PolicySection {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub warn: Vec<String>,
    pub hide: Vec<String>,
}

impl PolicySection {
    /// True if all lists are empty.
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty()
            && self.deny.is_empty()
            && self.warn.is_empty()
            && self.hide.is_empty()
    }
}

// =============================================================================
// YAML Serialization
// =============================================================================

impl AgentConfig {
    /// Serialize to YAML string.
    pub fn to_yaml(&self) -> String {
        let mut pairs: Vec<(String, YamlValue)> = Vec::new();

        pairs.push(("version".into(), YamlValue::Integer(1)));

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

        // Policy sections
        let policy = &self.policy;
        if !policy.network.is_empty() {
            pairs.push(("network".into(), section_to_yaml(&policy.network)));
        }
        if !policy.commands.is_empty() {
            pairs.push(("commands".into(), section_to_yaml(&policy.commands)));
        }
        if !policy.files.is_empty() {
            pairs.push(("files".into(), section_to_yaml(&policy.files)));
        }
        if !policy.envvars.is_empty() {
            pairs.push(("envvars".into(), section_to_yaml(&policy.envvars)));
        }
        if !policy.functions.is_empty() {
            pairs.push(("functions".into(), section_to_yaml(&policy.functions)));
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

        // Parse policy sections
        if let Some(v) = root.get("network") {
            config.policy.network = parse_policy_section(v);
        }
        if let Some(v) = root.get("commands") {
            config.policy.commands = parse_policy_section(v);
        }
        if let Some(v) = root.get("files") {
            config.policy.files = parse_policy_section(v);
        }
        if let Some(v) = root.get("envvars") {
            config.policy.envvars = parse_policy_section(v);
        }
        if let Some(v) = root.get("functions") {
            config.policy.functions = parse_policy_section(v);
        }

        Ok(config)
    }
}

// =============================================================================
// Helpers
// =============================================================================

fn hook_type_str(ht: &crate::event::HookType) -> String {
    match ht {
        crate::event::HookType::Native => "Native".into(),
        crate::event::HookType::Python => "Python".into(),
        crate::event::HookType::Nodejs => "Nodejs".into(),
        crate::event::HookType::Exec => "Exec".into(),
        crate::event::HookType::EnvVar => "EnvVar".into(),
        crate::event::HookType::Bash => "Bash".into(),
    }
}

fn parse_hook_type(s: &str) -> crate::event::HookType {
    match s {
        "Native" => crate::event::HookType::Native,
        "Python" => crate::event::HookType::Python,
        "Nodejs" => crate::event::HookType::Nodejs,
        "Exec" => crate::event::HookType::Exec,
        "EnvVar" => crate::event::HookType::EnvVar,
        "Bash" => crate::event::HookType::Bash,
        _ => crate::event::HookType::Native,
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

fn section_to_yaml(section: &PolicySection) -> YamlValue {
    let mut pairs: Vec<(String, YamlValue)> = Vec::new();
    if !section.allow.is_empty() {
        pairs.push(("allow".into(), strings_to_yaml(&section.allow)));
    }
    if !section.deny.is_empty() {
        pairs.push(("deny".into(), strings_to_yaml(&section.deny)));
    }
    if !section.warn.is_empty() {
        pairs.push(("warn".into(), strings_to_yaml(&section.warn)));
    }
    if !section.hide.is_empty() {
        pairs.push(("hide".into(), strings_to_yaml(&section.hide)));
    }
    YamlValue::Mapping(pairs)
}

fn strings_to_yaml(items: &[String]) -> YamlValue {
    YamlValue::Sequence(items.iter().map(|s| YamlValue::String(s.clone())).collect())
}

fn parse_policy_section(val: &YamlValue) -> PolicySection {
    PolicySection {
        allow: val
            .get("allow")
            .map(|v| v.string_list())
            .unwrap_or_default(),
        deny: val.get("deny").map(|v| v.string_list()).unwrap_or_default(),
        warn: val.get("warn").map(|v| v.string_list()).unwrap_or_default(),
        hide: val.get("hide").map(|v| v.string_list()).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::HookType;

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
            policy: AgentPolicySections {
                network: PolicySection {
                    allow: vec!["*.pypi.org".into()],
                    deny: vec!["*".into()],
                    warn: vec![],
                    hide: vec![],
                },
                commands: PolicySection {
                    allow: vec!["node".into(), "npm".into()],
                    deny: vec!["curl".into(), "wget".into()],
                    warn: vec!["ssh".into()],
                    hide: vec![],
                },
                files: PolicySection {
                    warn: vec!["~/.ssh/**".into()],
                    hide: vec!["/etc/shadow".into()],
                    ..Default::default()
                },
                envvars: PolicySection {
                    allow: vec!["HF_HUB_*".into()],
                    deny: vec!["*SECRET*".into()],
                    hide: vec!["MALWI_*".into()],
                    ..Default::default()
                },
                functions: PolicySection {
                    deny: vec!["eval".into()],
                    warn: vec!["dlopen".into()],
                    ..Default::default()
                },
            },
        };

        let yaml = config.to_yaml();
        let parsed = AgentConfig::from_yaml(&yaml).unwrap();

        assert_eq!(parsed.hooks.len(), 2);
        assert_eq!(parsed.hooks[0].symbol, "connect");
        assert_eq!(parsed.hooks[0].hook_type, HookType::Native);
        assert_eq!(parsed.hooks[0].arg_count, Some(6));
        assert!(parsed.hooks[0].capture_return);
        assert!(!parsed.hooks[0].capture_stack);

        assert_eq!(parsed.hooks[1].symbol, "urllib.request.urlopen");
        assert_eq!(parsed.hooks[1].hook_type, HookType::Python);
        assert!(parsed.hooks[1].capture_stack);

        assert_eq!(parsed.policy.network.allow, vec!["*.pypi.org"]);
        assert_eq!(parsed.policy.network.deny, vec!["*"]);
        assert_eq!(parsed.policy.commands.deny, vec!["curl", "wget"]);
        assert_eq!(parsed.policy.commands.warn, vec!["ssh"]);
        assert_eq!(parsed.policy.files.hide, vec!["/etc/shadow"]);
        assert_eq!(parsed.policy.envvars.hide, vec!["MALWI_*"]);
        assert_eq!(parsed.policy.functions.deny, vec!["eval"]);
    }

    #[test]
    fn test_agent_config_empty() {
        let config = AgentConfig::default();
        let yaml = config.to_yaml();
        let parsed = AgentConfig::from_yaml(&yaml).unwrap();
        assert!(parsed.hooks.is_empty());
        assert!(parsed.policy.network.is_empty());
    }

    #[test]
    fn test_agent_config_minimal() {
        // Use the same format our writer produces (roundtrip-safe)
        let config = AgentConfig {
            hooks: vec![HookConfig {
                hook_type: HookType::Native,
                symbol: "malloc".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let yaml = config.to_yaml();
        let parsed = AgentConfig::from_yaml(&yaml).unwrap();
        assert_eq!(parsed.hooks.len(), 1);
        assert_eq!(parsed.hooks[0].symbol, "malloc");
        assert_eq!(parsed.hooks[0].hook_type, HookType::Native);
    }
}
