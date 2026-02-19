use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::fmt;

use crate::error::{PolicyError, Result, ValidationError};

/// Raw parsed policy file from YAML.
#[derive(Debug, Clone)]
pub struct PolicyFile {
    pub version: u32,
    pub sections: HashMap<String, SectionValue>,
}

/// Value of a policy section - can be different formats.
///
/// Deserialization logic:
/// - Mapping → `AllowDeny` (errors propagate directly for clear messages)
/// - Sequence of all strings → `List`
/// - Sequence with maps → `RuleList`
#[derive(Debug, Clone)]
pub enum SectionValue {
    /// Allow/deny section with rules.
    AllowDeny(AllowDenySection),
    /// Simple list of values (e.g., for protocols).
    /// Also matches all-string rule lists; compiler handles the distinction.
    List(Vec<String>),
    /// Direct list of rules as implicit allow (new format).
    /// Matches when list contains constraint maps (e.g., `{"pattern": ["constraint"]}`).
    RuleList(Vec<Rule>),
}

impl<'de> Deserialize<'de> for SectionValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_yaml::Value::deserialize(deserializer)?;

        if value.is_mapping() {
            // Map → AllowDenySection; errors (like unknown keys) propagate directly
            serde_yaml::from_value::<AllowDenySection>(value)
                .map(SectionValue::AllowDeny)
                .map_err(de::Error::custom)
        } else if value.is_sequence() {
            // Try as Vec<String> first (pure string lists)
            if let Ok(list) = serde_yaml::from_value::<Vec<String>>(value.clone()) {
                Ok(SectionValue::List(list))
            } else {
                serde_yaml::from_value::<Vec<Rule>>(value)
                    .map(SectionValue::RuleList)
                    .map_err(de::Error::custom)
            }
        } else {
            Err(de::Error::custom(
                "expected a map or sequence for policy section",
            ))
        }
    }
}

/// A section with allow and deny rules, plus mode-specific deny keys.
#[derive(Debug, Clone, Default)]
pub struct AllowDenySection {
    pub allow: Vec<Rule>,
    pub deny: Vec<Rule>,
    pub warn: Vec<Rule>,
    pub log: Vec<Rule>,
    pub review: Vec<Rule>,
    pub noop: Vec<Rule>,
    /// Protocol allowlist — only meaningful in `network` sections.
    pub protocols: Vec<String>,
}

impl<'de> Deserialize<'de> for AllowDenySection {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AllowDenySectionVisitor;

        impl<'de> Visitor<'de> for AllowDenySectionVisitor {
            type Value = AllowDenySection;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a policy section with allow/deny/warn/log/review/noop keys")
            }

            fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut section = AllowDenySection::default();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "allow" => section.allow = map.next_value()?,
                        "deny" => section.deny = map.next_value()?,
                        "warn" => section.warn = map.next_value()?,
                        "log" => section.log = map.next_value()?,
                        "review" => section.review = map.next_value()?,
                        "noop" => section.noop = map.next_value()?,
                        "protocols" => section.protocols = map.next_value()?,
                        _ => {
                            return Err(de::Error::custom(format!(
                                "unknown key '{}' in policy section; valid keys are: allow, deny, warn, log, review, noop, protocols",
                                key
                            )));
                        }
                    }
                }

                Ok(section)
            }
        }

        deserializer.deserialize_map(AllowDenySectionVisitor)
    }
}

/// A single rule - either a simple pattern or pattern with constraints.
#[derive(Debug, Clone)]
pub enum Rule {
    /// Simple pattern string (e.g., "eval", "fs.*").
    Simple(String),
    /// Pattern with constraints (e.g., {"requests.*": ["https://api.example.com/*"]}).
    WithConstraints {
        pattern: String,
        constraints: Vec<String>,
    },
}

impl<'de> Deserialize<'de> for Rule {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RuleVisitor;

        impl<'de> Visitor<'de> for RuleVisitor {
            type Value = Rule;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string or a map with pattern and constraints")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Rule::Simple(value.to_string()))
            }

            fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                // Expect exactly one key-value pair: pattern -> constraints
                if let Some((pattern, constraints)) = map.next_entry::<String, Vec<String>>()? {
                    // Ensure no more entries
                    if map.next_entry::<String, Vec<String>>()?.is_some() {
                        return Err(de::Error::custom(
                            "rule with constraints should have exactly one pattern",
                        ));
                    }
                    Ok(Rule::WithConstraints {
                        pattern,
                        constraints,
                    })
                } else {
                    Err(de::Error::custom("empty rule map"))
                }
            }
        }

        deserializer.deserialize_any(RuleVisitor)
    }
}

impl<'de> Deserialize<'de> for PolicyFile {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PolicyFileVisitor;

        impl<'de> Visitor<'de> for PolicyFileVisitor {
            type Value = PolicyFile;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a policy file with version and sections")
            }

            fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut version: Option<u32> = None;
                let mut sections = HashMap::new();

                while let Some(key) = map.next_key::<String>()? {
                    if key == "version" {
                        version = Some(map.next_value()?);
                    } else {
                        // All other keys are sections
                        let value: SectionValue = map.next_value()?;
                        sections.insert(key, value);
                    }
                }

                let version =
                    version.ok_or_else(|| de::Error::custom("missing required 'version' field"))?;

                Ok(PolicyFile { version, sections })
            }
        }

        deserializer.deserialize_map(PolicyFileVisitor)
    }
}

/// Parse a YAML string into a PolicyFile.
pub fn parse_policy(yaml: &str) -> Result<PolicyFile> {
    let policy: PolicyFile = serde_yaml::from_str(yaml)?;

    // Basic version validation
    if policy.version == 0 {
        return Err(PolicyError::Validation(ValidationError::MissingVersion));
    }

    Ok(policy)
}

/// Parsed section name.
#[derive(Debug, Clone)]
pub struct ParsedSectionName {
    pub runtime: Option<String>,
    pub category: String,
}

/// Parse a section name like "python" or "commands" into components.
pub fn parse_section_name(name: &str) -> ParsedSectionName {
    // Split runtime.category
    if let Some(dot_pos) = name.find('.') {
        let (runtime, category) = name.split_at(dot_pos);
        ParsedSectionName {
            runtime: Some(runtime.to_string()),
            category: category[1..].to_string(), // Skip the '.'
        }
    } else {
        // No dot — bare runtime name (python, nodejs) maps to functions category
        let lower = name.to_lowercase();
        if matches!(lower.as_str(), "python" | "nodejs") {
            ParsedSectionName {
                runtime: Some(name.to_string()),
                category: "functions".to_string(),
            }
        } else {
            // Global category (e.g. "commands", "symbols")
            ParsedSectionName {
                runtime: None,
                category: name.to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        let yaml = "version: 1\n";
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(policy.version, 1);
        assert!(policy.sections.is_empty());
    }

    #[test]
    fn test_parse_simple_allow_deny() {
        let yaml = r#"
version: 1
python:
  allow:
    - json.loads
  deny:
    - eval
"#;
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(policy.version, 1);

        let section = policy.sections.get("python").unwrap();
        if let SectionValue::AllowDeny(ad) = section {
            assert_eq!(ad.allow.len(), 1);
            assert_eq!(ad.deny.len(), 1);
        } else {
            panic!("Expected AllowDeny section");
        }
    }

    #[test]
    fn test_parse_rule_with_constraints() {
        let yaml = r#"
version: 1
python:
  allow:
    - "requests.*": ["https://api.example.com/*"]
"#;
        let policy = parse_policy(yaml).unwrap();

        let section = policy.sections.get("python").unwrap();
        if let SectionValue::AllowDeny(ad) = section {
            assert_eq!(ad.allow.len(), 1);
            if let Rule::WithConstraints {
                pattern,
                constraints,
            } = &ad.allow[0]
            {
                assert_eq!(pattern, "requests.*");
                assert_eq!(constraints, &["https://api.example.com/*"]);
            } else {
                panic!("Expected WithConstraints rule");
            }
        } else {
            panic!("Expected AllowDeny section");
        }
    }

    #[test]
    fn test_parse_protocols_in_network_section() {
        let yaml = r#"
version: 1
network:
  allow:
    - "example.com/**"
  protocols: [tcp, https, http]
"#;
        let policy = parse_policy(yaml).unwrap();

        let section = policy.sections.get("network").unwrap();
        if let SectionValue::AllowDeny(ad) = section {
            assert_eq!(ad.allow.len(), 1);
            assert_eq!(ad.protocols, vec!["tcp", "https", "http"]);
        } else {
            panic!("Expected AllowDeny section");
        }
    }

    #[test]
    fn test_parse_section_name() {
        let parsed = parse_section_name("python");
        assert_eq!(parsed.runtime, Some("python".to_string()));
        assert_eq!(parsed.category, "functions");

        let parsed = parse_section_name("commands");
        assert_eq!(parsed.runtime, None);
        assert_eq!(parsed.category, "commands");

        let parsed = parse_section_name("network");
        assert_eq!(parsed.runtime, None);
        assert_eq!(parsed.category, "network");
    }

    #[test]
    fn test_parse_missing_version_fails() {
        let yaml = "python.functions:\n  deny:\n    - eval\n";
        assert!(parse_policy(yaml).is_err());
    }

    #[test]
    fn test_parse_direct_list_with_constraints() {
        let yaml = r#"
version: 1
nodejs:
  - "axios.*": ["https://api.example.com/*"]
  - JSON.parse
  - JSON.stringify
"#;
        let policy = parse_policy(yaml).unwrap();

        let section = policy.sections.get("nodejs").unwrap();
        // Should parse as RuleList because it contains a constraint map
        if let SectionValue::RuleList(rules) = section {
            assert_eq!(rules.len(), 3);
            // First rule has constraints
            if let Rule::WithConstraints {
                pattern,
                constraints,
            } = &rules[0]
            {
                assert_eq!(pattern, "axios.*");
                assert_eq!(constraints, &["https://api.example.com/*"]);
            } else {
                panic!("Expected WithConstraints rule");
            }
            // Rest are simple rules
            assert!(matches!(&rules[1], Rule::Simple(s) if s == "JSON.parse"));
            assert!(matches!(&rules[2], Rule::Simple(s) if s == "JSON.stringify"));
        } else {
            panic!("Expected RuleList section, got {:?}", section);
        }
    }

    #[test]
    fn test_parse_direct_list_all_strings() {
        // Pure string list parses as List (not RuleList)
        let yaml = r#"
version: 1
nodejs:
  - fs.readFileSync
  - path.join
  - path.resolve
"#;
        let policy = parse_policy(yaml).unwrap();

        let section = policy.sections.get("nodejs").unwrap();
        if let SectionValue::List(list) = section {
            assert_eq!(list.len(), 3);
            assert_eq!(list[0], "fs.readFileSync");
        } else {
            panic!("Expected List section, got {:?}", section);
        }
    }

    #[test]
    fn test_parse_envvar_with_operations() {
        let yaml = r#"
version: 1
envvars:
  - HOME: [read]
  - PATH: [read]
  - "APP_*": [read, write]
"#;
        let policy = parse_policy(yaml).unwrap();

        let section = policy.sections.get("envvars").unwrap();
        if let SectionValue::RuleList(rules) = section {
            assert_eq!(rules.len(), 3);
            // All should be WithConstraints
            if let Rule::WithConstraints {
                pattern,
                constraints,
            } = &rules[0]
            {
                assert_eq!(pattern, "HOME");
                assert_eq!(constraints, &["read"]);
            } else {
                panic!("Expected WithConstraints rule");
            }
        } else {
            panic!("Expected RuleList section");
        }
    }

    #[test]
    fn test_parse_network_with_endpoint_patterns() {
        let yaml = r#"
version: 1
network:
  allow:
    - "127.0.0.1:*"
    - "*:443"
  deny:
    - "*:22"
"#;
        let policy = parse_policy(yaml).unwrap();

        let section = policy.sections.get("network").unwrap();
        if let SectionValue::AllowDeny(ad) = section {
            assert_eq!(ad.allow.len(), 2);
            assert_eq!(ad.deny.len(), 1);
        } else {
            panic!("Expected AllowDeny section for network");
        }
    }

    #[test]
    fn test_unknown_key_error_message() {
        let yaml = r#"
version: 1
python:
  block:
    - eval
"#;
        let err = parse_policy(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unknown key 'block'"),
            "Expected unknown key error, got: {}",
            msg
        );
        assert!(
            msg.contains("valid keys are:"),
            "Expected valid keys hint, got: {}",
            msg
        );
    }
}
