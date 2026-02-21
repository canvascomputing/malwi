use std::collections::HashMap;

use crate::error::{PolicyError, Result, ValidationError};
use crate::yaml::{self, YamlValue};

/// Raw parsed policy file from YAML.
#[derive(Debug, Clone)]
pub struct PolicyFile {
    pub version: u32,
    pub sections: HashMap<String, SectionValue>,
    /// Names of policies to inherit sections from (e.g. `includes: [base]`).
    pub includes: Vec<String>,
}

/// Value of a policy section - can be different formats.
///
/// Conversion logic from YamlValue:
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

/// Parse a YAML string into a PolicyFile.
pub fn parse_policy(yaml_str: &str) -> Result<PolicyFile> {
    let root = yaml::parse(yaml_str)?;

    let pairs = match root {
        YamlValue::Mapping(pairs) => pairs,
        _ => {
            return Err(PolicyError::YamlParse(yaml::YamlError {
                line: 1,
                message: "expected a mapping at top level".to_string(),
            }))
        }
    };

    let mut version: Option<u32> = None;
    let mut sections = HashMap::new();
    let mut includes: Vec<String> = Vec::new();

    for (key, value) in pairs {
        if key == "version" {
            version = Some(value_to_u32(&value)?);
        } else if key == "includes" {
            includes = value_to_string_list(&value, "includes")?;
        } else {
            let section = value_to_section_value(&value, &key)?;
            sections.insert(key, section);
        }
    }

    let version = version.ok_or(PolicyError::YamlParse(yaml::YamlError {
        line: 0,
        message: "missing required 'version' field".to_string(),
    }))?;

    if version == 0 {
        return Err(PolicyError::Validation(ValidationError::MissingVersion));
    }

    Ok(PolicyFile {
        version,
        sections,
        includes,
    })
}

/// Convert a YamlValue to u32.
fn value_to_u32(value: &YamlValue) -> Result<u32> {
    match value {
        YamlValue::Integer(n) => Ok(*n as u32),
        YamlValue::String(s) => s.parse::<u32>().map_err(|_| {
            PolicyError::YamlParse(yaml::YamlError {
                line: 0,
                message: format!("expected integer, got: {}", s),
            })
        }),
        _ => Err(PolicyError::YamlParse(yaml::YamlError {
            line: 0,
            message: "expected integer".to_string(),
        })),
    }
}

/// Convert a YamlValue to SectionValue.
fn value_to_section_value(value: &YamlValue, section_name: &str) -> Result<SectionValue> {
    match value {
        YamlValue::Mapping(_) => {
            let section = value_to_allow_deny_section(value, section_name)?;
            Ok(SectionValue::AllowDeny(section))
        }
        YamlValue::Sequence(items) => {
            // Check if all items are plain strings → List
            let all_strings = items
                .iter()
                .all(|item| matches!(item, YamlValue::String(_)));
            if all_strings {
                let list: Vec<String> = items
                    .iter()
                    .map(|item| match item {
                        YamlValue::String(s) => s.clone(),
                        _ => unreachable!(),
                    })
                    .collect();
                Ok(SectionValue::List(list))
            } else {
                // Contains maps → RuleList
                let rules: Vec<Rule> = items
                    .iter()
                    .map(|item| value_to_rule(item, section_name))
                    .collect::<Result<_>>()?;
                Ok(SectionValue::RuleList(rules))
            }
        }
        _ => Err(PolicyError::YamlParse(yaml::YamlError {
            line: 0,
            message: format!(
                "expected a map or sequence for policy section '{}'",
                section_name
            ),
        })),
    }
}

/// Convert a YamlValue mapping to AllowDenySection.
fn value_to_allow_deny_section(value: &YamlValue, section_name: &str) -> Result<AllowDenySection> {
    let pairs = match value {
        YamlValue::Mapping(pairs) => pairs,
        _ => {
            return Err(PolicyError::YamlParse(yaml::YamlError {
                line: 0,
                message: format!(
                    "expected a mapping for section '{}', got: {:?}",
                    section_name, value
                ),
            }))
        }
    };

    let mut section = AllowDenySection::default();

    for (key, val) in pairs {
        match key.as_str() {
            "allow" => section.allow = value_to_rules(val, section_name)?,
            "deny" => section.deny = value_to_rules(val, section_name)?,
            "warn" => section.warn = value_to_rules(val, section_name)?,
            "log" => section.log = value_to_rules(val, section_name)?,
            "review" => section.review = value_to_rules(val, section_name)?,
            "noop" => section.noop = value_to_rules(val, section_name)?,
            "protocols" => section.protocols = value_to_string_list(val, section_name)?,
            _ => {
                return Err(PolicyError::YamlParse(yaml::YamlError {
                    line: 0,
                    message: format!(
                        "unknown key '{}' in policy section; valid keys are: allow, deny, warn, log, review, noop, protocols",
                        key
                    ),
                }))
            }
        }
    }

    Ok(section)
}

/// Convert a YamlValue sequence to a Vec<Rule>.
fn value_to_rules(value: &YamlValue, section_name: &str) -> Result<Vec<Rule>> {
    match value {
        YamlValue::Sequence(items) => items
            .iter()
            .map(|item| value_to_rule(item, section_name))
            .collect(),
        _ => Err(PolicyError::YamlParse(yaml::YamlError {
            line: 0,
            message: format!("expected a sequence of rules in section '{}'", section_name),
        })),
    }
}

/// Convert a YamlValue to a single Rule.
fn value_to_rule(value: &YamlValue, _section_name: &str) -> Result<Rule> {
    match value {
        YamlValue::String(s) => Ok(Rule::Simple(s.clone())),
        YamlValue::Mapping(pairs) => {
            if pairs.len() != 1 {
                return Err(PolicyError::YamlParse(yaml::YamlError {
                    line: 0,
                    message: "rule with constraints should have exactly one pattern".to_string(),
                }));
            }
            let (pattern, val) = &pairs[0];
            let constraints = value_to_string_list(val, pattern)?;
            Ok(Rule::WithConstraints {
                pattern: pattern.clone(),
                constraints,
            })
        }
        _ => Err(PolicyError::YamlParse(yaml::YamlError {
            line: 0,
            message: format!("expected string or map for rule, got: {:?}", value),
        })),
    }
}

/// Convert a YamlValue to Vec<String>.
fn value_to_string_list(value: &YamlValue, context: &str) -> Result<Vec<String>> {
    match value {
        YamlValue::Sequence(items) => {
            let mut result = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    YamlValue::String(s) => result.push(s.clone()),
                    _ => {
                        return Err(PolicyError::YamlParse(yaml::YamlError {
                            line: 0,
                            message: format!(
                                "expected string in list for '{}', got: {:?}",
                                context, item
                            ),
                        }))
                    }
                }
            }
            Ok(result)
        }
        _ => Err(PolicyError::YamlParse(yaml::YamlError {
            line: 0,
            message: format!("expected a sequence for '{}', got: {:?}", context, value),
        })),
    }
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
