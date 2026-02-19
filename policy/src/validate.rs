use regex::Regex;

use crate::compiled::{Category, Operation, Runtime};
use crate::error::ValidationError;
use crate::parser::{parse_section_name, PolicyFile, Rule, SectionValue};

/// Supported policy versions.
const SUPPORTED_VERSIONS: &[u32] = &[1];

/// Supported protocols.
const SUPPORTED_PROTOCOLS: &[&str] = &["tcp", "udp", "http", "https", "ws", "wss"];

/// Validate a parsed policy file.
pub fn validate_policy(policy: &PolicyFile) -> Result<(), ValidationError> {
    // Validate version
    if !SUPPORTED_VERSIONS.contains(&policy.version) {
        return Err(ValidationError::UnsupportedVersion(policy.version));
    }

    // Validate each section
    for (name, value) in &policy.sections {
        validate_section(name, value)?;
    }

    Ok(())
}

fn validate_section(name: &str, value: &SectionValue) -> Result<(), ValidationError> {
    // Reject removed @ syntax with a helpful message
    if name.contains('@') {
        return Err(ValidationError::DeprecatedAtSyntax(name.to_string()));
    }

    let parsed = parse_section_name(name);

    // Determine if this is a valid section name
    if let Some(runtime) = &parsed.runtime {
        if Runtime::parse(runtime).is_none() {
            return Err(ValidationError::UnknownSection(name.to_string()));
        }
        // Only bare runtime names (python:, nodejs:) are valid.
        // Dotted forms like python.functions: are not accepted.
        if name.contains('.') {
            return Err(ValidationError::UnknownSection(name.to_string()));
        }
    } else {
        // Global section: must be a known category OR "network"
        if parsed.category != "network" && Category::parse(&parsed.category).is_none() {
            return Err(ValidationError::UnknownSection(name.to_string()));
        }
    }

    // Validate section content based on type
    match value {
        SectionValue::AllowDeny(ad) => {
            // Validate all rules
            for rule in &ad.allow {
                validate_rule(rule, &parsed.category)?;
            }
            for rule in &ad.deny {
                validate_rule(rule, &parsed.category)?;
            }
            for rule in &ad.warn {
                validate_rule(rule, &parsed.category)?;
            }
            for rule in &ad.log {
                validate_rule(rule, &parsed.category)?;
            }
            for rule in &ad.review {
                validate_rule(rule, &parsed.category)?;
            }
            for rule in &ad.noop {
                validate_rule(rule, &parsed.category)?;
            }
            // Validate protocols field (only meaningful in network sections)
            if !ad.protocols.is_empty() {
                if parsed.category != "network" {
                    return Err(ValidationError::UnknownSection(format!(
                        "{}: 'protocols' field is only valid in network sections",
                        name
                    )));
                }
                for proto in &ad.protocols {
                    if !SUPPORTED_PROTOCOLS.contains(&proto.to_lowercase().as_str()) {
                        return Err(ValidationError::InvalidProtocol(proto.clone()));
                    }
                }
            }
        }
        SectionValue::List(list) => {
            // String lists are valid patterns for any section (no validation needed)
            // Protocols are now in AllowDenySection.protocols, not standalone List sections
            let _ = list;
        }
        SectionValue::RuleList(rules) => {
            // Validate each rule in the direct list (implicit allow)
            for rule in rules {
                validate_rule(rule, &parsed.category)?;
            }
        }
    }

    Ok(())
}

fn validate_rule(rule: &Rule, category: &str) -> Result<(), ValidationError> {
    match rule {
        Rule::Simple(pattern) => {
            validate_pattern(pattern)?;
        }
        Rule::WithConstraints {
            pattern,
            constraints,
        } => {
            validate_pattern(pattern)?;

            // For files and envvars categories, constraints can be operations
            if category == "files" || category == "envvars" {
                for constraint in constraints {
                    // Could be an operation or a pattern
                    if Operation::parse(constraint).is_none() && !looks_like_pattern(constraint) {
                        return Err(ValidationError::InvalidOperation(constraint.clone()));
                    }
                }
            } else {
                // Other categories: constraints are patterns
                for constraint in constraints {
                    validate_pattern(constraint)?;
                }
            }
        }
    }
    Ok(())
}

fn validate_pattern(pattern: &str) -> Result<(), ValidationError> {
    // Check for regex prefix and validate
    if let Some(regex_str) = pattern.strip_prefix("regex:") {
        if Regex::new(regex_str).is_err() {
            return Err(ValidationError::InvalidRegex {
                pattern: pattern.to_string(),
                reason: "invalid regex syntax".to_string(),
            });
        }
    }
    // Glob patterns and exact patterns are always valid syntax-wise
    Ok(())
}

fn looks_like_pattern(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.starts_with("regex:") || s.contains('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_policy;

    fn validate_yaml(yaml: &str) -> Result<(), ValidationError> {
        let policy = parse_policy(yaml).unwrap();
        validate_policy(&policy)
    }

    #[test]
    fn test_valid_minimal_policy() {
        assert!(validate_yaml("version: 1\n").is_ok());
    }

    #[test]
    fn test_unsupported_version() {
        let result = validate_yaml("version: 99\n");
        assert!(matches!(
            result,
            Err(ValidationError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn test_at_syntax_rejected() {
        let yaml = r#"
version: 1
python@warn:
  deny:
    - eval
"#;
        let result = validate_yaml(yaml);
        assert!(matches!(
            result,
            Err(ValidationError::DeprecatedAtSyntax(_))
        ));
    }

    #[test]
    fn test_unknown_section() {
        let yaml = r#"
version: 1
python.unknown_section:
  deny:
    - something
"#;
        let result = validate_yaml(yaml);
        assert!(matches!(result, Err(ValidationError::UnknownSection(_))));
    }

    #[test]
    fn test_invalid_regex() {
        let yaml = r#"
version: 1
python:
  deny:
    - "regex:[unclosed"
"#;
        let result = validate_yaml(yaml);
        assert!(matches!(result, Err(ValidationError::InvalidRegex { .. })));
    }

    #[test]
    fn test_mode_keys_valid() {
        for mode_key in &["deny", "review", "log", "warn", "noop"] {
            let yaml = format!(
                r#"
version: 1
python:
  {}:
    - eval
"#,
                mode_key
            );
            assert!(
                validate_yaml(&yaml).is_ok(),
                "mode key '{}' should be valid",
                mode_key
            );
        }
    }

    #[test]
    fn test_empty_allow_deny_is_ok() {
        let yaml = r#"
version: 1
python:
  allow: []
  deny: []
"#;
        assert!(validate_yaml(yaml).is_ok());
    }

    #[test]
    fn test_network_section_valid() {
        let yaml = r#"
version: 1
network:
  allow:
    - "huggingface.co/**"
    - "*.onion"
    - "*:22"
  protocols: [https, http]
"#;
        assert!(validate_yaml(yaml).is_ok());
    }

    #[test]
    fn test_network_invalid_protocol() {
        let yaml = r#"
version: 1
network:
  protocols: [https, ftp_invalid]
"#;
        let result = validate_yaml(yaml);
        assert!(matches!(result, Err(ValidationError::InvalidProtocol(_))));
    }

    #[test]
    fn test_old_networking_prefix_rejected() {
        let yaml = r#"
version: 1
networking.domains:
  deny:
    - "*.onion"
"#;
        let result = validate_yaml(yaml);
        assert!(matches!(result, Err(ValidationError::UnknownSection(_))));
    }

    #[test]
    fn test_runtime_prefixed_functions_rejected() {
        let yaml = r#"
version: 1
python.functions:
  deny:
    - eval
"#;
        let result = validate_yaml(yaml);
        assert!(matches!(result, Err(ValidationError::UnknownSection(_))));
    }

    #[test]
    fn test_runtime_prefixed_files_rejected() {
        let yaml = r#"
version: 1
python.files:
  deny:
    - "~/.ssh/**"
"#;
        let result = validate_yaml(yaml);
        assert!(matches!(result, Err(ValidationError::UnknownSection(_))));
    }

    #[test]
    fn test_runtime_prefixed_envvars_rejected() {
        let yaml = r#"
version: 1
python.envvars:
  deny:
    - "*SECRET*"
"#;
        let result = validate_yaml(yaml);
        assert!(matches!(result, Err(ValidationError::UnknownSection(_))));
    }

    #[test]
    fn test_runtime_prefixed_http_rejected() {
        let yaml = r#"
version: 1
python.http:
  allow:
    - "https://pypi.org/**"
"#;
        let result = validate_yaml(yaml);
        assert!(matches!(result, Err(ValidationError::UnknownSection(_))));
    }

    #[test]
    fn test_standalone_http_rejected() {
        let yaml = r#"
version: 1
http:
  deny:
    - "*.evil.com/**"
"#;
        let result = validate_yaml(yaml);
        assert!(matches!(result, Err(ValidationError::UnknownSection(_))));
    }

    #[test]
    fn test_global_files_valid() {
        let yaml = r#"
version: 1
files:
  deny:
    - "~/.ssh/**"
"#;
        assert!(validate_yaml(yaml).is_ok());
    }

    #[test]
    fn test_global_envvars_valid() {
        let yaml = r#"
version: 1
envvars:
  deny:
    - "*SECRET*"
"#;
        assert!(validate_yaml(yaml).is_ok());
    }
}
