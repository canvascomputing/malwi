//! Tests for policy validation.

use crate::error::ValidationError;
use crate::parser::parse_policy;
use crate::validate::validate_policy;

fn parse_and_validate(yaml: &str) -> Result<(), ValidationError> {
    let policy = parse_policy(yaml).map_err(|_| ValidationError::MissingVersion)?;
    validate_policy(&policy)
}

#[test]
fn test_validate_valid_minimal() {
    assert!(parse_and_validate("version: 1\n").is_ok());
}

#[test]
fn test_validate_unsupported_version() {
    let result = parse_and_validate("version: 99\n");
    assert!(matches!(
        result,
        Err(ValidationError::UnsupportedVersion(99))
    ));
}

#[test]
fn test_validate_at_syntax_rejected() {
    let yaml = r#"
version: 1
python@warn:
  deny:
    - eval
"#;
    let result = parse_and_validate(yaml);
    assert!(matches!(result, Err(ValidationError::DeprecatedAtSyntax(_))));
}

#[test]
fn test_validate_invalid_regex() {
    let yaml = r#"
version: 1
python:
  deny:
    - "regex:[unclosed"
"#;
    let result = parse_and_validate(yaml);
    assert!(matches!(result, Err(ValidationError::InvalidRegex { .. })));
}

#[test]
fn test_validate_unknown_section() {
    let yaml = r#"
version: 1
python.unknown_section:
  deny:
    - something
"#;
    let result = parse_and_validate(yaml);
    assert!(matches!(result, Err(ValidationError::UnknownSection(_))));
}

#[test]
fn test_validate_unknown_runtime() {
    let yaml = r#"
version: 1
ruby.functions:
  deny:
    - eval
"#;
    let result = parse_and_validate(yaml);
    assert!(matches!(result, Err(ValidationError::UnknownSection(_))));
}

#[test]
fn test_validate_invalid_protocol() {
    let yaml = r#"
version: 1
network:
  protocols: [tcp, gopher]
"#;
    let result = parse_and_validate(yaml);
    assert!(matches!(result, Err(ValidationError::InvalidProtocol(_))));
}

#[test]
fn test_validate_valid_protocols() {
    let yaml = r#"
version: 1
network:
  protocols: [tcp, udp, http, https, ws, wss]
"#;
    assert!(parse_and_validate(yaml).is_ok());
}

#[test]
fn test_validate_empty_allow_deny_is_ok() {
    let yaml = r#"
version: 1
python:
  allow: []
  deny: []
"#;
    assert!(parse_and_validate(yaml).is_ok());
}

#[test]
fn test_validate_all_mode_keys_valid() {
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
            parse_and_validate(&yaml).is_ok(),
            "mode key '{}' should be valid",
            mode_key
        );
    }
}

#[test]
fn test_validate_valid_global_categories() {
    for category in &["symbols", "files", "envvars", "commands"] {
        let yaml = format!(
            r#"
version: 1
{}:
  deny:
    - something
"#,
            category
        );
        assert!(
            parse_and_validate(&yaml).is_ok(),
            "global category '{}' should be valid",
            category
        );
    }
}

#[test]
fn test_validate_bare_runtime_sections() {
    for runtime in &["python", "nodejs"] {
        let yaml = format!(
            r#"
version: 1
{}:
  deny:
    - eval
"#,
            runtime
        );
        assert!(
            parse_and_validate(&yaml).is_ok(),
            "bare {} should be valid",
            runtime
        );
    }
}

#[test]
fn test_validate_dotted_runtime_rejected() {
    // python.functions:, python.symbols:, etc. are no longer valid
    for name in &["python.functions", "python.symbols", "nodejs.functions"] {
        let yaml = format!(
            r#"
version: 1
{}:
  deny:
    - eval
"#,
            name
        );
        let result = parse_and_validate(&yaml);
        assert!(
            matches!(result, Err(ValidationError::UnknownSection(_))),
            "{} should be rejected, got {:?}",
            name, result
        );
    }
}

#[test]
fn test_validate_networking_sections() {
    let yaml = r#"
version: 1
network:
  allow:
    - "*.example.com"
  deny:
    - "*:22"
"#;
    assert!(parse_and_validate(yaml).is_ok());
}

#[test]
fn test_validate_commands_section() {
    let yaml = r#"
version: 1
commands:
  allow:
    - "git *"
  deny:
    - curl
"#;
    assert!(parse_and_validate(yaml).is_ok());
}

#[test]
fn test_validate_valid_regex_patterns() {
    let yaml = r#"
version: 1
envvars:
  deny:
    - "regex:^(AWS|AZURE|GCP)_"
    - "regex:.*SECRET.*"
"#;
    assert!(parse_and_validate(yaml).is_ok());
}

#[test]
fn test_validate_mixed_rules() {
    let yaml = r#"
version: 1
python:
  allow:
    - json.loads
    - "requests.*": ["https://api.example.com/*"]
  deny:
    - eval
    - "subprocess.*": ["*sudo*"]
"#;
    assert!(parse_and_validate(yaml).is_ok());
}

#[test]
fn test_validate_file_operations() {
    let yaml = r#"
version: 1
files:
  allow:
    - "/tmp/*": [read]
    - "/app/*": [read, edit]
"#;
    assert!(parse_and_validate(yaml).is_ok());
}

#[test]
fn test_validate_complex_policy() {
    let yaml = r#"
version: 1
python:
  allow:
    - json.*
    - "requests.*": ["https://api.example.com/*"]
  deny:
    - eval
    - exec
    - __import__
files:
  allow:
    - "/tmp/*": [read, edit]
  log:
    - "~/.ssh/*"
envvars:
  deny:
    - "regex:^(AWS|AZURE|GCP)_"
nodejs:
  allow:
    - fs.readFileSync
    - path.*
network:
  deny:
    - "*.onion"
    - "*:22"
    - "*:23"
  protocols: [tcp, https]
commands:
  allow:
    - "git *"
    - "npm *"
  review:
    - curl
    - wget
"#;
    assert!(parse_and_validate(yaml).is_ok());
}
