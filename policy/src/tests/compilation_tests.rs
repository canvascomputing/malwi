//! Tests for policy compilation.

use crate::compiled::{Category, ConstraintKind, EnforcementMode, Operation, Runtime, SectionKey};
use crate::compiler::compile_policy_yaml;
use crate::pattern::compile_pattern;

#[test]
fn test_compile_glob_to_regex() {
    let pattern = compile_pattern("fs.*").unwrap();
    assert!(pattern.matches("fs.readFile"));
    assert!(pattern.matches("fs.writeFile"));
    assert!(!pattern.matches("http.request"));
}

#[test]
fn test_compile_exact_pattern() {
    let pattern = compile_pattern("eval").unwrap();
    assert!(pattern.matches("eval"));
    assert!(!pattern.matches("evaluate"));
    assert!(!pattern.matches("myeval"));
}

#[test]
fn test_compile_regex_pattern() {
    let pattern = compile_pattern("regex:^AWS_").unwrap();
    assert!(pattern.matches("AWS_ACCESS_KEY"));
    assert!(pattern.matches("AWS_SECRET"));
    assert!(!pattern.matches("MY_AWS_KEY"));
}

#[test]
fn test_compile_wildcard_patterns() {
    // Single * = any chars except path separator
    let p1 = compile_pattern("*.pypi.org").unwrap();
    assert!(p1.matches("files.pypi.org"));
    assert!(!p1.matches("pypi.org")); // No prefix to match *

    // ** = any chars including separator
    let p2 = compile_pattern("/app/**/*.py").unwrap();
    assert!(p2.matches("/app/src/main.py"));
    assert!(p2.matches("/app/src/lib/util.py"));
}

#[test]
fn test_compile_endpoint_pattern() {
    let p1 = compile_pattern("127.0.0.1:*").unwrap();
    assert!(p1.matches("127.0.0.1:8080"));
    assert!(p1.matches("127.0.0.1:443"));

    let p2 = compile_pattern("*:443").unwrap();
    assert!(p2.matches("example.com:443"));
    assert!(!p2.matches("example.com:80"));
}

#[test]
fn test_compile_invalid_regex_returns_error() {
    let result = compile_pattern("regex:[invalid");
    assert!(result.is_err());
}

#[test]
fn test_compile_extracts_mode_from_keys() {
    let policy = compile_policy_yaml(
        r#"
version: 1
files:
  warn:
    - "/etc/*"
"#,
    )
    .unwrap();

    let key = SectionKey::global(Category::Files);
    let section = policy.get_section(&key).unwrap();
    assert_eq!(section.mode, EnforcementMode::Warn);
}

#[test]
fn test_compile_default_mode_is_block() {
    let policy = compile_policy_yaml(
        r#"
version: 1
python:
  deny:
    - eval
"#,
    )
    .unwrap();

    let key = SectionKey::for_runtime(Runtime::Python, Category::Functions);
    let section = policy.get_section(&key).unwrap();
    assert_eq!(section.mode, EnforcementMode::Block);
}

#[test]
fn test_compile_all_mode_keys() {
    // Test each mode key compiles deny rules with the correct mode
    for (mode_key, expected) in [
        ("deny", EnforcementMode::Block),
        ("review", EnforcementMode::Review),
        ("log", EnforcementMode::Log),
        ("warn", EnforcementMode::Warn),
        ("noop", EnforcementMode::Noop),
    ] {
        let yaml = format!(
            r#"
version: 1
python:
  {}:
    - eval
"#,
            mode_key
        );
        let policy = compile_policy_yaml(&yaml).unwrap();
        let key = SectionKey::for_runtime(Runtime::Python, Category::Functions);
        let section = policy.get_section(&key).unwrap();
        assert_eq!(
            section.deny_rules.len(),
            1,
            "Key {} should produce a deny rule",
            mode_key
        );
        assert_eq!(
            section.deny_rules[0].mode, expected,
            "Key {} should have mode {:?}",
            mode_key, expected
        );
    }
}

#[test]
fn test_compile_file_operation_constraints() {
    let policy = compile_policy_yaml(
        r#"
version: 1
files:
  allow:
    - "/tmp/*": [read, edit]
"#,
    )
    .unwrap();

    let key = SectionKey::global(Category::Files);
    let section = policy.get_section(&key).unwrap();
    let rule = &section.allow_rules[0];

    assert_eq!(rule.constraints.len(), 1);
    if let ConstraintKind::Operation(ops) = &rule.constraints[0].kind {
        assert!(ops.contains(&Operation::Read));
        assert!(ops.contains(&Operation::Edit));
        assert!(!ops.contains(&Operation::Delete));
    } else {
        panic!("Expected Operation constraint");
    }
}

#[test]
fn test_compile_argument_constraints() {
    let policy = compile_policy_yaml(
        r#"
version: 1
python:
  allow:
    - "requests.*": ["https://api.example.com/*", "https://api2.example.com/*"]
"#,
    )
    .unwrap();

    let key = SectionKey::for_runtime(Runtime::Python, Category::Functions);
    let section = policy.get_section(&key).unwrap();
    let rule = &section.allow_rules[0];

    assert_eq!(rule.constraints.len(), 2);
    for constraint in &rule.constraints {
        assert!(matches!(constraint.kind, ConstraintKind::AnyArgument));
    }
}

#[test]
fn test_compile_protocols_list() {
    let policy = compile_policy_yaml(
        r#"
version: 1
network:
  protocols: [tcp, https, ws]
"#,
    )
    .unwrap();

    let key = SectionKey::global(Category::Protocols);
    let section = policy.get_section(&key).unwrap();
    assert_eq!(section.allowed_values, vec!["tcp", "https", "ws"]);
}

#[test]
fn test_compile_case_insensitive_domains() {
    let policy = compile_policy_yaml(
        r#"
version: 1
network:
  deny:
    - "*.ONION"
"#,
    )
    .unwrap();

    let key = SectionKey::global(Category::Domains);
    let section = policy.get_section(&key).unwrap();

    // Pattern should match case-insensitively
    assert!(section.deny_rules[0].pattern.matches("test.onion"));
    assert!(section.deny_rules[0].pattern.matches("TEST.ONION"));
    assert!(section.deny_rules[0].pattern.matches("Test.Onion"));
}

#[test]
fn test_compile_multiple_sections() {
    let policy = compile_policy_yaml(
        r#"
version: 1
python:
  deny:
    - eval
nodejs:
  allow:
    - fs.*
network:
  deny:
    - "*.onion"
commands:
  allow:
    - "git *"
"#,
    )
    .unwrap();

    assert!(policy
        .get_section(&SectionKey::for_runtime(
            Runtime::Python,
            Category::Functions
        ))
        .is_some());
    assert!(policy
        .get_section(&SectionKey::for_runtime(Runtime::Node, Category::Functions))
        .is_some());
    assert!(policy
        .get_section(&SectionKey::global(Category::Domains))
        .is_some());
    assert!(policy
        .get_section(&SectionKey::global(Category::Execution))
        .is_some());
}

#[test]
fn test_compile_empty_section() {
    let policy = compile_policy_yaml(
        r#"
version: 1
python:
  allow: []
  deny: []
"#,
    )
    .unwrap();

    let key = SectionKey::for_runtime(Runtime::Python, Category::Functions);
    let section = policy.get_section(&key).unwrap();
    assert!(section.allow_rules.is_empty());
    assert!(section.deny_rules.is_empty());
    assert!(section.is_empty());
}

#[test]
fn test_compile_special_characters_in_pattern() {
    let policy = compile_policy_yaml(
        r#"
version: 1
python:
  deny:
    - __import__
    - os.path.join
"#,
    )
    .unwrap();

    let key = SectionKey::for_runtime(Runtime::Python, Category::Functions);
    let section = policy.get_section(&key).unwrap();

    assert!(section.deny_rules[0].pattern.matches("__import__"));
    assert!(!section.deny_rules[0].pattern.matches("import"));

    assert!(section.deny_rules[1].pattern.matches("os.path.join"));
    assert!(!section.deny_rules[1].pattern.matches("os_path_join"));
}
