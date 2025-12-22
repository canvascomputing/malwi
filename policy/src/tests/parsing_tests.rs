//! Tests for YAML policy parsing.

use crate::parser::{parse_policy, parse_section_name, Rule, SectionValue};

#[test]
fn test_parse_minimal_policy() {
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

        if let Rule::Simple(s) = &ad.allow[0] {
            assert_eq!(s, "json.loads");
        } else {
            panic!("Expected simple rule");
        }

        if let Rule::Simple(s) = &ad.deny[0] {
            assert_eq!(s, "eval");
        } else {
            panic!("Expected simple rule");
        }
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
            assert_eq!(constraints.len(), 1);
            assert_eq!(constraints[0], "https://api.example.com/*");
        } else {
            panic!("Expected WithConstraints rule");
        }
    } else {
        panic!("Expected AllowDeny section");
    }
}

#[test]
fn test_parse_mode_keys() {
    let yaml = r#"
version: 1
files:
  log:
    - "~/.ssh/*"
  deny:
    - "*.pem"
"#;
    let policy = parse_policy(yaml).unwrap();

    let section = policy.sections.get("files").unwrap();
    if let SectionValue::AllowDeny(ad) = section {
        assert_eq!(ad.log.len(), 1);
        assert_eq!(ad.deny.len(), 1);
    } else {
        panic!("Expected AllowDeny section");
    }
}

#[test]
fn test_parse_file_operations() {
    let yaml = r#"
version: 1
files:
  allow:
    - "/tmp/*": [read, edit]
    - "/var/log/*": [read]
"#;
    let policy = parse_policy(yaml).unwrap();

    let section = policy.sections.get("files").unwrap();
    if let SectionValue::AllowDeny(ad) = section {
        assert_eq!(ad.allow.len(), 2);

        if let Rule::WithConstraints {
            pattern,
            constraints,
        } = &ad.allow[0]
        {
            assert_eq!(pattern, "/tmp/*");
            assert_eq!(constraints, &["read", "edit"]);
        } else {
            panic!("Expected WithConstraints rule");
        }

        if let Rule::WithConstraints {
            pattern,
            constraints,
        } = &ad.allow[1]
        {
            assert_eq!(pattern, "/var/log/*");
            assert_eq!(constraints, &["read"]);
        } else {
            panic!("Expected WithConstraints rule");
        }
    } else {
        panic!("Expected AllowDeny section");
    }
}

#[test]
fn test_parse_networking_sections() {
    let yaml = r#"
version: 1
network:
  allow:
    - "127.0.0.1:*"
  deny:
    - "*.onion"
    - "*:22"
  protocols: [tcp, https]
"#;
    let policy = parse_policy(yaml).unwrap();

    let section = policy.sections.get("network").unwrap();
    if let SectionValue::AllowDeny(ad) = section {
        assert_eq!(ad.allow.len(), 1);
        assert_eq!(ad.deny.len(), 2);

        if let Rule::Simple(s) = &ad.allow[0] {
            assert_eq!(s, "127.0.0.1:*");
        } else {
            panic!("Expected simple rule");
        }

        if let Rule::Simple(s) = &ad.deny[0] {
            assert_eq!(s, "*.onion");
        } else {
            panic!("Expected simple rule");
        }

        if let Rule::Simple(s) = &ad.deny[1] {
            assert_eq!(s, "*:22");
        } else {
            panic!("Expected simple rule");
        }

        assert_eq!(ad.protocols, vec!["tcp", "https"]);
    } else {
        panic!("Expected AllowDeny section");
    }
}

#[test]
fn test_parse_regex_pattern() {
    let yaml = r#"
version: 1
envvars:
  deny:
    - "regex:^(AWS|AZURE|GCP)_"
"#;
    let policy = parse_policy(yaml).unwrap();

    let section = policy.sections.get("envvars").unwrap();
    if let SectionValue::AllowDeny(ad) = section {
        if let Rule::Simple(pattern) = &ad.deny[0] {
            assert!(pattern.starts_with("regex:"));
        } else {
            panic!("Expected simple rule");
        }
    } else {
        panic!("Expected AllowDeny section");
    }
}

#[test]
fn test_parse_invalid_yaml_returns_error() {
    let yaml = "not: valid: yaml: {{";
    assert!(parse_policy(yaml).is_err());
}

#[test]
fn test_parse_missing_version_returns_error() {
    let yaml = "python:\n  deny:\n    - eval\n";
    assert!(parse_policy(yaml).is_err());
}

#[test]
fn test_parse_multiple_constraints() {
    let yaml = r#"
version: 1
python:
  allow:
    - "http.*": ["https://api1.com/*", "https://api2.com/*", "https://api3.com/*"]
"#;
    let policy = parse_policy(yaml).unwrap();

    let section = policy.sections.get("python").unwrap();
    if let SectionValue::AllowDeny(ad) = section {
        if let Rule::WithConstraints { constraints, .. } = &ad.allow[0] {
            assert_eq!(constraints.len(), 3);
        } else {
            panic!("Expected WithConstraints rule");
        }
    } else {
        panic!("Expected AllowDeny section");
    }
}

#[test]
fn test_parse_commands_section() {
    let yaml = r#"
version: 1
commands:
  allow:
    - "pip install *"
    - "git *"
  deny:
    - curl
    - wget
"#;
    let policy = parse_policy(yaml).unwrap();

    let section = policy.sections.get("commands").unwrap();
    if let SectionValue::AllowDeny(ad) = section {
        assert_eq!(ad.allow.len(), 2);
        assert_eq!(ad.deny.len(), 2);
    } else {
        panic!("Expected AllowDeny section");
    }
}

#[test]
fn test_parse_section_name_variants() {
    // Bare runtime name
    let p1 = parse_section_name("python");
    assert_eq!(p1.runtime, Some("python".to_string()));
    assert_eq!(p1.category, "functions");

    // Global section
    let p2 = parse_section_name("commands");
    assert_eq!(p2.runtime, None);
    assert_eq!(p2.category, "commands");

    // Network section
    let p3 = parse_section_name("network");
    assert_eq!(p3.runtime, None);
    assert_eq!(p3.category, "network");

    // Node section
    let p4 = parse_section_name("nodejs");
    assert_eq!(p4.runtime, Some("nodejs".to_string()));
    assert_eq!(p4.category, "functions");
}

#[test]
fn test_parse_empty_sections() {
    let yaml = r#"
version: 1
python:
  allow: []
  deny: []
"#;
    let policy = parse_policy(yaml).unwrap();

    let section = policy.sections.get("python").unwrap();
    if let SectionValue::AllowDeny(ad) = section {
        assert!(ad.allow.is_empty());
        assert!(ad.deny.is_empty());
    } else {
        panic!("Expected AllowDeny section");
    }
}

#[test]
fn test_parse_mixed_rules() {
    let yaml = r#"
version: 1
python:
  allow:
    - json.loads
    - "requests.*": ["https://api.example.com/*"]
    - os.path.join
"#;
    let policy = parse_policy(yaml).unwrap();

    let section = policy.sections.get("python").unwrap();
    if let SectionValue::AllowDeny(ad) = section {
        assert_eq!(ad.allow.len(), 3);

        // First is simple
        assert!(matches!(&ad.allow[0], Rule::Simple(_)));
        // Second has constraints
        assert!(matches!(&ad.allow[1], Rule::WithConstraints { .. }));
        // Third is simple
        assert!(matches!(&ad.allow[2], Rule::Simple(_)));
    } else {
        panic!("Expected AllowDeny section");
    }
}

// =====================================================================
// Tests for new direct list format
// =====================================================================

#[test]
fn test_parse_new_format_direct_list() {
    let yaml = r#"
version: 1
nodejs:
  - "axios.*": ["https://api.example.com/*"]
  - JSON.parse
  - JSON.stringify
  - "console.*"
"#;
    let policy = parse_policy(yaml).unwrap();

    let section = policy.sections.get("nodejs").unwrap();
    if let SectionValue::RuleList(rules) = section {
        assert_eq!(rules.len(), 4);

        // First has constraints
        assert!(matches!(&rules[0], Rule::WithConstraints { pattern, .. } if pattern == "axios.*"));
        // Rest are simple
        assert!(matches!(&rules[1], Rule::Simple(s) if s == "JSON.parse"));
        assert!(matches!(&rules[2], Rule::Simple(s) if s == "JSON.stringify"));
        assert!(matches!(&rules[3], Rule::Simple(s) if s == "console.*"));
    } else {
        panic!("Expected RuleList section, got {:?}", section);
    }
}

#[test]
fn test_parse_new_format_envvars_with_ops() {
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

        // All should be WithConstraints (operations)
        if let Rule::WithConstraints { pattern, constraints } = &rules[0] {
            assert_eq!(pattern, "HOME");
            assert_eq!(constraints, &["read"]);
        } else {
            panic!("Expected WithConstraints rule");
        }

        if let Rule::WithConstraints { pattern, constraints } = &rules[2] {
            assert_eq!(pattern, "APP_*");
            assert_eq!(constraints, &["read", "write"]);
        } else {
            panic!("Expected WithConstraints rule");
        }
    } else {
        panic!("Expected RuleList section");
    }
}

#[test]
fn test_parse_new_format_files_with_ops() {
    let yaml = r#"
version: 1
files:
  - "/app/data/*": [read, edit]
  - "/app/logs/*": [read, edit, delete]
  - "/app/uploads/*": [read]
"#;
    let policy = parse_policy(yaml).unwrap();

    let section = policy.sections.get("files").unwrap();
    if let SectionValue::RuleList(rules) = section {
        assert_eq!(rules.len(), 3);

        if let Rule::WithConstraints { pattern, constraints } = &rules[1] {
            assert_eq!(pattern, "/app/logs/*");
            assert_eq!(constraints, &["read", "edit", "delete"]);
        } else {
            panic!("Expected WithConstraints rule");
        }
    } else {
        panic!("Expected RuleList section");
    }
}

#[test]
fn test_parse_new_format_endpoints() {
    let yaml = r#"
version: 1
network:
  allow:
    - "127.0.0.1:*"
    - "10.0.0.0/8:5432"
    - "*:443"
"#;
    let policy = parse_policy(yaml).unwrap();

    let section = policy.sections.get("network").unwrap();
    if let SectionValue::AllowDeny(ad) = section {
        assert_eq!(ad.allow.len(), 3);

        if let Rule::Simple(s) = &ad.allow[0] {
            assert_eq!(s, "127.0.0.1:*");
        } else {
            panic!("Expected simple rule");
        }

        if let Rule::Simple(s) = &ad.allow[1] {
            assert_eq!(s, "10.0.0.0/8:5432");
        } else {
            panic!("Expected simple rule");
        }

        if let Rule::Simple(s) = &ad.allow[2] {
            assert_eq!(s, "*:443");
        } else {
            panic!("Expected simple rule");
        }
    } else {
        panic!("Expected AllowDeny section");
    }
}
