use std::collections::HashMap;

use crate::compiled::{
    Category, CompiledPolicy, CompiledRule, CompiledSection, Constraint, ConstraintKind,
    EnforcementMode, Operation, Runtime, SectionKey,
};
use crate::error::{PolicyError, Result};
use crate::parser::{parse_section_name, AllowDenySection, PolicyFile, Rule, SectionValue};
use crate::pattern::{compile_pattern, compile_pattern_case_insensitive, compile_url_pattern, CompiledPattern};

/// Compile a parsed policy into an efficient runtime representation.
///
/// Each rule carries its own `EnforcementMode` derived from the key it was
/// listed under (deny → Block, warn → Warn, etc.), so evaluation can return
/// the correct mode per matched rule.
pub fn compile_policy(policy: &PolicyFile) -> Result<CompiledPolicy> {
    let mut sections: HashMap<SectionKey, CompiledSection> = HashMap::new();

    for (name, value) in &policy.sections {
        let compiled_sections = compile_section(name, value)?;
        for (key, section) in compiled_sections {
            match sections.entry(key) {
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(section);
                }
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    // Merge: append rules from the new section into the existing one.
                    // Each rule already carries its own mode.
                    let existing = e.get_mut();
                    existing.allow_rules.extend(section.allow_rules);
                    existing.deny_rules.extend(section.deny_rules);
                    existing.allowed_values.extend(section.allowed_values);
                    // Keep the strictest section-level mode as the default.
                    if mode_severity(section.mode) > mode_severity(existing.mode) {
                        existing.mode = section.mode;
                    }
                }
            }
        }
    }

    Ok(CompiledPolicy {
        version: policy.version,
        sections,
    })
}

/// Numeric severity for enforcement modes (higher = stricter).
fn mode_severity(mode: EnforcementMode) -> u8 {
    match mode {
        EnforcementMode::Noop => 0,
        EnforcementMode::Log => 1,
        EnforcementMode::Warn => 2,
        EnforcementMode::Review => 3,
        EnforcementMode::Block => 4,
    }
}

/// Pattern type determined by auto-classification of network patterns.
enum PatternType {
    /// Contains `/` — matches against full URL and schemeless URL.
    Url,
    /// Contains `:` (host:port format) — matches against endpoint strings.
    Endpoint,
    /// Bare hostname pattern — matches against domain names.
    Domain,
}

/// Classify a network pattern into URL, endpoint, or domain.
fn classify_network_pattern(pattern: &str) -> PatternType {
    if pattern.contains('/') {
        PatternType::Url
    } else if pattern.contains(':') {
        PatternType::Endpoint
    } else {
        PatternType::Domain
    }
}

/// Compute the section-level enforcement mode from which keys have rules.
/// This is the fallback mode for implicit denials (unmatched patterns).
fn compute_section_mode(ad: &AllowDenySection) -> EnforcementMode {
    if !ad.deny.is_empty() {
        return EnforcementMode::Block;
    }
    if !ad.review.is_empty() {
        return EnforcementMode::Review;
    }
    if !ad.warn.is_empty() {
        return EnforcementMode::Warn;
    }
    if !ad.log.is_empty() {
        return EnforcementMode::Log;
    }
    if !ad.noop.is_empty() {
        return EnforcementMode::Noop;
    }
    // Default: Block (unmatched patterns are blocked)
    EnforcementMode::Block
}

fn compile_section(name: &str, value: &SectionValue) -> Result<Vec<(SectionKey, CompiledSection)>> {
    let parsed = parse_section_name(name);

    // Special handling for "network" section — expands into multiple categories
    if parsed.category == "network" {
        return compile_network_section(value);
    }

    // Determine runtime
    let runtime = parsed.runtime.as_deref().and_then(Runtime::parse);

    // Determine category.
    // Bare runtime names (python, nodejs) produce category "functions" from the parser,
    // which maps to Category::Functions directly (not via Category::parse).
    let category = if runtime.is_some() && parsed.category == "functions" {
        Category::Functions
    } else {
        Category::parse(&parsed.category)
            .ok_or_else(|| PolicyError::Validation(crate::error::ValidationError::UnknownSection(name.to_string())))?
    };

    let key = SectionKey::new(runtime, category);
    let case_insensitive = category.is_case_insensitive();

    let section = match value {
        SectionValue::AllowDeny(ad) => compile_allow_deny_section(ad, case_insensitive, category)?,
        SectionValue::List(list) => {
            // Convert string list to implicit allow rules
            let mode = EnforcementMode::default();
            let mut section = CompiledSection {
                mode,
                ..Default::default()
            };
            for pattern_str in list {
                let rule = Rule::Simple(pattern_str.clone());
                section.allow_rules.push(compile_rule(&rule, case_insensitive, category, mode)?);
            }
            section
        }
        SectionValue::RuleList(rules) => {
            // Direct list of rules = implicit allow (new format)
            let mode = EnforcementMode::default();
            let mut section = CompiledSection {
                mode,
                ..Default::default()
            };
            for rule in rules {
                section.allow_rules.push(compile_rule(rule, case_insensitive, category, mode)?);
            }
            section
        }
    };

    Ok(vec![(key, section)])
}

/// Compile a `network` section into multiple compiled sections (Http, Domains, Endpoints, Protocols).
///
/// Patterns are auto-classified:
/// - Contains `/` → URL pattern (Category::Http)
/// - Contains `:` → endpoint pattern (Category::Endpoints)
/// - Otherwise → domain pattern (Category::Domains)
///
/// The `protocols` field becomes a Protocols section with allowed_values.
fn compile_network_section(
    value: &SectionValue,
) -> Result<Vec<(SectionKey, CompiledSection)>> {
    let ad = match value {
        SectionValue::AllowDeny(ad) => ad,
        _ => {
            return Err(PolicyError::Validation(
                crate::error::ValidationError::UnknownSection(
                    "network section must use allow/deny format".to_string(),
                ),
            ));
        }
    };

    let mut url_allow = vec![];
    let mut url_deny = vec![];
    let mut domain_allow = vec![];
    let mut domain_deny = vec![];
    let mut endpoint_allow = vec![];
    let mut endpoint_deny = vec![];

    // Allow rules
    for rule in &ad.allow {
        let pattern_str = rule_pattern(rule);
        let mode = EnforcementMode::Block; // mode on allow rules is not used for matching
        match classify_network_pattern(pattern_str) {
            PatternType::Url => url_allow.push(compile_rule(rule, false, Category::Http, mode)?),
            PatternType::Domain => domain_allow.push(compile_rule(rule, true, Category::Domains, mode)?),
            PatternType::Endpoint => endpoint_allow.push(compile_rule(rule, false, Category::Endpoints, mode)?),
        }
    }

    // Deny-side rules: each key's rules get their respective mode
    let deny_keys: &[(&Vec<Rule>, EnforcementMode)] = &[
        (&ad.deny, EnforcementMode::Block),
        (&ad.review, EnforcementMode::Review),
        (&ad.warn, EnforcementMode::Warn),
        (&ad.log, EnforcementMode::Log),
        (&ad.noop, EnforcementMode::Noop),
    ];
    for (rules, mode) in deny_keys {
        for rule in *rules {
            let pattern_str = rule_pattern(rule);
            match classify_network_pattern(pattern_str) {
                PatternType::Url => url_deny.push(compile_rule(rule, false, Category::Http, *mode)?),
                PatternType::Domain => domain_deny.push(compile_rule(rule, true, Category::Domains, *mode)?),
                PatternType::Endpoint => endpoint_deny.push(compile_rule(rule, false, Category::Endpoints, *mode)?),
            }
        }
    }

    let mut results = vec![];

    if !url_allow.is_empty() || !url_deny.is_empty() {
        let mode = strictest_mode_of_rules(&url_deny, ad);
        results.push((
            SectionKey::global(Category::Http),
            CompiledSection {
                mode,
                allow_rules: url_allow,
                deny_rules: url_deny,
                ..Default::default()
            },
        ));
    }
    if !domain_allow.is_empty() || !domain_deny.is_empty() {
        let mode = strictest_mode_of_rules(&domain_deny, ad);
        results.push((
            SectionKey::global(Category::Domains),
            CompiledSection {
                mode,
                allow_rules: domain_allow,
                deny_rules: domain_deny,
                ..Default::default()
            },
        ));
    }
    if !endpoint_allow.is_empty() || !endpoint_deny.is_empty() {
        let mode = strictest_mode_of_rules(&endpoint_deny, ad);
        results.push((
            SectionKey::global(Category::Endpoints),
            CompiledSection {
                mode,
                allow_rules: endpoint_allow,
                deny_rules: endpoint_deny,
                ..Default::default()
            },
        ));
    }

    // Protocols from the special field
    if !ad.protocols.is_empty() {
        let mode = compute_section_mode(ad);
        results.push((
            SectionKey::global(Category::Protocols),
            CompiledSection {
                mode,
                allowed_values: ad.protocols.clone(),
                ..Default::default()
            },
        ));
    }

    Ok(results)
}

/// Compute the strictest mode among deny rules assigned to a sub-section,
/// falling back to `compute_section_mode` if there are no rules.
fn strictest_mode_of_rules(deny_rules: &[CompiledRule], ad: &AllowDenySection) -> EnforcementMode {
    let mut strictest = None;
    for rule in deny_rules {
        let sev = mode_severity(rule.mode);
        if strictest.is_none_or(|s| sev > s) {
            strictest = Some(sev);
        }
    }
    match strictest {
        Some(s) => {
            // Map severity back to mode
            if s >= mode_severity(EnforcementMode::Block) { EnforcementMode::Block }
            else if s >= mode_severity(EnforcementMode::Review) { EnforcementMode::Review }
            else if s >= mode_severity(EnforcementMode::Warn) { EnforcementMode::Warn }
            else if s >= mode_severity(EnforcementMode::Log) { EnforcementMode::Log }
            else { EnforcementMode::Noop }
        }
        None => compute_section_mode(ad),
    }
}

/// Extract the pattern string from a rule.
fn rule_pattern(rule: &Rule) -> &str {
    match rule {
        Rule::Simple(s) => s,
        Rule::WithConstraints { pattern, .. } => pattern,
    }
}

fn compile_allow_deny_section(
    ad: &AllowDenySection,
    case_insensitive: bool,
    category: Category,
) -> Result<CompiledSection> {
    let mode = compute_section_mode(ad);
    let mut section = CompiledSection {
        mode,
        ..Default::default()
    };

    // Allow rules
    for rule in &ad.allow {
        section.allow_rules.push(compile_rule(rule, case_insensitive, category, mode)?);
    }

    // Deny-side rules, each with their key's mode
    for rule in &ad.deny {
        section.deny_rules.push(compile_rule(rule, case_insensitive, category, EnforcementMode::Block)?);
    }
    for rule in &ad.review {
        section.deny_rules.push(compile_rule(rule, case_insensitive, category, EnforcementMode::Review)?);
    }
    for rule in &ad.warn {
        section.deny_rules.push(compile_rule(rule, case_insensitive, category, EnforcementMode::Warn)?);
    }
    for rule in &ad.log {
        section.deny_rules.push(compile_rule(rule, case_insensitive, category, EnforcementMode::Log)?);
    }
    for rule in &ad.noop {
        section.deny_rules.push(compile_rule(rule, case_insensitive, category, EnforcementMode::Noop)?);
    }

    Ok(section)
}

fn compile_rule(rule: &Rule, case_insensitive: bool, category: Category, mode: EnforcementMode) -> Result<CompiledRule> {
    let is_url_category = category == Category::Http;

    match rule {
        Rule::Simple(pattern) => {
            let compiled = if is_url_category {
                compile_url_pattern(pattern)?
            } else if case_insensitive {
                compile_pattern_case_insensitive(pattern)?
            } else {
                compile_pattern(pattern)?
            };
            Ok(CompiledRule::new(compiled, mode))
        }
        Rule::WithConstraints {
            pattern,
            constraints,
        } => {
            let compiled_pattern = if is_url_category {
                compile_url_pattern(pattern)?
            } else if case_insensitive {
                compile_pattern_case_insensitive(pattern)?
            } else {
                compile_pattern(pattern)?
            };

            let compiled_constraints = compile_constraints(constraints, category)?;

            Ok(CompiledRule::with_constraints(
                compiled_pattern,
                compiled_constraints,
                mode,
            ))
        }
    }
}

fn compile_constraints(constraints: &[String], category: Category) -> Result<Vec<Constraint>> {
    let mut result = Vec::new();

    // For files and envvars categories, check if constraints are operations
    if category == Category::Files || category == Category::EnvVars {
        let operations: Vec<Operation> = constraints
            .iter()
            .filter_map(|c| Operation::parse(c))
            .collect();

        if !operations.is_empty() {
            // Create a dummy pattern that always matches for operation constraints
            let dummy_pattern = CompiledPattern::Exact(String::new());
            result.push(Constraint {
                kind: ConstraintKind::Operation(operations),
                pattern: dummy_pattern,
            });
            return Ok(result);
        }
    }

    // Otherwise, constraints are argument patterns
    for constraint_str in constraints {
        let pattern = compile_pattern(constraint_str)?;
        result.push(Constraint {
            kind: ConstraintKind::AnyArgument,
            pattern,
        });
    }

    Ok(result)
}

/// Parse and compile a YAML policy string.
pub fn compile_policy_yaml(yaml: &str) -> Result<CompiledPolicy> {
    use crate::parser::parse_policy;
    use crate::validate::validate_policy;

    let parsed = parse_policy(yaml)?;
    validate_policy(&parsed)?;
    compile_policy(&parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_simple_policy() {
        let yaml = r#"
version: 1
python:
  deny:
    - eval
"#;
        let policy = compile_policy_yaml(yaml).unwrap();
        assert_eq!(policy.version, 1);

        let key = SectionKey::for_runtime(Runtime::Python, Category::Functions);
        let section = policy.get_section(&key).unwrap();
        assert_eq!(section.deny_rules.len(), 1);
        assert!(section.deny_rules[0].pattern.matches("eval"));
    }

    #[test]
    fn test_compile_glob_pattern() {
        let yaml = r#"
version: 1
python:
  allow:
    - "json.*"
"#;
        let policy = compile_policy_yaml(yaml).unwrap();
        let key = SectionKey::for_runtime(Runtime::Python, Category::Functions);
        let section = policy.get_section(&key).unwrap();

        assert!(section.allow_rules[0].pattern.matches("json.loads"));
        assert!(section.allow_rules[0].pattern.matches("json.dumps"));
        assert!(!section.allow_rules[0].pattern.matches("pickle.loads"));
    }

    #[test]
    fn test_compile_with_mode() {
        let yaml = r#"
version: 1
files:
  log:
    - "/etc/*"
"#;
        let policy = compile_policy_yaml(yaml).unwrap();
        let key = SectionKey::global(Category::Files);
        let section = policy.get_section(&key).unwrap();

        assert_eq!(section.mode, EnforcementMode::Log);
    }

    #[test]
    fn test_compile_with_constraints() {
        let yaml = r#"
version: 1
python:
  allow:
    - "requests.*": ["https://api.example.com/*"]
"#;
        let policy = compile_policy_yaml(yaml).unwrap();
        let key = SectionKey::for_runtime(Runtime::Python, Category::Functions);
        let section = policy.get_section(&key).unwrap();

        assert_eq!(section.allow_rules.len(), 1);
        assert!(!section.allow_rules[0].constraints.is_empty());
    }

    #[test]
    fn test_compile_file_operations() {
        let yaml = r#"
version: 1
files:
  allow:
    - "/tmp/*": [read, edit]
"#;
        let policy = compile_policy_yaml(yaml).unwrap();
        let key = SectionKey::global(Category::Files);
        let section = policy.get_section(&key).unwrap();

        let rule = &section.allow_rules[0];
        assert_eq!(rule.constraints.len(), 1);
        if let ConstraintKind::Operation(ops) = &rule.constraints[0].kind {
            assert!(ops.contains(&Operation::Read));
            assert!(ops.contains(&Operation::Edit));
        } else {
            panic!("Expected Operation constraint");
        }
    }

    #[test]
    fn test_compile_network_domains_case_insensitive() {
        let yaml = r#"
version: 1
network:
  deny:
    - "*.ONION"
"#;
        let policy = compile_policy_yaml(yaml).unwrap();
        let key = SectionKey::global(Category::Domains);
        let section = policy.get_section(&key).unwrap();

        // Should match case-insensitively
        assert!(section.deny_rules[0].pattern.matches("test.onion"));
        assert!(section.deny_rules[0].pattern.matches("TEST.ONION"));
    }

    #[test]
    fn test_compile_network_protocols() {
        let yaml = r#"
version: 1
network:
  protocols: [tcp, https]
"#;
        let policy = compile_policy_yaml(yaml).unwrap();
        let key = SectionKey::global(Category::Protocols);
        let section = policy.get_section(&key).unwrap();

        assert_eq!(section.allowed_values, vec!["tcp", "https"]);
    }

    #[test]
    fn test_compile_direct_list_as_rules() {
        let yaml = r#"
version: 1
nodejs:
  - "axios.*": ["https://api.example.com/*"]
  - JSON.parse
  - JSON.stringify
"#;
        let policy = compile_policy_yaml(yaml).unwrap();
        let key = SectionKey::for_runtime(Runtime::Node, Category::Functions);
        let section = policy.get_section(&key).unwrap();

        // Should have 3 allow rules
        assert_eq!(section.allow_rules.len(), 3);
        assert!(section.deny_rules.is_empty());

        // First rule has constraints
        assert!(section.allow_rules[0].pattern.matches("axios.get"));
        assert!(!section.allow_rules[0].constraints.is_empty());

        // Other rules are simple patterns
        assert!(section.allow_rules[1].pattern.matches("JSON.parse"));
        assert!(section.allow_rules[2].pattern.matches("JSON.stringify"));
    }

    #[test]
    fn test_compile_string_list_as_rules_for_functions() {
        // Pure string list for functions should be treated as rules, not allowed_values
        let yaml = r#"
version: 1
nodejs:
  - JSON.parse
  - JSON.stringify
"#;
        let policy = compile_policy_yaml(yaml).unwrap();
        let key = SectionKey::for_runtime(Runtime::Node, Category::Functions);
        let section = policy.get_section(&key).unwrap();

        // Should be allow rules, not allowed_values
        assert_eq!(section.allow_rules.len(), 2);
        assert!(section.allowed_values.is_empty());
        assert!(section.allow_rules[0].pattern.matches("JSON.parse"));
    }

    #[test]
    fn test_compile_network_auto_classification() {
        let yaml = r#"
version: 1
network:
  allow:
    - "huggingface.co/**"
    - "*.example.com"
    - "127.0.0.1:*"
  deny:
    - "*.evil.com/**"
    - "*.onion"
    - "*:22"
  protocols: [https, http]
"#;
        let policy = compile_policy_yaml(yaml).unwrap();

        // URL patterns
        let http_key = SectionKey::global(Category::Http);
        let http = policy.get_section(&http_key).unwrap();
        assert_eq!(http.allow_rules.len(), 1); // huggingface.co/**
        assert_eq!(http.deny_rules.len(), 1);  // *.evil.com/**

        // Domain patterns
        let domain_key = SectionKey::global(Category::Domains);
        let domains = policy.get_section(&domain_key).unwrap();
        assert_eq!(domains.allow_rules.len(), 1); // *.example.com
        assert_eq!(domains.deny_rules.len(), 1);  // *.onion

        // Endpoint patterns
        let ep_key = SectionKey::global(Category::Endpoints);
        let eps = policy.get_section(&ep_key).unwrap();
        assert_eq!(eps.allow_rules.len(), 1); // 127.0.0.1:*
        assert_eq!(eps.deny_rules.len(), 1);  // *:22

        // Protocols
        let proto_key = SectionKey::global(Category::Protocols);
        let protos = policy.get_section(&proto_key).unwrap();
        assert_eq!(protos.allowed_values, vec!["https", "http"]);
    }

    #[test]
    fn test_compile_network_with_warn_key() {
        // network: with allow, deny, and warn keys
        let yaml = r#"
version: 1
network:
  allow:
    - "huggingface.co/**"
  warn:
    - "*.onion"
  protocols: [https, http]
"#;
        let policy = compile_policy_yaml(yaml).unwrap();

        // URL allow from allow key
        let http_key = SectionKey::global(Category::Http);
        let http = policy.get_section(&http_key).unwrap();
        assert_eq!(http.allow_rules.len(), 1);

        // Domain deny from warn key
        let domain_key = SectionKey::global(Category::Domains);
        let domains = policy.get_section(&domain_key).unwrap();
        assert_eq!(domains.deny_rules.len(), 1);
        assert_eq!(domains.deny_rules[0].mode, EnforcementMode::Warn);
    }
}
