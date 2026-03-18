use std::collections::HashMap;

use super::compiled::{
    Category, CompiledNetworkRule, CompiledPolicy, CompiledRule, CompiledSection, Constraint,
    ConstraintKind, EnforcementMode, Runtime, SectionKey,
};
use super::error::{PolicyError, Result};
use super::parser::{parse_section_name, AllowDenySection, PolicyFile, Rule, SectionValue};
use super::pattern::{compile_pattern, compile_pattern_case_insensitive, compile_url_pattern};

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
                    existing.hide_rules.extend(section.hide_rules);
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
        EnforcementMode::Hide => 5,
    }
}

/// Compute the section-level enforcement mode from which keys have rules.
/// This is the fallback mode for implicit denials (unmatched patterns).
fn compute_section_mode(section: &AllowDenySection) -> EnforcementMode {
    if !section.deny.is_empty() {
        return EnforcementMode::Block;
    }
    if !section.review.is_empty() {
        return EnforcementMode::Review;
    }
    if !section.warn.is_empty() {
        return EnforcementMode::Warn;
    }
    if !section.log.is_empty() {
        return EnforcementMode::Log;
    }
    if !section.noop.is_empty() {
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
        Category::parse(&parsed.category).ok_or_else(|| {
            PolicyError::Validation(super::error::ValidationError::UnknownSection(
                name.to_string(),
            ))
        })?
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
                section
                    .allow_rules
                    .push(compile_rule(&rule, case_insensitive, category, mode)?);
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
                section
                    .allow_rules
                    .push(compile_rule(rule, case_insensitive, category, mode)?);
            }
            section
        }
    };

    Ok(vec![(key, section)])
}

/// Compile a `network` section into a unified Network section + optional Protocols section.
///
/// Every pattern is compiled for all three match modes (URL, domain, endpoint)
/// so evaluation can try each pattern against all available event representations
/// in a single pass — no classification heuristic needed.
///
/// The `protocols` field becomes a separate Protocols section with allowed_values.
fn compile_network_section(value: &SectionValue) -> Result<Vec<(SectionKey, CompiledSection)>> {
    let section = match value {
        SectionValue::AllowDeny(s) => s,
        _ => {
            return Err(PolicyError::Validation(
                super::error::ValidationError::UnknownSection(
                    "network section must use allow/deny format".to_string(),
                ),
            ));
        }
    };

    let mut network_allow = vec![];
    let mut network_deny = vec![];

    // Allow rules — compile each for all representations
    for rule in &section.allow {
        let pattern_str = rule_pattern(rule);
        network_allow.push(compile_network_rule(pattern_str, EnforcementMode::Block)?);
    }

    // Deny-side rules: each key's rules get their respective mode
    let deny_keys: &[(&Vec<Rule>, EnforcementMode)] = &[
        (&section.deny, EnforcementMode::Block),
        (&section.review, EnforcementMode::Review),
        (&section.warn, EnforcementMode::Warn),
        (&section.log, EnforcementMode::Log),
        (&section.noop, EnforcementMode::Noop),
        (&section.hide, EnforcementMode::Hide),
    ];
    for (rules, mode) in deny_keys {
        for rule in *rules {
            let pattern_str = rule_pattern(rule);
            network_deny.push(compile_network_rule(pattern_str, *mode)?);
        }
    }

    let mut results = vec![];

    if !network_allow.is_empty() || !network_deny.is_empty() {
        let mode = strictest_mode_of_network_rules(&network_deny, section);
        results.push((
            SectionKey::global(Category::Network),
            CompiledSection {
                mode,
                network_allow_rules: network_allow,
                network_deny_rules: network_deny,
                ..Default::default()
            },
        ));
    }

    // Protocols from the special field
    if !section.protocols.is_empty() {
        let mode = compute_section_mode(section);
        results.push((
            SectionKey::global(Category::Protocols),
            CompiledSection {
                mode,
                allowed_values: section.protocols.clone(),
                ..Default::default()
            },
        ));
    }

    Ok(results)
}

/// Compile a network pattern into a `CompiledNetworkRule` with three matchers.
fn compile_network_rule(pattern: &str, mode: EnforcementMode) -> Result<CompiledNetworkRule> {
    Ok(CompiledNetworkRule {
        url_pattern: compile_url_pattern(pattern)?,
        domain_pattern: compile_pattern_case_insensitive(pattern)?,
        endpoint_pattern: compile_pattern(pattern)?,
        mode,
    })
}

/// Compute the strictest mode among network deny rules,
/// falling back to `compute_section_mode` if there are no rules.
fn strictest_mode_of_network_rules(
    deny_rules: &[CompiledNetworkRule],
    section: &AllowDenySection,
) -> EnforcementMode {
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
            if s >= mode_severity(EnforcementMode::Block) {
                EnforcementMode::Block
            } else if s >= mode_severity(EnforcementMode::Review) {
                EnforcementMode::Review
            } else if s >= mode_severity(EnforcementMode::Warn) {
                EnforcementMode::Warn
            } else if s >= mode_severity(EnforcementMode::Log) {
                EnforcementMode::Log
            } else {
                EnforcementMode::Noop
            }
        }
        None => compute_section_mode(section),
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
    section: &AllowDenySection,
    case_insensitive: bool,
    category: Category,
) -> Result<CompiledSection> {
    let mode = compute_section_mode(section);
    let mut compiled = CompiledSection {
        mode,
        ..Default::default()
    };

    // Allow rules
    for rule in &section.allow {
        compiled
            .allow_rules
            .push(compile_rule(rule, case_insensitive, category, mode)?);
    }

    // Deny-side rules, each with their key's mode
    let deny_keys: &[(&Vec<Rule>, EnforcementMode)] = &[
        (&section.deny, EnforcementMode::Block),
        (&section.review, EnforcementMode::Review),
        (&section.warn, EnforcementMode::Warn),
        (&section.log, EnforcementMode::Log),
        (&section.noop, EnforcementMode::Noop),
    ];
    for (rules, deny_mode) in deny_keys {
        for rule in *rules {
            compiled
                .deny_rules
                .push(compile_rule(rule, case_insensitive, category, *deny_mode)?);
        }
    }

    // Hide rules — compiled separately, checked before allow/deny
    for rule in &section.hide {
        compiled.hide_rules.push(compile_rule(
            rule,
            case_insensitive,
            category,
            EnforcementMode::Hide,
        )?);
    }

    Ok(compiled)
}

fn compile_rule(
    rule: &Rule,
    case_insensitive: bool,
    category: Category,
    mode: EnforcementMode,
) -> Result<CompiledRule> {
    match rule {
        Rule::Simple(pattern) => {
            let compiled = if case_insensitive {
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
            let compiled_pattern = if case_insensitive {
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

fn compile_constraints(constraints: &[String], _category: Category) -> Result<Vec<Constraint>> {
    let mut result = Vec::new();

    // Constraints are argument patterns
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
    use super::parser::parse_policy;
    use super::validate::validate_policy;

    let parsed = parse_policy(yaml)?;
    validate_policy(&parsed)?;
    compile_policy(&parsed)
}

/// Parse and compile a YAML policy string, resolving `includes:` directives.
///
/// The `resolver` function maps include names (e.g. "base") to YAML strings.
/// Returns `UnknownInclude` if any included name is not resolved.
pub fn compile_policy_yaml_with_includes(
    yaml: &str,
    resolver: &dyn Fn(&str) -> Option<String>,
) -> Result<CompiledPolicy> {
    use super::parser::parse_policy;
    use super::validate::validate_policy;

    let mut parsed = parse_policy(yaml)?;
    resolve_includes(&mut parsed, resolver)?;
    validate_policy(&parsed)?;
    compile_policy(&parsed)
}

/// Resolve `includes:` directives by merging sections from included policies.
///
/// For each included policy name:
/// 1. Load and parse via the resolver function.
/// 2. Recursively resolve its own includes.
/// 3. Merge its sections into the child: sections absent in the child are copied;
///    sections present in both get the included rules appended after the child's
///    (child rules listed first = higher priority via specificity).
pub fn resolve_includes(
    policy: &mut PolicyFile,
    resolver: &dyn Fn(&str) -> Option<String>,
) -> Result<()> {
    if policy.includes.is_empty() {
        return Ok(());
    }

    let include_names = std::mem::take(&mut policy.includes);

    for name in &include_names {
        let included_yaml = resolver(name).ok_or_else(|| {
            PolicyError::Validation(super::error::ValidationError::UnknownInclude(name.clone()))
        })?;
        let mut included = super::parser::parse_policy(&included_yaml)?;

        // Recursively resolve the included policy's own includes
        resolve_includes(&mut included, resolver)?;

        // Merge: for each section in the included policy
        for (section_name, included_value) in included.sections {
            match policy.sections.entry(section_name) {
                std::collections::hash_map::Entry::Vacant(e) => {
                    // Child doesn't have this section — copy from included
                    e.insert(included_value);
                }
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    // Child has this section — append included rules after child's
                    merge_section_values(e.get_mut(), included_value);
                }
            }
        }
    }

    Ok(())
}

/// Merge an included section's values into an existing child section.
///
/// Child rules come first (higher priority via specificity); included rules
/// are appended after, but only if their pattern doesn't already exist in the
/// child at any disposition. This prevents a base deny from overriding a child
/// warn for the same pattern.
///
/// Only AllowDeny sections are merged field-by-field; for other section types
/// the child's value takes precedence entirely.
fn merge_section_values(child: &mut SectionValue, included: SectionValue) {
    match (child, included) {
        (SectionValue::AllowDeny(child_ad), SectionValue::AllowDeny(included_ad)) => {
            // Collect all patterns the child defines at any disposition.
            let child_patterns: std::collections::HashSet<String> = child_ad
                .all_rules()
                .map(|r| rule_pattern(r).to_string())
                .collect();

            let not_in_child = |r: &Rule| !child_patterns.contains(rule_pattern(r));

            child_ad
                .allow
                .extend(included_ad.allow.into_iter().filter(|r| not_in_child(r)));
            child_ad
                .deny
                .extend(included_ad.deny.into_iter().filter(|r| not_in_child(r)));
            child_ad
                .warn
                .extend(included_ad.warn.into_iter().filter(|r| not_in_child(r)));
            child_ad
                .log
                .extend(included_ad.log.into_iter().filter(|r| not_in_child(r)));
            child_ad
                .review
                .extend(included_ad.review.into_iter().filter(|r| not_in_child(r)));
            child_ad
                .noop
                .extend(included_ad.noop.into_iter().filter(|r| not_in_child(r)));
            child_ad
                .hide
                .extend(included_ad.hide.into_iter().filter(|r| not_in_child(r)));
            if child_ad.protocols.is_empty() && !included_ad.protocols.is_empty() {
                child_ad.protocols = included_ad.protocols;
            }
        }
        // For List/RuleList, child takes precedence entirely
        _ => {}
    }
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
    fn test_compile_file_constraints_as_argument_patterns() {
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
        // Constraints are now compiled as AnyArgument patterns
        assert_eq!(rule.constraints.len(), 2);
        assert!(matches!(
            rule.constraints[0].kind,
            ConstraintKind::AnyArgument
        ));
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
        let key = SectionKey::global(Category::Network);
        let section = policy.get_section(&key).unwrap();

        // Domain matcher should match case-insensitively
        assert!(section.network_deny_rules[0]
            .domain_pattern
            .matches("test.onion"));
        assert!(section.network_deny_rules[0]
            .domain_pattern
            .matches("TEST.ONION"));
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
    fn test_compile_network_unified_rules() {
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

        // All network patterns in a single unified section
        let net_key = SectionKey::global(Category::Network);
        let net = policy.get_section(&net_key).unwrap();
        assert_eq!(net.network_allow_rules.len(), 3);
        assert_eq!(net.network_deny_rules.len(), 3);

        // Each rule has all 3 matchers compiled
        let allow0 = &net.network_allow_rules[0]; // huggingface.co/**
        assert!(allow0.url_pattern.matches("huggingface.co/model"));
        assert!(!allow0.url_pattern.matches("evil.com/model"));

        let deny2 = &net.network_deny_rules[2]; // *:22
        assert!(deny2.endpoint_pattern.matches("example.com:22"));

        // Protocols still separate
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

        let net_key = SectionKey::global(Category::Network);
        let net = policy.get_section(&net_key).unwrap();

        // Allow from allow key
        assert_eq!(net.network_allow_rules.len(), 1);

        // Deny from warn key
        assert_eq!(net.network_deny_rules.len(), 1);
        assert_eq!(net.network_deny_rules[0].mode, EnforcementMode::Warn);
    }
}
