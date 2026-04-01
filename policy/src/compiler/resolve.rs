//! Resolve a CompiledPolicy into a Policy (the final, evaluator-ready form).
//!
//! - Simple sections (functions, commands, files, envvars): rules sorted by
//!   specificity, first match = correct answer.
//! - Network section: rules preserved with all 3 matchers (URL, domain, endpoint)
//!   for runtime multi-representation matching.

use super::compiled::{
    Category, CompiledNetworkRule, CompiledPolicy, CompiledSection, EnforcementMode, Runtime,
    SectionKey,
};
use crate::resolved::{Decision, NetworkRule, NetworkRuleSet, Policy, Rule, RuleSet};
use malwi_protocol::event::HookType;

/// Resolve a compiled policy into the final evaluator-ready form.
pub fn prioritize_and_resolve(compiled: &CompiledPolicy) -> Policy {
    let mut functions = RuleSet::empty();
    let mut commands = RuleSet::empty();
    let mut files = RuleSet::empty();
    let mut envvars = RuleSet::empty();
    let mut network = NetworkRuleSet::empty();

    for (key, section) in compiled.iter_sections() {
        if section.mode == EnforcementMode::Noop || section.is_empty() {
            continue;
        }

        match key.category {
            Category::Functions => {
                merge_into_ruleset(&mut functions, section, "functions", key);
            }
            Category::Execution => {
                merge_into_ruleset(&mut commands, section, "commands", key);
            }
            Category::Files => {
                merge_into_ruleset(&mut files, section, "files", key);
            }
            Category::EnvVars => {
                merge_into_ruleset(&mut envvars, section, "envvars", key);
            }
            Category::Network => {
                build_network_rules(&mut network, section);
            }
            Category::Protocols => {
                network
                    .allowed_protocols
                    .extend(section.allowed_values.iter().cloned());
            }
        }
    }

    // Sort simple sections by specificity
    sort_ruleset(&mut functions);
    sort_ruleset(&mut commands);
    sort_ruleset(&mut files);
    sort_ruleset(&mut envvars);

    Policy {
        functions,
        commands,
        files,
        envvars,
        network,
    }
}

/// Map a CompiledRule's enforcement mode to a Decision.
fn mode_to_decision(mode: EnforcementMode, section_name: &str) -> Decision {
    match mode {
        EnforcementMode::Block => Decision::Block {
            section: section_name.into(),
        },
        EnforcementMode::Review | EnforcementMode::Warn => Decision::Warn {
            section: section_name.into(),
        },
        EnforcementMode::Log => Decision::Trace,
        EnforcementMode::Noop => Decision::Suppress,
        EnforcementMode::Hide => Decision::Hide,
    }
}

/// Map a policy Runtime to the corresponding HookType for runtime filtering.
fn runtime_to_hook_type(runtime: Option<Runtime>) -> Option<HookType> {
    match runtime {
        None => None, // global section, no filter
        Some(Runtime::Python) => Some(HookType::Python),
        Some(Runtime::Node) => Some(HookType::Nodejs),
    }
}

/// Merge a CompiledSection's rules into a RuleSet (for simple sections).
fn merge_into_ruleset(
    ruleset: &mut RuleSet,
    section: &CompiledSection,
    section_name: &str,
    key: &SectionKey,
) {
    let runtime_filter = runtime_to_hook_type(key.runtime);

    // Hide rules
    for rule in &section.hide_rules {
        ruleset.rules.push(Rule {
            pattern: rule.pattern.original().to_string(),
            decision: Decision::Hide,
            label: rule.pattern.original().to_string(),
            runtime_filter: runtime_filter.clone(),
        });
    }

    // Deny rules (with per-rule enforcement mode)
    for rule in &section.deny_rules {
        ruleset.rules.push(Rule {
            pattern: rule.pattern.original().to_string(),
            decision: mode_to_decision(rule.mode, section_name),
            label: rule.pattern.original().to_string(),
            runtime_filter: runtime_filter.clone(),
        });
    }

    // Allow rules — for runtime-scoped functions sections, skip allow rules
    // to avoid cross-runtime implicit deny (e.g., nodejs allow "dns.lookup"
    // shouldn't implicitly deny native "open").
    let include_allow = key.runtime.is_none();
    if include_allow {
        for rule in &section.allow_rules {
            ruleset.rules.push(Rule {
                pattern: rule.pattern.original().to_string(),
                decision: Decision::Suppress,
                label: rule.pattern.original().to_string(),
                runtime_filter: None,
            });
        }

        // When allow rules exist, implicit deny for unmatched
        if section.has_allow_rules() {
            ruleset.default_decision = Decision::Block {
                section: section_name.into(),
            };
        }
    }
}

/// Sort a RuleSet by specificity (highest first, block before allow on tie).
fn sort_ruleset(ruleset: &mut RuleSet) {
    use crate::eval::pattern_score;

    // Compute scores
    let mut scored: Vec<(usize, usize, u8)> = ruleset
        .rules
        .iter()
        .enumerate()
        .map(|(i, rule)| {
            let score = if matches!(rule.decision, Decision::Hide) {
                usize::MAX // hide always first
            } else {
                pattern_score(&rule.pattern)
            };
            let group = match rule.decision {
                Decision::Hide => 0,
                Decision::Block { .. } => 1,
                Decision::Warn { .. } => 2,
                Decision::Trace => 3,
                Decision::Suppress => 4,
            };
            (i, score, group)
        })
        .collect();

    // Sort: highest score first, block-before-allow on tie
    scored.sort_by(|a, b| b.1.cmp(&a.1).then(a.2.cmp(&b.2)));

    // Reorder rules
    let old_rules = std::mem::take(&mut ruleset.rules);
    ruleset.rules = scored
        .into_iter()
        .map(|(i, _, _)| old_rules[i].clone())
        .collect();
}

/// Build NetworkRuleSet from a compiled Network section.
fn build_network_rules(network: &mut NetworkRuleSet, section: &CompiledSection) {
    // Allow rules
    for rule in &section.network_allow_rules {
        network
            .allow_rules
            .push(compiled_net_to_rule(rule, Decision::Suppress));
    }
    if !section.network_allow_rules.is_empty() {
        network.has_allow_rules = true;
    }

    // Deny rules (with per-rule enforcement mode)
    for rule in &section.network_deny_rules {
        let decision = mode_to_decision(rule.mode, "network");
        match decision {
            Decision::Hide => {
                network
                    .hide_rules
                    .push(compiled_net_to_rule(rule, decision));
            }
            _ => {
                network
                    .deny_rules
                    .push(compiled_net_to_rule(rule, decision));
            }
        }
    }

    // Hide rules from regular (non-network) hide_rules
    for rule in &section.hide_rules {
        network.hide_rules.push(NetworkRule {
            url_pattern: rule.pattern.original().to_string(),
            domain_pattern: rule.pattern.original().to_string(),
            endpoint_pattern: rule.pattern.original().to_string(),
            decision: Decision::Hide,
            label: rule.pattern.original().to_string(),
        });
    }
}

/// Convert a CompiledNetworkRule to a NetworkRule, preserving all 3 matchers.
fn compiled_net_to_rule(rule: &CompiledNetworkRule, decision: Decision) -> NetworkRule {
    NetworkRule {
        url_pattern: rule.url_pattern.original().to_string(),
        domain_pattern: rule.domain_pattern.original().to_string(),
        endpoint_pattern: rule.endpoint_pattern.original().to_string(),
        decision,
        label: rule.url_pattern.original().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::compile::compile_policy_yaml;

    fn resolve_yaml(yaml: &str) -> Policy {
        let compiled = compile_policy_yaml(yaml).unwrap();
        prioritize_and_resolve(&compiled)
    }

    #[test]
    fn test_resolve_simple_deny() {
        let policy = resolve_yaml("version: 1\nsymbols:\n  deny:\n    - eval\n    - dlopen\n");
        assert!(policy.functions.is_active());
        assert_eq!(policy.functions.rules.len(), 2);
        assert!(matches!(
            policy.functions.rules[0].decision,
            Decision::Block { .. }
        ));
    }

    #[test]
    fn test_resolve_allow_deny_sorted_by_specificity() {
        let policy =
            resolve_yaml("version: 1\nsymbols:\n  allow:\n    - \"*\"\n  deny:\n    - eval\n");
        // eval (spec=8) should be before * (spec=0)
        assert!(policy.functions.rules.len() >= 2);
        assert_eq!(policy.functions.rules[0].pattern, "eval");
        assert!(matches!(
            policy.functions.rules[0].decision,
            Decision::Block { .. }
        ));
        // * should be last
        let last = policy.functions.rules.last().unwrap();
        assert_eq!(last.pattern, "*");
        assert!(matches!(last.decision, Decision::Suppress));
    }

    #[test]
    fn test_resolve_implicit_deny_when_allow_exists() {
        let policy = resolve_yaml("version: 1\nsymbols:\n  allow:\n    - \"json.*\"\n");
        assert!(matches!(
            policy.functions.default_decision,
            Decision::Block { .. }
        ));
    }

    #[test]
    fn test_resolve_network_preserves_patterns() {
        let policy = resolve_yaml(
            "version: 1\nnetwork:\n  allow:\n    - \"*.pypi.org\"\n  deny:\n    - \"*\"\n",
        );
        assert!(policy.network.is_active());
        assert_eq!(policy.network.allow_rules.len(), 1);
        assert_eq!(policy.network.deny_rules.len(), 1);
        assert!(policy.network.has_allow_rules);
    }

    #[test]
    fn test_resolve_network_protocols() {
        let policy = resolve_yaml(
            "version: 1\nnetwork:\n  allow:\n    - \"*.example.com\"\n  protocols:\n    - https\n    - http\n",
        );
        assert_eq!(policy.network.allowed_protocols, vec!["https", "http"]);
    }

    #[test]
    fn test_resolve_files_section() {
        let policy =
            resolve_yaml("version: 1\nfiles:\n  deny:\n    - \"*.pem\"\n    - \"~/.ssh/**\"\n");
        assert!(policy.files.is_active());
        assert_eq!(policy.files.rules.len(), 2);
    }

    #[test]
    fn test_resolve_envvars_hide() {
        let policy = resolve_yaml("version: 1\nenvvars:\n  hide:\n    - \"MALWI_*\"\n");
        assert!(policy.envvars.is_active());
        assert!(matches!(policy.envvars.rules[0].decision, Decision::Hide));
    }

    #[test]
    fn test_resolve_warn_mode() {
        let policy = resolve_yaml("version: 1\nsymbols:\n  warn:\n    - dlopen\n");
        assert!(matches!(
            policy.functions.rules[0].decision,
            Decision::Warn { .. }
        ));
    }

    #[test]
    fn test_resolve_commands() {
        let policy = resolve_yaml(
            "version: 1\ncommands:\n  allow:\n    - node\n    - npm\n  deny:\n    - curl\n",
        );
        assert!(policy.commands.is_active());
        // curl (spec=8) before node (spec=8) — tie, block before allow
        let curl = policy
            .commands
            .rules
            .iter()
            .find(|r| r.pattern == "curl")
            .unwrap();
        assert!(matches!(curl.decision, Decision::Block { .. }));
    }

    #[test]
    fn test_resolve_runtime_scoped_log_rule() {
        let policy = resolve_yaml("version: 1\nnodejs:\n  log:\n    - \"dns.lookup\"\n");
        // Should have a runtime-filtered rule
        let dns_rule = policy
            .functions
            .rules
            .iter()
            .find(|r| r.pattern == "dns.lookup")
            .expect("dns.lookup rule should exist");
        assert!(matches!(dns_rule.decision, Decision::Trace));
        assert_eq!(
            dns_rule.runtime_filter,
            Some(malwi_protocol::event::HookType::Nodejs)
        );
    }

    #[test]
    fn test_resolve_default_security_dns_lookup() {
        use crate::templates::DEFAULT_SECURITY_YAML;
        let compiled = compile_policy_yaml(&DEFAULT_SECURITY_YAML).unwrap();
        let policy = prioritize_and_resolve(&compiled);

        // Check dns.lookup rule exists with Nodejs filter
        let dns_rule = policy
            .functions
            .rules
            .iter()
            .find(|r| r.pattern == "dns.lookup");
        assert!(dns_rule.is_some(), "dns.lookup should be in resolved rules");
        let dns_rule = dns_rule.unwrap();
        assert!(
            matches!(dns_rule.decision, Decision::Trace),
            "dns.lookup should be Trace (log mode), got {:?}",
            dns_rule.decision
        );

        // Verify check_event works
        let event = malwi_protocol::event::TraceEvent {
            hook_type: malwi_protocol::event::HookType::Nodejs,
            function: "dns.lookup".into(),
            event_type: malwi_protocol::event::EventType::Enter,
            arguments: vec![malwi_protocol::event::Argument {
                raw_value: 0,
                display: Some("example.com".into()),
            }],
            ..Default::default()
        };
        let outcome = policy.check_event(&event);
        assert!(
            outcome.should_send(),
            "dns.lookup should be displayed, got {:?}",
            outcome
        );
    }

    // ── Convergence tests: old engine vs new evaluator ───────────

    mod convergence {
        use super::*;
        use crate::compiler::engine::PolicyEngine;
        use malwi_protocol::event::{Argument, EventType, HookType, NetworkInfo, TraceEvent};

        fn make_event(hook_type: HookType, function: &str) -> TraceEvent {
            TraceEvent {
                hook_type,
                function: function.into(),
                event_type: EventType::Enter,
                ..Default::default()
            }
        }

        fn make_event_with_args(hook_type: HookType, function: &str, args: &[&str]) -> TraceEvent {
            TraceEvent {
                hook_type,
                function: function.into(),
                event_type: EventType::Enter,
                arguments: args
                    .iter()
                    .map(|s| Argument {
                        raw_value: 0,
                        display: Some(s.to_string()),
                    })
                    .collect(),
                ..Default::default()
            }
        }

        fn make_network_event(function: &str, domain: &str) -> TraceEvent {
            TraceEvent {
                hook_type: HookType::Native,
                function: function.into(),
                event_type: EventType::Enter,
                network_info: Some(NetworkInfo {
                    domain: Some(domain.into()),
                    ..Default::default()
                }),
                ..Default::default()
            }
        }

        /// Assert the new evaluator is at least as strict as the old engine.
        /// "At least as strict" means: if old blocks, new must block.
        /// The new evaluator may also block things the old didn't (it uses
        /// specificity-sorted rules which can be stricter).
        fn assert_new_at_least_as_strict(yaml: &str, event: &TraceEvent, context: &str) {
            let compiled = compile_policy_yaml(yaml).unwrap();
            let old_engine = PolicyEngine::new(compiled);

            let compiled2 = compile_policy_yaml(yaml).unwrap();
            let new_policy = prioritize_and_resolve(&compiled2);

            // Old engine: use evaluate_native_function for Native hook type
            let old_decision = match event.hook_type {
                HookType::Native => {
                    let args: Vec<&str> = event
                        .arguments
                        .iter()
                        .filter_map(|a| a.display.as_deref())
                        .collect();
                    old_engine.evaluate_native_function(&event.function, &args)
                }
                HookType::Python => {
                    let args: Vec<&str> = event
                        .arguments
                        .iter()
                        .filter_map(|a| a.display.as_deref())
                        .collect();
                    old_engine.evaluate_function(
                        crate::compiler::compiled::Runtime::Python,
                        &event.function,
                        &args,
                    )
                }
                HookType::Nodejs => {
                    let args: Vec<&str> = event
                        .arguments
                        .iter()
                        .filter_map(|a| a.display.as_deref())
                        .collect();
                    old_engine.evaluate_function(
                        crate::compiler::compiled::Runtime::Node,
                        &event.function,
                        &args,
                    )
                }
                HookType::Exec | HookType::Bash => old_engine.evaluate_execution(&event.function),
                HookType::EnvVar => old_engine.evaluate_envvar(&event.function),
            };
            let old_blocked = old_decision.is_denied();

            let new_outcome = new_policy.check_event(event);
            let new_blocked = new_outcome.is_blocked();

            if old_blocked {
                assert!(
                    new_blocked,
                    "Convergence failure ({}): old engine blocked but new evaluator allowed",
                    context
                );
            }
        }

        #[test]
        fn test_convergence_broad_allow_specific_deny() {
            let yaml = "version: 1\nsymbols:\n  allow:\n    - \"*\"\n  deny:\n    - eval\n";
            assert_new_at_least_as_strict(
                yaml,
                &make_event(HookType::Python, "eval"),
                "allow *, deny eval → eval must be blocked",
            );
        }

        #[test]
        fn test_convergence_specific_allow_broad_deny() {
            let yaml = "version: 1\nsymbols:\n  allow:\n    - \"json.*\"\n  deny:\n    - \"*\"\n";
            let event = make_event(HookType::Python, "json.loads");
            let compiled = compile_policy_yaml(yaml).unwrap();
            let new_policy = prioritize_and_resolve(&compiled);
            let outcome = new_policy.check_event(&event);
            // json.loads should be allowed (more specific allow)
            assert!(
                !outcome.is_blocked(),
                "json.loads should be allowed by specific allow pattern"
            );
        }

        #[test]
        fn test_convergence_network_domain_deny() {
            let yaml = "version: 1\nnetwork:\n  deny:\n    - \"*.evil.com\"\n";
            assert_new_at_least_as_strict(
                yaml,
                &make_network_event("connect", "malware.evil.com"),
                "deny *.evil.com → malware.evil.com must be blocked",
            );
        }

        #[test]
        fn test_convergence_network_allow_deny() {
            let yaml =
                "version: 1\nnetwork:\n  allow:\n    - \"*.pypi.org\"\n  deny:\n    - \"*\"\n";
            let event = make_network_event("connect", "files.pypi.org");
            let compiled = compile_policy_yaml(yaml).unwrap();
            let new_policy = prioritize_and_resolve(&compiled);
            let outcome = new_policy.check_event(&event);
            assert!(!outcome.is_blocked(), "*.pypi.org should be allowed");

            let evil = make_network_event("connect", "evil.com");
            let outcome2 = new_policy.check_event(&evil);
            assert!(
                outcome2.is_blocked(),
                "evil.com should be blocked by deny *"
            );
        }

        #[test]
        fn test_convergence_file_tilde_deny() {
            let yaml = "version: 1\nfiles:\n  deny:\n    - \"~/.ssh/**\"\n";
            let home = std::env::var("HOME").unwrap();
            let path = format!("{home}/.ssh/id_rsa");
            assert_new_at_least_as_strict(
                yaml,
                &make_event_with_args(HookType::Native, "open", &[&path]),
                "deny ~/.ssh/** → absolute path should be blocked",
            );
        }

        #[test]
        fn test_convergence_envvar_hide() {
            let yaml = "version: 1\nenvvars:\n  hide:\n    - \"MALWI_*\"\n";
            let compiled = compile_policy_yaml(yaml).unwrap();
            let new_policy = prioritize_and_resolve(&compiled);
            let event = make_event(HookType::EnvVar, "MALWI_URL");
            let outcome = new_policy.check_event(&event);
            assert!(
                matches!(outcome, crate::Outcome::Hide),
                "MALWI_URL should be hidden, got {:?}",
                outcome
            );
        }

        #[test]
        fn test_convergence_implicit_deny() {
            let yaml = "version: 1\ncommands:\n  allow:\n    - node\n    - npm\n";
            assert_new_at_least_as_strict(
                yaml,
                &make_event(HookType::Exec, "curl"),
                "allow node/npm → curl should be implicitly denied",
            );
        }

        #[test]
        fn test_convergence_default_security_policy() {
            use crate::templates::DEFAULT_SECURITY_YAML;
            let compiled = compile_policy_yaml(&DEFAULT_SECURITY_YAML).unwrap();
            let policy = prioritize_and_resolve(&compiled);

            // getpass should be warned (symbols section)
            let event = make_event(HookType::Native, "getpass");
            let outcome = policy.check_event(&event);
            assert!(outcome.should_send(), "getpass should be displayed");

            // dns.lookup should be logged (nodejs section)
            let dns = TraceEvent {
                hook_type: HookType::Nodejs,
                function: "dns.lookup".into(),
                event_type: EventType::Enter,
                ..Default::default()
            };
            let outcome = policy.check_event(&dns);
            assert!(outcome.should_send(), "dns.lookup should be displayed");

            // Unlisted native function should be suppressed
            let event = make_event(HookType::Native, "printf");
            let outcome = policy.check_event(&event);
            assert!(!outcome.should_send(), "printf should be suppressed");
        }
    }
}
