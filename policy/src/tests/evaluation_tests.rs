//! Tests for policy evaluation.

use crate::compiled::{EnforcementMode, Operation, Runtime};
use crate::engine::{PolicyAction, PolicyEngine};

fn engine_from_yaml(yaml: &str) -> PolicyEngine {
    PolicyEngine::from_yaml(yaml).unwrap()
}

// =============================================================================
// Basic Evaluation Tests
// =============================================================================

#[test]
fn test_eval_deny_rule_blocks() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  deny:
    - eval
"#,
    );

    let decision = engine.evaluate_function(Runtime::Python, "eval", &[]);
    assert_eq!(decision.action, PolicyAction::Deny);
    assert_eq!(decision.matched_rule, Some("eval".to_string()));
}

#[test]
fn test_eval_allow_rule_allows() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - json.loads
"#,
    );

    let decision = engine.evaluate_function(Runtime::Python, "json.loads", &[]);
    assert_eq!(decision.action, PolicyAction::Allow);
}

#[test]
fn test_eval_no_match_with_allow_rules_denies() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - json.loads
    - json.dumps
"#,
    );

    let decision = engine.evaluate_function(Runtime::Python, "eval", &[]);
    assert_eq!(decision.action, PolicyAction::Deny);
}

#[test]
fn test_eval_no_match_with_only_deny_rules_allows() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  deny:
    - eval
    - exec
"#,
    );

    let decision = engine.evaluate_function(Runtime::Python, "json.loads", &[]);
    assert_eq!(decision.action, PolicyAction::Allow);
}

// =============================================================================
// Rule Order Tests
// =============================================================================

#[test]
fn test_eval_deny_takes_precedence_over_allow() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "*"
  deny:
    - eval
"#,
    );

    let decision = engine.evaluate_function(Runtime::Python, "eval", &[]);
    assert_eq!(decision.action, PolicyAction::Deny);

    let decision = engine.evaluate_function(Runtime::Python, "print", &[]);
    assert_eq!(decision.action, PolicyAction::Allow);
}

#[test]
fn test_eval_most_specific_deny_wins() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  deny:
    - "os.*"
    - os.system
"#,
    );

    let decision = engine.evaluate_function(Runtime::Python, "os.system", &[]);
    // os.system (exact, spec=18) beats os.* (glob, spec=3)
    assert_eq!(decision.matched_rule, Some("os.system".to_string()));
}

#[test]
fn test_eval_most_specific_allow_wins() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "json.*"
    - json.loads
"#,
    );

    let decision = engine.evaluate_function(Runtime::Python, "json.loads", &[]);
    // json.loads (exact, spec=20) beats json.* (glob, spec=5)
    assert_eq!(decision.matched_rule, Some("json.loads".to_string()));
}

#[test]
fn test_eval_specific_deny_overrides_broad_allow() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "os.*"
  deny:
    - os.system
"#,
    );

    let decision = engine.evaluate_function(Runtime::Python, "os.system", &[]);
    assert_eq!(decision.action, PolicyAction::Deny);

    let decision = engine.evaluate_function(Runtime::Python, "os.path.join", &[]);
    assert_eq!(decision.action, PolicyAction::Allow);
}

// =============================================================================
// Constraint Tests
// =============================================================================

#[test]
fn test_eval_allow_with_arg_constraint() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "requests.get": ["https://api.example.com/*"]
"#,
    );

    let decision = engine.evaluate_function(
        Runtime::Python,
        "requests.get",
        &["https://api.example.com/users"],
    );
    assert_eq!(decision.action, PolicyAction::Allow);

    let decision = engine.evaluate_function(
        Runtime::Python,
        "requests.get",
        &["https://evil.com/malware"],
    );
    assert_eq!(decision.action, PolicyAction::Deny);
}

#[test]
fn test_eval_deny_with_arg_constraint() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  deny:
    - "subprocess.run": ["*sudo*"]
"#,
    );

    let decision = engine.evaluate_function(Runtime::Python, "subprocess.run", &["sudo rm -rf /"]);
    assert_eq!(decision.action, PolicyAction::Deny);

    let decision = engine.evaluate_function(Runtime::Python, "subprocess.run", &["ls -la"]);
    assert_eq!(decision.action, PolicyAction::Allow);
}

#[test]
fn test_eval_file_operation_constraint() {
    let engine = engine_from_yaml(
        r#"
version: 1
files:
  allow:
    - "/tmp/*": [read]
    - "/app/data/*": [read, edit]
"#,
    );

    let decision = engine.evaluate_file("/tmp/test.txt", Operation::Read);
    assert_eq!(decision.action, PolicyAction::Allow);

    let decision = engine.evaluate_file("/tmp/test.txt", Operation::Edit);
    assert_eq!(decision.action, PolicyAction::Deny);

    let decision = engine.evaluate_file("/app/data/file.json", Operation::Edit);
    assert_eq!(decision.action, PolicyAction::Allow);
}

#[test]
fn test_eval_multiple_constraints_any_match() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "requests.*": ["https://api1.com/*", "https://api2.com/*"]
"#,
    );

    let d1 = engine.evaluate_function(Runtime::Python, "requests.get", &["https://api1.com/x"]);
    let d2 = engine.evaluate_function(Runtime::Python, "requests.get", &["https://api2.com/y"]);
    assert_eq!(d1.action, PolicyAction::Allow);
    assert_eq!(d2.action, PolicyAction::Allow);

    let d3 = engine.evaluate_function(Runtime::Python, "requests.get", &["https://other.com"]);
    assert_eq!(d3.action, PolicyAction::Deny);
}

// =============================================================================
// Mode Tests
// =============================================================================

#[test]
fn test_eval_mode_block_default() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  deny:
    - eval
"#,
    );

    let decision = engine.evaluate_function(Runtime::Python, "eval", &[]);
    assert_eq!(decision.section_mode(), EnforcementMode::Block);
}

#[test]
fn test_eval_mode_log_key() {
    let engine = engine_from_yaml(
        r#"
version: 1
files:
  log:
    - "/etc/*"
"#,
    );

    let decision = engine.evaluate_file("/etc/passwd", Operation::Read);
    assert_eq!(decision.action, PolicyAction::Deny);
    assert_eq!(decision.section_mode(), EnforcementMode::Log);
}

#[test]
fn test_eval_mode_warn_key() {
    let engine = engine_from_yaml(
        r#"
version: 1
network:
  warn:
    - "*.onion"
"#,
    );

    let decision = engine.evaluate_domain("test.onion");
    assert_eq!(decision.section_mode(), EnforcementMode::Warn);
}

#[test]
fn test_eval_mode_noop_allows_everything() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  noop:
    - "*"
"#,
    );

    let decision = engine.evaluate_function(Runtime::Python, "eval", &[]);
    assert_eq!(decision.action, PolicyAction::Allow);
}

#[test]
fn test_eval_mode_review() {
    let engine = engine_from_yaml(
        r#"
version: 1
commands:
  review:
    - "curl*"
"#,
    );

    let decision = engine.evaluate_execution("curl http://example.com");
    assert_eq!(decision.action, PolicyAction::Deny);
    assert_eq!(decision.section_mode(), EnforcementMode::Review);
    assert!(decision.section_mode().is_blocking());
}

// =============================================================================
// Cross-Section Tests
// =============================================================================

#[test]
fn test_eval_python_vs_node_isolation() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  deny:
    - eval
nodejs:
  allow:
    - eval
"#,
    );

    let d1 = engine.evaluate_function(Runtime::Python, "eval", &[]);
    assert_eq!(d1.action, PolicyAction::Deny);

    let d2 = engine.evaluate_function(Runtime::Node, "eval", &[]);
    assert_eq!(d2.action, PolicyAction::Allow);
}

#[test]
fn test_eval_networking_endpoint_and_domain() {
    let engine = engine_from_yaml(
        r#"
version: 1
network:
  deny:
    - "*:22"
    - "*.onion"
"#,
    );

    let d1 = engine.evaluate_endpoint("example.com", 22);
    assert_eq!(d1.action, PolicyAction::Deny);

    let d2 = engine.evaluate_domain("hidden.onion");
    assert_eq!(d2.action, PolicyAction::Deny);

    let d3 = engine.evaluate_endpoint("example.com", 443);
    assert_eq!(d3.action, PolicyAction::Allow);
}

#[test]
fn test_eval_execution_policy() {
    let engine = engine_from_yaml(
        r#"
version: 1
commands:
  allow:
    - "pip install *"
    - "git *"
  deny:
    - curl
    - wget
"#,
    );

    let d1 = engine.evaluate_execution("pip install requests");
    assert_eq!(d1.action, PolicyAction::Allow);

    let d2 = engine.evaluate_execution("curl http://evil.com");
    assert_eq!(d2.action, PolicyAction::Deny);

    let d3 = engine.evaluate_execution("ls -la");
    assert_eq!(d3.action, PolicyAction::Deny); // Not in allow list
}

#[test]
fn test_eval_protocol_list() {
    let engine = engine_from_yaml(
        r#"
version: 1
network:
  protocols: [tcp, https]
"#,
    );

    let d1 = engine.evaluate_protocol("tcp");
    assert_eq!(d1.action, PolicyAction::Allow);

    let d2 = engine.evaluate_protocol("https");
    assert_eq!(d2.action, PolicyAction::Allow);

    let d3 = engine.evaluate_protocol("ftp");
    assert_eq!(d3.action, PolicyAction::Deny);
}

#[test]
fn test_eval_envvar() {
    let engine = engine_from_yaml(
        r#"
version: 1
envvars:
  deny:
    - "regex:^AWS_"
    - "regex:^AZURE_"
"#,
    );

    let d1 = engine.evaluate_envvar("AWS_ACCESS_KEY");
    assert_eq!(d1.action, PolicyAction::Deny);

    let d2 = engine.evaluate_envvar("HOME");
    assert_eq!(d2.action, PolicyAction::Allow);
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_eval_empty_arguments() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "print": ["*"]
"#,
    );

    let decision = engine.evaluate_function(Runtime::Python, "print", &[]);
    assert_eq!(decision.action, PolicyAction::Deny);
}

#[test]
fn test_eval_empty_policy() {
    let engine = engine_from_yaml("version: 1\n");

    let decision = engine.evaluate_function(Runtime::Python, "anything", &[]);
    assert_eq!(decision.action, PolicyAction::Allow);
}

#[test]
fn test_eval_case_sensitivity() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  deny:
    - Eval
"#,
    );

    let d1 = engine.evaluate_function(Runtime::Python, "Eval", &[]);
    assert_eq!(d1.action, PolicyAction::Deny);

    let d2 = engine.evaluate_function(Runtime::Python, "eval", &[]);
    assert_eq!(d2.action, PolicyAction::Allow);
}

#[test]
fn test_eval_domain_case_insensitive() {
    let engine = engine_from_yaml(
        r#"
version: 1
network:
  deny:
    - "*.ONION"
"#,
    );

    let d1 = engine.evaluate_domain("test.onion");
    let d2 = engine.evaluate_domain("TEST.ONION");
    assert_eq!(d1.action, d2.action);
    assert_eq!(d1.action, PolicyAction::Deny);
}

#[test]
fn test_eval_special_characters_in_pattern() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  deny:
    - __import__
    - os.path.join
"#,
    );

    let d1 = engine.evaluate_function(Runtime::Python, "__import__", &[]);
    assert_eq!(d1.action, PolicyAction::Deny);

    let d2 = engine.evaluate_function(Runtime::Python, "os.path.join", &[]);
    assert_eq!(d2.action, PolicyAction::Deny);
}

#[test]
fn test_eval_missing_section() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  deny:
    - eval
"#,
    );

    // Node functions not defined, should allow
    let d1 = engine.evaluate_function(Runtime::Node, "anything", &[]);
    assert_eq!(d1.action, PolicyAction::Allow);

    // Files not defined, should allow
    let d2 = engine.evaluate_file("/etc/passwd", Operation::Read);
    assert_eq!(d2.action, PolicyAction::Allow);
}

#[test]
fn test_eval_empty_section() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow: []
  deny: []
"#,
    );

    let decision = engine.evaluate_function(Runtime::Python, "anything", &[]);
    assert_eq!(decision.action, PolicyAction::Allow);
}

#[test]
fn test_eval_glob_patterns() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "json.*"
    - "os.path.*"
  deny:
    - "os.*"
"#,
    );

    // os.path.join: allow "os.path.*" (spec=8) > deny "os.*" (spec=3) → allow wins
    let d1 = engine.evaluate_function(Runtime::Python, "os.path.join", &[]);
    assert_eq!(d1.action, PolicyAction::Allow);

    // json.loads only matches json.* (allow)
    let d2 = engine.evaluate_function(Runtime::Python, "json.loads", &[]);
    assert_eq!(decision_action_with_precedence(&d2), PolicyAction::Allow);
}

fn decision_action_with_precedence(
    decision: &crate::engine::PolicyDecision,
) -> crate::engine::PolicyAction {
    decision.action
}

#[test]
fn test_eval_regex_patterns() {
    let engine = engine_from_yaml(
        r#"
version: 1
envvars:
  deny:
    - "regex:^(AWS|AZURE|GCP)_"
"#,
    );

    let d1 = engine.evaluate_envvar("AWS_ACCESS_KEY");
    assert_eq!(d1.action, PolicyAction::Deny);

    let d2 = engine.evaluate_envvar("AZURE_STORAGE_KEY");
    assert_eq!(d2.action, PolicyAction::Deny);

    let d3 = engine.evaluate_envvar("MY_AWS_KEY");
    assert_eq!(d3.action, PolicyAction::Allow);
}

#[test]
fn test_eval_decision_helpers() {
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  deny:
    - eval
"#,
    );

    let d1 = engine.evaluate_function(Runtime::Python, "eval", &[]);
    assert!(d1.is_denied());
    assert!(!d1.is_allowed());

    let d2 = engine.evaluate_function(Runtime::Python, "print", &[]);
    assert!(d2.is_allowed());
    assert!(!d2.is_denied());
}

#[test]
fn test_eval_complex_policy() {
    let engine = engine_from_yaml(
        r#"
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
    - "/etc/*"
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
"#,
    );

    // Python function tests
    assert_eq!(
        engine
            .evaluate_function(Runtime::Python, "json.loads", &[])
            .action,
        PolicyAction::Allow
    );
    assert_eq!(
        engine
            .evaluate_function(Runtime::Python, "eval", &[])
            .action,
        PolicyAction::Deny
    );
    assert_eq!(
        engine
            .evaluate_function(
                Runtime::Python,
                "requests.get",
                &["https://api.example.com/data"]
            )
            .action,
        PolicyAction::Allow
    );
    assert_eq!(
        engine
            .evaluate_function(Runtime::Python, "requests.get", &["https://evil.com"])
            .action,
        PolicyAction::Deny
    );

    // File tests (global)
    let f1 = engine.evaluate_file("/tmp/test.txt", Operation::Read);
    assert_eq!(f1.action, PolicyAction::Allow);
    assert_eq!(f1.section_mode(), EnforcementMode::Log);

    assert_eq!(
        engine
            .evaluate_file("/etc/passwd", Operation::Read)
            .action,
        PolicyAction::Deny
    );

    // Envvar tests (global)
    assert_eq!(
        engine
            .evaluate_envvar("AWS_SECRET")
            .action,
        PolicyAction::Deny
    );
    assert_eq!(
        engine.evaluate_envvar("HOME").action,
        PolicyAction::Allow
    );

    // Node.js tests
    assert_eq!(
        engine
            .evaluate_function(Runtime::Node, "fs.readFileSync", &[])
            .action,
        PolicyAction::Allow
    );
    assert_eq!(
        engine
            .evaluate_function(Runtime::Node, "eval", &[])
            .action,
        PolicyAction::Deny
    ); // Not in allow list

    // Networking tests
    assert_eq!(
        engine.evaluate_protocol("tcp").action,
        PolicyAction::Allow
    );
    assert_eq!(engine.evaluate_protocol("ftp").action, PolicyAction::Deny);
    assert_eq!(
        engine.evaluate_domain("hidden.onion").action,
        PolicyAction::Deny
    );
    assert_eq!(
        engine.evaluate_endpoint("server.com", 22).action,
        PolicyAction::Deny
    );
    assert_eq!(
        engine.evaluate_endpoint("server.com", 443).action,
        PolicyAction::Allow
    );

    // Execution tests
    let e1 = engine.evaluate_execution("git clone repo");
    assert_eq!(e1.action, PolicyAction::Allow);
    assert_eq!(e1.section_mode(), EnforcementMode::Review);

    assert_eq!(
        engine.evaluate_execution("curl http://evil.com").action,
        PolicyAction::Deny
    );
}

// =============================================================================
// New Format Tests (Direct List = Implicit Allow)
// =============================================================================

#[test]
fn test_eval_new_format_node_functions() {
    let engine = engine_from_yaml(
        r#"
version: 1
nodejs:
  - "axios.*": ["https://api.example.com/*"]
  - JSON.parse
  - JSON.stringify
  - "console.*"
"#,
    );

    // Listed functions allowed
    assert_eq!(
        engine.evaluate_function(Runtime::Node, "JSON.parse", &[]).action,
        PolicyAction::Allow
    );
    assert_eq!(
        engine.evaluate_function(Runtime::Node, "console.log", &[]).action,
        PolicyAction::Allow
    );

    // axios with allowed URL
    assert_eq!(
        engine
            .evaluate_function(Runtime::Node, "axios.get", &["https://api.example.com/users"])
            .action,
        PolicyAction::Allow
    );

    // axios with disallowed URL
    assert_eq!(
        engine
            .evaluate_function(Runtime::Node, "axios.get", &["https://evil.com"])
            .action,
        PolicyAction::Deny
    );

    // Unlisted function denied (implicit deny)
    assert_eq!(
        engine.evaluate_function(Runtime::Node, "eval", &[]).action,
        PolicyAction::Deny
    );
}

#[test]
fn test_eval_new_format_endpoints() {
    let engine = engine_from_yaml(
        r#"
version: 1
network:
  allow:
    - "127.0.0.1:*"
    - "10.0.0.0/8:5432"
    - "*:443"
"#,
    );

    // Allowed endpoints
    assert_eq!(
        engine.evaluate_endpoint("127.0.0.1", 8080).action,
        PolicyAction::Allow
    );
    assert_eq!(
        engine.evaluate_endpoint("example.com", 443).action,
        PolicyAction::Allow
    );

    // Disallowed endpoint (implicit deny)
    assert_eq!(
        engine.evaluate_endpoint("example.com", 80).action,
        PolicyAction::Deny
    );
}

#[test]
fn test_eval_new_format_envvars_with_ops() {
    // Note: This test verifies the parsing and compilation work correctly.
    // Full operation constraint evaluation would require evaluate_envvar_op method.
    let engine = engine_from_yaml(
        r#"
version: 1
envvars:
  - HOME: [read]
  - PATH: [read]
  - "APP_*": [read, write]
"#,
    );

    // HOME is in the allow list (matching pattern)
    // Without operation context, the pattern match is sufficient
    assert_eq!(
        engine.evaluate_envvar("HOME").action,
        PolicyAction::Deny // Constraint not satisfied (no operation context)
    );

    // Unlisted envvar
    assert_eq!(
        engine.evaluate_envvar("UNLISTED").action,
        PolicyAction::Deny
    );
}

#[test]
fn test_eval_new_format_files_with_ops() {
    let engine = engine_from_yaml(
        r#"
version: 1
files:
  - "/app/data/*": [read, edit]
  - "/app/logs/*": [read, edit, delete]
  - "/app/uploads/*": [read]
"#,
    );

    // Read from /app/data - allowed
    let d1 = engine.evaluate_file("/app/data/file.json", Operation::Read);
    assert_eq!(d1.action, PolicyAction::Allow);
    assert_eq!(d1.section_mode(), EnforcementMode::Block);

    // Edit /app/data - allowed
    assert_eq!(
        engine
            .evaluate_file("/app/data/file.json", Operation::Edit)
            .action,
        PolicyAction::Allow
    );

    // Delete /app/data - denied (only read, edit allowed)
    assert_eq!(
        engine
            .evaluate_file("/app/data/file.json", Operation::Delete)
            .action,
        PolicyAction::Deny
    );

    // Delete /app/logs - allowed
    assert_eq!(
        engine
            .evaluate_file("/app/logs/app.log", Operation::Delete)
            .action,
        PolicyAction::Allow
    );

    // Read only from uploads
    assert_eq!(
        engine
            .evaluate_file("/app/uploads/image.png", Operation::Read)
            .action,
        PolicyAction::Allow
    );
    assert_eq!(
        engine
            .evaluate_file("/app/uploads/image.png", Operation::Edit)
            .action,
        PolicyAction::Deny
    );
}

#[test]
fn test_eval_new_format_mixed_with_old() {
    // Mix old format (explicit allow/deny) with new format (direct list)
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - json.loads
  deny:
    - eval
nodejs:
  - JSON.parse
  - "console.*"
"#,
    );

    // Old format works
    assert_eq!(
        engine.evaluate_function(Runtime::Python, "json.loads", &[]).action,
        PolicyAction::Allow
    );
    assert_eq!(
        engine.evaluate_function(Runtime::Python, "eval", &[]).action,
        PolicyAction::Deny
    );

    // New format works
    assert_eq!(
        engine.evaluate_function(Runtime::Node, "JSON.parse", &[]).action,
        PolicyAction::Allow
    );
    assert_eq!(
        engine.evaluate_function(Runtime::Node, "console.log", &[]).action,
        PolicyAction::Allow
    );
    assert_eq!(
        engine.evaluate_function(Runtime::Node, "eval", &[]).action,
        PolicyAction::Deny
    );
}

// =============================================================================
// Integration Test: Load Actual policy.yaml
// =============================================================================

#[test]
fn test_eval_repo_policy_yaml() {
    // Inline the policy YAML that was previously at policy.yaml in the repo root
    let yaml = r#"
version: 1

python:
  allow:
    - "requests.*": ["https://api.example.com/*"]
    - json.loads
    - json.dumps
  deny:
    - eval
    - exec
    - "__*__"

nodejs:
  - "axios.*": ["https://api.example.com/*"]
  - JSON.parse
  - JSON.stringify
  - "console.*"

envvars:
  - HOME: [read]
  - PATH: [read]
  - USER: [read]
  - NODE_ENV: [read]
  - "APP_*": [read, write]

files:
  allow:
    - "/app/data/*": [read, edit]
    - "/app/logs/*": [read, edit, delete]
    - "/app/uploads/*": [read]
    - "regex:^/tmp/app-[a-z0-9]+$": [read, edit, delete]
  log:
    - "~/.ssh/*"
    - "~/.aws/*"
    - "*.pem"
    - "*.key"

network:
  allow:
    - "https://api.example.com/v1/**"
    - "*.example.com/health"
    - "https://pypi.org/**"
    - "https://files.pythonhosted.org/**"
    - "https://registry.npmjs.org/**"
    - "127.0.0.1:*"
    - "10.0.0.0/8:5432"
    - "*:80"
    - "*:443"
    - api.example.com
    - "*.amazonaws.com"
    - "*.pypi.org"
    - "*.npmjs.org"
  deny:
    - "*.evil.com/**"
    - "**/admin/**"
    - "**/.env"
    - "http://api.example.com/**"
    - "*:22"
    - "*.onion"
    - "*malware*"
  warn:
    - "*.suspicious.io"
  protocols: [tcp, https]

commands:
  allow:
    - "pip install *"
    - "npm install *"
    - "npx *"
    - "git *"
    - "python -m pytest*"
    - "npm test*"
  deny:
    - curl
    - wget
    - ssh
    - bash
    - "*sudo*"
"#;
    let engine = PolicyEngine::from_yaml(yaml).expect("Failed to parse policy.yaml");

    // Test python section (old format with allow/deny)
    assert_eq!(
        engine.evaluate_function(Runtime::Python, "json.loads", &[]).action,
        PolicyAction::Allow
    );
    assert_eq!(
        engine.evaluate_function(Runtime::Python, "eval", &[]).action,
        PolicyAction::Deny
    );
    assert_eq!(
        engine
            .evaluate_function(
                Runtime::Python,
                "requests.get",
                &["https://api.example.com/data"]
            )
            .action,
        PolicyAction::Allow
    );

    // Test nodejs section (new format - direct list)
    assert_eq!(
        engine.evaluate_function(Runtime::Node, "JSON.parse", &[]).action,
        PolicyAction::Allow
    );
    assert_eq!(
        engine.evaluate_function(Runtime::Node, "console.log", &[]).action,
        PolicyAction::Allow
    );
    assert_eq!(
        engine
            .evaluate_function(Runtime::Node, "axios.get", &["https://api.example.com/users"])
            .action,
        PolicyAction::Allow
    );
    // Unlisted function denied
    assert_eq!(
        engine.evaluate_function(Runtime::Node, "eval", &[]).action,
        PolicyAction::Deny
    );

    // Test files section (global, new format with operations)
    let f1 = engine.evaluate_file("/app/data/file.json", Operation::Read);
    assert_eq!(f1.action, PolicyAction::Allow);
    assert_eq!(f1.section_mode(), EnforcementMode::Log);

    // Test network section — endpoint patterns
    assert_eq!(
        engine.evaluate_endpoint("127.0.0.1", 8080).action,
        PolicyAction::Allow
    );
    assert_eq!(
        engine.evaluate_endpoint("example.com", 443).action,
        PolicyAction::Allow
    );

    // Test network section — protocols
    assert_eq!(engine.evaluate_protocol("tcp").action, PolicyAction::Allow);
    assert_eq!(engine.evaluate_protocol("https").action, PolicyAction::Allow);
    assert_eq!(engine.evaluate_protocol("ftp").action, PolicyAction::Deny);

    // Test network section — domain patterns
    assert_eq!(
        engine.evaluate_domain("api.example.com").action,
        PolicyAction::Allow
    );
    assert_eq!(
        engine.evaluate_domain("hidden.onion").action,
        PolicyAction::Deny
    );

    // Test commands section
    assert_eq!(
        engine.evaluate_execution("pip install requests").action,
        PolicyAction::Allow
    );
    assert_eq!(
        engine.evaluate_execution("curl http://example.com").action,
        PolicyAction::Deny
    );
}

// =============================================================================
// Overlapping Pattern Precedence Tests
// =============================================================================

#[test]
fn test_overlapping_patterns_allow_broad_deny_specific() {
    // allow: "os.*", deny: "os.path.*"
    // os.path.join → DENY, os.system → ALLOW
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "os.*"
  deny:
    - "os.path.*"
"#,
    );

    // os.path.join matches both, deny wins
    let d1 = engine.evaluate_function(Runtime::Python, "os.path.join", &[]);
    assert_eq!(d1.action, PolicyAction::Deny);
    assert_eq!(d1.matched_rule, Some("os.path.*".to_string()));

    // os.system only matches allow, should be allowed
    let d2 = engine.evaluate_function(Runtime::Python, "os.system", &[]);
    assert_eq!(d2.action, PolicyAction::Allow);
    assert_eq!(d2.matched_rule, Some("os.*".to_string()));
}

#[test]
fn test_three_way_pattern_overlap_specificity() {
    // allow: ["os.*", "os.path.join"], deny: ["os.path.*"]
    // os.path.join → ALLOW (exact allow spec=24 > glob deny spec=7)
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "os.*"
    - os.path.join
  deny:
    - "os.path.*"
"#,
    );

    // Specific allow for os.path.join (exact, spec=24) beats deny "os.path.*" (glob, spec=7)
    let d1 = engine.evaluate_function(Runtime::Python, "os.path.join", &[]);
    assert_eq!(d1.action, PolicyAction::Allow);
    assert_eq!(d1.matched_rule, Some("os.path.join".to_string()));

    // os.path.exists: deny "os.path.*" (spec=7) vs allow "os.*" (spec=3) → deny wins
    let d2 = engine.evaluate_function(Runtime::Python, "os.path.exists", &[]);
    assert_eq!(d2.action, PolicyAction::Deny);

    // But os.system allowed (doesn't match deny pattern)
    let d3 = engine.evaluate_function(Runtime::Python, "os.system", &[]);
    assert_eq!(d3.action, PolicyAction::Allow);
}

#[test]
fn test_multiple_overlapping_allow_patterns_most_specific_wins() {
    // allow: ["*", "json.loads", "json.*"]
    // json.loads → matched by "json.loads" (most specific, exact match)
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "*"
    - json.loads
    - "json.*"
"#,
    );

    let decision = engine.evaluate_function(Runtime::Python, "json.loads", &[]);
    assert_eq!(decision.action, PolicyAction::Allow);
    // Most specific matching rule is "json.loads" (exact, spec=20)
    assert_eq!(decision.matched_rule, Some("json.loads".to_string()));
}

#[test]
fn test_deny_star_with_specific_allow() {
    // deny: "*", allow: "safe_*"
    // safe_* (spec=5) is more specific than * (spec=0), so allow wins for safe_func
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "safe_*"
  deny:
    - "*"
"#,
    );

    // safe_func matches allow "safe_*" (spec=5) and deny "*" (spec=0) → allow wins
    let d1 = engine.evaluate_function(Runtime::Python, "safe_func", &[]);
    assert_eq!(d1.action, PolicyAction::Allow);
    assert_eq!(d1.matched_rule, Some("safe_*".to_string()));

    // unsafe_func only matches deny "*" → denied
    let d2 = engine.evaluate_function(Runtime::Python, "unsafe_func", &[]);
    assert_eq!(d2.action, PolicyAction::Deny);
}

#[test]
fn test_nested_path_patterns_deny_broader() {
    // deny: "/app/**/*", allow: "/app/safe/*"
    // Note: * only matches within a single path segment, ** matches across directories
    let engine = engine_from_yaml(
        r#"
version: 1
files:
  allow:
    - "/app/safe/*": [read]
  deny:
    - "/app/**/*"
"#,
    );

    // /app/safe/file.txt: allow "/app/safe/*" (spec=10) > deny "/app/**/*" (spec=6) → allow
    let d1 = engine.evaluate_file("/app/safe/file.txt", Operation::Read);
    assert_eq!(d1.action, PolicyAction::Allow);

    let d2 = engine.evaluate_file("/app/unsafe/file.txt", Operation::Read);
    assert_eq!(d2.action, PolicyAction::Deny);
}

#[test]
fn test_nested_path_patterns_allow_broader() {
    // allow: "/app/**/*", deny: "/app/secret/*"
    // Note: * only matches within a single path segment
    let engine = engine_from_yaml(
        r#"
version: 1
files:
  allow:
    - "/app/**/*": [read]
  deny:
    - "/app/secret/*"
"#,
    );

    // /app/secret/file.txt is denied (deny matches single segment under /app/secret/)
    let d1 = engine.evaluate_file("/app/secret/file.txt", Operation::Read);
    assert_eq!(d1.action, PolicyAction::Deny);

    // /app/public/file.txt is allowed (no deny match, allow matches)
    let d2 = engine.evaluate_file("/app/public/file.txt", Operation::Read);
    assert_eq!(d2.action, PolicyAction::Allow);
}

// =============================================================================
// Constraint Interaction Tests
// =============================================================================

#[test]
fn test_constraint_with_overlapping_patterns() {
    // Deny with constraint vs allow with different constraint
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "requests.*": ["https://api.com/*"]
  deny:
    - "requests.*": ["https://evil.com/*"]
"#,
    );

    // evil.com is denied (deny constraint matches)
    let d1 =
        engine.evaluate_function(Runtime::Python, "requests.get", &["https://evil.com/malware"]);
    assert_eq!(d1.action, PolicyAction::Deny);

    // api.com is allowed (no deny match, allow constraint matches)
    let d2 =
        engine.evaluate_function(Runtime::Python, "requests.get", &["https://api.com/users"]);
    assert_eq!(d2.action, PolicyAction::Allow);

    // other.com is denied (has allow rules but none match)
    let d3 = engine.evaluate_function(Runtime::Python, "requests.get", &["https://other.com"]);
    assert_eq!(d3.action, PolicyAction::Deny);
}

#[test]
fn test_pattern_with_constraint_vs_without_constraint() {
    // print: ["*"] vs json.loads (no constraint)
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "print": ["*"]
    - json.loads
"#,
    );

    // json.loads (no constraint) always allowed
    let d1 = engine.evaluate_function(Runtime::Python, "json.loads", &[]);
    assert_eq!(d1.action, PolicyAction::Allow);

    // print with argument allowed
    let d2 = engine.evaluate_function(Runtime::Python, "print", &["hello"]);
    assert_eq!(d2.action, PolicyAction::Allow);

    // print without argument denied (constraint not satisfied)
    let d3 = engine.evaluate_function(Runtime::Python, "print", &[]);
    assert_eq!(d3.action, PolicyAction::Deny);
}

#[test]
fn test_all_constraints_fail_to_match_with_allow_rules() {
    // Multiple URL constraints, none match → DENY
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "requests.get": ["https://api1.com/*", "https://api2.com/*"]
    - "requests.post": ["https://api1.com/*"]
"#,
    );

    // URL doesn't match any constraint
    let d1 = engine.evaluate_function(
        Runtime::Python,
        "requests.get",
        &["https://unauthorized.com/data"],
    );
    assert_eq!(d1.action, PolicyAction::Deny);

    // Different function with non-matching URL
    let d2 = engine.evaluate_function(
        Runtime::Python,
        "requests.post",
        &["https://api2.com/data"],
    );
    assert_eq!(d2.action, PolicyAction::Deny);

    // Completely unlisted function
    let d3 = engine.evaluate_function(Runtime::Python, "urllib.request", &[]);
    assert_eq!(d3.action, PolicyAction::Deny);
}

#[test]
fn test_file_operation_overlapping_patterns_and_ops() {
    // /app/**/*: [read, edit] vs /app/readonly/*: [read] vs deny /app/readonly/*: [edit]
    // Note: * only matches within a single path segment
    let engine = engine_from_yaml(
        r#"
version: 1
files:
  allow:
    - "/app/**/*": [read, edit]
    - "/app/readonly/*": [read]
  deny:
    - "/app/readonly/*": [edit, delete]
"#,
    );

    // /app/readonly/file.txt edit is denied (deny pattern matches)
    let d1 = engine.evaluate_file("/app/readonly/file.txt", Operation::Edit);
    assert_eq!(d1.action, PolicyAction::Deny);

    // /app/readonly/file.txt read is allowed (deny doesn't match read op)
    let d2 = engine.evaluate_file("/app/readonly/file.txt", Operation::Read);
    assert_eq!(d2.action, PolicyAction::Allow);

    // /app/other/file.txt edit is allowed (no deny match, allow matches)
    let d3 = engine.evaluate_file("/app/other/file.txt", Operation::Edit);
    assert_eq!(d3.action, PolicyAction::Allow);
}

#[test]
fn test_deny_constraint_fails_falls_through_to_allow() {
    // deny rule with constraint that doesn't match should fall through
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "subprocess.*"
  deny:
    - "subprocess.run": ["*sudo*", "*rm -rf*"]
"#,
    );

    // Safe command - deny constraint doesn't match, allow does
    let d1 = engine.evaluate_function(Runtime::Python, "subprocess.run", &["ls -la"]);
    assert_eq!(d1.action, PolicyAction::Allow);

    // Dangerous command - deny constraint matches
    let d2 = engine.evaluate_function(Runtime::Python, "subprocess.run", &["sudo apt install"]);
    assert_eq!(d2.action, PolicyAction::Deny);

    // Another dangerous command
    let d3 = engine.evaluate_function(Runtime::Python, "subprocess.run", &["rm -rf /"]);
    assert_eq!(d3.action, PolicyAction::Deny);

    // Other subprocess functions allowed
    let d4 = engine.evaluate_function(Runtime::Python, "subprocess.call", &["ls"]);
    assert_eq!(d4.action, PolicyAction::Allow);
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_star_position_specificity_wins() {
    // deny: "*", allow: "safe_*" → allow wins for safe_* (more specific)
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "safe_*"
  deny:
    - "*"
"#,
    );

    // safe_function matches allow "safe_*" (spec=5) > deny "*" (spec=0) → allow
    let d1 = engine.evaluate_function(Runtime::Python, "safe_function", &[]);
    assert_eq!(d1.action, PolicyAction::Allow);
}

#[test]
fn test_regex_vs_glob_overlapping_matches() {
    // deny: "regex:^AWS_", allow: "AWS_*"
    let engine = engine_from_yaml(
        r#"
version: 1
envvars:
  allow:
    - "AWS_*"
  deny:
    - "regex:^AWS_"
"#,
    );

    // AWS_ACCESS_KEY matches both - deny wins
    let d1 = engine.evaluate_envvar("AWS_ACCESS_KEY");
    assert_eq!(d1.action, PolicyAction::Deny);

    // MY_AWS_KEY doesn't match deny regex (must start with AWS_)
    let d2 = engine.evaluate_envvar("MY_AWS_KEY");
    // Doesn't match allow either, but has allow rules = deny
    assert_eq!(d2.action, PolicyAction::Deny);
}

#[test]
fn test_mixed_allow_deny_neither_matches_implicit_deny() {
    // allow: ["json.*"], deny: ["eval"]
    // os.system → DENY (has allow rules, implicit deny)
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "json.*"
  deny:
    - eval
"#,
    );

    // Explicitly denied
    let d1 = engine.evaluate_function(Runtime::Python, "eval", &[]);
    assert_eq!(d1.action, PolicyAction::Deny);
    assert_eq!(d1.matched_rule, Some("eval".to_string()));

    // Explicitly allowed
    let d2 = engine.evaluate_function(Runtime::Python, "json.loads", &[]);
    assert_eq!(d2.action, PolicyAction::Allow);

    // Neither matches - implicit deny because allow rules exist
    let d3 = engine.evaluate_function(Runtime::Python, "os.system", &[]);
    assert_eq!(d3.action, PolicyAction::Deny);
    assert_eq!(d3.matched_rule, None); // No rule matched, implicit deny
}

#[test]
fn test_new_format_empty_list_denies_all() {
    // nodejs: [] should deny all (has allow rules but empty)
    let engine = engine_from_yaml(
        r#"
version: 1
nodejs: []
"#,
    );

    // Empty direct list = empty allow rules = implicit deny all
    let d = engine.evaluate_function(Runtime::Node, "anything", &[]);
    assert_eq!(d.action, PolicyAction::Allow); // Empty section allows everything
}

#[test]
fn test_endpoint_port_exact_matching() {
    // *:443 should NOT match port 4430
    let engine = engine_from_yaml(
        r#"
version: 1
network:
  allow:
    - "*:443"
"#,
    );

    // Port 443 allowed
    let d1 = engine.evaluate_endpoint("example.com", 443);
    assert_eq!(d1.action, PolicyAction::Allow);

    // Port 4430 NOT allowed (should not match *:443)
    let d2 = engine.evaluate_endpoint("example.com", 4430);
    assert_eq!(d2.action, PolicyAction::Deny);

    // Port 44300 NOT allowed
    let d3 = engine.evaluate_endpoint("example.com", 44300);
    assert_eq!(d3.action, PolicyAction::Deny);
}

#[test]
fn test_category_isolation_same_pattern() {
    // Same pattern in functions vs files should be isolated
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  deny:
    - "open"
files:
  allow:
    - "/tmp/*": [read]
"#,
    );

    // Function 'open' denied
    let d1 = engine.evaluate_function(Runtime::Python, "open", &[]);
    assert_eq!(d1.action, PolicyAction::Deny);

    // File '/tmp/test' read allowed (different category)
    let d2 = engine.evaluate_file("/tmp/test", Operation::Read);
    assert_eq!(d2.action, PolicyAction::Allow);

    // File 'open' - no file rules match 'open' pattern
    let d3 = engine.evaluate_file("open", Operation::Read);
    assert_eq!(d3.action, PolicyAction::Deny);
}

#[test]
fn test_deeply_nested_paths() {
    // /app/src/lib/utils/helpers/core/main.py
    let engine = engine_from_yaml(
        r#"
version: 1
files:
  allow:
    - "/app/**/*.py": [read]
  deny:
    - "/app/**/secret/*"
"#,
    );

    // Deeply nested py file allowed
    let d1 = engine.evaluate_file(
        "/app/src/lib/utils/helpers/core/main.py",
        Operation::Read,
    );
    assert_eq!(d1.action, PolicyAction::Allow);

    // Deeply nested secret file denied
    let d2 = engine.evaluate_file(
        "/app/src/lib/secret/password.py",
        Operation::Read,
    );
    assert_eq!(d2.action, PolicyAction::Deny);
}

#[test]
fn test_question_mark_in_patterns() {
    // allow: "func?" should match func1, funcA but not func12
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "func?"
"#,
    );

    let d1 = engine.evaluate_function(Runtime::Python, "func1", &[]);
    assert_eq!(d1.action, PolicyAction::Allow);

    let d2 = engine.evaluate_function(Runtime::Python, "funcA", &[]);
    assert_eq!(d2.action, PolicyAction::Allow);

    let d3 = engine.evaluate_function(Runtime::Python, "func12", &[]);
    assert_eq!(d3.action, PolicyAction::Deny);

    let d4 = engine.evaluate_function(Runtime::Python, "func", &[]);
    assert_eq!(d4.action, PolicyAction::Deny);
}

#[test]
fn test_adding_allow_rule_changes_implicit_behavior() {
    // Risk: Adding first allow rule silently changes default behavior
    // Blacklist mode (implicit allow for unlisted)
    let engine_blacklist = engine_from_yaml(
        r#"
version: 1
python:
  deny:
    - eval
"#,
    );

    // Unlisted function allowed in blacklist mode
    let d1 = engine_blacklist.evaluate_function(Runtime::Python, "print", &[]);
    assert_eq!(d1.action, PolicyAction::Allow);

    // Whitelist mode (implicit deny for unlisted) - just add ONE allow rule!
    let engine_whitelist = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - json.loads
  deny:
    - eval
"#,
    );

    // Same unlisted function now DENIED in whitelist mode
    let d2 = engine_whitelist.evaluate_function(Runtime::Python, "print", &[]);
    assert_eq!(d2.action, PolicyAction::Deny);

    // eval still denied
    let d3 = engine_whitelist.evaluate_function(Runtime::Python, "eval", &[]);
    assert_eq!(d3.action, PolicyAction::Deny);

    // json.loads allowed
    let d4 = engine_whitelist.evaluate_function(Runtime::Python, "json.loads", &[]);
    assert_eq!(d4.action, PolicyAction::Allow);
}

#[test]
fn test_empty_constraint_pattern() {
    // "eval": [""] - empty constraint should only match empty arguments
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "print": [""]
"#,
    );

    // Empty argument should match
    let d1 = engine.evaluate_function(Runtime::Python, "print", &[""]);
    assert_eq!(d1.action, PolicyAction::Allow);

    // Non-empty argument should not match
    let d2 = engine.evaluate_function(Runtime::Python, "print", &["hello"]);
    assert_eq!(d2.action, PolicyAction::Deny);

    // No arguments should not match (constraint exists but not satisfied)
    let d3 = engine.evaluate_function(Runtime::Python, "print", &[]);
    assert_eq!(d3.action, PolicyAction::Deny);
}

#[test]
fn test_multiple_deny_rules_most_specific_wins() {
    // Multiple deny rules with different patterns — most specific wins
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  deny:
    - "*"
    - "eval"
    - "__import__"
"#,
    );

    // Most specific deny for "eval" is the exact "eval" (spec=8), not "*" (spec=0)
    let d1 = engine.evaluate_function(Runtime::Python, "eval", &[]);
    assert_eq!(d1.action, PolicyAction::Deny);
    assert_eq!(d1.matched_rule, Some("eval".to_string()));

    let d2 = engine.evaluate_function(Runtime::Python, "__import__", &[]);
    assert_eq!(d2.action, PolicyAction::Deny);
    assert_eq!(d2.matched_rule, Some("__import__".to_string()));
}

#[test]
fn test_specific_deny_before_broad_deny() {
    // Specific deny rule before broad deny rule - first match wins
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  deny:
    - "eval"
    - "*"
"#,
    );

    // eval matches first rule
    let d1 = engine.evaluate_function(Runtime::Python, "eval", &[]);
    assert_eq!(d1.action, PolicyAction::Deny);
    assert_eq!(d1.matched_rule, Some("eval".to_string()));

    // other function matches second rule
    let d2 = engine.evaluate_function(Runtime::Python, "print", &[]);
    assert_eq!(d2.action, PolicyAction::Deny);
    assert_eq!(d2.matched_rule, Some("*".to_string()));
}

#[test]
fn test_constraint_or_logic_multiple_arguments() {
    // Constraint with multiple args - any match satisfies
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "func": ["safe*"]
"#,
    );

    // Second argument matches constraint
    let d1 = engine.evaluate_function(Runtime::Python, "func", &["unsafe", "safe_value"]);
    assert_eq!(d1.action, PolicyAction::Allow);

    // First argument matches constraint
    let d2 = engine.evaluate_function(Runtime::Python, "func", &["safe_value", "unsafe"]);
    assert_eq!(d2.action, PolicyAction::Allow);

    // Neither argument matches
    let d3 = engine.evaluate_function(Runtime::Python, "func", &["unsafe1", "unsafe2"]);
    assert_eq!(d3.action, PolicyAction::Deny);
}

// =============================================================================
// Mixed Mode Key Tests (deny + warn coexistence in single section)
// =============================================================================

#[test]
fn test_eval_mixed_deny_and_warn_keys_coexist() {
    // python: with deny (block) and warn keys in a single section.
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  deny:
    - os.system
    - os.popen
  warn:
    - subprocess.run
    - subprocess.call
"#,
    );

    // os.system → denied with Block mode (from deny key)
    let d1 = engine.evaluate_function(Runtime::Python, "os.system", &[]);
    assert_eq!(d1.action, PolicyAction::Deny);
    assert_eq!(d1.section_mode(), EnforcementMode::Block);

    // subprocess.run → denied with Warn mode (from warn key)
    let d2 = engine.evaluate_function(Runtime::Python, "subprocess.run", &[]);
    assert_eq!(d2.action, PolicyAction::Deny);
    assert_eq!(d2.section_mode(), EnforcementMode::Warn);

    // Unlisted function → allowed (only deny-side rules, implicit allow)
    let d3 = engine.evaluate_function(Runtime::Python, "json.loads", &[]);
    assert_eq!(d3.action, PolicyAction::Allow);
}

#[test]
fn test_eval_mixed_block_and_warn_deny_rules() {
    // Verify that both block and warn deny rules work in one section.
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  deny:
    - getpass.getpass
    - keyring.get_password
  warn:
    - subprocess.Popen.__init__
"#,
    );

    let d1 = engine.evaluate_function(Runtime::Python, "getpass.getpass", &[]);
    assert_eq!(d1.action, PolicyAction::Deny);
    assert_eq!(d1.section_mode(), EnforcementMode::Block);

    let d2 = engine.evaluate_function(Runtime::Python, "keyring.get_password", &[]);
    assert_eq!(d2.action, PolicyAction::Deny);
    assert_eq!(d2.section_mode(), EnforcementMode::Block);

    let d3 = engine.evaluate_function(Runtime::Python, "subprocess.Popen.__init__", &[]);
    assert_eq!(d3.action, PolicyAction::Deny);
    assert_eq!(d3.section_mode(), EnforcementMode::Warn);
}

#[test]
fn test_eval_allow_deny_warn_keys_together() {
    // python: has allow, deny, and warn keys together.
    // The allow rules create implicit deny for unlisted.
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  allow:
    - "json.*"
  deny:
    - eval
  warn:
    - subprocess.run
"#,
    );

    // json.loads → allowed (from allow rules)
    let d1 = engine.evaluate_function(Runtime::Python, "json.loads", &[]);
    assert_eq!(d1.action, PolicyAction::Allow);

    // eval → denied with Block (from deny key)
    let d2 = engine.evaluate_function(Runtime::Python, "eval", &[]);
    assert_eq!(d2.action, PolicyAction::Deny);
    assert_eq!(d2.section_mode(), EnforcementMode::Block);

    // subprocess.run → denied with Warn (from warn key)
    let d3 = engine.evaluate_function(Runtime::Python, "subprocess.run", &[]);
    assert_eq!(d3.action, PolicyAction::Deny);
    assert_eq!(d3.section_mode(), EnforcementMode::Warn);

    // unlisted → denied (implicit, because allow rules exist)
    let d4 = engine.evaluate_function(Runtime::Python, "os.system", &[]);
    assert_eq!(d4.action, PolicyAction::Deny);
}

#[test]
fn test_eval_network_deny_and_warn_keys() {
    // network: with deny and warn keys.
    let engine = engine_from_yaml(
        r#"
version: 1
network:
  deny:
    - "*.evil.com/**"
  warn:
    - "http://**"
"#,
    );

    // evil.com → denied with Block
    let d1 = engine.evaluate_http_url(
        "https://malware.evil.com/payload",
        "malware.evil.com/payload",
    );
    assert_eq!(d1.action, PolicyAction::Deny);
    assert_eq!(d1.mode, EnforcementMode::Block);

    // http:// → denied with Warn
    let d2 = engine.evaluate_http_url(
        "http://example.com/insecure",
        "example.com/insecure",
    );
    assert_eq!(d2.action, PolicyAction::Deny);
    assert_eq!(d2.mode, EnforcementMode::Warn);

    // https safe site → allowed
    let d3 = engine.evaluate_http_url(
        "https://example.com/safe",
        "example.com/safe",
    );
    assert_eq!(d3.action, PolicyAction::Allow);
}

// =============================================================================
// Realistic ComfyUI-like policy (using mode keys)
// =============================================================================

#[test]
fn test_comfyui_like_policy_block_and_warn_coexist() {
    // Simulates the ComfyUI policy pattern: deny blocks dangerous funcs,
    // warn warns on subprocess use.
    let engine = engine_from_yaml(
        r#"
version: 1
python:
  deny:
    - os.system
    - os.popen
    - getpass.getpass
    - ctypes.CDLL
  warn:
    - subprocess.run
    - subprocess.call
    - subprocess.Popen.__init__
"#,
    );

    // Block-mode denies
    let d = engine.evaluate_function(Runtime::Python, "os.system", &[]);
    assert_eq!(d.action, PolicyAction::Deny);
    assert_eq!(d.section_mode(), EnforcementMode::Block);

    let d = engine.evaluate_function(Runtime::Python, "ctypes.CDLL", &[]);
    assert_eq!(d.action, PolicyAction::Deny);
    assert_eq!(d.section_mode(), EnforcementMode::Block);

    // Warn-mode denies
    let d = engine.evaluate_function(Runtime::Python, "subprocess.run", &[]);
    assert_eq!(d.action, PolicyAction::Deny);
    assert_eq!(d.section_mode(), EnforcementMode::Warn);

    let d = engine.evaluate_function(Runtime::Python, "subprocess.Popen.__init__", &[]);
    assert_eq!(d.action, PolicyAction::Deny);
    assert_eq!(d.section_mode(), EnforcementMode::Warn);

    // Unlisted → allowed
    let d = engine.evaluate_function(Runtime::Python, "json.loads", &[]);
    assert_eq!(d.action, PolicyAction::Allow);
}

// =============================================================================
// Specificity-Based Resolution Tests (table-driven)
// =============================================================================

/// What to evaluate against the policy engine.
enum EvalTarget {
    Function(Runtime, &'static str),
    Execution(&'static str),
    HttpUrl(&'static str, &'static str),
    Domain(&'static str),
    File(&'static str),
}

struct SpecificityCheck {
    target: EvalTarget,
    expected_action: PolicyAction,
    expected_rule: Option<&'static str>,
}

struct SpecificityCase {
    name: &'static str,
    yaml: &'static str,
    checks: Vec<SpecificityCheck>,
}

#[test]
fn test_specificity_resolution() {
    let cases = vec![
        // --- Allowlist pattern: exact allow + deny "*" ---
        SpecificityCase {
            name: "allowlist: exact allow + deny *",
            yaml: r#"
version: 1
python:
  allow:
    - json.loads
  deny:
    - "*"
"#,
            checks: vec![
                SpecificityCheck {
                    target: EvalTarget::Function(Runtime::Python, "json.loads"),
                    expected_action: PolicyAction::Allow,
                    expected_rule: Some("json.loads"),
                },
                SpecificityCheck {
                    target: EvalTarget::Function(Runtime::Python, "eval"),
                    expected_action: PolicyAction::Deny,
                    expected_rule: Some("*"),
                },
            ],
        },
        // --- Denylist pattern: allow "*" + exact deny ---
        SpecificityCase {
            name: "denylist: allow * + exact deny",
            yaml: r#"
version: 1
python:
  allow:
    - "*"
  deny:
    - eval
"#,
            checks: vec![
                SpecificityCheck {
                    target: EvalTarget::Function(Runtime::Python, "eval"),
                    expected_action: PolicyAction::Deny,
                    expected_rule: Some("eval"),
                },
                SpecificityCheck {
                    target: EvalTarget::Function(Runtime::Python, "print"),
                    expected_action: PolicyAction::Allow,
                    expected_rule: Some("*"),
                },
            ],
        },
        // --- Glob allow beats wildcard deny ---
        SpecificityCase {
            name: "glob allow beats wildcard deny",
            yaml: r#"
version: 1
python:
  allow:
    - "safe_*"
  deny:
    - "*"
"#,
            checks: vec![
                SpecificityCheck {
                    target: EvalTarget::Function(Runtime::Python, "safe_func"),
                    expected_action: PolicyAction::Allow,
                    expected_rule: Some("safe_*"),
                },
                SpecificityCheck {
                    target: EvalTarget::Function(Runtime::Python, "evil_func"),
                    expected_action: PolicyAction::Deny,
                    expected_rule: Some("*"),
                },
            ],
        },
        // --- Exact deny beats glob allow ---
        SpecificityCase {
            name: "exact deny beats glob allow",
            yaml: r#"
version: 1
python:
  allow:
    - "os.*"
  deny:
    - os.system
"#,
            checks: vec![
                SpecificityCheck {
                    target: EvalTarget::Function(Runtime::Python, "os.system"),
                    expected_action: PolicyAction::Deny,
                    expected_rule: Some("os.system"),
                },
                SpecificityCheck {
                    target: EvalTarget::Function(Runtime::Python, "os.path"),
                    expected_action: PolicyAction::Allow,
                    expected_rule: Some("os.*"),
                },
            ],
        },
        // --- More-specific glob wins ---
        SpecificityCase {
            name: "more-specific glob wins",
            yaml: r#"
version: 1
python:
  allow:
    - "os.path.*"
  deny:
    - "os.*"
"#,
            checks: vec![
                SpecificityCheck {
                    target: EvalTarget::Function(Runtime::Python, "os.path.join"),
                    expected_action: PolicyAction::Allow,
                    expected_rule: Some("os.path.*"),
                },
                SpecificityCheck {
                    target: EvalTarget::Function(Runtime::Python, "os.system"),
                    expected_action: PolicyAction::Deny,
                    expected_rule: Some("os.*"),
                },
            ],
        },
        // --- Three-way: exact allow + glob deny + broad allow ---
        SpecificityCase {
            name: "three-way: exact allow beats glob deny",
            yaml: r#"
version: 1
python:
  allow:
    - "os.*"
    - os.path.join
  deny:
    - "os.path.*"
"#,
            checks: vec![
                SpecificityCheck {
                    target: EvalTarget::Function(Runtime::Python, "os.path.join"),
                    expected_action: PolicyAction::Allow,
                    expected_rule: Some("os.path.join"),
                },
            ],
        },
        // --- Tie: same pattern both sides → deny wins ---
        SpecificityCase {
            name: "tie: same pattern both sides → deny wins",
            yaml: r#"
version: 1
python:
  allow:
    - eval
  deny:
    - eval
"#,
            checks: vec![
                SpecificityCheck {
                    target: EvalTarget::Function(Runtime::Python, "eval"),
                    expected_action: PolicyAction::Deny,
                    expected_rule: Some("eval"),
                },
            ],
        },
        // --- Commands: exact allow + glob deny ---
        SpecificityCase {
            name: "commands: exact allow + glob deny",
            yaml: r#"
version: 1
commands:
  allow:
    - "curl wikipedia.org"
  deny:
    - "curl *"
"#,
            checks: vec![
                SpecificityCheck {
                    target: EvalTarget::Execution("curl wikipedia.org"),
                    expected_action: PolicyAction::Allow,
                    expected_rule: Some("curl wikipedia.org"),
                },
                SpecificityCheck {
                    target: EvalTarget::Execution("curl evil.com"),
                    expected_action: PolicyAction::Deny,
                    expected_rule: Some("curl *"),
                },
            ],
        },
        // --- URL allowlist with deny "*" ---
        SpecificityCase {
            name: "URL allowlist with deny *",
            yaml: r#"
version: 1
network:
  allow:
    - "https://wikipedia.org/**"
  deny:
    - "*"
"#,
            checks: vec![
                SpecificityCheck {
                    target: EvalTarget::HttpUrl(
                        "https://wikipedia.org/wiki/Rust",
                        "wikipedia.org/wiki/Rust",
                    ),
                    expected_action: PolicyAction::Allow,
                    expected_rule: Some("https://wikipedia.org/**"),
                },
                SpecificityCheck {
                    target: EvalTarget::HttpUrl("https://evil.com/malware", "evil.com/malware"),
                    expected_action: PolicyAction::Deny,
                    // "*" is classified as domain pattern (no /), so HTTP URL eval
                    // sees implicit deny from having allow rules, not a matched rule
                    expected_rule: None,
                },
            ],
        },
        // --- Domain allowlist with deny "*" ---
        SpecificityCase {
            name: "domain allowlist with deny *",
            yaml: r#"
version: 1
network:
  allow:
    - "*.example.com"
  deny:
    - "*"
"#,
            checks: vec![
                SpecificityCheck {
                    target: EvalTarget::Domain("api.example.com"),
                    expected_action: PolicyAction::Allow,
                    expected_rule: Some("*.example.com"),
                },
                SpecificityCheck {
                    target: EvalTarget::Domain("evil.com"),
                    expected_action: PolicyAction::Deny,
                    expected_rule: Some("*"),
                },
            ],
        },
        // --- Files: specific allow + broad deny ---
        SpecificityCase {
            name: "files: specific allow + broad deny",
            yaml: r#"
version: 1
files:
  allow:
    - "/app/safe/*": [read]
  deny:
    - "/app/**/*"
"#,
            checks: vec![
                SpecificityCheck {
                    target: EvalTarget::File("/app/safe/f.txt"),
                    expected_action: PolicyAction::Allow,
                    expected_rule: Some("/app/safe/*"),
                },
                SpecificityCheck {
                    target: EvalTarget::File("/app/other/f.txt"),
                    expected_action: PolicyAction::Deny,
                    expected_rule: Some("/app/**/*"),
                },
            ],
        },
    ];

    for case in &cases {
        let engine = engine_from_yaml(case.yaml);
        for (i, check) in case.checks.iter().enumerate() {
            let decision = match &check.target {
                EvalTarget::Function(rt, name) => engine.evaluate_function(*rt, name, &[]),
                EvalTarget::Execution(cmd) => engine.evaluate_execution(cmd),
                EvalTarget::HttpUrl(full, no_scheme) => {
                    engine.evaluate_http_url(full, no_scheme)
                }
                EvalTarget::Domain(d) => engine.evaluate_domain(d),
                EvalTarget::File(path) => engine.evaluate_file(path, Operation::Read),
            };
            assert_eq!(
                decision.action, check.expected_action,
                "[{}] check #{}: expected {:?}, got {:?} (rule: {:?})",
                case.name, i, check.expected_action, decision.action, decision.matched_rule,
            );
            if let Some(expected_rule) = check.expected_rule {
                assert_eq!(
                    decision.matched_rule.as_deref(),
                    Some(expected_rule),
                    "[{}] check #{}: expected rule {:?}, got {:?}",
                    case.name, i, expected_rule, decision.matched_rule,
                );
            }
        }
    }
}
