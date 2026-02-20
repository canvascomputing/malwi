//! Review mode tests.
//!
//! Tests for the interactive review mode that prompts before function execution.

use crate::common::*;
use crate::skip_if_no_bash_primary;
use crate::skip_if_no_node_primary;
use std::path::PathBuf;

fn setup() {
    build_fixtures();
}

/// Find Python 3.11+ specifically (required for argument extraction)
fn find_python311() -> Option<PathBuf> {
    for path in ["/usr/local/bin/python3.12", "/usr/local/bin/python3.11"] {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

// ============================================================================
// Review Mode Tests - Native Hooks
// ============================================================================

#[test]
fn test_review_mode_approve_allows_native_execution() {
    setup();

    // Test review mode with approve (Y) - function should execute
    let output = run_tracer_with_stdin(
        &[
            "x",
            "-r",
            "-s",
            "simple_target_marker",
            "--",
            "./simple_target",
        ],
        "Y\nY\n", // Approve all calls
    );

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = strip_ansi_codes(&stdout_raw);

    // Should complete successfully
    assert!(
        output.status.success(),
        "Review mode approve test failed. stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    // Should show review prompt
    assert!(
        has_review_prompt(&stdout),
        "Expected review prompt 'Approve? [Y/n/i]:'. stdout: {}",
        stdout
    );

    // Should have traced the function (shown in review summary)
    assert!(
        stdout.contains("simple_target_marker"),
        "Expected simple_target_marker in output. stdout: {}",
        stdout
    );
}

#[test]
fn test_review_mode_deny_blocks_native_execution() {
    setup();

    // Test review mode with deny (n) - function should be blocked
    let output = run_tracer_with_stdin(
        &[
            "x",
            "-r",
            "-s",
            "simple_target_marker",
            "--",
            "./simple_target",
        ],
        "n\nn\n", // Deny all calls
    );

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = strip_ansi_codes(&stdout_raw);

    // Should show review prompt
    assert!(
        has_review_prompt(&stdout),
        "Expected review prompt. stdout: {}",
        stdout
    );

    // Should show BLOCKED message
    assert!(
        has_review_blocked(&stdout, "simple_target_marker"),
        "Expected BLOCKED message for simple_target_marker. stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}

#[test]
fn test_review_mode_inspect_shows_details_then_reprompts() {
    setup();

    // Test review mode with inspect (i) then approve - should show details
    let output = run_tracer_with_stdin(
        &[
            "x",
            "-r",
            "-s",
            "simple_target_marker",
            "--",
            "./simple_target",
        ],
        "i\nY\ni\nY\n", // Inspect then approve for each call
    );

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = strip_ansi_codes(&stdout_raw);

    // Should complete successfully (approved after inspect)
    assert!(
        output.status.success(),
        "Review mode inspect test failed. stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    // Should show review prompt
    assert!(
        has_review_prompt(&stdout),
        "Expected review prompt. stdout: {}",
        stdout
    );

    // Should show details section after pressing 'i'
    assert!(
        has_review_details(&stdout),
        "Expected '--- Details ---' section after inspect. stdout: {}",
        stdout
    );
}

// ============================================================================
// Review Mode Tests - Python Hooks
// ============================================================================

#[test]
fn test_review_mode_approve_allows_python_execution() {
    setup();

    let python = match find_python() {
        Some(p) => p,
        None => {
            println!("SKIPPED: Python review test: python3 not found");
            return;
        }
    };

    // Create test script
    let test_script = r#"
def target_func(x):
    return x * 2

result = target_func(21)
print(f"Result: {result}")
"#;
    std::fs::write("/tmp/test_review_py.py", test_script).unwrap();

    let output = run_tracer_with_stdin(
        &[
            "x",
            "-r",
            "--py",
            "target_func",
            "--",
            python.to_str().unwrap(),
            "/tmp/test_review_py.py",
        ],
        "Y\n", // Approve
    );

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = strip_ansi_codes(&stdout_raw);

    // Should complete successfully
    assert!(
        output.status.success(),
        "Python review approve test failed. stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    // Should show review prompt with Python function
    assert!(
        stdout.contains("target_func"),
        "Expected target_func in review prompt. stdout: {}",
        stdout
    );

    // Function should have executed (result printed)
    assert!(
        stdout.contains("Result: 42"),
        "Expected function to execute and print result. stdout: {}",
        stdout
    );
}

#[test]
fn test_review_mode_deny_raises_python_permission_error() {
    setup();

    let python = match find_python() {
        Some(p) => p,
        None => {
            println!("SKIPPED: Python review test: python3 not found");
            return;
        }
    };

    // Create test script that catches the PermissionError
    let test_script = r#"
def target_func(x):
    return x * 2

try:
    result = target_func(21)
    print(f"Result: {result}")
except PermissionError as e:
    print(f"Blocked: {e}")
"#;
    std::fs::write("/tmp/test_review_py_deny.py", test_script).unwrap();

    let output = run_tracer_with_stdin(
        &[
            "x",
            "-r",
            "--py",
            "target_func",
            "--",
            python.to_str().unwrap(),
            "/tmp/test_review_py_deny.py",
        ],
        "n\n", // Deny
    );

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = strip_ansi_codes(&stdout_raw);

    // Should show BLOCKED message
    assert!(
        has_review_blocked(&stdout, "target_func"),
        "Expected BLOCKED message for target_func. stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    // Function should have been blocked (PermissionError caught or uncaught)
    let was_blocked = stdout.contains("Blocked:")
        || stdout.contains("PermissionError")
        || stderr.contains("PermissionError");
    assert!(
        was_blocked,
        "Expected PermissionError when function blocked. stdout: {}, stderr: {}",
        stdout, stderr
    );

    // Should NOT have the successful result
    assert!(
        !stdout.contains("Result: 42"),
        "Function should not have executed. stdout: {}",
        stdout
    );
}

#[test]
fn test_review_mode_inspect_shows_python_arguments() {
    setup();

    let python = match find_python311() {
        Some(p) => p,
        None => {
            println!("SKIPPED: Python review inspect test: Python 3.11+ not found");
            return;
        }
    };

    // Create test script with arguments to inspect
    let test_script = r#"
def greet(name, greeting="Hello"):
    return f"{greeting}, {name}!"

print(greet("World", "Hi"))
"#;
    std::fs::write("/tmp/test_review_py_inspect.py", test_script).unwrap();

    let output = run_tracer_with_stdin(
        &[
            "x",
            "-r",
            "--py",
            "greet",
            "--",
            python.to_str().unwrap(),
            "/tmp/test_review_py_inspect.py",
        ],
        "i\nY\n", // Inspect then approve
    );

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = strip_ansi_codes(&stdout_raw);

    // Should show details section with argument values
    assert!(
        has_review_details(&stdout),
        "Expected details section. stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    // Details should show argument values (World, Hi)
    let has_args = stdout.contains("World") || stdout.contains("Hi");
    assert!(
        has_args,
        "Expected argument values in details. stdout: {}",
        stdout
    );
}

// ============================================================================
// Review Mode Tests - JavaScript/Node.js Hooks
// ============================================================================

#[test]
fn test_review_mode_approve_allows_v8_execution() {
    setup();

    skip_if_no_node_primary!(node => {
        let output = run_tracer_with_stdin(
            &[
                "x", "-r",
                "--js", "targetFunc",
                "--",
                node.to_str().unwrap(),
                "--eval", "function targetFunc() { return 42; } console.log('Result:', targetFunc());",
            ],
            "Y\n",  // Approve
        );

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = strip_ansi_codes(&stdout_raw);

        // Should complete successfully
        assert!(
            output.status.success(),
            "V8 review approve test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // Should have review prompt or trace event
        let has_js_event = stdout.contains("targetFunc") || stdout.contains("<anonymous>");
        assert!(
            has_js_event || has_review_prompt(&stdout),
            "Expected targetFunc trace or review prompt. stdout: {}",
            stdout
        );

        // Function should have executed
        assert!(
            stdout.contains("Result:") || stdout.contains("42"),
            "Expected function to execute. stdout: {}",
            stdout
        );
    });
}

#[test]
fn test_review_mode_deny_blocks_v8_execution() {
    setup();

    skip_if_no_node_primary!(node => {
        let output = run_tracer_with_stdin(
            &[
                "x", "-r",
                "--js", "eval",
                "--",
                node.to_str().unwrap(),
                "--eval", "let executed = false; try { eval(\"executed = true\"); } catch (e) { console.log('EVAL_BLOCKED', e.name); } console.log('EXECUTED', executed);",
            ],
            "n\n",  // Deny eval/codegen
        );

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = strip_ansi_codes(&stdout_raw);

        assert!(
            output.status.success(),
            "V8 review deny test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // Denied eval() should not execute the assignment.
        assert!(
            stdout.contains("EXECUTED false"),
            "Expected eval payload to be blocked. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // Confirm we actually hit the deny path.
        assert!(
            stdout.contains("EVAL_BLOCKED") || stdout.contains("denied:"),
            "Expected blocked eval signal. stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}

// ============================================================================
// Review Mode Tests - Edge Cases
// ============================================================================

#[test]
fn test_review_mode_empty_input_defaults_to_approve() {
    setup();

    // Empty input (just Enter) should default to approve (Y)
    let output = run_tracer_with_stdin(
        &[
            "x",
            "-r",
            "-s",
            "simple_target_marker",
            "--",
            "./simple_target",
        ],
        "\n\n", // Just Enter = approve
    );

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = strip_ansi_codes(&stdout_raw);

    // Should complete successfully (empty = approve)
    assert!(
        output.status.success(),
        "Review mode empty input test failed. stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    // Should NOT show denied
    assert!(
        !stdout.contains("denied:"),
        "Empty input should approve, not block. stdout: {}",
        stdout
    );
}

#[test]
fn test_review_mode_prompts_for_each_call() {
    setup();

    // Test review mode with multiple calls of the same function
    // simple_target calls simple_target_marker twice
    let output = run_tracer_with_stdin(
        &[
            "x",
            "-r",
            "-s",
            "simple_target_marker",
            "--",
            "./simple_target",
        ],
        "Y\nY\n", // Approve both calls
    );

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = strip_ansi_codes(&stdout_raw);

    // Should complete successfully
    assert!(
        output.status.success(),
        "Review mode multiple calls test failed. stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    // Should have multiple prompts for the same function
    let prompt_count = stdout.matches("Approve?").count();
    assert!(
        prompt_count >= 2,
        "Expected at least 2 review prompts for simple_target_marker. Got {}. stdout: {}",
        prompt_count,
        stdout
    );
}

#[test]
fn test_review_mode_approve_is_case_insensitive() {
    setup();

    // Test that 'y' (lowercase) also approves
    let output = run_tracer_with_stdin(
        &[
            "x",
            "-r",
            "-s",
            "simple_target_marker",
            "--",
            "./simple_target",
        ],
        "y\ny\n", // lowercase y
    );

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = strip_ansi_codes(&stdout_raw);

    // Should complete successfully
    assert!(
        output.status.success(),
        "Review mode lowercase 'y' test failed. stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    // Should NOT show denied
    assert!(
        !stdout.contains("denied:"),
        "Lowercase 'y' should approve. stdout: {}",
        stdout
    );
}

#[test]
fn test_review_mode_enabled_with_short_flag() {
    setup();

    // Test -r short flag works
    let output = run_tracer_with_stdin(
        &[
            "x",
            "-r",
            "-s",
            "simple_target_marker",
            "--",
            "./simple_target",
        ],
        "Y\nY\n",
    );

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stdout = strip_ansi_codes(&stdout_raw);

    assert!(
        has_review_prompt(&stdout),
        "Short -r flag should enable review mode. stdout: {}",
        stdout
    );
}

#[test]
fn test_review_mode_enabled_with_long_flag() {
    setup();

    // Test --review long flag works
    let output = run_tracer_with_stdin(
        &[
            "x",
            "--review",
            "-s",
            "simple_target_marker",
            "--",
            "./simple_target",
        ],
        "Y\nY\n",
    );

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stdout = strip_ansi_codes(&stdout_raw);

    assert!(
        has_review_prompt(&stdout),
        "Long --review flag should enable review mode. stdout: {}",
        stdout
    );
}

// ============================================================================
// Review Mode Tests - Blocked Function Cache (Hang Regression)
// ============================================================================

#[test]
fn test_review_mode_deny_caches_block_decision() {
    setup();

    // When a function is denied in review mode, subsequent calls to the same
    // function should be silently blocked by the agent-side cache without
    // another HTTP round-trip. Without the cache, each blocked call triggers
    // a synchronous HTTP request, and retrying callers (like socket()) cause
    // an infinite loop of blocking round-trips.
    //
    // simple_target calls simple_target_marker twice. Denying the first call
    // should cache the block; the second call should be blocked instantly.
    // The process must complete within the timeout (no hang).
    let output = run_tracer_with_stdin_timeout(
        &[
            "x",
            "-r",
            "-s",
            "simple_target_marker",
            "--",
            "./simple_target",
        ],
        "n\n", // Deny the first call; second should be cached
        std::time::Duration::from_secs(10),
    );

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = strip_ansi_codes(&stdout_raw);

    // Process must have completed (not killed by timeout)
    // On timeout kill, exit status is non-zero from signal
    assert!(
        output.status.success() || output.status.code().is_some(),
        "Process should complete, not hang. stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    // Should show exactly one BLOCKED message (first call denied by user)
    // The second call should be silently blocked by the agent cache
    assert!(
        has_review_blocked(&stdout, "simple_target_marker"),
        "Expected BLOCKED message for simple_target_marker. stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    // Should show exactly one review prompt (not two — second call is cached)
    let prompt_count = stdout.matches("Approve?").count();
    assert_eq!(
        prompt_count, 1,
        "Expected exactly 1 review prompt (second call cached). Got {}. stdout: {}",
        prompt_count, stdout
    );
}

// ============================================================================
// Review Mode Tests - Exec Command Blocking in Shell Scripts
// ============================================================================

#[test]
fn test_review_mode_deny_blocks_exec_in_shell_script() {
    setup();

    skip_if_no_bash_primary!(bash => {
        // Write a shell script that calls cat (external binary, goes through execve)
        // followed by echo (bash builtin, does NOT go through execve)
        let script_path = std::env::temp_dir().join(format!(
            "malwi-review-exec-test-{}.sh",
            std::process::id()
        ));
        std::fs::write(&script_path, "#!/bin/bash\ncat /dev/null\necho SCRIPT_CONTINUED\n")
            .expect("failed to write test script");

        // Run with review mode (-r) and exec filter (-c cat)
        // Deny the cat execution
        let output = run_tracer_with_stdin(
            &[
                "x", "-r",
                "-c", "cat",
                "--",
                bash.to_str().unwrap(),
                script_path.to_str().unwrap(),
            ],
            "n\n",  // Deny the cat call
        );

        let _ = std::fs::remove_file(&script_path);

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stdout = strip_ansi_codes(&stdout_raw);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        // Should show review prompt for the exec event
        assert!(
            has_review_prompt(&stdout),
            "Expected review prompt for cat. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // Should show denied message for cat
        assert!(
            stdout.contains("denied:") && stdout.contains("cat"),
            "Expected denied message for cat. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // The bash script should continue past the blocked command
        // (echo is a builtin, not intercepted by exec filter)
        assert!(
            stdout.contains("SCRIPT_CONTINUED"),
            "Expected script to continue after blocked command. stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}
