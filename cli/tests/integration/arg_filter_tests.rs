//! Argument filter integration tests.
//!
//! Tests for per-function bracket syntax argument filters.

use crate::common::*;

fn setup() {
    build_fixtures();
}

// ============================================================================
// Per-Function Argument Filter Tests
// ============================================================================

#[test]
fn test_per_function_arg_filter_shows_matching_exec() {
    setup();

    let node = match find_node() {
        Some(n) => n,
        None => {
            println!("SKIPPED: test: node not found");
            return;
        }
    };

    // Filter for echo calls whose args contain "hello"
    let output = run_tracer(&[
        "x",
        "-c",
        "echo[*hello*]",
        "--",
        node.to_str().unwrap(),
        "-e",
        "require('child_process').spawnSync('echo', ['hello world'])",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout_clean = strip_ansi_codes(&stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Arg filter matching test failed. stdout: {}, stderr: {}",
        stdout_clean,
        stderr
    );

    // Should show echo trace because args contain "hello"
    let has_echo_trace = stdout_clean
        .lines()
        .any(|l| l.contains("[malwi]") && l.contains("echo"));
    assert!(
        has_echo_trace,
        "Expected echo trace with matching arg filter. stdout: {}",
        stdout_clean
    );
}

#[test]
fn test_per_function_arg_filter_hides_non_matching_exec() {
    setup();

    let node = match find_node() {
        Some(n) => n,
        None => {
            println!("SKIPPED: test: node not found");
            return;
        }
    };

    // Filter for echo calls whose args contain "hello" — but the actual arg is "goodbye"
    let output = run_tracer(&[
        "x",
        "-c",
        "echo[*hello*]",
        "--",
        node.to_str().unwrap(),
        "-e",
        "require('child_process').spawnSync('echo', ['goodbye'])",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout_clean = strip_ansi_codes(&stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Arg filter non-matching test failed. stdout: {}, stderr: {}",
        stdout_clean,
        stderr
    );

    // Should NOT show echo trace because args don't contain "hello"
    let has_echo_trace = stdout_clean
        .lines()
        .any(|l| l.contains("[malwi]") && l.contains("echo"));
    assert!(
        !has_echo_trace,
        "Should NOT show echo when arg filter doesn't match. stdout: {}",
        stdout_clean
    );
}

#[test]
fn test_inverted_arg_filter_excludes_matching_exec() {
    setup();

    let node = match find_node() {
        Some(n) => n,
        None => {
            println!("SKIPPED: test: node not found");
            return;
        }
    };

    // Inverted filter: show exec events NOT matching "hello"
    // Spawn two commands: echo hello and echo goodbye
    let output = run_tracer(&[
        "x",
        "-c", "echo[!*hello*]",
        "--",
        node.to_str().unwrap(),
        "-e", "require('child_process').spawnSync('echo', ['hello']); require('child_process').spawnSync('echo', ['goodbye'])",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout_clean = strip_ansi_codes(&stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Inverted arg filter test failed. stdout: {}, stderr: {}",
        stdout_clean,
        stderr
    );

    // Should show "goodbye" but NOT "hello"
    let lines: Vec<&str> = stdout_clean
        .lines()
        .filter(|l| l.contains("[malwi]") && l.contains("echo"))
        .collect();

    // At least one exec event should show (the goodbye one)
    assert!(
        lines.iter().any(|l| l.contains("goodbye")),
        "Inverted filter should show 'goodbye'. stdout: {}",
        stdout_clean
    );

    // The "hello" event should be filtered out
    assert!(
        !lines.iter().any(|l| l.contains("hello")),
        "Inverted filter should exclude 'hello'. stdout: {}",
        stdout_clean
    );
}
