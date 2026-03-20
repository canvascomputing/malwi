//! Argument filter integration tests.
//!
//! Tests for per-function bracket syntax argument filters.

use crate::common::*;
use crate::skip_if_no_node_primary;

fn setup() {
    build_fixtures();
}

// ============================================================================
// Per-Function Argument Filter Tests
// ============================================================================

#[test]
fn test_per_function_arg_filter_shows_matching_exec() {
    setup();

    skip_if_no_node_primary!(node => {
        // Filter for echo calls whose args contain "hello"
        let output = cmd(&format!(
            "x -c 'echo[*hello*]' -- {} -e {}",
            node.display(),
            sq("require('child_process').spawnSync('echo', ['hello world'])")
        )).run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        assert!(
            output.success(),
            "Arg filter matching test failed. stdout: {}, stderr: {}",
            stdout,
            stderr
        );

        // Should show echo trace because args contain "hello"
        assert!(
            output.has_traced("echo"),
            "Expected echo trace with matching arg filter. stdout: {}",
            stdout
        );
    });
}

#[test]
fn test_per_function_arg_filter_hides_non_matching_exec() {
    setup();

    skip_if_no_node_primary!(node => {
        // Filter for echo calls whose args contain "hello" — but the actual arg is "goodbye"
        let output = cmd(&format!(
            "x -c 'echo[*hello*]' -- {} -e {}",
            node.display(),
            sq("require('child_process').spawnSync('echo', ['goodbye'])")
        )).run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        assert!(
            output.success(),
            "Arg filter non-matching test failed. stdout: {}, stderr: {}",
            stdout,
            stderr
        );

        // Should NOT show echo trace because args don't contain "hello"
        assert!(
            !output.has_traced("echo"),
            "Should NOT show echo when arg filter doesn't match. stdout: {}",
            stdout
        );
    });
}

#[test]
fn test_inverted_arg_filter_excludes_matching_exec() {
    setup();

    skip_if_no_node_primary!(node => {
        // Inverted filter: show exec events NOT matching "hello"
        // Spawn two commands: echo hello and echo goodbye
        let output = cmd(&format!(
            "x -c 'echo[!*hello*]' -- {} -e {}",
            node.display(),
            sq("require('child_process').spawnSync('echo', ['hello']); require('child_process').spawnSync('echo', ['goodbye'])")
        )).run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        assert!(
            output.success(),
            "Inverted arg filter test failed. stdout: {}, stderr: {}",
            stdout,
            stderr
        );

        // Should show "goodbye" but NOT "hello"
        let lines: Vec<&str> = stdout
            .lines()
            .filter(|l| l.contains("[malwi]") && l.contains("echo"))
            .collect();

        // At least one exec event should show (the goodbye one)
        assert!(
            lines.iter().any(|l| l.contains("goodbye")),
            "Inverted filter should show 'goodbye'. stdout: {}",
            stdout
        );

        // The "hello" event should be filtered out
        assert!(
            !lines.iter().any(|l| l.contains("hello")),
            "Inverted filter should exclude 'hello'. stdout: {}",
            stdout
        );
    });
}
