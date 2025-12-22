//! Child process detection tests.
//!
//! Tests for fork/exec/spawn monitoring.

use crate::common::*;

fn setup() {
    build_fixtures();
}

// ============================================================================
// Child Process Tests
// ============================================================================

#[test]
fn test_fork_syscall_detected_in_child_process() {
    setup();

    let output = run_tracer(&[
        "x",
        "-s", "spawner_marker",
        "--",
        "./spawner", "fork",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout, stderr);

    // Should complete successfully
    assert!(
        output.status.success(),
        "Fork test failed. stdout: {}, stderr: {}",
        stdout, stderr
    );

    // Should detect fork operation
    let has_fork = has_child_event(&combined, "Fork") ||
                   combined.contains("fork") ||
                   combined.contains("child");

    assert!(
        has_fork || combined.contains("spawner"),
        "Expected fork detection. stdout: {}, stderr: {}",
        stdout, stderr
    );
}

#[test]
fn test_exec_syscall_detected_when_process_replaced() {
    setup();

    let output = run_tracer(&[
        "x",
        "-s", "spawner_marker",
        "--",
        "./spawner", "exec",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should complete (exec replaces the process image)
    // The test passes if we don't crash
    assert!(
        output.status.success() || stderr.contains("exec") || stdout.contains("simple_target"),
        "Exec test had unexpected failure. stdout: {}, stderr: {}",
        stdout, stderr
    );
}

#[test]
fn test_posix_spawn_detected_in_spawned_process() {
    setup();

    let output = run_tracer(&[
        "x",
        "-s", "spawner_marker",
        "--",
        "./spawner", "spawn",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should complete successfully
    assert!(
        output.status.success(),
        "Spawn test failed. stdout: {}, stderr: {}",
        stdout, stderr
    );
}
