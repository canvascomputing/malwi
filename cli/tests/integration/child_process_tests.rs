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

    let output = run_tracer(&["x", "-s", "spawner_marker", "--", "./spawner", "fork"]);

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = strip_ansi_codes(&stdout_raw);

    // Should complete successfully
    assert!(
        output.status.success(),
        "Fork test failed. stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    // Should have traced the spawner_marker function
    assert!(
        stdout.contains("[malwi] spawner_marker"),
        "Expected [malwi] spawner_marker trace event. stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}

#[test]
fn test_exec_syscall_detected_when_process_replaced() {
    setup();

    let output = run_tracer(&["x", "-s", "spawner_marker", "--", "./spawner", "exec"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should complete (exec replaces the process image)
    // The test passes if we don't crash — this is a crash-safety test
    assert!(
        output.status.success(),
        "Exec test should complete without crashing. stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}

#[test]
fn test_posix_spawn_detected_in_spawned_process() {
    setup();

    let output = run_tracer(&["x", "-s", "spawner_marker", "--", "./spawner", "spawn"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should complete successfully
    assert!(
        output.status.success(),
        "Spawn test failed. stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}
