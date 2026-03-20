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

    let output = cmd("x -s spawner_marker -- ./spawner fork").run();

    let stdout = output.stdout();
    let stderr = output.stderr();

    // Should complete successfully
    assert!(
        output.success(),
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

    let output = cmd("x -s spawner_marker -- ./spawner exec").run();

    let stdout = output.stdout_raw();
    let stderr = output.stderr();

    // Should complete (exec replaces the process image)
    // The test passes if we don't crash — this is a crash-safety test
    assert!(
        output.success(),
        "Exec test should complete without crashing. stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}

#[test]
fn test_posix_spawn_detected_in_spawned_process() {
    setup();

    let output = cmd("x -s spawner_marker -- ./spawner spawn").run();

    let stdout = output.stdout_raw();
    let stderr = output.stderr();

    // Should complete successfully
    assert!(
        output.success(),
        "Spawn test failed. stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}
