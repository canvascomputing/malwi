//! Direct syscall detection tests.
//!
//! Detection is controlled by the `syscalls:` policy section.
//! Currently stubbed out — syscall detection is not yet implemented
//! in malwi-hook. These tests will be re-enabled when the feature
//! is re-implemented.

use crate::common::*;
use std::io::Write;
use std::time::Duration;

fn setup() {
    build_fixtures();
}

/// Write a temporary policy YAML file with the given content.
fn write_temp_policy(name: &str, content: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "malwi-test-policy-{}-{}.yaml",
        name,
        std::process::id()
    ));
    let mut f = std::fs::File::create(&path).expect("create temp policy");
    f.write_all(content.as_bytes()).expect("write temp policy");
    path
}

// ============================================================================
// Positive test: direct syscall in user code should be detected
// ============================================================================

#[test]
#[ignore = "syscall detection not yet implemented in malwi-hook"]
fn test_direct_syscall_detected_in_user_binary() {
    setup();

    let policy_path = write_temp_policy(
        "positive",
        r#"
version: 1
syscalls:
  deny:
    - "*"
"#,
    );

    let output = run_tracer_with_timeout(
        &[
            "x",
            "-p",
            policy_path.to_str().unwrap(),
            "-s",
            "malloc", // Need at least one hook for the agent to connect
            "--",
            "./direct_syscall_target",
        ],
        Duration::from_secs(30),
    );

    let _ = std::fs::remove_file(&policy_path);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let clean_stdout = strip_ansi_codes(&stdout);

    // The target should have run successfully
    assert!(
        stdout.contains("direct_syscall_target: result=")
            || stderr.contains("direct_syscall_target:"),
        "Target should have executed. stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    // Should detect the direct socket() syscall — policy deny prints "denied: syscall:socket"
    assert!(
        clean_stdout.contains("denied") && clean_stdout.contains("syscall:socket"),
        "Expected denied syscall:socket event. stdout:\n{}\nstderr:\n{}",
        clean_stdout,
        stderr
    );
}

// ============================================================================
// Negative test: normal libc calls should NOT trigger direct syscall events
// ============================================================================

#[test]
#[ignore = "syscall detection not yet implemented in malwi-hook"]
fn test_no_false_positive_direct_syscall_for_libc_calls() {
    setup();

    let policy_path = write_temp_policy(
        "negative",
        r#"
version: 1
syscalls:
  deny:
    - "*"
"#,
    );

    let output = run_tracer_with_timeout(
        &[
            "x",
            "-p",
            policy_path.to_str().unwrap(),
            "-s",
            "malloc",
            "--",
            "./simple_target",
        ],
        Duration::from_secs(30),
    );

    let _ = std::fs::remove_file(&policy_path);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let clean_stdout = strip_ansi_codes(&stdout);

    // simple_target uses libc malloc/free — should NOT generate direct syscall events
    assert!(
        !clean_stdout.contains("syscall:"),
        "Should NOT have syscall events for libc calls. stdout:\n{}\nstderr:\n{}",
        clean_stdout,
        stderr
    );

    // But should still have normal malloc traces
    assert!(
        clean_stdout.contains("malloc"),
        "Should still have normal malloc traces. stdout:\n{}\nstderr:\n{}",
        clean_stdout,
        stderr
    );
}

// ============================================================================
// Without syscalls section, syscall monitor should NOT be enabled
// ============================================================================

#[test]
fn test_no_stalker_without_syscalls_section() {
    setup();

    let policy_path = write_temp_policy(
        "nostalker",
        r#"
version: 1
symbols:
  deny:
    - malloc
"#,
    );

    let output = run_tracer_with_timeout(
        &[
            "x",
            "-p",
            policy_path.to_str().unwrap(),
            "--",
            "./direct_syscall_target",
        ],
        Duration::from_secs(15),
    );

    let _ = std::fs::remove_file(&policy_path);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let clean_stdout = strip_ansi_codes(&stdout);

    // Without syscalls section, no direct syscall events
    assert!(
        !clean_stdout.contains("syscall:"),
        "Should NOT have syscall events without syscalls section. stdout:\n{}\nstderr:\n{}",
        clean_stdout,
        stderr
    );
}
