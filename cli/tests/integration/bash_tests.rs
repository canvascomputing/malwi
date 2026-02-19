//! Bash execution tracing tests.
//!
//! Tests for bash-specific hooks: shell_execve, eval_builtin, source_builtin.
//! Requires custom non-SIP bash binaries in MALWI_TEST_BINARIES.
//!
//! Note: `echo` is a bash builtin and does NOT go through shell_execve.
//! Tests use external commands like `cat`, `ls`, `true` to verify shell_execve hook.

use std::io::Write;
use std::path::PathBuf;

use crate::common::*;
use crate::skip_if_no_bash;

fn setup() {
    build_fixtures();
}

static POLICY_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Write a temporary policy YAML file and return its path.
fn write_temp_policy(content: &str) -> (PathBuf, std::fs::File) {
    let dir = std::env::temp_dir();
    let id = POLICY_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = dir.join(format!(
        "malwi-bash-test-policy-{}-{}.yaml",
        std::process::id(),
        id
    ));
    let mut f = std::fs::File::create(&path).expect("failed to create temp policy file");
    f.write_all(content.as_bytes())
        .expect("failed to write policy");
    f.flush().expect("failed to flush policy");
    (path, f)
}

// ============================================================================
// External Command Tracing via shell_execve
// ============================================================================

#[test]
fn test_bash_traces_external_command() {
    setup();

    skip_if_no_bash!(bash => {
        // Use cat (external command) — echo is a bash builtin and skips shell_execve
        let output = run_tracer_with_timeout(
            &[
                "x",
                "-c", "*",
                "--",
                bash.to_str().unwrap(),
                "-c", "cat /dev/null",
            ],
            std::time::Duration::from_secs(10),
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        let has_cat_trace = stdout.lines().any(|l| l.contains("[malwi]") && l.contains("cat"));
        assert!(
            has_cat_trace,
            "Expected cat trace from bash shell_execve. stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}

#[test]
fn test_bash_traces_command_with_args() {
    setup();

    skip_if_no_bash!(bash => {
        let output = run_tracer_with_timeout(
            &[
                "x",
                "-c", "*",
                "--",
                bash.to_str().unwrap(),
                "-c", "ls /tmp",
            ],
            std::time::Duration::from_secs(10),
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        let has_ls_trace = stdout.lines().any(|l| l.contains("[malwi]") && l.contains(" ls"));
        assert!(
            has_ls_trace,
            "Expected ls trace. stdout: {}",
            stdout
        );
    });
}

#[test]
fn test_bash_traces_compound_commands() {
    setup();

    skip_if_no_bash!(bash => {
        // Use external true and cat — both go through shell_execve
        let output = run_tracer_with_timeout(
            &[
                "x",
                "-c", "*",
                "--",
                bash.to_str().unwrap(),
                "-c", "cat /dev/null && ls /dev/null",
            ],
            std::time::Duration::from_secs(10),
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        // Both commands should be traced
        let has_cat_trace = stdout.lines().any(|l| l.contains("[malwi]") && l.contains("cat"));
        let has_ls_trace = stdout.lines().any(|l| l.contains("[malwi]") && l.contains(" ls"));
        assert!(
            has_cat_trace,
            "Expected cat trace in compound command. stdout: {}",
            stdout
        );
        assert!(
            has_ls_trace,
            "Expected ls trace in compound command. stdout: {}",
            stdout
        );
    });
}

#[test]
fn test_bash_traces_pipeline_commands() {
    setup();

    skip_if_no_bash!(bash => {
        // Pipeline: cat (external) piped to head (external).
        // Both are always external binaries — never bash builtins — so both
        // go through fork+exec and are intercepted on all bash versions.
        //
        // Note: Under heavy CI load, the agent's initial hook installation can race
        // with very short-lived pipeline commands on some bash builds. A small delay
        // makes the test deterministic without changing what we assert.
        let output = run_tracer_with_timeout(
            &[
                "x",
                "-c", "*",
                "--",
                bash.to_str().unwrap(),
                "-c", "/bin/sleep 0.2; cat /dev/null | head -1 /dev/null",
            ],
            std::time::Duration::from_secs(15),
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        // Both pipeline commands should be traced
        let has_cat = stdout.lines().any(|l| l.contains("[malwi]") && l.contains("cat"));
        assert!(
            has_cat,
            "Expected cat trace in pipeline. stdout: {}",
            stdout
        );
        let has_head = stdout.lines().any(|l| l.contains("[malwi]") && l.contains("head"));
        assert!(
            has_head,
            "Expected head trace in pipeline. stdout: {}",
            stdout
        );
    });
}

#[test]
fn test_bash_script_file_execution() {
    setup();

    skip_if_no_bash!(bash => {
        // Write a temporary script using external commands
        let script_path = std::env::temp_dir().join(format!(
            "malwi-bash-test-script-{}.sh",
            std::process::id()
        ));
        std::fs::write(&script_path, "#!/bin/bash\ncat /dev/null\nls /dev/null\n")
            .expect("failed to write test script");

        let output = run_tracer_with_timeout(
            &[
                "x",
                "-c", "*",
                "--",
                bash.to_str().unwrap(),
                script_path.to_str().unwrap(),
            ],
            std::time::Duration::from_secs(10),
        );

        let _ = std::fs::remove_file(&script_path);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        // Should trace external commands inside the script
        let has_cat_trace = stdout.lines().any(|l| l.contains("[malwi]") && l.contains("cat"));
        assert!(
            has_cat_trace,
            "Expected cat trace from script file. stdout: {}",
            stdout
        );
    });
}

#[test]
fn test_bash_traces_builtin_echo() {
    setup();

    skip_if_no_bash!(bash => {
        // echo is a bash builtin — traced via execute_command_internal hook
        let output = run_tracer_with_timeout(
            &[
                "x",
                "-c", "*",
                "--",
                bash.to_str().unwrap(),
                "-c", "echo from_builtin",
            ],
            std::time::Duration::from_secs(10),
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        let has_echo_trace = stdout.lines().any(|l| l.contains("[malwi]") && l.contains("echo"));
        assert!(
            has_echo_trace,
            "Expected echo trace for builtin echo. stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}

#[test]
fn test_bash_traces_builtin_cd() {
    setup();

    skip_if_no_bash!(bash => {
        let output = run_tracer_with_timeout(
            &[
                "x",
                "-c", "*",
                "--",
                bash.to_str().unwrap(),
                "-c", "cd /tmp",
            ],
            std::time::Duration::from_secs(10),
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        let has_cd_trace = stdout.lines().any(|l| l.contains("[malwi]") && l.contains(" cd"));
        assert!(
            has_cd_trace,
            "Expected cd trace for builtin cd. stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}

#[test]
fn test_bash_traces_builtin_export() {
    setup();

    skip_if_no_bash!(bash => {
        let output = run_tracer_with_timeout(
            &[
                "x",
                "-c", "*",
                "--",
                bash.to_str().unwrap(),
                "-c", "export FOO=bar",
            ],
            std::time::Duration::from_secs(10),
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        let has_export_trace = stdout.lines().any(|l| l.contains("[malwi]") && l.contains("export"));
        assert!(
            has_export_trace,
            "Expected export trace for builtin export. stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}

// ============================================================================
// Policy Blocking Tests
// ============================================================================

#[test]
fn test_bash_policy_blocks_denied_command() {
    setup();

    skip_if_no_bash!(bash => {
        let (policy_path, _f) =
            write_temp_policy("version: 1\ncommands:\n  deny:\n    - cat\n");

        let output = run_tracer_with_timeout(
            &[
                "x",
                "-p", policy_path.to_str().unwrap(),
                "--",
                bash.to_str().unwrap(),
                "-c", "cat /dev/null",
            ],
            std::time::Duration::from_secs(10),
        );

        let _ = std::fs::remove_file(&policy_path);

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stdout = strip_ansi_codes(&stdout_raw);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        // Should show denied message
        assert!(
            stdout.contains("denied:") && stdout.contains("cat"),
            "Expected denied message for cat. stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}

#[test]
fn test_bash_policy_allows_permitted_command() {
    setup();

    skip_if_no_bash!(bash => {
        // Policy blocks curl but allows cat
        let (policy_path, _f) =
            write_temp_policy("version: 1\ncommands:\n  deny:\n    - curl\n");

        let output = run_tracer_with_timeout(
            &[
                "x",
                "-p", policy_path.to_str().unwrap(),
                "--",
                bash.to_str().unwrap(),
                "-c", "cat /dev/null",
            ],
            std::time::Duration::from_secs(10),
        );

        let _ = std::fs::remove_file(&policy_path);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        // cat should NOT be blocked
        let stdout_clean = strip_ansi_codes(&stdout);
        assert!(
            !stdout_clean.contains("denied:"),
            "cat should NOT be blocked when only curl is denied. stdout: {}",
            stdout
        );
    });
}

// ============================================================================
// Eval Builtin Tracing
// ============================================================================

#[test]
fn test_bash_traces_eval_builtin() {
    setup();

    skip_if_no_bash!(bash => {
        let output = run_tracer_with_timeout(
            &[
                "x",
                "-c", "*",
                "--",
                bash.to_str().unwrap(),
                "-c", "eval \"echo from_eval\"",
            ],
            std::time::Duration::from_secs(10),
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        // Should trace the eval builtin
        let has_eval_trace = stdout.lines().any(|l| l.contains("[malwi]") && l.contains("eval"));
        assert!(
            has_eval_trace,
            "Expected eval trace. stdout: {}",
            stdout
        );
    });
}

#[test]
fn test_bash_policy_blocks_eval() {
    setup();

    skip_if_no_bash!(bash => {
        let (policy_path, _f) =
            write_temp_policy("version: 1\ncommands:\n  deny:\n    - eval\n");

        let output = run_tracer_with_timeout(
            &[
                "x",
                "-p", policy_path.to_str().unwrap(),
                "--",
                bash.to_str().unwrap(),
                "-c", "eval \"echo should_not_run\"",
            ],
            std::time::Duration::from_secs(10),
        );

        let _ = std::fs::remove_file(&policy_path);

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stdout = strip_ansi_codes(&stdout_raw);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        // Should show denied for eval
        assert!(
            stdout.contains("denied:") && stdout.contains("eval"),
            "Expected denied message for eval. stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}

// ============================================================================
// Source Builtin Tracing
// ============================================================================

#[test]
fn test_bash_traces_source_builtin() {
    setup();

    skip_if_no_bash!(bash => {
        // Write a temporary script to source
        let script_path = std::env::temp_dir().join(format!(
            "malwi-bash-source-test-{}.sh",
            std::process::id()
        ));
        std::fs::write(&script_path, "echo sourced\n")
            .expect("failed to write source script");

        let cmd = format!("source {}", script_path.to_str().unwrap());
        let output = run_tracer_with_timeout(
            &[
                "x",
                "-c", "*",
                "--",
                bash.to_str().unwrap(),
                "-c", &cmd,
            ],
            std::time::Duration::from_secs(10),
        );

        let _ = std::fs::remove_file(&script_path);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        // Should trace the source builtin
        let has_source_trace = stdout.lines().any(|l| l.contains("[malwi]") && l.contains("source"));
        assert!(
            has_source_trace,
            "Expected source trace. stdout: {}",
            stdout
        );
    });
}

#[test]
fn test_bash_policy_blocks_source() {
    setup();

    skip_if_no_bash!(bash => {
        let script_path = std::env::temp_dir().join(format!(
            "malwi-bash-source-block-test-{}.sh",
            std::process::id()
        ));
        std::fs::write(&script_path, "echo should_not_run\n")
            .expect("failed to write source script");

        let (policy_path, _f) =
            write_temp_policy("version: 1\ncommands:\n  deny:\n    - source\n");

        let cmd = format!("source {}", script_path.to_str().unwrap());
        let output = run_tracer_with_timeout(
            &[
                "x",
                "-p", policy_path.to_str().unwrap(),
                "--",
                bash.to_str().unwrap(),
                "-c", &cmd,
            ],
            std::time::Duration::from_secs(10),
        );

        let _ = std::fs::remove_file(&policy_path);
        let _ = std::fs::remove_file(&script_path);

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stdout = strip_ansi_codes(&stdout_raw);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        // Should show denied for source
        assert!(
            stdout.contains("denied:") && stdout.contains("source"),
            "Expected denied message for source. stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}
