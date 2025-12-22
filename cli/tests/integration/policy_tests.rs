//! Policy enforcement tests.
//!
//! Tests for policy-driven blocking, BLOCKED output, and proper error signaling.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use crate::common::*;

fn setup() {
    build_fixtures();
}

static POLICY_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Write a temporary policy YAML file and return its path.
/// Uses a unique name per call to avoid conflicts when tests run in parallel.
fn write_temp_policy(content: &str) -> (PathBuf, std::fs::File) {
    let dir = std::env::temp_dir();
    let id = POLICY_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = dir.join(format!(
        "malwi-test-policy-{}-{}.yaml",
        std::process::id(),
        id
    ));
    let mut f = std::fs::File::create(&path).expect("failed to create temp policy file");
    f.write_all(content.as_bytes()).expect("failed to write policy");
    f.flush().expect("failed to flush policy");
    (path, f)
}

// ============================================================================
// Policy Block Tests - Exec Commands
// ============================================================================

#[test]
fn test_policy_block_exec_shows_blocked_message() {
    setup();

    let node = match find_node() {
        Some(n) => n,
        None => {
            println!("SKIPPED: test: node not found");
            return;
        }
    };

    let (policy_path, _f) = write_temp_policy("version: 1\ncommands:\n  deny:\n    - echo\n");

    let output = run_tracer_with_timeout(
        &[
            "x",
            "-p", policy_path.to_str().unwrap(),
            "--",
            node.to_str().unwrap(),
            "-e", "require('child_process').spawnSync('echo', ['hello'])",
        ],
        std::time::Duration::from_secs(10),
    );

    let _ = std::fs::remove_file(&policy_path);

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stdout = strip_ansi_codes(&stdout_raw);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should show denied message for echo
    assert!(
        stdout.contains("denied:") && stdout.contains("echo"),
        "Expected denied message for echo. stdout: {}, stderr: {}",
        stdout, stderr
    );
}

// ============================================================================
// Policy Block Tests - Native Functions
// ============================================================================

#[test]
fn test_policy_block_socket_terminates_instead_of_looping() {
    setup();

    let node = match find_node() {
        Some(n) => n,
        None => {
            println!("SKIPPED: test: node not found");
            return;
        }
    };

    // Policy that blocks socket
    let (policy_path, _f) = write_temp_policy(r#"
version: 1
symbols:
  deny:
    - socket
"#);

    // Try to make a network connection — socket() will be blocked.
    // The process should fail quickly with an error, NOT loop infinitely.
    let output = run_tracer_with_timeout(
        &[
            "x",
            "-p", policy_path.to_str().unwrap(),
            "--",
            node.to_str().unwrap(),
            "-e", "try { require('net').connect(1, '127.0.0.1'); } catch(e) {} setTimeout(() => process.exit(0), 500)",
        ],
        std::time::Duration::from_secs(10),
    );

    let _ = std::fs::remove_file(&policy_path);

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stdout = strip_ansi_codes(&stdout_raw);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("stdout lines: {}", stdout.lines().count());
    println!("stderr: {}", stderr);

    // The key assertion: the process must have completed within the timeout.
    // Before the fix (returning -1 + errno), socket() returned 0 which looks
    // like a valid fd, causing infinite retry loops that never terminated.
    // Now socket() fails with EACCES, so node sees the error and stops retrying.
    // We verify at least one denied message appeared.
    let blocked_count = stdout.matches("denied:").count();
    assert!(
        blocked_count >= 1,
        "Expected at least one denied socket message (got {}). stderr: {}",
        blocked_count, stderr
    );

    // The process should have exited (not been killed by timeout).
    // This confirms the socket error propagated correctly.
    assert!(
        output.status.success() || output.status.code().is_some(),
        "Process should have exited normally, not been killed. stderr: {}",
        stderr
    );
}

// ============================================================================
// V8 Optimized Frame Crash Tests
// ============================================================================

#[test]
fn test_nodejs_execsync_does_not_crash_v8() {
    setup();

    let node = match find_node() {
        Some(n) => n,
        None => {
            println!("SKIPPED: test: node not found");
            return;
        }
    };

    // This scenario previously crashed V8 with:
    //   "Missing deoptimization information for OptimizedFrame::Summarize"
    // The crash happened because CurrentStackTrace tried to walk through
    // TurboFan-optimized frames that lacked deopt metadata.
    let output = run_tracer_with_timeout(
        &[
            "x",
            "--js", "*",
            "--",
            node.to_str().unwrap(),
            "-e", "require('child_process').execSync('echo test').toString()",
        ],
        std::time::Duration::from_secs(15),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should NOT crash with V8 fatal error
    assert!(
        !stderr.contains("Fatal error"),
        "V8 crashed with fatal error. stderr: {}",
        stderr
    );
    assert!(
        !stderr.contains("OptimizedFrame::Summarize"),
        "V8 crashed in OptimizedFrame::Summarize. stderr: {}",
        stderr
    );

    // Should complete successfully
    assert!(
        output.status.success(),
        "execSync test should succeed. stdout: {}, stderr: {}",
        stdout, stderr
    );
}

// ============================================================================
// Monitor Mode Tests
// ============================================================================

/// Find a free TCP port by binding to port 0.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

#[test]
fn test_policy_block_in_monitor_mode_sends_to_monitor() {
    setup();

    let node = match find_node() {
        Some(n) => n,
        None => {
            println!("SKIPPED: test: node not found");
            return;
        }
    };

    let port = free_port();

    // Start monitor server in the background
    let mut monitor = Command::new(tracer_binary())
        .args(["m", "--port", &port.to_string()])
        .env("MALWI_AGENT_LIB", agent_library())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn monitor");

    // Wait for monitor to be ready
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > std::time::Duration::from_secs(5) {
            monitor.kill().ok();
            panic!("Monitor server didn't start within 5 seconds");
        }
        if std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // Run tracer with --monitor and a blocking policy
    let (policy_path, _f) = write_temp_policy("version: 1\ncommands:\n  deny:\n    - echo\n");

    let tracer_output = run_tracer_with_timeout(
        &[
            "x",
            "--monitor",
            "--monitor-port", &port.to_string(),
            "-p", policy_path.to_str().unwrap(),
            "--",
            node.to_str().unwrap(),
            "-e", "require('child_process').spawnSync('echo', ['hello'])",
        ],
        std::time::Duration::from_secs(10),
    );

    let _ = std::fs::remove_file(&policy_path);

    // Give monitor a moment to flush output, then kill it
    std::thread::sleep(std::time::Duration::from_millis(200));
    monitor.kill().ok();
    let monitor_output = monitor.wait_with_output().expect("failed to read monitor output");

    let tracer_stdout = strip_ansi_codes(&String::from_utf8_lossy(&tracer_output.stdout));
    let monitor_stdout = strip_ansi_codes(&String::from_utf8_lossy(&monitor_output.stdout));

    // denied message should appear in monitor, not in tracer stdout
    assert!(
        monitor_stdout.contains("denied:"),
        "Expected denied message in monitor output. monitor: {}, tracer: {}",
        monitor_stdout, tracer_stdout
    );
    assert!(
        !tracer_stdout.contains("denied:"),
        "denied message should NOT appear in tracer stdout when --monitor is used. tracer: {}",
        tracer_stdout
    );
}

// ============================================================================
// Policy Warn Tests - Exec Commands
// ============================================================================

#[test]
fn test_policy_warn_exec_shows_single_warning_with_full_command() {
    setup();

    let node = match find_node() {
        Some(n) => n,
        None => {
            println!("SKIPPED: test: node not found");
            return;
        }
    };

    // Policy with warn mode that denies echo
    let (policy_path, _f) = write_temp_policy(
        "version: 1\ncommands:\n  warn:\n    - echo\n",
    );

    let output = run_tracer_with_timeout(
        &[
            "x",
            "-p", policy_path.to_str().unwrap(),
            "--",
            node.to_str().unwrap(),
            "-e", "require('child_process').spawnSync('echo', ['hello'])",
        ],
        std::time::Duration::from_secs(10),
    );

    let _ = std::fs::remove_file(&policy_path);

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stdout = strip_ansi_codes(&stdout_raw);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("stdout:\n{}", stdout);
    println!("stderr:\n{}", stderr);

    // Count [malwi] lines — should be exactly one warning line
    let malwi_lines: Vec<&str> = stdout.lines()
        .filter(|l| l.contains("[malwi]"))
        .collect();

    assert!(
        malwi_lines.len() == 1,
        "Expected exactly 1 [malwi] line, got {}:\n{}",
        malwi_lines.len(),
        malwi_lines.join("\n")
    );

    let line = malwi_lines[0];

    // Should contain "warning:" and the command with args
    assert!(
        line.contains("warning:"),
        "Expected 'warning:' in line: {}",
        line
    );
    assert!(
        line.contains("echo"),
        "Expected 'echo' in line: {}",
        line
    );
    assert!(
        line.contains("hello"),
        "Expected 'hello' (argument) in line: {}",
        line
    );

    // Should NOT contain parens (old review summary format)
    assert!(
        !line.contains('('),
        "Should not contain parens (old format): {}",
        line
    );

    // Should NOT contain section name or rule suffix
    assert!(
        !line.contains("commands"),
        "Should not contain section name: {}",
        line
    );
    assert!(
        !line.contains("'echo'"),
        "Should not contain quoted rule suffix: {}",
        line
    );
}

// ============================================================================
// Bash Install Policy — Malicious Script Blocking
// ============================================================================

/// Simulates a malicious install script that mixes legitimate operations
/// (mkdir, curl) with attack techniques (interpreter abuse, persistence,
/// obfuscation). Verifies that the bash-install-style
/// policy blocks the malicious commands while allowing the legitimate ones.
#[test]
fn test_bash_install_policy_blocks_malicious_script() {
    setup();

    let bash = match find_primary_bash() {
        Some(b) => b,
        None => {
            println!("SKIPPED: test: bash not found");
            return;
        }
    };

    // Compact policy covering key bash-install threat categories:
    // allow download/install tools, deny interpreters/persistence/obfuscation.
    let (policy_path, _f) = write_temp_policy(
        r#"
version: 1
commands:
  allow:
    - curl
    - wget
    - mkdir
    - git
    - chmod
    - tar
    - cp
    - "true"
    - "false"
  deny:
    - "python*"
    - perl
    - ruby
    - node
    - crontab
    - at
    - launchctl
    - base64
    - xxd
    - dig
    - nslookup
    - nc
    - ssh
    - pbcopy
"#,
    );

    // Simulated malicious install script
    let script_content = r#"#!/bin/bash
# === Legitimate operations ===
mkdir -p /tmp/malwi-test-policy-dir

# === Attack: interpreter for credential theft (S4.2) ===
python3 --version

# === Attack: persistence via cron (S3.2) ===
crontab -l

# === Attack: obfuscation tool (S4.1) ===
base64 --help
"#;
    let script_path = std::env::temp_dir().join(format!(
        "malwi-test-malicious-{}-{:x}.sh",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&script_path, script_content).expect("write test script");

    let output = run_tracer_with_timeout_noninteractive(
        &[
            "x",
            "-p",
            policy_path.to_str().unwrap(),
            "--",
            bash.to_str().unwrap(),
            script_path.to_str().unwrap(),
        ],
        std::time::Duration::from_secs(8),
    );

    let _ = std::fs::remove_file(&script_path);

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stdout = strip_ansi_codes(&stdout_raw);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("stdout:\n{}", stdout);
    println!("stderr:\n{}", stderr);

    // Malicious commands should be denied.
    // Check each; at least 2 must be denied (handles systems missing a command).
    let denied_commands = ["python3", "crontab", "base64"];
    let mut denied_count = 0;
    for cmd in &denied_commands {
        if stdout.lines().any(|l| l.contains("denied:") && l.contains(cmd)) {
            denied_count += 1;
            println!("  DENIED (expected): {}", cmd);
        } else {
            println!("  not denied: {} (may not be in PATH)", cmd);
        }
    }
    assert!(
        denied_count >= 2,
        "Expected at least 2 denied commands, got {}. Checked: {:?}\nstdout:\n{}\nstderr:\n{}",
        denied_count, denied_commands, stdout, stderr
    );

    // Legitimate command (mkdir) should NOT be denied.
    assert!(
        !stdout.lines().any(|l| l.contains("denied:") && l.contains("mkdir")),
        "mkdir should NOT be denied (it's in the allow list). stdout:\n{}",
        stdout
    );

    let _ = std::fs::remove_file(&policy_path);
}

/// Review-mode behavior should be deterministic with explicit stdin input.
#[test]
fn test_bash_install_policy_review_rule_with_stdin_decision() {
    setup();

    let bash = match find_primary_bash() {
        Some(b) => b,
        None => {
            println!("SKIPPED: test: bash not found");
            return;
        }
    };

    let (policy_path, _f) = write_temp_policy(
        r#"
version: 1
commands:
  review:
    - chmod
"#,
    );

    let script_content = r#"#!/bin/bash
chmod 755 /tmp/malwi-review-test-file
"#;
    let script_path = std::env::temp_dir().join(format!(
        "malwi-test-review-{}-{:x}.sh",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&script_path, script_content).expect("write review test script");

    let output = run_tracer_with_stdin_timeout(
        &[
            "x",
            "-p",
            policy_path.to_str().unwrap(),
            "--",
            bash.to_str().unwrap(),
            script_path.to_str().unwrap(),
        ],
        "n\n",
        std::time::Duration::from_secs(8),
    );

    let _ = std::fs::remove_file(&script_path);
    let _ = std::fs::remove_file(&policy_path);

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stdout = strip_ansi_codes(&stdout_raw);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.contains("denied:") && stdout.contains("chmod"),
        "Expected denied review decision for chmod. stdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
}
