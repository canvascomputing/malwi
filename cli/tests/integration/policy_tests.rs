//! Policy enforcement tests.
//!
//! Tests for policy-driven blocking, BLOCKED output, and proper error signaling.

use crate::common::*;
use crate::skip_if_no_bash_primary;
use crate::skip_if_no_node_primary;
use std::process::{Command, Stdio};

fn setup() {
    build_fixtures();
}

// ============================================================================
// Policy Block Tests - Exec Commands
// ============================================================================

#[test]
fn test_policy_block_exec_shows_blocked_message() {
    setup();

    skip_if_no_node_primary!(node => {
        let (policy_path, _f) = write_temp_policy("version: 1\ncommands:\n  deny:\n    - echo\n");

        let code = "require('child_process').spawnSync('echo', ['hello'])";
        let output = cmd(&format!("x -p {} -- {} -e {}", policy_path.display(), node.display(), sq(code)))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&policy_path);

        let stdout = output.stdout();
        let stderr = output.stderr();

        // Should show denied message for echo
        assert!(
            stdout.contains("denied:") && stdout.contains("echo"),
            "Expected denied message for echo. stdout: {}, stderr: {}",
            stdout,
            stderr
        );
    });
}

// ============================================================================
// Policy Block Tests - Native Functions
// ============================================================================

#[test]
fn test_policy_block_socket_terminates_instead_of_looping() {
    setup();

    skip_if_no_node_primary!(node => {
        // Policy that blocks socket
        let (policy_path, _f) = write_temp_policy(
            r#"
version: 1
symbols:
  deny:
    - socket
"#,
        );

        // Try to make a network connection — socket() will be blocked.
        // The process should fail quickly with an error, NOT loop infinitely.
        let code = "try { require('net').connect(1, '127.0.0.1'); } catch(e) {} setTimeout(() => process.exit(0), 500)";
        let output = cmd(&format!("x -p {} -- {} -e {}", policy_path.display(), node.display(), sq(code)))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&policy_path);

        let stdout = output.stdout();
        let stderr = output.stderr();

        println!("stdout lines: {}", stdout.lines().count());
        println!("stderr: {}", stderr);

        // The key assertion: the process must have completed within the timeout.
        // Before the fix (returning -1 + errno), socket() returned 0 which looks
        // like a valid fd, causing infinite retry loops that never terminated.
        // Now socket() fails with EACCES, so node sees the error and stops retrying.
        // We verify at least one denied message appeared.
        assert!(
            stdout.contains("denied: socket(AF_INET, SOCK_STREAM"),
            "Expected denied socket(AF_INET, SOCK_STREAM) message. stdout: {}, stderr: {}",
            stdout,
            stderr
        );

        // The process should have exited (not been killed by timeout).
        // This confirms the socket error propagated correctly.
        assert!(
            output.success() || output.inner.status.code().is_some(),
            "Process should have exited normally, not been killed. stderr: {}",
            stderr
        );
    });
}

// ============================================================================
// V8 Optimized Frame Crash Tests
// ============================================================================

#[test]
fn test_nodejs_execsync_does_not_crash_v8() {
    setup();

    skip_if_no_node_primary!(node => {
        // This scenario previously crashed V8 with:
        //   "Missing deoptimization information for OptimizedFrame::Summarize"
        // The crash happened because CurrentStackTrace tried to walk through
        // TurboFan-optimized frames that lacked deopt metadata.
        let code = "require('child_process').execSync('echo test').toString()";
        let output = cmd(&format!("x --js * -- {} -e {}", node.display(), sq(code)))
            .timeout(secs(15)).run();

        let stdout = output.stdout_raw();
        let stderr = output.stderr();

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
        assert!(
            !stderr.contains("maybe_code"),
            "V8 GC crash in InnerPointerToCodeCache. stderr: {}",
            stderr
        );

        // Should complete successfully
        assert!(
            output.success(),
            "execSync test should succeed. stdout: {}, stderr: {}",
            stdout,
            stderr
        );
    });
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

    skip_if_no_node_primary!(node => {
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

        let port_str = port.to_string();
        let code = "require('child_process').spawnSync('echo', ['hello'])";
        let tracer_output = cmd(&format!("x --monitor --monitor-port {} -p {} -- {} -e {}",
                port_str, policy_path.display(), node.display(), sq(code)))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&policy_path);

        // Give monitor a moment to flush output, then kill it
        std::thread::sleep(std::time::Duration::from_millis(200));
        monitor.kill().ok();
        let monitor_output = monitor
            .wait_with_output()
            .expect("failed to read monitor output");

        let tracer_stdout = tracer_output.stdout();
        let monitor_stdout = strip_ansi_codes(&String::from_utf8_lossy(&monitor_output.stdout));

        // denied message should appear in monitor, not in tracer stdout
        assert!(
            monitor_stdout.contains("denied:"),
            "Expected denied message in monitor output. monitor: {}, tracer: {}",
            monitor_stdout,
            tracer_stdout
        );
        assert!(
            !tracer_stdout.contains("denied:"),
            "denied message should NOT appear in tracer stdout when --monitor is used. tracer: {}",
            tracer_stdout
        );
    });
}

// ============================================================================
// Policy Warn Tests - Exec Commands
// ============================================================================

#[test]
fn test_policy_warn_exec_shows_single_warning_with_full_command() {
    setup();

    skip_if_no_node_primary!(node => {
        // Policy with warn mode that denies echo
        let (policy_path, _f) = write_temp_policy("version: 1\ncommands:\n  warn:\n    - echo\n");

        let code = "require('child_process').spawnSync('echo', ['hello'])";
        let output = cmd(&format!("x -p {} -- {} -e {}", policy_path.display(), node.display(), sq(code)))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&policy_path);

        let stdout = output.stdout();
        let stderr = output.stderr();

        println!("stdout:\n{}", stdout);
        println!("stderr:\n{}", stderr);

        // Count [malwi] lines — should be exactly one warning line
        let malwi_lines: Vec<&str> = stdout.lines().filter(|l| l.contains("[malwi]")).collect();

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
        assert!(line.contains("echo"), "Expected 'echo' in line: {}", line);
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
    });
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

    skip_if_no_bash_primary!(bash => {
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

        let output = cmd(&format!("x -p {} -- {} {}", policy_path.display(), bash.display(), script_path.display()))
            .noninteractive().timeout(secs(8)).run();

        let _ = std::fs::remove_file(&script_path);

        let stdout = output.stdout();
        let stderr = output.stderr();

        println!("stdout:\n{}", stdout);
        println!("stderr:\n{}", stderr);

        // Malicious commands should be denied.
        // Check each; at least 2 must be denied (handles systems missing a command).
        let denied_commands = ["python3", "crontab", "base64"];
        let mut denied_count = 0;
        for cmd in &denied_commands {
            if has_denied_line(&stdout, cmd) {
                denied_count += 1;
                println!("  DENIED (expected): {}", cmd);
            } else {
                println!("  not denied: {} (may not be in PATH)", cmd);
            }
        }
        assert!(
            denied_count >= 2,
            "Expected at least 2 denied commands, got {}. Checked: {:?}\nstdout:\n{}\nstderr:\n{}",
            denied_count,
            denied_commands,
            stdout,
            stderr
        );

        // Legitimate command (mkdir) should NOT be denied.
        assert!(
            !has_denied_line(&stdout, "mkdir"),
            "mkdir should NOT be denied (it's in the allow list). stdout:\n{}",
            stdout
        );

        let _ = std::fs::remove_file(&policy_path);
    });
}

// ============================================================================
// Policy Warn Tests - EnvVar
// ============================================================================

/// Regression test for envvar warn double-logging fix.
/// Verifies that a warned envvar access produces exactly one [malwi] line,
/// not a duplicate line without the "warning:" prefix.
#[test]
fn test_policy_warn_envvar_shows_single_warning_line() {
    setup();

    skip_if_no_bash_primary!(bash => {
        let (policy_path, _f) =
            write_temp_policy("version: 1\nenvvars:\n  warn:\n    - TEST_SECRET_*\n");

        // Script that sets and reads a variable matching the warn pattern
        let script_path = std::env::temp_dir().join(format!(
            "malwi-test-envvar-warn-{}-{:x}.sh",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &script_path,
            "#!/bin/bash\nexport TEST_SECRET_KEY=sensitive\necho $TEST_SECRET_KEY\n",
        )
        .expect("write test script");

        let output = cmd(&format!("x -p {} -- {} {}", policy_path.display(), bash.display(), script_path.display()))
            .noninteractive().timeout(secs(10)).run();

        let _ = std::fs::remove_file(&script_path);
        let _ = std::fs::remove_file(&policy_path);

        let stdout = output.stdout();
        let stderr = output.stderr();

        println!("stdout:\n{}", stdout);
        println!("stderr:\n{}", stderr);

        // Count [malwi] lines that mention TEST_SECRET_KEY
        let malwi_lines: Vec<&str> = stdout
            .lines()
            .filter(|l| l.contains("[malwi]") && l.contains("TEST_SECRET_KEY"))
            .collect();

        assert!(
            !malwi_lines.is_empty(),
            "Expected at least one [malwi] warning line for TEST_SECRET_KEY. stdout:\n{}\nstderr:\n{}",
            stdout,
            stderr
        );

        // Each [malwi] line should contain "warning:" — no duplicate without it
        for line in &malwi_lines {
            assert!(
                line.contains("warning:"),
                "Expected 'warning:' in [malwi] line (double-logging regression): {}",
                line
            );
        }
    });
}

/// Policy `review:` rules are displayed as traced events (review mode removed).
#[test]
fn test_bash_policy_review_rule_traces_command() {
    setup();

    skip_if_no_bash_primary!(bash => {
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
        std::fs::write(&script_path, script_content).expect("write test script");

        let output = cmd(&format!("x -p {} -- {} {}", policy_path.display(), bash.display(), script_path.display()))
            .timeout(secs(8)).run();

        let _ = std::fs::remove_file(&script_path);
        let _ = std::fs::remove_file(&policy_path);

        let stdout = output.stdout();
        let stderr = output.stderr();

        // Review rules produce warnings (not blocked, not silently traced)
        assert!(
            output.has_warning("chmod"),
            "Expected chmod to show as warning. stdout:\n{}\nstderr:\n{}",
            stdout,
            stderr
        );
    });
}
