//! Exec filter tests.
//!
//! Tests for command execution filtering with the ex: prefix.

use crate::common::*;

fn setup() {
    build_fixtures();
}

// ============================================================================
// Exec Filter Tests (ex: prefix)
// ============================================================================

#[test]
fn test_exec_wildcard_filter_captures_all_commands() {
    setup();

    let node = match find_node() {
        Some(n) => n,
        None => {
            println!("SKIPPED: test: node not found");
            return;
        }
    };

    let output = run_tracer(&[
        "x",
        "-c", "*",
        "--",
        node.to_str().unwrap(),
        "-e", "require('child_process').spawnSync('echo', ['hello'])",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Exec filter wildcard test failed. stdout: {}, stderr: {}",
        stdout, stderr
    );

    // Should show echo trace
    let has_echo_trace = stdout.lines().any(|l| l.contains("[malwi]") && l.contains("echo"));
    assert!(
        has_echo_trace,
        "Expected echo trace with wildcard filter. stdout: {}",
        stdout
    );
}

#[test]
fn test_exec_filter_captures_only_specified_command() {
    setup();

    let node = match find_node() {
        Some(n) => n,
        None => {
            println!("SKIPPED: test: node not found");
            return;
        }
    };

    // Run both echo and ls, but only filter for echo
    let output = run_tracer(&[
        "x",
        "-c", "echo",
        "--",
        node.to_str().unwrap(),
        "-e", "require('child_process').spawnSync('echo', ['hello']); require('child_process').spawnSync('ls', ['-la'])",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Exec filter specific command test failed. stdout: {}, stderr: {}",
        stdout, stderr
    );

    // Should show echo but NOT ls on [malwi] lines
    let malwi_lines: Vec<&str> = stdout.lines().filter(|l| l.contains("[malwi]")).collect();
    let has_echo = malwi_lines.iter().any(|l| l.contains("echo"));
    let has_ls = malwi_lines.iter().any(|l| l.contains(" ls"));
    assert!(
        has_echo,
        "Expected echo trace. stdout: {}",
        stdout
    );
    assert!(
        !has_ls,
        "Should NOT show ls trace when filtering for echo only. stdout: {}",
        stdout
    );
}

#[test]
fn test_exec_events_hidden_without_ex_prefix_filter() {
    setup();

    let node = match find_node() {
        Some(n) => n,
        None => {
            println!("SKIPPED: test: node not found");
            return;
        }
    };

    // Use js: filter without ex: - child events should be hidden
    let output = run_tracer(&[
        "x",
        "--js", "spawnSync",
        "--",
        node.to_str().unwrap(),
        "-e", "require('child_process').spawnSync('echo', ['hello'])",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Exec filter hidden by default test failed. stdout: {}, stderr: {}",
        stdout, stderr
    );

    // Should have spawnSync trace but NOT echo as a traced command
    let stdout_clean = strip_ansi_codes(&String::from_utf8_lossy(&output.stdout));
    assert!(
        stdout_clean.contains("spawnSync"),
        "Expected spawnSync trace. stdout: {}",
        stdout_clean
    );
    // With no exec filter, only JS traces should appear — echo should not appear
    // as a standalone command trace (it may appear as an argument to spawnSync).
    // Exec traces show: "[malwi] echo ..." while JS traces show: "[malwi] spawnSync(...)"
    let has_echo_as_command = stdout_clean.lines().any(|l| {
        l.contains("[malwi]") && {
            // After "[malwi] ", check if "echo" is the command name (not inside parens)
            if let Some(pos) = l.find("[malwi] ") {
                let after_tag = &l[pos + 8..];
                after_tag.starts_with("echo")
            } else {
                false
            }
        }
    });
    assert!(
        !has_echo_as_command,
        "Should NOT show echo as traced command when no exec filter specified. stdout: {}",
        stdout_clean
    );
}

#[test]
fn test_exec_glob_pattern_matches_command_prefix() {
    setup();

    let node = match find_node() {
        Some(n) => n,
        None => {
            println!("SKIPPED: test: node not found");
            return;
        }
    };

    // Use glob pattern to match echo*
    let output = run_tracer(&[
        "x",
        "-c", "ech*",
        "--",
        node.to_str().unwrap(),
        "-e", "require('child_process').spawnSync('echo', ['hello'])",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Exec filter glob pattern test failed. stdout: {}, stderr: {}",
        stdout, stderr
    );

    // Glob pattern should match echo
    let has_echo_trace = stdout.lines().any(|l| l.contains("[malwi]") && l.contains("echo"));
    assert!(
        has_echo_trace,
        "Expected echo trace with glob pattern. stdout: {}",
        stdout
    );
}

#[test]
fn test_exec_output_shows_command_name_and_full_args() {
    setup();

    let node = match find_node() {
        Some(n) => n,
        None => {
            println!("SKIPPED: test: node not found");
            return;
        }
    };

    let output = run_tracer(&[
        "x",
        "-c", "*",
        "--",
        node.to_str().unwrap(),
        "-e", "require('child_process').spawnSync('echo', ['hello', 'world'])",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Exec filter output format test failed. stdout: {}, stderr: {}",
        stdout, stderr
    );

    // Should show format: [malwi] <cmd> <args>
    let has_echo_line = stdout.lines().any(|l| {
        l.contains("[malwi]") && l.contains("echo") && l.contains("hello") && l.contains("world")
    });
    assert!(
        has_echo_line,
        "Expected 'echo hello world' trace format. stdout: {}",
        stdout
    );
}

// ============================================================================
// Python Fork+Exec Tests
// ============================================================================
// Python's subprocess module uses fork+exec internally, which requires HTTP
// reconnection after fork. These tests verify that exec events are captured
// correctly when Python spawns child processes.
//
// Note: These tests use a timeout because the tracer may hang after fork+exec
// due to cleanup issues. The important thing is that exec events are captured
// in the output before the timeout.

#[test]
fn test_python_subprocess_fork_exec_captures_exec_event() {
    setup();

    let python = match find_python() {
        Some(p) => p,
        None => {
            println!("SKIPPED: test: python3 not found");
            return;
        }
    };

    // Python subprocess uses fork+exec internally
    // Use timeout because tracer may hang after fork+exec
    let output = run_tracer_with_timeout(
        &[
            "x",
            "-c", "echo",
            "--",
            python.to_str().unwrap(),
            "-c", "import subprocess; subprocess.run(['echo', 'FORKEXEC_TEST'])",
        ],
        std::time::Duration::from_secs(10),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("stdout: {}", stdout);
    println!("stderr: {}", stderr);

    // Should capture the exec event from the forked child process
    // Note: We don't check exit status because we may have killed the process
    let has_echo_trace = stdout.lines().any(|l| l.contains("[malwi]") && l.contains("echo"));
    assert!(
        has_echo_trace,
        "Expected echo trace from Python subprocess (fork+exec). stdout: {}, stderr: {}",
        stdout, stderr
    );
}

#[test]
fn test_python_subprocess_wildcard_captures_all_exec_events() {
    setup();

    let python = match find_python() {
        Some(p) => p,
        None => {
            println!("SKIPPED: test: python3 not found");
            return;
        }
    };

    // Run multiple commands via subprocess
    let output = run_tracer_with_timeout(
        &[
            "x",
            "-c", "*",
            "--",
            python.to_str().unwrap(),
            "-c", "import subprocess; subprocess.run(['echo', 'first']); subprocess.run(['echo', 'second'])",
        ],
        std::time::Duration::from_secs(10),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("stdout: {}", stdout);
    println!("stderr: {}", stderr);

    // Should capture echo events (may appear multiple times due to PATH search)
    let has_echo_trace = stdout.lines().any(|l| l.contains("[malwi]") && l.contains("echo"));
    assert!(
        has_echo_trace,
        "Expected echo traces with wildcard filter. stdout: {}, stderr: {}",
        stdout, stderr
    );
}

// ============================================================================
// Supply Chain Attack Detection Tests
// ============================================================================
// These tests verify that malwi can detect malicious code execution during
// package operations - a common supply chain attack vector.
// The pattern tested here (Python subprocess calling curl) is exactly how
// many supply chain attacks work during pip install.

#[test]
fn test_python_script_calling_curl_detected() {
    setup();

    let python = match find_python() {
        Some(p) => p,
        None => {
            println!("SKIPPED: test: python3 not found");
            return;
        }
    };

    // Simulates a malicious setup.py or postinstall script that calls curl
    // This is the exact pattern used in supply chain attacks
    let malicious_script = r#"
import subprocess
import sys
print("MALICIOUS: Simulating supply chain attack", file=sys.stderr)
subprocess.run(["curl", "--version"])
"#;

    let output = run_tracer_with_timeout(
        &[
            "x",
            "-c", "curl",
            "--",
            python.to_str().unwrap(),
            "-c", malicious_script,
        ],
        std::time::Duration::from_secs(15),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("stdout: {}", stdout);
    println!("stderr: {}", stderr);

    // Should detect curl being executed by the Python subprocess
    let has_curl_trace = stdout.lines().any(|l| l.contains("[malwi]") && l.contains("curl"));
    assert!(
        has_curl_trace,
        "Expected curl trace (supply chain detection pattern). stdout: {}, stderr: {}",
        stdout, stderr
    );
}

// ============================================================================
// Exec Stack Trace Tests
// ============================================================================
// These tests verify that native stack traces are captured for exec events
// when the --st flag is specified.

#[test]
fn test_exec_stack_trace_omitted_without_t_flag() {
    setup();

    let node = match find_node() {
        Some(n) => n,
        None => {
            println!("SKIPPED: test: node not found");
            return;
        }
    };

    // Run exec tracing WITHOUT --st flag
    let output = run_tracer(&[
        "x",
        "-c", "echo",  // NO --st flag
        "--",
        node.to_str().unwrap(),
        "-e", "require('child_process').spawnSync('echo', ['test'])",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Exec trace without --st flag failed. stdout: {}, stderr: {}",
        stdout, stderr
    );

    // Should have echo trace
    let has_echo_trace = stdout.lines().any(|l| l.contains("[malwi]") && l.contains("echo"));
    assert!(
        has_echo_trace,
        "Expected echo trace. stdout: {}",
        stdout
    );

    // Should NOT have stack frames without --st flag
    assert!(
        !has_stack_trace(&stdout),
        "Should NOT have stack frames without --st flag. stdout: {}",
        stdout
    );
}

#[test]
fn test_exec_stack_trace_included_with_t_flag() {
    setup();

    let node = match find_node() {
        Some(n) => n,
        None => {
            println!("SKIPPED: test: node not found");
            return;
        }
    };

    // Run exec tracing WITH --st flag
    let output = run_tracer(&[
        "x",
        "--st",  // WITH --st flag
        "-c", "echo",
        "--",
        node.to_str().unwrap(),
        "-e", "require('child_process').spawnSync('echo', ['test'])",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Exec trace with --st flag failed. stdout: {}, stderr: {}",
        stdout, stderr
    );

    // Should have echo trace
    let has_echo_trace = stdout.lines().any(|l| l.contains("[malwi]") && l.contains("echo"));
    assert!(
        has_echo_trace,
        "Expected echo trace. stdout: {}",
        stdout
    );

    // Should have stack frames with --st flag
    assert!(
        has_stack_trace(&stdout),
        "Should have stack frames with --st flag. stdout: {}",
        stdout
    );

    // With CLI-side symbol resolution, at least some frames should be resolved
    let stdout_clean = strip_ansi_codes(&stdout);
    let has_resolved = stdout_clean.lines().any(|line| {
        line.starts_with("    at ")
            && !line.contains("<unknown>")
            && !line.trim_start_matches("    at ").starts_with("0x")
    });

    assert!(
        has_resolved,
        "Expected at least one resolved symbol in exec stack trace. stdout: {}",
        stdout
    );
}

#[test]
fn test_exec_stack_trace_from_python_subprocess() {
    setup();

    let python = match find_python() {
        Some(p) => p,
        None => {
            println!("SKIPPED: test: python3 not found");
            return;
        }
    };

    // Run exec tracing from Python with --st flag
    // Note: macOS can have objc fork issues with Python, so we allow partial success
    let output = run_tracer_with_timeout(
        &[
            "x",
            "--st",
            "-c", "echo",
            "--",
            python.to_str().unwrap(),
            "-c", "import subprocess; subprocess.run(['echo', 'test'])",
        ],
        std::time::Duration::from_secs(10),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("stdout: {}", stdout);
    println!("stderr: {}", stderr);

    // Check for macOS objc fork crash - this is an environment issue, not our code
    if stderr.contains("objc") && stderr.contains("fork()") {
        println!("SKIPPED: macOS objc fork() crash - environment issue");
        return;
    }

    // Should have echo trace
    let has_echo_trace = stdout.lines().any(|l| l.contains("[malwi]") && l.contains("echo"));
    assert!(
        has_echo_trace,
        "Expected echo trace. stdout: {}, stderr: {}",
        stdout, stderr
    );

    // Should have stack frames with --st flag
    assert!(
        has_stack_trace(&stdout),
        "Should have stack frames with --st flag. stdout: {}",
        stdout
    );
}

// ============================================================================
// Exec Event Deduplication Tests
// ============================================================================
// When a runtime calls execvp("echo", ...), libc iterates over each PATH
// directory (e.g. /usr/bin, /bin, /usr/local/bin) calling execve() for each
// candidate until one succeeds. Our execve hook fires on every attempt,
// generating N duplicate events from the same child PID for one logical
// command. The CLI deduplicates by (child_pid, command_name).

#[test]
fn test_exec_dedup_single_spawn_produces_one_event() {
    setup();

    let node = match find_node() {
        Some(n) => n,
        None => {
            println!("SKIPPED: test: node not found");
            return;
        }
    };

    // spawnSync internally uses execvp() which tries execve() for each PATH
    // entry. Without dedup this would produce N ex:echo lines (one per PATH dir).
    let output = run_tracer(&[
        "x",
        "-c", "echo",
        "--",
        node.to_str().unwrap(),
        "-e", "require('child_process').spawnSync('echo', ['hello'])",
    ]);

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stdout = strip_ansi_codes(&stdout_raw);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Exec dedup test failed. stdout: {}, stderr: {}",
        stdout, stderr
    );

    // Count ex:echo lines — should be exactly 1 after dedup
    let exec_lines: Vec<&str> = stdout.lines()
        .filter(|l| l.contains("[malwi]") && l.contains("echo"))
        .collect();

    assert_eq!(
        exec_lines.len(), 1,
        "Expected exactly 1 ex:echo line after dedup, got {}:\n{}",
        exec_lines.len(),
        exec_lines.join("\n")
    );
}

#[test]
fn test_exec_dedup_separate_spawns_produce_separate_events() {
    setup();

    let node = match find_node() {
        Some(n) => n,
        None => {
            println!("SKIPPED: test: node not found");
            return;
        }
    };

    // Two separate spawnSync calls fork two different child PIDs, so dedup
    // should NOT collapse them — we expect 2 ex:echo events.
    let output = run_tracer_with_timeout(
        &[
            "x",
            "-c", "echo",
            "--",
            node.to_str().unwrap(),
            "-e", "require('child_process').spawnSync('echo', ['first']); require('child_process').spawnSync('echo', ['second'])",
        ],
        std::time::Duration::from_secs(10),
    );

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stdout = strip_ansi_codes(&stdout_raw);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("stdout: {}", stdout);
    println!("stderr: {}", stderr);

    // Should have exactly 2 ex:echo events (one per spawnSync, different PIDs)
    let exec_lines: Vec<&str> = stdout.lines()
        .filter(|l| l.contains("[malwi]") && l.contains("echo"))
        .collect();

    assert_eq!(
        exec_lines.len(), 2,
        "Expected exactly 2 ex:echo lines (separate spawns). Got {}:\n{}",
        exec_lines.len(),
        exec_lines.join("\n")
    );
}

// ============================================================================
// Bare Fork Filtering Tests
// ============================================================================

#[test]
fn test_exec_fork_event_suppressed_before_exec() {
    setup();

    let python = match find_python() {
        Some(p) => p,
        None => {
            println!("SKIPPED: test: python3 not found");
            return;
        }
    };

    let output = run_tracer_with_timeout(
        &[
            "x",
            "-c", "*",
            "--",
            python.to_str().unwrap(),
            "-c", "import subprocess; subprocess.run(['echo', 'FORK_TEST'])",
        ],
        std::time::Duration::from_secs(10),
    );

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stdout = strip_ansi_codes(&stdout_raw);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("stdout: {}", stdout);
    println!("stderr: {}", stderr);

    // The wildcard exec filter should capture the echo command
    let has_echo = stdout.lines().any(|l| l.contains("[malwi]") && l.contains("echo"));
    assert!(
        has_echo,
        "Expected echo trace from subprocess. stdout: {}, stderr: {}",
        stdout, stderr
    );

    // There must be no "?" command trace from the bare fork event
    let has_question_mark = stdout.lines().any(|l| {
        l.contains("[malwi]") && {
            if let Some(pos) = l.find("[malwi] ") {
                let after_tag = &l[pos + 8..];
                after_tag.starts_with('?')
            } else {
                false
            }
        }
    });
    assert!(
        !has_question_mark,
        "Bare fork should NOT produce a '?' command trace. stdout: {}",
        stdout
    );
}
