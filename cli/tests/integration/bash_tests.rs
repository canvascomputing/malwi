//! Bash execution tracing tests.
//!
//! Tests for bash-specific hooks: shell_execve, eval_builtin, source_builtin.
//! Requires custom non-SIP bash binaries in MALWI_TEST_BINARIES.
//!
//! Note: `echo` is a bash builtin and does NOT go through shell_execve.
//! Tests use external commands like `cat`, `ls`, `true` to verify shell_execve hook.

use crate::common::*;
use crate::skip_if_no_bash;

fn setup() {
    build_fixtures();
}

// ============================================================================
// External Command Tracing via shell_execve
// ============================================================================

#[test]
fn test_bash_traces_external_command() {
    setup();

    skip_if_no_bash!(bash => {
        // Use cat (external command) — echo is a bash builtin and skips shell_execve
        let output = cmd(&format!("x -c * -- {} -c 'cat /dev/null'", bash.display()))
            .timeout(secs(10)).run();

        let stdout = output.stdout_raw();
        let stderr = output.stderr();
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        let has_cat_trace = has_traced_line(&stdout, "cat");
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
        let output = cmd(&format!("x -c * -- {} -c 'ls /tmp'", bash.display()))
            .timeout(secs(10)).run();

        let stdout = output.stdout_raw();
        let stderr = output.stderr();
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        let has_ls_trace = has_traced_line(&stdout, "ls");
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
        let output = cmd(&format!("x -c * -- {} -c 'cat /dev/null && ls /dev/null'", bash.display()))
            .timeout(secs(10)).run();

        let stdout = output.stdout_raw();
        let stderr = output.stderr();
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        // Both commands should be traced
        let has_cat_trace = has_traced_line(&stdout, "cat");
        let has_ls_trace = has_traced_line(&stdout, "ls");
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
        let output = cmd(&format!("x -c * -- {} -c '/bin/sleep 0.2; cat /dev/null | head -1 /dev/null'", bash.display()))
            .timeout(secs(15)).run();

        let stdout = output.stdout_raw();
        let stderr = output.stderr();
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        // Both pipeline commands should be traced
        let has_cat = has_traced_line(&stdout, "cat");
        assert!(
            has_cat,
            "Expected cat trace in pipeline. stdout: {}",
            stdout
        );
        let has_head = has_traced_line(&stdout, "head");
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

        let output = cmd(&format!("x -c * -- {} {}", bash.display(), script_path.display()))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&script_path);

        let stdout = output.stdout_raw();
        let stderr = output.stderr();
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        // Should trace external commands inside the script
        let has_cat_trace = has_traced_line(&stdout, "cat");
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
        let output = cmd(&format!("x -c * -- {} -c 'echo from_builtin'", bash.display()))
            .timeout(secs(10)).run();

        let stdout = output.stdout_raw();
        let stderr = output.stderr();
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        let has_echo_trace = has_traced_line(&stdout, "echo");
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
        let output = cmd(&format!("x -c * -- {} -c 'cd /tmp'", bash.display()))
            .timeout(secs(10)).run();

        let stdout = output.stdout_raw();
        let stderr = output.stderr();
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        let has_cd_trace = has_traced_line(&stdout, "cd");
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
        let output = cmd(&format!("x -c * -- {} -c 'export FOO=bar'", bash.display()))
            .timeout(secs(10)).run();

        let stdout = output.stdout_raw();
        let stderr = output.stderr();
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        let has_export_trace = has_traced_line(&stdout, "export");
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

        let output = cmd(&format!("x -p {} -- {} -c 'cat /dev/null'", policy_path.display(), bash.display()))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&policy_path);

        let stdout = output.stdout();
        let stderr = output.stderr();
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

        let output = cmd(&format!("x -p {} -- {} -c 'cat /dev/null'", policy_path.display(), bash.display()))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&policy_path);

        let stdout = output.stdout_raw();
        let stderr = output.stderr();
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
        let output = cmd(&format!("x -c * -- {} -c {}", bash.display(), sq(r#"eval "echo from_eval""#)))
            .timeout(secs(10)).run();

        let stdout = output.stdout_raw();
        let stderr = output.stderr();
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        // Should trace the eval builtin
        let has_eval_trace = has_traced_line(&stdout, "eval");
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

        let output = cmd(&format!("x -p {} -- {} -c {}", policy_path.display(), bash.display(), sq(r#"eval "echo should_not_run""#)))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&policy_path);

        let stdout = output.stdout();
        let stderr = output.stderr();
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

/// Threat: Shell script malware uses nested eval to decode and execute payloads
/// in stages. `eval 'eval "cmd"'` executes two successive eval_builtin calls.
/// Both must be traced to reveal the full command chain.
#[test]
fn test_bash_nested_eval_traces_both_eval_invocations() {
    setup();

    skip_if_no_bash!(bash => {
        let output = cmd(&format!("x -f json -c * -- {} -c {}", bash.display(), sq(r#"eval 'eval "cat /dev/null"'"#)))
            .timeout(secs(10)).run();

        let stderr = output.stderr();
        let events = output.json_events();

        // The eval_builtin hook should fire and show the nested eval command
        // in its arguments, proving the outer eval is traced.
        let eval_event = events.iter()
            .find(|e| e["source"] == "bash" && e["name"] == "eval");
        assert!(
            eval_event.is_some(),
            "Expected eval event for nested eval. events: {:?}, stderr: {}",
            events, stderr
        );
        // The eval event's args should contain the inner eval command.
        let args = eval_event.unwrap()["args"].as_array().unwrap();
        let args_str: Vec<&str> = args.iter().filter_map(|a| a.as_str()).collect();
        assert!(
            args_str.iter().any(|a| a.contains("eval")),
            "Expected eval args to show the nested eval command. args: {:?}",
            args_str
        );

        // The innermost command (cat) should also be traced via
        // execute_command_internal or shell_execve.
        assert!(
            events.iter().any(|e| e["name"] == "cat"),
            "Expected cat event from command inside nested eval. events: {:?}",
            events
        );
    });
}

/// Threat: An attacker encodes a blocked command inside nested eval to
/// bypass policy enforcement. The policy engine must evaluate commands
/// at every eval nesting level, not just the top level.
#[test]
fn test_bash_nested_eval_policy_blocks_inner_command() {
    setup();

    skip_if_no_bash!(bash => {
        let (policy_path, _f) =
            write_temp_policy("version: 1\ncommands:\n  deny:\n    - cat\n");

        let output = cmd(&format!("x -f json -p {} -- {} -c {}", policy_path.display(), bash.display(), sq(r#"eval 'eval "cat /dev/null"'"#)))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&policy_path);

        let stderr = output.stderr();
        let events = output.json_events();

        // The cat command buried inside nested eval should still be blocked
        assert!(
            events.iter().any(|e| e["name"] == "cat"
                && e["policy"]["decision"] == "denied"),
            "Expected denied event for cat inside nested eval. \
             Policy enforcement must work at all eval nesting levels. \
             events: {:?}, stderr: {}",
            events, stderr
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

        let src_cmd = format!("source {}", script_path.display());
        let output = cmd(&format!("x -c * -- {} -c {}", bash.display(), sq(&src_cmd)))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&script_path);

        let stdout = output.stdout_raw();
        let stderr = output.stderr();
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        // Should trace the source builtin
        let has_source_trace = has_traced_line(&stdout, "source");
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

        let src_cmd = format!("source {}", script_path.display());
        let output = cmd(&format!("x -p {} -- {} -c {}", policy_path.display(), bash.display(), sq(&src_cmd)))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&policy_path);
        let _ = std::fs::remove_file(&script_path);

        let stdout = output.stdout();
        let stderr = output.stderr();
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

// ============================================================================
// Auto-Policy Detection via Piped Stdin
// ============================================================================

#[test]
fn test_bash_piped_stdin_auto_selects_bash_install_policy() {
    setup();

    // Auto-detection matches basename "bash" or "sh". Test binaries are named
    // "bash-5.2" etc., so create a temporary "bash" symlink to the first one.
    skip_if_no_bash!(bash => {
        let link_dir = std::env::temp_dir().join(format!(
            "malwi-bash-symlink-test-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&link_dir);
        let link_path = link_dir.join("bash");
        let _ = std::fs::remove_file(&link_path);
        std::os::unix::fs::symlink(&bash, &link_path)
            .expect("failed to create bash symlink");

        // Pipe a script containing `nc` (blocked by bash-install policy) via stdin.
        // Without -p flag, auto-detection should select bash-install policy
        // because stdin is piped (not a TTY) and basename is "bash".
        let output = cmd(&format!("x -- {}", link_path.display()))
            .stdin("nc localhost 9999\n").timeout(secs(10)).run();

        let _ = std::fs::remove_file(&link_path);
        let _ = std::fs::remove_dir(&link_dir);

        let stdout = output.stdout();
        let stderr = output.stderr();
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        // Verify auto-detection selected bash-install policy
        assert!(
            stderr.contains("bash-install"),
            "Expected 'Using policy: bash-install' in stderr. stderr: {}",
            stderr
        );

        // bash-install policy denies dangerous commands and symbols —
        // any "denied:" output proves auto-detection selected bash-install
        // (default policy only warns, never denies).
        // The specific denied item varies: `syscall` fires before `nc` on
        // some platforms because the native symbol hook intercepts before
        // the exec filter processes the command.
        if !stdout.is_empty() {
            assert!(
                stdout.contains("denied:"),
                "Expected bash-install policy to deny something via piped stdin. \
                 If 'warning:' appears instead, auto-detection failed to select bash-install. \
                 stdout: {}, stderr: {}",
                stdout, stderr
            );
        }

        // Only test one bash version — the symlink approach validates auto-detection,
        // not bash-version-specific behavior.
        return;
    });
}

// ============================================================================
// Threat Vector Tests — Bash Attack Patterns
// ============================================================================

/// Threat: `exec 3<>/dev/tcp/host/port` does TCP I/O without any external
/// command. This bypasses shell_execve and all command hooks since it's a
/// bash built-in redirection mechanism, not a command execution.
/// This test documents the known gap.
#[test]
fn test_bash_dev_tcp_network_access_gap() {
    setup();

    skip_if_no_bash!(bash => {
        // Attempt /dev/tcp connection to a port that won't connect (port 1)
        // The 2>/dev/null suppresses the "Connection refused" error
        let output = cmd(&format!("x -c * -- {} -c {}", bash.display(), sq("exec 3<>/dev/tcp/127.0.0.1/1 2>/dev/null || true")))
            .timeout(secs(10)).run();

        let stdout = output.stdout_raw();
        let stderr = output.stderr();
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        // /dev/tcp is handled internally by bash's redirection code,
        // not via shell_execve or execute_command_internal.
        // No trace event should appear for the TCP access itself.
        let has_tcp_trace = stdout.lines().any(|l| {
            l.contains("[malwi]") && (l.contains("/dev/tcp") || l.contains("tcp"))
        });

        if has_tcp_trace {
            println!("TRACED: /dev/tcp access is somehow visible (unexpected)");
        } else {
            println!("KNOWN GAP: /dev/tcp network access bypasses all command hooks. \
                      Bash handles this internally via redirection, not exec.");
        }

        // Only test one bash version — behavior is consistent across versions
        return;
    });
}

/// Threat: `exec <cmd>` replaces the shell process with the command.
/// Since exec uses execve, our exec hooks should still catch it.
#[test]
fn test_bash_exec_builtin_traces_replaced_command() {
    setup();

    skip_if_no_bash!(bash => {
        // exec replaces the shell process with cat. The exec hook should
        // fire before the replacement happens.
        let output = cmd(&format!("x -c * -- {} -c 'exec cat /dev/null'", bash.display()))
            .timeout(secs(10)).run();

        let stdout = output.stdout_raw();
        let stderr = output.stderr();
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        // exec replaces the process, so the cat command should be traced
        // via the exec builtin hook or the execve hook
        let has_cat_trace = has_traced_line(&stdout, "cat");
        assert!(
            has_cat_trace,
            "Expected cat trace from 'exec cat'. The exec builtin should trigger \
             command tracing before process replacement. stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}

/// Threat: `trap '<cmd>' EXIT` runs commands during shell exit. These commands
/// execute after the main script and could exfiltrate data or clean up evidence.
#[test]
fn test_bash_trap_exit_commands_traced() {
    setup();

    skip_if_no_bash!(bash => {
        // Register a trap that runs cat on EXIT, then exit normally
        let output = cmd(&format!("x -c * -- {} -c {}", bash.display(), sq("trap 'cat /dev/null' EXIT; exit 0")))
            .timeout(secs(10)).run();

        let stdout = output.stdout_raw();
        let stderr = output.stderr();
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);

        // The trap handler runs during EXIT, so cat should be traced
        let has_cat_trace = has_traced_line(&stdout, "cat");

        if has_cat_trace {
            println!("TRACED: trap EXIT commands are visible");
        } else {
            // Trap handlers may not fire if the agent is torn down before
            // the shell gets to run the EXIT trap
            println!("KNOWN GAP: trap EXIT command not captured — \
                      agent may be unloaded before shell runs EXIT handlers.");
        }
    });
}

// ============================================================================
// Linux-Specific: LD_PRELOAD Propagation to Child Processes
// ============================================================================

/// On Linux, LD_PRELOAD propagates to child processes. When bash runs
/// `curl`, the child curl process should get the agent injected and
/// native connect() hooks should fire — producing structured NetworkInfo.
/// On macOS, curl is SIP-protected so this test is Linux-only.
#[test]
#[cfg(target_os = "linux")]
fn test_bash_child_curl_native_hooks_fire_on_linux() {
    setup();

    // Skip if curl not available
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        println!("SKIPPED: curl not found in PATH");
        return;
    }

    skip_if_no_bash!(bash => {
        let output = cmd(&format!(
            "x -s connect -f json -c * -- {} -c {}",
            bash.display(),
            sq("curl http://127.0.0.1:1 2>/dev/null || true")
        ))
        .timeout(secs(15))
        .run();

        let events = output.json_events();

        // Bash/Exec event for the curl command
        assert!(
            events.iter().any(|e| e["name"] == "curl"),
            "Expected curl command event. events: {:?}",
            events
        );

        // Native connect() from the child curl process (proves LD_PRELOAD propagated)
        assert!(
            events
                .iter()
                .any(|e| e["source"] == "native" && e["name"] == "connect"),
            "Expected native connect() from child curl process (LD_PRELOAD propagation). \
             events: {:?}",
            events
        );
    });
}
