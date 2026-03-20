//! Fork + network tracing tests.
//!
//! Tests for network symbol capture across fork, thread, and multi-child scenarios.
//!
//! Fork+hook tracing works by:
//! 1. Bypassing the dead mpsc batching channel in forked children (the flush
//!    thread doesn't survive fork) and sending events directly via HTTP.
//! 2. Reinitializing the ForkSafeMutex in the HTTP client when the underlying
//!    pthread mutex was held by a dead thread at fork time.

use crate::common::*;

fn setup() {
    build_fixtures();
}

/// Build a trace command for tracing network symbols + marker function.
pub(crate) fn net_trace_cmd(mode: &str) -> Cmd {
    cmd(&format!(
        "x -s getaddrinfo -s socket -s connect -s daemon_net_marker -- ./daemon_net {}",
        mode
    ))
}

/// Check that network-related symbols appear in trace output.
pub(crate) fn assert_has_network_traces(output: &str, context: &str) {
    let clean = strip_ansi_codes(output);
    let has_marker = has_traced_line(&clean, "daemon_net_marker");
    assert!(
        has_marker,
        "Expected daemon_net_marker trace event. {context}\nOutput:\n{output}"
    );

    // At least one network symbol should appear (getaddrinfo, socket, or connect)
    let has_net = has_traced_line(&clean, "getaddrinfo")
        || has_traced_line(&clean, "socket")
        || has_traced_line(&clean, "connect");
    assert!(
        has_net,
        "Expected network symbol trace event (getaddrinfo/socket/connect). {context}\nOutput:\n{output}"
    );
}

/// Fork, child does network calls, parent waits.
#[test]
fn test_fork_connect_traces_network_symbols() {
    setup();

    let output = net_trace_cmd("fork-connect").run();

    let stdout = output.stdout_raw();
    let stderr = output.stderr();

    assert!(
        output.success(),
        "fork-connect failed. stdout: {stdout}, stderr: {stderr}"
    );

    assert_has_network_traces(&stdout, "mode=fork-connect");
}

/// Fork, child spawns thread with network calls, parent waits.
#[test]
fn test_fork_thread_connect_traces_network_from_thread() {
    setup();

    let output = net_trace_cmd("fork-thread-connect").run();

    let stdout = output.stdout_raw();
    let stderr = output.stderr();

    assert!(
        output.success(),
        "fork-thread-connect failed. stdout: {stdout}, stderr: {stderr}"
    );

    assert_has_network_traces(&stdout, "mode=fork-thread-connect");
}

/// Fork 3 children, each does network calls concurrently, parent waits.
#[test]
fn test_fork_multi_connect_traces_all_children() {
    setup();

    let output = net_trace_cmd("fork-multi-connect").run();

    let stdout = output.stdout_raw();
    let stderr = output.stderr();

    assert!(
        output.success(),
        "fork-multi-connect failed. stdout: {stdout}, stderr: {stderr}"
    );

    assert_has_network_traces(&stdout, "mode=fork-multi-connect");
}
