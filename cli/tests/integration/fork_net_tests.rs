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

/// Build args for tracing network symbols + marker function.
pub(crate) fn net_trace_args(mode: &str) -> Vec<&str> {
    vec![
        "x",
        "-s",
        "getaddrinfo",
        "-s",
        "socket",
        "-s",
        "connect",
        "-s",
        "daemon_net_marker",
        "--",
        "./daemon_net",
        mode,
    ]
}

/// Check that network-related symbols appear in trace output.
pub(crate) fn assert_has_network_traces(output: &str, context: &str) {
    let clean = strip_ansi_codes(output);
    let has_marker = clean
        .lines()
        .any(|l| l.contains("[malwi]") && l.contains("daemon_net_marker"));
    assert!(
        has_marker,
        "Expected daemon_net_marker trace event. {context}\nOutput:\n{output}"
    );

    // At least one network symbol should appear (getaddrinfo, socket, or connect)
    let has_net = clean.lines().any(|l| {
        l.contains("[malwi]")
            && (l.contains("getaddrinfo") || l.contains("socket") || l.contains("connect"))
    });
    assert!(
        has_net,
        "Expected network symbol trace event (getaddrinfo/socket/connect). {context}\nOutput:\n{output}"
    );
}

/// Fork, child does network calls, parent waits.
#[test]
fn test_fork_connect_traces_network_symbols() {
    setup();

    let args = net_trace_args("fork-connect");
    let output = run_tracer(&args);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "fork-connect failed. stdout: {stdout}, stderr: {stderr}"
    );

    assert_has_network_traces(&stdout, "mode=fork-connect");
}

/// Fork, child spawns thread with network calls, parent waits.
#[test]
fn test_fork_thread_connect_traces_network_from_thread() {
    setup();

    let args = net_trace_args("fork-thread-connect");
    let output = run_tracer(&args);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "fork-thread-connect failed. stdout: {stdout}, stderr: {stderr}"
    );

    assert_has_network_traces(&stdout, "mode=fork-thread-connect");
}

/// Fork 3 children, each does network calls concurrently, parent waits.
#[test]
fn test_fork_multi_connect_traces_all_children() {
    setup();

    let args = net_trace_args("fork-multi-connect");
    let output = run_tracer(&args);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "fork-multi-connect failed. stdout: {stdout}, stderr: {stderr}"
    );

    assert_has_network_traces(&stdout, "mode=fork-multi-connect");
}
