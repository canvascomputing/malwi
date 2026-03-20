//! Daemon (double-fork orphan) tracing tests.
//!
//! Tests that trace events survive the double-fork daemon pattern:
//! fork → setsid → fork → parent exits → grandchild (daemon) runs.
//!
//! The grandchild reconnects to the CLI's HTTP server via a Reconnect message,
//! allowing its trace events to be received even after the original parent exits.

use crate::common::*;
use crate::fork_net_tests::{assert_has_network_traces, net_trace_cmd};

fn setup() {
    build_fixtures();
}

/// Double-fork daemon (fork -> setsid -> fork), grandchild does network calls.
#[test]
fn test_daemon_connect_traces_network_from_daemon() {
    setup();

    let output = net_trace_cmd("daemon-connect").timeout(secs(10)).run();

    let stdout = output.stdout_raw();
    let stderr = output.stderr();

    assert_has_network_traces(&stdout, &format!("mode=daemon-connect\nstderr: {stderr}"));
}
