//! Daemon (double-fork orphan) tracing tests.
//!
//! Tests that trace events survive the double-fork daemon pattern:
//! fork → setsid → fork → parent exits → grandchild (daemon) runs.
//!
//! The grandchild reconnects to the CLI's HTTP server via a Reconnect message,
//! allowing its trace events to be received even after the original parent exits.

use crate::common::*;
use crate::fork_net_tests::{assert_has_network_traces, net_trace_args};

fn setup() {
    build_fixtures();
}

/// Double-fork daemon (fork -> setsid -> fork), grandchild does network calls.
#[test]
fn test_daemon_connect_traces_network_from_daemon() {
    setup();

    let args = net_trace_args("daemon-connect");
    let output = run_tracer_with_timeout(&args, std::time::Duration::from_secs(10));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_has_network_traces(&stdout, &format!("mode=daemon-connect\nstderr: {stderr}"));
}
