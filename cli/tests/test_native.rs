//! Native function tracing integration tests.
//!
//! Tests: native symbols, child process detection, perf.
//! No runtime dependencies — fastest binary.

#[path = "integration/child_process_tests.rs"]
mod child_process_tests;
#[path = "integration/common/mod.rs"]
mod common;
#[path = "integration/daemon_tests.rs"]
mod daemon_tests;
#[path = "integration/exec_filter_tests.rs"]
mod exec_filter_tests;
#[path = "integration/fork_net_tests.rs"]
mod fork_net_tests;
#[path = "integration/native_tests.rs"]
mod native_tests;
#[path = "integration/perf_tests.rs"]
mod perf_tests;
