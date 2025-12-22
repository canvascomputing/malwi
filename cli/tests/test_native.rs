//! Native function tracing integration tests.
//!
//! Tests: native symbols, child process detection, perf, direct syscalls.
//! No runtime dependencies — fastest binary.

#[path = "integration/common/mod.rs"]
mod common;
#[path = "integration/native_tests.rs"]
mod native_tests;
#[path = "integration/child_process_tests.rs"]
mod child_process_tests;
#[path = "integration/perf_tests.rs"]
mod perf_tests;
#[path = "integration/direct_syscall_tests.rs"]
mod direct_syscall_tests;
