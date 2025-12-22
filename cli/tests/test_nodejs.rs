//! Node.js integration tests.
//!
//! Tests: V8 bytecode tracing, exec filtering, argument filtering.
//! Multi-version: runs against all discovered Node.js versions.

#[path = "integration/common/mod.rs"]
mod common;
#[path = "integration/nodejs_tests.rs"]
mod nodejs_tests;
#[path = "integration/exec_filter_tests.rs"]
mod exec_filter_tests;
#[path = "integration/arg_filter_tests.rs"]
mod arg_filter_tests;
