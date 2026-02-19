//! Python integration tests.
//!
//! Tests: sys.setprofile tracing, cross-runtime interactions.
//! Multi-version: runs against all discovered Python versions.

#[path = "integration/common/mod.rs"]
mod common;
#[path = "integration/cross_runtime_tests.rs"]
mod cross_runtime_tests;
#[path = "integration/python_tests.rs"]
mod python_tests;
