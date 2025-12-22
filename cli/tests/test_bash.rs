//! Bash integration tests.
//!
//! Tests: shell_execve, eval, source, builtin tracing.
//! Multi-version: runs against all discovered Bash versions.

#[path = "integration/common/mod.rs"]
mod common;
#[path = "integration/bash_tests.rs"]
mod bash_tests;
