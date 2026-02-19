//! Policy enforcement integration tests.
//!
//! Tests: air-gap policy, HTTP tracing + policy, exploit detection, review mode, policy parsing.
//! Single-version: uses _primary! macros (policy behavior is runtime-agnostic).

#[path = "integration/air_gap_tests.rs"]
mod air_gap_tests;
#[path = "integration/common/mod.rs"]
mod common;
#[path = "integration/exploit_tests.rs"]
mod exploit_tests;
#[path = "integration/http_tests.rs"]
mod http_tests;
#[path = "integration/policy_tests.rs"]
mod policy_tests;
#[path = "integration/review_mode_tests.rs"]
mod review_mode_tests;
