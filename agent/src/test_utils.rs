//! Shared test utilities for the agent crate.

use std::sync::Once;

static HOOK_INIT: Once = Once::new();

/// Initialize malwi-hook for tests (once per process).
///
/// This function ensures malwi-hook is initialized exactly once, regardless of
/// how many tests call it or in what order they run. Unlike the anti-pattern of
/// calling `init()` in each test, this approach is safe for parallel test execution.
pub fn init_hook() {
    HOOK_INIT.call_once(|| {
        malwi_intercept::init();
    });
}

// Backwards-compat alias for older test code.
pub fn init_gum() {
    init_hook();
}
