//! Node.js Filter Management - Coordination Layer.
//!
//! This module coordinates Node.js tracing initialization and filter management.
//! The actual implementation is in the addon/ submodule:
//!
//! - `addon/`: Addon embedding, extraction, callback, FFI, and loading
//!
//! ## Architecture
//!
//! Node.js tracing uses an N-API addon for function wrapping:
//! - The addon wraps JavaScript functions with C++ wrappers
//! - Arguments are captured via napi_get_cb_info()
//! - Events are sent to Rust via a C callback
//! - Addon is injected via Script::Run hook when Node.js starts executing JavaScript

use std::ffi::CString;
use std::sync::LazyLock;

use log::debug;

use super::addon;
use super::state::AddonPhase;
use crate::tracing::FilterManager;

// =============================================================================
// FILTERS
// =============================================================================

/// Node.js filter manager using the shared FilterManager.
static NODEJS_FILTERS: LazyLock<FilterManager> = LazyLock::new(|| {
    FilterManager::with_callback(
        "Nodejs",
        Box::new(|pattern, capture_stack| {
            // Forward to addon if loaded
            if let Some(ffi) = addon::ADDON_FFI.get() {
                if let Ok(c_pattern) = CString::new(pattern) {
                    let count = unsafe { (ffi.add_filter)(c_pattern.as_ptr(), capture_stack) };
                    debug!("Forwarded filter to addon: {} functions wrapped", count);
                }
            }
        }),
    )
});

/// Add a Node.js function pattern to the filter list.
pub fn add_filter(pattern: &str, capture_stack: bool) {
    NODEJS_FILTERS.add(pattern, capture_stack);
}

/// Check if any Node.js filters are registered.
pub fn has_filters() -> bool {
    NODEJS_FILTERS.has_any()
}

/// Check if function name matches any filter.
/// Returns (matches, capture_stack).
pub fn check_filter(name: &str) -> (bool, bool) {
    NODEJS_FILTERS.check(name)
}

/// Get a copy of all registered filters.
pub fn get_filters() -> Vec<crate::tracing::Filter> {
    NODEJS_FILTERS.get_all()
}

// =============================================================================
// THREAD ID
// =============================================================================

/// Get the current thread ID using the shared tracing module.
pub fn get_thread_id() -> u64 {
    crate::tracing::thread::id()
}

// =============================================================================
// INITIALIZATION
// =============================================================================

/// Initialize Node.js JavaScript tracing via addon.
///
/// Uses NODE_OPTIONS --require preloading.
pub fn initialize() -> bool {
    if !AddonPhase::advance(AddonPhase::Uninitialized, AddonPhase::Initializing) {
        return AddonPhase::current() >= AddonPhase::Initializing;
    }

    let result = addon::node_options_initialize();

    if !result {
        AddonPhase::reset_to(AddonPhase::Initializing, AddonPhase::Uninitialized);
    }

    result
}
