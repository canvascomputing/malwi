//! Node.js Filter Management.
//!
//! Manages Node.js function tracing filters and coordinates addon extraction.
//! The addon is extracted for stack parser FFI access via dlopen — no N-API wrapping.

use std::sync::LazyLock;

use super::addon;
use crate::tracing::FilterManager;

// =============================================================================
// FILTERS
// =============================================================================

/// Node.js filter manager using the shared FilterManager.
static NODEJS_FILTERS: LazyLock<FilterManager> = LazyLock::new(|| FilterManager::new("Nodejs"));

/// Add a Node.js function pattern to the filter list.
pub fn add_filter(pattern: &str, capture_stack: bool) {
    NODEJS_FILTERS.add(pattern, capture_stack);
    if capture_stack {
        super::hooks::bytecode::enable_stack_capture();
    }
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

/// Extract the V8 addon for stack parser FFI access.
pub fn initialize() -> bool {
    addon::extract_addon_for_ffi()
}
