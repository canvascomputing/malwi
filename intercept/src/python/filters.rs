//! Python filter management.
//!
//! Manages the filter patterns used to match Python function names.
//! Uses the shared FilterManager from tracing module.

use std::sync::LazyLock;

use log::debug;

use crate::tracing::FilterManager;

use super::profile::register_profile_hook_with_gil;
use super::{is_loaded, PROFILE_HOOK_REGISTERED};

use std::sync::atomic::Ordering;

/// Python filter manager using the shared FilterManager.
/// The callback eagerly registers the profile hook when filters are added.
pub static PYTHON_FILTERS: LazyLock<FilterManager> = LazyLock::new(|| {
    FilterManager::with_callback(
        "Python",
        Box::new(|_pattern, _capture_stack| {
            // Eagerly register profile hook now that we have filters
            // This ensures fast scripts are traced before they complete
            if is_loaded() && !PROFILE_HOOK_REGISTERED.load(Ordering::SeqCst) {
                debug!("Eagerly registering profile hook after filter added");
                register_profile_hook_with_gil();
            }
        }),
    )
});

/// Check if qualified function name matches any registered filter (with glob support).
/// Returns (matches, capture_stack) - whether pattern matches and if stack should be captured.
pub fn matches_filter(qualified_name: &str) -> (bool, bool) {
    PYTHON_FILTERS.check(qualified_name)
}

/// Add a Python function pattern to the filter list.
/// Supports glob patterns like "os.*" or "*.spawn".
/// Eagerly registers the profile hook if Python is loaded (via FilterManager callback).
///
/// # Arguments
/// * `pattern` - Glob pattern to match function names
/// * `capture_stack` - Whether to capture Python call stack for matched functions
pub fn add_filter(pattern: &str, capture_stack: bool) {
    // FilterManager callback handles eager profile hook registration
    PYTHON_FILTERS.add(pattern, capture_stack);
}

/// Check if any filters are registered or envvar monitoring is active.
///
/// The envvar monitoring check is needed because `enable_envvar_monitoring()`
/// does not add a filter to PYTHON_FILTERS — adding `_Environ.__getitem__`
/// as a filter caused `register_pending_hooks()` to call
/// `PyImport_ImportModule("_Environ")`, which crashes on Python 3.10 since
/// `_Environ` is not a top-level importable module. Instead, envvar
/// monitoring registers the profile hook directly and signals its presence
/// here so the audit hook's deferred registration path still triggers.
pub fn has_any_filters() -> bool {
    PYTHON_FILTERS.has_any() || super::is_envvar_monitoring_enabled()
}
