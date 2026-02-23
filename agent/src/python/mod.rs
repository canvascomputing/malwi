//! Python Profiling Hook support.
//!
//! Uses Python's PyEval_SetProfile / PyEval_SetProfileAllThreads (PEP 669) to trace
//! Python function calls. Requires proper GIL management for external threads.
//!
//! ## Module Structure
//!
//! - `ffi`: Python C API types and function pointers
//! - `filters`: Filter management (PYTHON_FILTERS, matches_filter)
//! - `profile`: Profile hook registration and callback
//! - `stack`: Python stack capture
//! - `audit`: Audit hook registration (PEP 578)
//! - `format`: Argument formatting for known Python functions
//! - `helpers`: Internal helper functions for Python introspection

mod audit;
mod detect;
mod ffi;
mod filters;
pub mod format;
mod helpers;
mod hooks;
mod profile;
mod stack;
pub mod version;

use std::sync::atomic::{AtomicBool, Ordering};

/// Whether Python envvar monitoring is enabled.
static PYTHON_ENVVAR_MONITORING: AtomicBool = AtomicBool::new(false);

// Re-export items used by profile and filters modules internally
pub(crate) use profile::PROFILE_HOOK_REGISTERED;

// =============================================================================
// PUBLIC API — Standard runtime convention
// =============================================================================

pub use detect::{detected_version, is_loaded};

/// Add a Python function pattern to the filter list.
/// Supports glob patterns like "os.*" or "*.spawn".
/// Eagerly registers the profile hook if Python is loaded (via FilterManager callback).
///
/// # Arguments
/// * `pattern` - Glob pattern to match function names
/// * `capture_stack` - Whether to capture Python call stack for matched functions
pub fn add_filter(pattern: &str, capture_stack: bool) {
    filters::add_filter(pattern, capture_stack);
}

/// Check if qualified function name matches any registered filter.
/// Returns (matches, capture_stack).
pub fn check_filter(name: &str) -> (bool, bool) {
    filters::matches_filter(name)
}

/// Check if any Python filters are registered.
pub fn has_filters() -> bool {
    filters::has_any_filters()
}

/// Check if profile hook is registered.
pub fn ensure_profile_hook_registered() -> bool {
    PROFILE_HOOK_REGISTERED.load(Ordering::SeqCst)
}

/// Register audit hook (PEP 578) - for logging Python runtime events
/// and triggering deferred profile hook registration.
pub fn register_audit_hook() -> bool {
    audit::register_audit_hook()
}

/// Start a best-effort background task to register the audit hook.
///
/// This is useful when the agent is loaded very early and Python's exported
/// symbols are not visible yet.
pub fn start_audit_registration_task() {
    audit::start_audit_registration_task()
}

/// Enable Python envvar monitoring.
///
/// The profile hook handles `_Environ.__getitem__` via a direct
/// `is_envvar_monitoring_enabled()` check — no filter entry needed.
///
/// IMPORTANT: Do NOT add `_Environ.__getitem__` to PYTHON_FILTERS here.
/// An earlier implementation added it as a filter entry so that
/// `has_any_filters()` would return true and trigger profile hook
/// registration. However, filter entries are also fed to
/// `register_pending_hooks()`, which calls `PyImport_ImportModule` on
/// the module portion. `_Environ` is not a top-level importable module
/// (it is an internal class in `os.py`), and attempting to import it
/// crashes Python 3.10. Instead, this function registers the profile
/// hook directly and `has_any_filters()` checks the envvar monitoring
/// flag separately.
pub fn enable_envvar_monitoring() {
    if PYTHON_ENVVAR_MONITORING.swap(true, Ordering::SeqCst) {
        return; // Already enabled
    }
    // Register the profile hook directly — not via add_filter.
    // See doc comment above for Python 3.10 rationale.
    if is_loaded() && !PROFILE_HOOK_REGISTERED.load(Ordering::SeqCst) {
        profile::register_profile_hook_with_gil();
    }
}

/// Check if Python envvar monitoring is enabled.
pub fn is_envvar_monitoring_enabled() -> bool {
    PYTHON_ENVVAR_MONITORING.load(Ordering::SeqCst)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use malwi_protocol::glob::matches_glob;

    #[test]
    fn test_matches_glob_exact() {
        assert!(matches_glob("os.spawn", "os.spawn"));
        assert!(!matches_glob("os.spawn", "os.system"));
        assert!(!matches_glob("os.spawn", "json.loads"));
    }

    #[test]
    fn test_matches_glob_wildcard_suffix() {
        assert!(matches_glob("os.*", "os.spawn"));
        assert!(matches_glob("os.*", "os.system"));
        assert!(!matches_glob("os.*", "json.loads"));
        // Note: * matches any characters including dots
        assert!(matches_glob("os.*", "os.path.join"));
        // Use more specific pattern to match only direct children
        assert!(matches_glob("os.path.*", "os.path.join"));
        assert!(!matches_glob("os.path.*", "os.spawn"));
    }

    #[test]
    fn test_matches_glob_wildcard_prefix() {
        assert!(matches_glob("*.spawn", "os.spawn"));
        assert!(matches_glob("*.spawn", "subprocess.spawn"));
        assert!(!matches_glob("*.spawn", "os.system"));
    }

    #[test]
    fn test_matches_glob_wildcard_middle() {
        assert!(matches_glob("json.*s", "json.loads"));
        assert!(matches_glob("json.*s", "json.dumps"));
        assert!(!matches_glob("json.*s", "json.load"));
    }

    #[test]
    fn test_matches_glob_wildcard_only() {
        assert!(matches_glob("*", "anything"));
        assert!(matches_glob("*", "os.spawn"));
        assert!(matches_glob("*", ""));
    }

    #[test]
    fn test_matches_glob_multiple_wildcards() {
        assert!(matches_glob("*load*", "json.loads"));
        assert!(matches_glob("*load*", "pickle.load"));
        assert!(matches_glob("*load*", "loader"));
        assert!(!matches_glob("*load*", "json.dumps"));
    }
}
