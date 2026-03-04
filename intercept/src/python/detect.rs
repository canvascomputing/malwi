//! Python process detection and version querying.

use crate::native;

/// Check if Python runtime is loaded in the process.
pub fn is_loaded() -> bool {
    native::find_export(None, "Py_GetVersion").is_ok()
}

/// Get the detected Python version, if any.
///
/// Delegates to [`super::version::get()`] which caches the result.
pub fn detected_version() -> Option<super::version::Version> {
    super::version::get()
}
