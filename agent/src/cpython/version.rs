//! Python version detection via Py_GetVersion().
//!
//! Since the agent runs inside the Python process, we can call Py_GetVersion()
//! directly to get the version string (e.g., "3.12.0 (main, Oct 2 2023, ...)").

use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::OnceLock;

use log::debug;

use crate::native;

/// Python version (major.minor.patch)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl Version {
    pub const fn new(major: u8, minor: u8, patch: u8) -> Self {
        Self { major, minor, patch }
    }

    /// Check if this version is at least major.minor
    pub const fn at_least(&self, major: u8, minor: u8) -> bool {
        self.major > major || (self.major == major && self.minor >= minor)
    }

    /// Parse version string like "3.12.0 (main, ...)" -> Version(3, 12, 0)
    pub fn parse(version_str: &str) -> Option<Self> {
        // Get the "3.12.0" part before any space
        let version_part = version_str.split_whitespace().next()?;
        let parts: Vec<&str> = version_part.split('.').collect();
        if parts.len() < 2 {
            return None;
        }

        let major = parts[0].parse().ok()?;
        let minor = parts[1].parse().ok()?;
        let patch = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
        Some(Self { major, minor, patch })
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Py_GetVersion() function signature
type PyGetVersionFn = unsafe extern "C" fn() -> *const c_char;

/// Cached Python version
static PYTHON_VERSION: OnceLock<Option<Version>> = OnceLock::new();

/// Get the Python version by calling Py_GetVersion().
///
/// Returns None if Python is not loaded or version cannot be parsed.
/// Result is cached after first call.
pub fn get() -> Option<Version> {
    *PYTHON_VERSION.get_or_init(|| {
        // Find Py_GetVersion symbol
        let py_get_version: PyGetVersionFn = match native::find_export(None, "Py_GetVersion") {
            Ok(addr) => unsafe { std::mem::transmute::<usize, PyGetVersionFn>(addr) },
            Err(_) => {
                debug!("Py_GetVersion not found - Python not loaded");
                return None;
            }
        };

        // Call Py_GetVersion() to get version string
        let version_ptr = unsafe { py_get_version() };
        if version_ptr.is_null() {
            debug!("Py_GetVersion returned null");
            return None;
        }

        // Convert to Rust string and parse
        let version_cstr = unsafe { CStr::from_ptr(version_ptr) };
        let version_str = match version_cstr.to_str() {
            Ok(s) => s,
            Err(_) => {
                debug!("Py_GetVersion returned invalid UTF-8");
                return None;
            }
        };

        match Version::parse(version_str) {
            Some(v) => {
                debug!("Detected Python version: {}", v);
                Some(v)
            }
            None => {
                debug!("Failed to parse Python version from: {}", version_str);
                None
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parses_full_build_string_correctly() {
        let v = Version::parse("3.12.0 (main, Oct 2 2023, 10:00:00)").unwrap();
        assert_eq!(v.major, 3);
        assert_eq!(v.minor, 12);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_version_parses_major_minor_patch_format() {
        let v = Version::parse("3.11.5").unwrap();
        assert_eq!(v.major, 3);
        assert_eq!(v.minor, 11);
        assert_eq!(v.patch, 5);
    }

    #[test]
    fn test_version_defaults_patch_to_zero_when_missing() {
        let v = Version::parse("3.9").unwrap();
        assert_eq!(v.major, 3);
        assert_eq!(v.minor, 9);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_version_at_least_compares_correctly() {
        let v312 = Version::new(3, 12, 0);
        assert!(v312.at_least(3, 12));
        assert!(v312.at_least(3, 11));
        assert!(v312.at_least(3, 9));
        assert!(!v312.at_least(3, 13));

        let v313 = Version::new(3, 13, 0);
        assert!(v313.at_least(3, 13));
        assert!(v313.at_least(3, 12));

        let v311 = Version::new(3, 11, 0);
        assert!(!v311.at_least(3, 12));
    }

    #[test]
    fn test_version_display_formats_as_major_minor_patch() {
        let v = Version::new(3, 12, 5);
        assert_eq!(format!("{}", v), "3.12.5");
    }
}
