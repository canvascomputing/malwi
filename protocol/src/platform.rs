//! Platform-specific constants and utilities.
//!
//! Centralizes platform-dependent values to avoid scattered #[cfg] blocks.

use std::path::PathBuf;

/// Library file extension for the current platform.
pub const LIB_EXTENSION: &str = if cfg!(target_os = "macos") {
    "dylib"
} else if cfg!(target_os = "windows") {
    "dll"
} else {
    "so"
};

/// Library file prefix for the current platform.
pub const LIB_PREFIX: &str = if cfg!(target_os = "windows") { "" } else { "lib" };

/// Returns the agent library filename for the current platform.
pub fn agent_lib_name() -> String {
    format!("{}malwi_agent.{}", LIB_PREFIX, LIB_EXTENSION)
}

/// Returns the platform-appropriate temp directory.
pub fn temp_dir() -> PathBuf {
    std::env::temp_dir()
}

/// Environment variable name for library preloading.
/// Returns `None` on Windows where preloading isn't supported.
pub const PRELOAD_ENV_VAR: Option<&str> = if cfg!(target_os = "macos") {
    Some("DYLD_INSERT_LIBRARIES")
} else if cfg!(target_os = "linux") {
    Some("LD_PRELOAD")
} else {
    None
};

/// Returns platform-appropriate library installation directories.
#[cfg(target_os = "macos")]
pub fn installed_lib_paths() -> Vec<PathBuf> {
    vec!["/usr/local/lib".into(), "/opt/homebrew/lib".into()]
}

/// Returns platform-appropriate library installation directories.
#[cfg(target_os = "linux")]
pub fn installed_lib_paths() -> Vec<PathBuf> {
    vec!["/usr/local/lib".into(), "/usr/lib".into()]
}

/// Returns platform-appropriate library installation directories.
/// Empty on Windows since spawn mode is not supported.
#[cfg(target_os = "windows")]
pub fn installed_lib_paths() -> Vec<PathBuf> {
    vec![]
}

/// Fallback for other platforms.
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn installed_lib_paths() -> Vec<PathBuf> {
    vec!["/usr/local/lib".into()]
}
