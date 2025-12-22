#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use crate::types::{ExportInfo, HookError, ModuleInfo};

#[cfg(target_os = "macos")]
mod darwin;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
pub use darwin::*;

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn enumerate_modules() -> Vec<ModuleInfo> {
    Vec::new()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn find_global_export_by_name(_symbol: &str) -> Result<usize, HookError> {
    Err(HookError::Unsupported)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn find_export_by_name(_module_name: &str, _symbol: &str) -> Result<usize, HookError> {
    Err(HookError::Unsupported)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn enumerate_exports(_module_name: &str) -> Result<Vec<ExportInfo>, HookError> {
    Err(HookError::Unsupported)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn enumerate_symbols(_module_name: &str) -> Result<Vec<ExportInfo>, HookError> {
    Err(HookError::Unsupported)
}
