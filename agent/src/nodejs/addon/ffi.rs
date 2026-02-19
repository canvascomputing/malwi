//! Addon FFI Resolution.
//!
//! This module handles:
//! 1. Resolving the addon's C FFI function pointers via dlopen/dlsym
//! 2. Exposing FFI functions for the addon to call back into Rust

use std::ffi::{c_char, CStr, CString};
use std::sync::OnceLock;

use log::{debug, warn};

use crate::nodejs::ffi::{AddFilterFn, EnableTracingFn, GetModuleVersionFn};

/// Cached addon function pointers.
pub struct AddonFfi {
    pub enable_tracing: EnableTracingFn,
    pub add_filter: AddFilterFn,
    /// Optional: returns the NODE_MODULE_VERSION the addon was built for.
    /// May be None for older addons that don't export this function.
    pub get_module_version: Option<GetModuleVersionFn>,
}

/// Addon FFI functions (resolved once after loading).
pub static ADDON_FFI: OnceLock<AddonFfi> = OnceLock::new();

/// Resolve addon FFI functions from the loaded addon.
#[cfg(unix)]
pub fn resolve_addon_ffi(addon_path: &std::path::Path) -> Option<AddonFfi> {
    debug!("Resolving addon FFI from {:?}", addon_path);

    // Use dlopen/dlsym to get the C function pointers
    unsafe {
        use std::os::unix::ffi::OsStrExt;

        let path_cstr = CString::new(addon_path.as_os_str().as_bytes()).ok()?;
        let handle = libc::dlopen(path_cstr.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        if handle.is_null() {
            let err = CStr::from_ptr(libc::dlerror());
            warn!("Failed to dlopen addon: {:?}", err);
            return None;
        }

        macro_rules! resolve_sym {
            ($name:expr, $ty:ty) => {{
                let sym_name = CString::new($name).ok()?;
                let sym = libc::dlsym(handle, sym_name.as_ptr());
                if sym.is_null() {
                    warn!("Failed to resolve {}", $name);
                    return None;
                }
                std::mem::transmute::<*mut libc::c_void, $ty>(sym)
            }};
        }

        let enable_tracing: EnableTracingFn =
            resolve_sym!("malwi_addon_enable_tracing", EnableTracingFn);
        let add_filter: AddFilterFn = resolve_sym!("malwi_addon_add_filter", AddFilterFn);

        // Optional: get_module_version (may not exist in older addons)
        let get_module_version_sym = CString::new("malwi_addon_get_module_version").ok()?;
        let get_module_version_ptr = libc::dlsym(handle, get_module_version_sym.as_ptr());
        let get_module_version: Option<GetModuleVersionFn> = if !get_module_version_ptr.is_null() {
            Some(
                std::mem::transmute::<*mut libc::c_void, GetModuleVersionFn>(
                    get_module_version_ptr,
                ),
            )
        } else {
            debug!("malwi_addon_get_module_version not found (addon may be older version)");
            None
        };

        debug!("Addon FFI functions resolved successfully");

        Some(AddonFfi {
            enable_tracing,
            add_filter,
            get_module_version,
        })
    }
}

#[cfg(windows)]
pub fn resolve_addon_ffi(_addon_path: &std::path::Path) -> Option<AddonFfi> {
    // TODO: Implement Windows support using LoadLibrary/GetProcAddress
    warn!("Windows addon FFI not yet implemented");
    None
}

// =============================================================================
// FFI EXPORTS (for addon to call back into Rust)
// =============================================================================

/// FFI struct for returning filter data to the addon.
/// Uses C-compatible layout for FFI safety.
#[repr(C)]
pub struct FilterData {
    pub pattern: *const c_char,
    pub pattern_len: u32,
    pub capture_stack: bool,
}

/// Get all Node.js filters for the addon.
///
/// This function is called by the addon to get filters that were stored
/// in the Rust agent (received via HTTP from the CLI).
///
/// # Safety
/// - `out_filters` must point to an array of at least `max_count` FilterData structs
/// - The returned pattern pointers are valid until `malwi_addon_free_filters` is called
/// - Caller must call `malwi_addon_free_filters` to free the pattern strings
///
/// # Returns
/// The number of filters written to the output array.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn malwi_addon_get_filters(out_filters: *mut FilterData, max_count: u32) -> u32 {
    if out_filters.is_null() || max_count == 0 {
        return 0;
    }

    let filters = crate::nodejs::filters::get_filters();
    let count = std::cmp::min(filters.len(), max_count as usize);

    for (i, filter) in filters.iter().take(count).enumerate() {
        // The addon wraps functions with a module prefix (e.g. "fs.readFileSync").
        // Allow users to specify bare function-name patterns ("myFunc") and have
        // them match any module by expanding to "*.myFunc" when exporting filters
        // to the addon wrapper.
        let pattern_for_addon = if filter.pattern == "*" || filter.pattern.contains('.') {
            filter.pattern.as_str().to_string()
        } else {
            format!("*.{}", filter.pattern)
        };

        // Create a CString for the pattern and leak it (caller must free)
        let pattern_cstr = match CString::new(pattern_for_addon) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let pattern_ptr = pattern_cstr.as_ptr();
        let pattern_len = unsafe { CStr::from_ptr(pattern_ptr) }.to_bytes().len() as u32;

        // Leak the CString so the pointer stays valid
        std::mem::forget(pattern_cstr);

        unsafe {
            let filter_data = out_filters.add(i);
            (*filter_data).pattern = pattern_ptr;
            (*filter_data).pattern_len = pattern_len;
            (*filter_data).capture_stack = filter.capture_stack;
        }
    }

    count as u32
}

/// Free filter pattern strings allocated by `malwi_addon_get_filters`.
///
/// # Safety
/// - `filters` must point to an array of `count` FilterData structs
/// - Each pattern pointer in the array must have been allocated by `malwi_addon_get_filters`
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn malwi_addon_free_filters(filters: *mut FilterData, count: u32) {
    if filters.is_null() || count == 0 {
        return;
    }

    for i in 0..(count as usize) {
        unsafe {
            let filter_data = filters.add(i);
            if !(*filter_data).pattern.is_null() {
                // Reconstruct the CString and drop it to free memory
                let _ = CString::from_raw((*filter_data).pattern as *mut c_char);
            }
        }
    }
}

/// Get the trace callback function pointer for the addon.
///
/// This is called by the addon to get the callback that should be used
/// for sending trace events to the Rust agent.
///
/// # Returns
/// The trace callback function pointer, cast to a generic pointer.
#[no_mangle]
pub extern "C" fn malwi_nodejs_get_trace_callback() -> *const std::ffi::c_void {
    super::malwi_nodejs_trace_callback as *const std::ffi::c_void
}
