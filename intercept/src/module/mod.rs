//! Module enumeration and symbol lookup.
//!
//! Cross-platform: works on macOS, Linux, and Windows without any
//! platform-specific parsing (Mach-O, ELF, PE).

use crate::ffi as gum;
use crate::types::{ExportInfo, HookError, ModuleInfo};
use core::ffi::c_char;

// ── Helpers ──────────────────────────────────────────────────────

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Extract a Rust `&str` from a gum `*const gchar` pointer.
///
/// # Safety
/// Pointer must be valid, NUL-terminated, or null (returns "").
unsafe fn gchar_to_str<'a>(p: *const c_char) -> &'a str {
    if p.is_null() {
        ""
    } else {
        core::ffi::CStr::from_ptr(p).to_str().unwrap_or("")
    }
}

/// Convert a `*mut GumModule` to `ModuleInfo`, then `g_object_unref` it.
///
/// # Safety
/// `module` must be a valid, non-null `GumModule*` with a floating or owned reference.
unsafe fn module_to_info(module: *mut gum::GumModule) -> ModuleInfo {
    let path_ptr = gum::gum_module_get_name(module);
    let path_str = gchar_to_str(path_ptr);
    let name = basename(path_str).to_string();

    let full_path_ptr = gum::gum_module_get_path(module);
    let full_path = gchar_to_str(full_path_ptr).to_string();

    let range = gum::gum_module_get_range(module);
    let (base, size) = if range.is_null() {
        (0, 0)
    } else {
        ((*range).base_address as usize, (*range).size as usize)
    };

    ModuleInfo {
        name,
        path: full_path,
        base_address: base,
        size,
    }
}

// ── Public API ───────────────────────────────────────────────────

pub fn enumerate_modules() -> Vec<ModuleInfo> {
    let mut out: Vec<ModuleInfo> = Vec::new();

    unsafe extern "C" fn callback(
        module: *mut gum::GumModule,
        user_data: gum::gpointer,
    ) -> gum::gboolean {
        let out = &mut *(user_data as *mut Vec<ModuleInfo>);

        let path_ptr = gum::gum_module_get_name(module);
        let path_str = gchar_to_str(path_ptr);
        let name = basename(path_str).to_string();

        let full_path_ptr = gum::gum_module_get_path(module);
        let full_path = gchar_to_str(full_path_ptr).to_string();

        let range = gum::gum_module_get_range(module);
        let (base, size) = if range.is_null() {
            (0, 0)
        } else {
            ((*range).base_address as usize, (*range).size as usize)
        };

        out.push(ModuleInfo {
            name,
            path: full_path,
            base_address: base,
            size,
        });
        1 // TRUE — continue enumeration
    }

    unsafe {
        gum::gum_process_enumerate_modules(
            Some(callback),
            &mut out as *mut Vec<ModuleInfo> as gum::gpointer,
        );
    }

    out
}

pub fn find_module_by_name(name: &str) -> Option<ModuleInfo> {
    let cstr = std::ffi::CString::new(name).ok()?;
    unsafe {
        let module = gum::gum_process_find_module_by_name(cstr.as_ptr());
        if module.is_null() {
            return None;
        }
        let info = module_to_info(module);
        gum::g_object_unref(module as gum::gpointer);
        Some(info)
    }
}

pub fn find_global_export_by_name(symbol: &str) -> Result<usize, HookError> {
    let cstr = std::ffi::CString::new(symbol).map_err(|_| HookError::WrongSignature)?;
    let addr = unsafe { gum::gum_module_find_global_export_by_name(cstr.as_ptr()) };
    if addr != 0 {
        return Ok(addr as usize);
    }

    // Compatibility: try with/without leading underscore (Mach-O naming).
    if let Some(stripped) = symbol.strip_prefix('_') {
        if let Ok(alt) = std::ffi::CString::new(stripped) {
            let addr = unsafe { gum::gum_module_find_global_export_by_name(alt.as_ptr()) };
            if addr != 0 {
                return Ok(addr as usize);
            }
        }
    } else {
        let mut buf = String::with_capacity(symbol.len() + 1);
        buf.push('_');
        buf.push_str(symbol);
        if let Ok(alt) = std::ffi::CString::new(buf) {
            let addr = unsafe { gum::gum_module_find_global_export_by_name(alt.as_ptr()) };
            if addr != 0 {
                return Ok(addr as usize);
            }
        }
    }

    Err(HookError::WrongSignature)
}

pub fn find_export_by_name(module_name: &str, symbol: &str) -> Result<usize, HookError> {
    let mod_cstr = std::ffi::CString::new(module_name).map_err(|_| HookError::WrongSignature)?;
    let sym_cstr = std::ffi::CString::new(symbol).map_err(|_| HookError::WrongSignature)?;
    unsafe {
        let module = gum::gum_process_find_module_by_name(mod_cstr.as_ptr());
        if module.is_null() {
            return Err(HookError::WrongSignature);
        }
        let addr = gum::gum_module_find_export_by_name(module, sym_cstr.as_ptr());
        gum::g_object_unref(module as gum::gpointer);
        if addr != 0 {
            Ok(addr as usize)
        } else {
            Err(HookError::WrongSignature)
        }
    }
}

pub fn enumerate_exports(module_name: &str) -> Result<Vec<ExportInfo>, HookError> {
    let cstr = std::ffi::CString::new(module_name).map_err(|_| HookError::WrongSignature)?;
    let mut out: Vec<ExportInfo> = Vec::new();

    unsafe extern "C" fn callback(
        details: *const gum::GumExportDetails,
        user_data: gum::gpointer,
    ) -> gum::gboolean {
        let out = &mut *(user_data as *mut Vec<ExportInfo>);
        let name_ptr = (*details).name;
        if name_ptr.is_null() {
            return 1;
        }
        let raw = core::ffi::CStr::from_ptr(name_ptr).to_string_lossy();
        // Strip leading underscore (Mach-O prefix) for consistency.
        let name = raw.strip_prefix('_').unwrap_or(&raw).to_string();
        out.push(ExportInfo {
            name,
            address: (*details).address as usize,
        });
        1 // TRUE — continue
    }

    unsafe {
        let module = gum::gum_process_find_module_by_name(cstr.as_ptr());
        if module.is_null() {
            return Err(HookError::WrongSignature);
        }
        gum::gum_module_enumerate_exports(
            module,
            Some(callback),
            &mut out as *mut Vec<ExportInfo> as gum::gpointer,
        );
        gum::g_object_unref(module as gum::gpointer);
    }

    Ok(out)
}

pub fn enumerate_symbols(module_name: &str) -> Result<Vec<ExportInfo>, HookError> {
    let cstr = std::ffi::CString::new(module_name).map_err(|_| HookError::WrongSignature)?;
    let mut out: Vec<ExportInfo> = Vec::new();

    unsafe extern "C" fn callback(
        details: *const gum::GumSymbolDetails,
        user_data: gum::gpointer,
    ) -> gum::gboolean {
        let out = &mut *(user_data as *mut Vec<ExportInfo>);
        let name_ptr = (*details).name;
        if name_ptr.is_null() {
            return 1;
        }
        let raw = core::ffi::CStr::from_ptr(name_ptr).to_string_lossy();
        // Strip one leading underscore (Mach-O prefix).
        let name = raw.strip_prefix('_').unwrap_or(&raw).to_string();
        let addr = (*details).address;
        if addr != 0 {
            out.push(ExportInfo {
                name,
                address: addr as usize,
            });
        }
        1 // TRUE — continue
    }

    unsafe {
        let module = gum::gum_process_find_module_by_name(cstr.as_ptr());
        if module.is_null() {
            return Err(HookError::WrongSignature);
        }
        gum::gum_module_enumerate_symbols(
            module,
            Some(callback),
            &mut out as *mut Vec<ExportInfo> as gum::gpointer,
        );
        gum::g_object_unref(module as gum::gpointer);
    }

    Ok(out)
}

/// Scan a module's data ranges for pointer-sized values matching
/// `old_value` and replace them with `new_value`.
///
/// Used when `interceptor.replace()` fails (e.g. signed code pages on macOS)
/// but the target is dispatched through pointer tables in DATA segments.
/// Scans all readable non-executable ranges (DATA, DATA_CONST, AUTH, BSS).
///
/// # Safety
/// Caller must ensure `old_value` is a valid function pointer that appears in
/// the module's data segments, and `new_value` is a valid replacement.
pub unsafe fn rebind_pointers_by_value(
    module_name: &str,
    old_value: usize,
    new_value: usize,
) -> Result<usize, HookError> {
    // GUM_PAGE constants
    const GUM_PAGE_READ: gum::GumPageProtection = 1;
    const GUM_PAGE_WRITE: gum::GumPageProtection = 2;
    let mod_cstr = std::ffi::CString::new(module_name).map_err(|_| HookError::WrongSignature)?;
    let module = gum::gum_process_find_module_by_name(mod_cstr.as_ptr());
    if module.is_null() {
        return Err(HookError::WrongSignature);
    }

    // Collect all readable non-executable ranges (DATA, DATA_CONST, AUTH, BSS).
    // We use GUM_PAGE_READ to enumerate ALL readable ranges, then skip
    // executable ones in the callback. This covers __DATA (RW), __DATA_CONST (R),
    // __AUTH (RW), and __AUTH_CONST (R) segments.
    let mut ranges: Vec<gum::GumMemoryRange> = Vec::new();

    unsafe extern "C" fn range_callback(
        details: *const gum::GumRangeDetails,
        user_data: gum::gpointer,
    ) -> gum::gboolean {
        let prot = (*details).protection;
        // Skip executable ranges (code segments)
        if (prot & 4) != 0 {
            return 1; // continue, skip this range
        }
        let ranges = &mut *(user_data as *mut Vec<gum::GumMemoryRange>);
        let range = (*details).range;
        if !range.is_null() {
            ranges.push(*range);
        }
        1 // continue
    }

    gum::gum_module_enumerate_ranges(
        module,
        GUM_PAGE_READ,
        Some(range_callback),
        &mut ranges as *mut Vec<gum::GumMemoryRange> as gum::gpointer,
    );
    gum::g_object_unref(module as gum::gpointer);

    if ranges.is_empty() {
        return Err(HookError::WrongSignature);
    }

    // Build hex pattern from old_value bytes (little-endian)
    let bytes = old_value.to_le_bytes();
    let hex: String = bytes.iter().map(|b| format!("{:02x} ", b)).collect();
    let hex = hex.trim_end();
    let pattern_cstr = std::ffi::CString::new(hex).map_err(|_| HookError::WrongSignature)?;
    let pattern = gum::gum_match_pattern_new_from_string(pattern_cstr.as_ptr());
    if pattern.is_null() {
        return Err(HookError::WrongSignature);
    }

    // Scan each range for matches and patch them
    let mut matches: Vec<usize> = Vec::new();

    unsafe extern "C" fn match_callback(
        address: gum::GumAddress,
        _size: gum::gsize,
        user_data: gum::gpointer,
    ) -> gum::gboolean {
        let matches = &mut *(user_data as *mut Vec<usize>);
        matches.push(address as usize);
        1 // continue
    }

    for range in &ranges {
        gum::gum_memory_scan(
            range as *const gum::GumMemoryRange,
            pattern,
            Some(match_callback),
            &mut matches as *mut Vec<usize> as gum::gpointer,
        );
    }

    gum::gum_match_pattern_unref(pattern);

    // Patch each match — make writable first (needed for __DATA_CONST, __AUTH_CONST).
    // Check mprotect return: on Linux, RELRO pages cannot be made writable and
    // writing to them would SIGSEGV.
    let mut patched = 0usize;
    for addr in matches {
        let ok = gum::gum_try_mprotect(addr as gum::gpointer, 8, GUM_PAGE_READ | GUM_PAGE_WRITE);
        if ok != 0 {
            core::ptr::write_unaligned(addr as *mut usize, new_value);
            patched += 1;
        }
    }

    if patched == 0 {
        Err(HookError::WrongSignature)
    } else {
        Ok(patched)
    }
}

pub fn resolve_address_module(address: usize) -> Option<String> {
    unsafe {
        let module = gum::gum_process_find_module_by_address(address as gum::GumAddress);
        if module.is_null() {
            return None;
        }
        let name_ptr = gum::gum_module_get_name(module);
        let name = gchar_to_str(name_ptr);
        let result = basename(name).to_string();
        gum::g_object_unref(module as gum::gpointer);
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerate_modules_finds_system_libs() {
        let _g = crate::lock_hook_tests();
        crate::gum::init_runtime();
        let modules = enumerate_modules();
        assert!(!modules.is_empty());

        let has_system = modules.iter().any(|m| {
            m.name.contains("libSystem") || m.name.contains("dyld") || m.name.contains("libc")
        });
        assert!(
            has_system,
            "modules: {:?}",
            modules.iter().map(|m| &m.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn find_export_resolves_malloc() {
        let _g = crate::lock_hook_tests();
        crate::gum::init_runtime();
        let malloc_addr = find_global_export_by_name("malloc").expect("malloc should resolve");
        assert_ne!(malloc_addr, 0);
    }

    #[test]
    fn find_export_in_module_resolves_malloc() {
        let _g = crate::lock_hook_tests();
        crate::gum::init_runtime();
        let malloc_addr = find_global_export_by_name("malloc").expect("malloc should resolve");
        let module_name = resolve_address_module(malloc_addr).expect("dladdr should find module");
        let addr =
            find_export_by_name(&module_name, "malloc").expect("malloc in its defining module");
        assert_ne!(addr, 0);
    }

    #[test]
    fn find_export_returns_error_for_missing() {
        let _g = crate::lock_hook_tests();
        crate::gum::init_runtime();
        assert!(
            find_global_export_by_name("this_symbol_definitely_does_not_exist_xyz123").is_err()
        );
    }

    #[test]
    fn enumerate_exports_returns_libc_symbols() {
        let _g = crate::lock_hook_tests();
        crate::gum::init_runtime();
        let malloc_addr = find_global_export_by_name("malloc").expect("malloc should resolve");
        let module_name = resolve_address_module(malloc_addr).expect("dladdr should find module");
        let exports = enumerate_exports(&module_name).expect("enumerate exports");
        let names: std::collections::HashSet<_> = exports.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains("malloc"), "missing malloc");
        assert!(names.contains("free"), "missing free");
    }

    #[test]
    fn module_info_has_valid_ranges() {
        let _g = crate::lock_hook_tests();
        crate::gum::init_runtime();
        for m in enumerate_modules() {
            if m.size > 0 {
                assert!(m.base_address > 0);
            }
        }
    }

    #[no_mangle]
    #[inline(never)]
    pub extern "C" fn malwi_intercept_test_symbol() -> u32 {
        123
    }

    #[test]
    fn enumerate_symbols_finds_symbol_in_main_executable() {
        let _g = crate::lock_hook_tests();
        crate::gum::init_runtime();
        assert_eq!(malwi_intercept_test_symbol(), 123);

        let module_name = resolve_address_module(malwi_intercept_test_symbol as *const () as usize)
            .expect("should find module for test symbol");

        let symbols = enumerate_symbols(&module_name).expect("enumerate symbols");
        assert!(
            symbols
                .iter()
                .any(|s| s.name.contains("malwi_intercept_test_symbol")),
            "missing symbol in main executable; module_name={module_name}, symbols_len={}",
            symbols.len()
        );
    }

    #[test]
    fn resolve_address_module_finds_malloc_module() {
        let _g = crate::lock_hook_tests();
        crate::gum::init_runtime();
        let malloc_addr = find_global_export_by_name("malloc").expect("malloc should resolve");
        let module_name =
            resolve_address_module(malloc_addr).expect("should resolve malloc to a module");
        assert!(
            module_name.contains("malloc") || module_name.contains("libc"),
            "expected module containing 'malloc' or 'libc', got: {module_name}"
        );
    }

    #[test]
    fn find_module_by_name_finds_module() {
        let _g = crate::lock_hook_tests();
        crate::gum::init_runtime();
        let modules = enumerate_modules();
        let first = modules.first().expect("at least one module should exist");
        let found = find_module_by_name(&first.name).expect("should find module by name");
        assert_eq!(found.name, first.name);
        assert_eq!(found.base_address, first.base_address);
    }

    #[test]
    fn find_module_by_name_returns_none_for_missing() {
        let _g = crate::lock_hook_tests();
        crate::gum::init_runtime();
        assert!(find_module_by_name("nonexistent_module_xyz_999").is_none());
    }
}
