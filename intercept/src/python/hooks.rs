//! Interceptor-based hooking for Python C functions.
//!
//! Uses `Interceptor::replace` to substitute C functions with tracing
//! replacements. The replacement receives actual C arguments, enabling
//! argument extraction on every call and true blocking for denied calls.
//!
//! When the profile hook sees a matching C function via PYTRACE_C_CALL,
//! it installs the replacement. Since PYTRACE_C_CALL fires BEFORE CPython
//! calls the C function, the replacement handles the current call too.
//!
//! This also closes the C→C call tracing gap: e.g., pickle.loads internally
//! calling os.getpid via PyObject_Call is invisible to the profile hook,
//! but the replacement catches it.

use std::collections::HashSet;
use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};

use crate::Interceptor;
use log::debug;

use crate::native;
use crate::tracing::filter::Filter;

use super::ffi::{Py_IsInitializedFn, PYTHON_API};

// =============================================================================
// STATE
// =============================================================================

/// Set of C function pointers already hooked by the interceptor.
static HOOKED_C_FUNCTIONS: LazyLock<Mutex<HashSet<usize>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// A pending C hook waiting for module import resolution.
struct PendingCHook {
    module: String,
    function: String,
    display_name: String,
    capture_stack: bool,
    attempts: u8,
}

/// Max import attempts before giving up on a pending hook.
const MAX_PENDING_ATTEMPTS: u8 = 50;

/// Pending exact filter patterns not yet resolved to C hooks.
static PENDING_C_HOOKS: LazyLock<Mutex<Vec<PendingCHook>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

/// Fast check: are there any pending hooks left to resolve?
static HAS_PENDING_C_HOOKS: AtomicBool = AtomicBool::new(false);

/// Whether Python is fully initialized (set once, never cleared).
static PYTHON_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Check whether there are pending C hooks awaiting resolution.
pub fn has_pending() -> bool {
    HAS_PENDING_C_HOOKS.load(Ordering::Relaxed)
}

// =============================================================================
// PENDING HOOK MANAGEMENT
// =============================================================================

/// Parse exact (non-glob) filter patterns into pending C hooks.
///
/// Only exact patterns like "os.getpid" are eligible for eager resolution.
/// Glob patterns (containing `*` or `?`) are handled lazily via the profile hook.
///
/// Called after profile hook registration.
pub fn register_pending_hooks(filters: &[Filter]) {
    let mut pending = PENDING_C_HOOKS.lock().unwrap_or_else(|e| e.into_inner());

    for filter in filters {
        let pattern = &filter.pattern;
        // Skip glob patterns — only exact "module.function" patterns
        if pattern.contains('*') || pattern.contains('?') {
            continue;
        }
        // Must be a simple "module.function" pattern (e.g., "os.getpid").
        // Skip multi-dot patterns like "http.client.HTTPConnection.__init__"
        // — these are class methods, not importable C builtins.
        //
        // NOTE: Only real user filter patterns reach here. Internal signals
        // like envvar monitoring do NOT add to PYTHON_FILTERS (see
        // enable_envvar_monitoring() in mod.rs). If a pattern somehow leaks
        // in that names a non-importable module, PyImport_ImportModule will
        // fail — which crashes Python 3.10 for modules like "_Environ".
        // Keep the filter list clean to avoid this.
        if let Some(dot_pos) = pattern.find('.') {
            let func = &pattern[dot_pos + 1..];
            if func.contains('.') {
                continue; // Multi-dot — not a simple C function
            }
            let module = &pattern[..dot_pos];
            if !module.is_empty() && !func.is_empty() {
                pending.push(PendingCHook {
                    module: module.to_string(),
                    function: func.to_string(),
                    display_name: pattern.clone(),
                    capture_stack: filter.capture_stack,
                    attempts: 0,
                });
            }
        }
    }

    if !pending.is_empty() {
        debug!(
            "Registered {} pending C function hooks for eager resolution",
            pending.len()
        );
        HAS_PENDING_C_HOOKS.store(true, Ordering::Release);
    }
}

/// Try to resolve pending hooks by importing modules and looking up functions.
///
/// Called on each profile event until all pending hooks are resolved.
/// Guarded by the HAS_PENDING_C_HOOKS atomic so this is ~1ns no-op when empty.
///
/// # Safety
/// Must be called with GIL held (from profile hook context).
pub unsafe fn try_resolve_pending() {
    // Don't attempt imports during Python bootstrap — the import system
    // isn't ready yet and re-entrant imports crash the interpreter.
    // Py_IsInitialized returns 0 until _Py_InitializeMain completes.
    if !PYTHON_INITIALIZED.load(Ordering::Relaxed) {
        match native::find_export(None, "Py_IsInitialized") {
            Ok(addr) => {
                let is_initialized: Py_IsInitializedFn = std::mem::transmute(addr);
                if is_initialized() == 0 {
                    return;
                }
                PYTHON_INITIALIZED.store(true, Ordering::Relaxed);
            }
            Err(_) => return, // Not found yet — retry next time
        }
    }

    let api = match PYTHON_API.get() {
        Some(api) => api,
        None => return,
    };

    let (import_module, get_function) = match (api.import_module, api.pycfunction_get_function) {
        (Some(im), Some(gf)) => (im, gf),
        _ => {
            // Can't do eager resolution without these APIs
            HAS_PENDING_C_HOOKS.store(false, Ordering::Release);
            return;
        }
    };

    let mut pending = PENDING_C_HOOKS.lock().unwrap_or_else(|e| e.into_inner());

    // Iterate backwards to allow efficient removal
    let mut i = pending.len();
    while i > 0 {
        i -= 1;
        let hook = &pending[i];

        // Try to import the module
        let c_module = match CString::new(hook.module.as_str()) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let module_obj = import_module(c_module.as_ptr());
        if module_obj.is_null() {
            // Module not available yet — clear exception and maybe retry
            if let Some(err_clear) = api.err_clear {
                err_clear();
            }
            pending[i].attempts += 1;
            if pending[i].attempts >= MAX_PENDING_ATTEMPTS {
                debug!(
                    "Giving up on pending C hook '{}' after {} attempts",
                    pending[i].display_name, pending[i].attempts
                );
                pending.swap_remove(i);
            }
            continue;
        }

        // Get the function attribute from the module
        let c_func_name = match CString::new(hook.function.as_str()) {
            Ok(s) => s,
            Err(_) => {
                (api.py_decref)(module_obj);
                continue;
            }
        };
        let func_obj = (api.get_attr_string)(module_obj, c_func_name.as_ptr());
        (api.py_decref)(module_obj);

        if func_obj.is_null() {
            if let Some(err_clear) = api.err_clear {
                err_clear();
            }
            continue;
        }

        // Get the C function pointer and method flags
        let c_func_ptr = get_function(func_obj);
        let method_flags = match api.pycfunction_get_flags {
            Some(get_flags) => get_flags(func_obj),
            None => 0,
        };

        (api.py_decref)(func_obj);

        if c_func_ptr.is_null() {
            if let Some(err_clear) = api.err_clear {
                err_clear();
            }
            continue;
        }

        let addr = c_func_ptr as usize;
        replace_interceptor(addr, &hook.display_name, hook.capture_stack, method_flags);

        // Remove from pending (resolved)
        pending.swap_remove(i);
    }

    if pending.is_empty() {
        HAS_PENDING_C_HOOKS.store(false, Ordering::Release);
    }
}

// =============================================================================
// INTERCEPTOR HOOKING
// =============================================================================

/// User data passed to the replacement function via leaked Box.
struct HookData {
    display_name: String,
    capture_stack: bool,
    method_flags: i32,
    /// Pointer to the trampoline that calls through to the original function.
    /// Set by `Interceptor::replace()`.
    trampoline: *const c_void,
}

// Safety: HookData is only accessed from the replacement function,
// which runs on the calling thread. The `trampoline` pointer is a
// trampoline address that doesn't change after replace().
unsafe impl Send for HookData {}
unsafe impl Sync for HookData {}

/// Replace a C function at the given address with our tracing replacement.
///
/// Uses `Interceptor::replace` so the replacement receives the actual C
/// arguments directly, enabling argument extraction and true call blocking.
///
/// Acquires the HOOKED_C_FUNCTIONS lock once to check+insert. Returns true
/// if the function was already replaced.
fn replace_interceptor(
    addr: usize,
    display_name: &str,
    capture_stack: bool,
    method_flags: i32,
) -> bool {
    let mut hooked = HOOKED_C_FUNCTIONS.lock().unwrap_or_else(|e| e.into_inner());

    if !hooked.insert(addr) {
        return true; // Already replaced
    }

    // Select replacement function based on calling convention.
    // METH_FASTCALL uses 3-arg ABI: fn(self, *args, nargs).
    // All others (METH_NOARGS, METH_O, METH_VARARGS) use 2-arg ABI: fn(self, arg).
    let convention = method_flags & super::ffi::METH_CONVENTION_MASK;
    let replacement: *const c_void = if convention & super::ffi::METH_FASTCALL != 0 {
        replacement_3arg as *const c_void
    } else {
        replacement_2arg as *const c_void
    };

    let data = Box::new(HookData {
        display_name: display_name.to_string(),
        capture_stack,
        method_flags,
        trampoline: std::ptr::null(),
    });
    let data_ptr = Box::into_raw(data);
    let user_data = data_ptr as *mut c_void;

    let interceptor = Interceptor::obtain();
    let mut trampoline: *const c_void = std::ptr::null();

    interceptor.begin_transaction();
    let result = interceptor.replace(
        addr as *mut c_void,
        replacement,
        user_data,
        &mut trampoline as *mut *const c_void,
    );
    if result.is_ok() {
        // Write trampoline BEFORE end_transaction makes the replacement live,
        // preventing a TOCTOU race where the replacement runs with a null trampoline.
        unsafe {
            (*data_ptr).trampoline = trampoline;
        }
    }
    interceptor.end_transaction();

    match result {
        Ok(()) => {
            debug!(
                "Replaced C function '{}' at {:#x} via interceptor",
                display_name, addr
            );
        }
        Err(e) => {
            // Clean up leaked data and remove from set on failure
            unsafe {
                let _ = Box::from_raw(data_ptr);
            }
            hooked.remove(&addr);
            debug!(
                "Failed to replace C function '{}' at {:#x}: {:?}",
                display_name, addr, e
            );
        }
    }

    false // Was not previously replaced
}

/// Ensure a C function (from PYTRACE_C_CALL arg) has a tracing replacement installed.
///
/// If the function is already replaced, this is a no-op. Otherwise, installs
/// the replacement via `Interceptor::replace`.
///
/// # Safety
/// Must be called with GIL held. `arg` must be a valid PyCFunctionObject pointer.
pub unsafe fn ensure_replaced(arg: *mut c_void, display_name: &str, capture_stack: bool) {
    let api = match PYTHON_API.get() {
        Some(api) => api,
        None => return,
    };

    let get_function = match api.pycfunction_get_function {
        Some(f) => f,
        None => return,
    };

    let c_func_ptr = get_function(arg);
    if c_func_ptr.is_null() {
        if let Some(err_clear) = api.err_clear {
            err_clear();
        }
        return;
    }

    let addr = c_func_ptr as usize;

    // Get method flags for argument extraction in the interceptor
    let method_flags = match api.pycfunction_get_flags {
        Some(get_flags) => get_flags(arg),
        None => 0,
    };

    // Single-lock: check + replace in one call
    replace_interceptor(addr, display_name, capture_stack, method_flags);
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracing::filter::Filter;

    /// Test that register_pending_hooks correctly filters patterns:
    /// - Glob patterns (containing * or ?) are skipped
    /// - Multi-dot patterns (e.g., "http.client.HTTPConnection") are skipped
    /// - Patterns without a dot are skipped
    /// - Only simple "module.function" patterns are accepted
    ///
    /// Uses a single test to avoid static state interference between tests.
    #[test]
    fn test_register_pending_hooks_skips_globs_and_accepts_exact() {
        // Before any registration, pending state from previous register calls
        // may or may not be set, so we focus on verifying the behavior after
        // our specific calls.

        // Register only glob/invalid patterns — these should all be skipped
        let glob_only_filters = vec![
            Filter::new("os.*", false),                                // glob with *
            Filter::new("sys.get?", false),                            // glob with ?
            Filter::new("http.client.HTTPConnection.__init__", false), // multi-dot
            Filter::new("nodot", false),                               // no dot at all
            Filter::new(".leadingdot", false),                         // leading dot, empty module
            Filter::new("trailingdot.", false), // trailing dot, empty function
        ];

        // Get count before
        let count_before = PENDING_C_HOOKS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();

        register_pending_hooks(&glob_only_filters);

        // Count should not have increased — all patterns were ineligible
        let count_after_globs = PENDING_C_HOOKS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        assert_eq!(
            count_before, count_after_globs,
            "Glob/multi-dot/invalid patterns should not be added to pending hooks"
        );

        // Now register valid exact patterns
        let exact_filters = vec![
            Filter::new("os.getpid", true),
            Filter::new("json.loads", false),
        ];

        register_pending_hooks(&exact_filters);

        let count_after_exact = PENDING_C_HOOKS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        assert_eq!(
            count_after_exact,
            count_after_globs + 2,
            "Exact module.function patterns should be added to pending hooks"
        );

        // has_pending should be true now
        assert!(
            has_pending(),
            "has_pending() should be true after adding exact patterns"
        );
    }
}

// =============================================================================
// REPLACEMENT FUNCTIONS
// =============================================================================

// Re-entrancy guard for replacement callbacks (per-thread).
thread_local! {
    static IN_PY_C_HOOK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

use super::ffi::{METH_CONVENTION_MASK, METH_FASTCALL, METH_NOARGS, METH_O, METH_VARARGS};

/// Replacement for C functions using 2-arg ABI: fn(self, arg) -> *mut c_void.
///
/// Covers METH_NOARGS, METH_O, and METH_VARARGS calling conventions.
/// Extracts arguments from the direct C parameters, sends trace event,
/// and either calls the original or raises PermissionError.
///
/// # Safety
/// Called by frida-gum as a replacement for the original C function.
/// GIL is held (we are being called from CPython's call machinery).
unsafe extern "C" fn replacement_2arg(self_obj: *mut c_void, arg: *mut c_void) -> *mut c_void {
    let ctx = crate::interceptor::invocation::get_current_invocation();
    if ctx.is_null() {
        super::helpers::raise_permission_error();
        return std::ptr::null_mut();
    }
    let user_data = crate::interceptor::invocation::get_replacement_data(ctx);
    if user_data.is_null() {
        super::helpers::raise_permission_error();
        return std::ptr::null_mut();
    }
    let data = &*(user_data as *const HookData);
    let original: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
        std::mem::transmute(data.trampoline);

    // Re-entrancy guard: during PyObject_Repr etc., call original directly
    if IN_PY_C_HOOK.with(|h| h.get()) {
        return original(self_obj, arg);
    }
    IN_PY_C_HOOK.with(|h| h.set(true));

    let result = handle_replacement(data, self_obj, arg, std::ptr::null_mut());

    IN_PY_C_HOOK.with(|h| h.set(false));

    match result {
        ReplacementDecision::Allow => original(self_obj, arg),
        ReplacementDecision::Deny => {
            super::helpers::raise_permission_error();
            std::ptr::null_mut()
        }
    }
}

/// Replacement for C functions using 3-arg ABI: fn(self, args_ptr, nargs) -> *mut c_void.
///
/// Covers METH_FASTCALL calling convention.
///
/// # Safety
/// Called by frida-gum as a replacement for the original C function.
unsafe extern "C" fn replacement_3arg(
    self_obj: *mut c_void,
    args_ptr: *mut c_void,
    nargs: *mut c_void,
) -> *mut c_void {
    let ctx = crate::interceptor::invocation::get_current_invocation();
    if ctx.is_null() {
        super::helpers::raise_permission_error();
        return std::ptr::null_mut();
    }
    let user_data = crate::interceptor::invocation::get_replacement_data(ctx);
    if user_data.is_null() {
        super::helpers::raise_permission_error();
        return std::ptr::null_mut();
    }
    let data = &*(user_data as *const HookData);
    let original: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void =
        std::mem::transmute(data.trampoline);

    // Re-entrancy guard
    if IN_PY_C_HOOK.with(|h| h.get()) {
        return original(self_obj, args_ptr, nargs);
    }
    IN_PY_C_HOOK.with(|h| h.set(true));

    let result = handle_replacement(data, self_obj, args_ptr, nargs);

    IN_PY_C_HOOK.with(|h| h.set(false));

    match result {
        ReplacementDecision::Allow => original(self_obj, args_ptr, nargs),
        ReplacementDecision::Deny => {
            super::helpers::raise_permission_error();
            std::ptr::null_mut()
        }
    }
}

enum ReplacementDecision {
    Allow,
    Deny,
}

/// Common logic for both replacement functions: extract args, send event, get decision.
///
/// `third_arg` is null for 2-arg replacements, nargs for METH_FASTCALL.
///
/// # Safety
/// GIL must be held. Pointers must be valid Python objects.
unsafe fn handle_replacement(
    data: &HookData,
    self_obj: *mut c_void,
    second_arg: *mut c_void,
    third_arg: *mut c_void,
) -> ReplacementDecision {
    let api = match PYTHON_API.get() {
        Some(api) => api,
        None => return ReplacementDecision::Allow,
    };

    // Get the current Python frame for source location
    let frame = match api.eval_get_frame {
        Some(eval_get_frame) => eval_get_frame(),
        None => std::ptr::null_mut(),
    };

    let runtime_stack = super::helpers::maybe_capture_stack(frame, data.capture_stack);
    let (source_file, source_line) = super::helpers::extract_frame_location(frame);

    // Extract arguments from direct C parameters
    let mut arguments =
        extract_args_from_params(self_obj, second_arg, third_arg, data.method_flags, api);

    // Module-level C functions (e.g. _socket.getaddrinfo) have the module
    // object as self_obj — not a meaningful argument. Instance methods (e.g.
    // socket.socket.connect) have the instance, which formatters expect.
    // Detect by dot count: "module.func" = 1 dot, "module.type.method" = 2+.
    if !arguments.is_empty() && data.display_name.matches('.').count() <= 1 {
        arguments.remove(0);
    }

    let network_info = super::format::format_python_arguments(&data.display_name, &mut arguments);

    let event = crate::tracing::event::python_enter(&data.display_name)
        .arguments(arguments)
        .network_info(network_info)
        .runtime_stack(runtime_stack)
        .source_location(source_file, source_line, None)
        .build();

    if super::helpers::send_trace_event(event).is_err() {
        ReplacementDecision::Deny
    } else {
        ReplacementDecision::Allow
    }
}

/// Extract arguments from direct C function parameters based on calling convention.
///
/// Unlike `extract_c_function_arguments` (which reads from InvocationContext registers),
/// this reads from the actual function parameters passed to the replacement.
///
/// # Safety
/// All pointers must be valid Python objects (or null). GIL must be held.
unsafe fn extract_args_from_params(
    self_obj: *mut c_void,
    second_arg: *mut c_void,
    third_arg: *mut c_void,
    method_flags: i32,
    api: &super::ffi::PythonApi,
) -> Vec<crate::Argument> {
    if method_flags == 0 {
        return Vec::new();
    }

    let convention = method_flags & METH_CONVENTION_MASK;

    match convention {
        METH_NOARGS => Vec::new(),
        METH_O => {
            // fn(self, arg) — two C arguments
            let mut args = Vec::with_capacity(2);
            args.push(pyobj_to_argument(self_obj, api));
            args.push(pyobj_to_argument(second_arg, api));
            args
        }
        c if c & METH_VARARGS != 0 => {
            // fn(self, args_tuple) — self + Python tuple of positional args
            let mut args = vec![pyobj_to_argument(self_obj, api)];
            args.extend(super::helpers::extract_tuple_arguments(second_arg));
            args
        }
        c if c & METH_FASTCALL != 0 => {
            // fn(self, *args_array, nargs) — self + C array of PyObject*
            let args_array = second_arg as *const *mut c_void;
            let nargs = third_arg as isize;
            let mut args = vec![pyobj_to_argument(self_obj, api)];
            if !args_array.is_null() && nargs > 0 {
                for i in 0..nargs.min(8) {
                    let item = *args_array.add(i as usize);
                    args.push(pyobj_to_argument(item, api));
                }
            }
            args
        }
        _ => Vec::new(),
    }
}

/// Convert a raw PyObject pointer to an `Argument` by calling `PyObject_Repr`.
///
/// # Safety
/// `obj` must be a valid PyObject pointer (or null). GIL must be held.
unsafe fn pyobj_to_argument(obj: *mut c_void, api: &super::ffi::PythonApi) -> crate::Argument {
    let display = if obj.is_null() {
        None
    } else if let Some(object_repr) = api.object_repr {
        super::helpers::get_object_display(obj, api, object_repr, 200)
    } else {
        None
    };
    crate::Argument {
        raw_value: obj as usize,
        display,
    }
}
