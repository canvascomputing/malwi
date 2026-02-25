//! Interceptor-based hooking for Python C functions.
//!
//! When the profile hook sees a matching C function via PYTRACE_C_CALL,
//! it extracts the native function pointer via PyCFunction_GetFunction
//! and hooks it with the Interceptor. From then on, ALL calls to that
//! C function — whether from Python or from other C code — are caught.
//!
//! This closes the C→C call tracing gap: e.g., pickle.loads internally
//! calling os.getpid via PyObject_Call is invisible to the profile hook,
//! but the interceptor catches it.

use std::collections::HashSet;
use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};

use log::debug;
use malwi_intercept::{CallListener, Interceptor, InvocationContext};

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
static HAS_PENDING: AtomicBool = AtomicBool::new(false);

/// Whether Python is fully initialized (set once, never cleared).
static PY_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Check whether there are pending C hooks awaiting resolution.
pub fn has_pending() -> bool {
    HAS_PENDING.load(Ordering::Relaxed)
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
        HAS_PENDING.store(true, Ordering::Release);
    }
}

/// Try to resolve pending hooks by importing modules and looking up functions.
///
/// Called on each profile event until all pending hooks are resolved.
/// Guarded by the HAS_PENDING atomic so this is ~1ns no-op when empty.
///
/// # Safety
/// Must be called with GIL held (from profile hook context).
pub unsafe fn try_resolve_pending() {
    // Don't attempt imports during Python bootstrap — the import system
    // isn't ready yet and re-entrant imports crash the interpreter.
    // Py_IsInitialized returns 0 until _Py_InitializeMain completes.
    if !PY_INITIALIZED.load(Ordering::Relaxed) {
        match native::find_export(None, "Py_IsInitialized") {
            Ok(addr) => {
                let is_initialized: Py_IsInitializedFn = std::mem::transmute(addr);
                if is_initialized() == 0 {
                    return;
                }
                PY_INITIALIZED.store(true, Ordering::Relaxed);
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
            HAS_PENDING.store(false, Ordering::Release);
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

        // Get the C function pointer
        let c_func_ptr = get_function(func_obj);
        (api.py_decref)(func_obj);

        if c_func_ptr.is_null() {
            if let Some(err_clear) = api.err_clear {
                err_clear();
            }
            continue;
        }

        // Hook it
        let addr = c_func_ptr as usize;
        attach_interceptor(addr, &hook.display_name, hook.capture_stack);

        // Remove from pending (resolved)
        pending.swap_remove(i);
    }

    if pending.is_empty() {
        HAS_PENDING.store(false, Ordering::Release);
    }
}

// =============================================================================
// INTERCEPTOR HOOKING
// =============================================================================

/// User data passed to the interceptor callback via leaked Box.
struct HookData {
    display_name: String,
    capture_stack: bool,
}

/// Attach an interceptor hook to a C function at the given address.
///
/// Acquires the HOOKED_C_FUNCTIONS lock once to check+insert, then attaches
/// the interceptor. Returns true if the function was already hooked.
fn attach_interceptor(addr: usize, display_name: &str, capture_stack: bool) -> bool {
    let mut hooked = HOOKED_C_FUNCTIONS.lock().unwrap_or_else(|e| e.into_inner());

    if !hooked.insert(addr) {
        return true; // Already hooked
    }

    let data = Box::new(HookData {
        display_name: display_name.to_string(),
        capture_stack,
    });
    let user_data = Box::into_raw(data) as *mut c_void;

    let interceptor = Interceptor::obtain();
    let listener = CallListener {
        on_enter: Some(on_c_function_enter),
        on_leave: None,
        user_data,
    };

    interceptor.begin_transaction();
    let result = interceptor.attach(addr as *mut c_void, listener);
    interceptor.end_transaction();

    match result {
        Ok(()) => {
            debug!(
                "Hooked C function '{}' at {:#x} via interceptor",
                display_name, addr
            );
        }
        Err(e) => {
            // Clean up leaked data and remove from set on failure
            unsafe {
                let _ = Box::from_raw(user_data as *mut HookData);
            }
            hooked.remove(&addr);
            debug!(
                "Failed to hook C function '{}' at {:#x}: {:?}",
                display_name, addr, e
            );
        }
    }

    false // Was not previously hooked
}

/// Check if a C function (from PYTRACE_C_CALL arg) is already hooked.
/// If not hooked, attempt to hook it. Returns true if the function IS hooked
/// (either already was, or just got hooked successfully).
///
/// # Safety
/// Must be called with GIL held. `arg` must be a valid PyCFunctionObject pointer.
pub unsafe fn is_hooked_or_hook(arg: *mut c_void, display_name: &str, capture_stack: bool) -> bool {
    let api = match PYTHON_API.get() {
        Some(api) => api,
        None => return false,
    };

    let get_function = match api.pycfunction_get_function {
        Some(f) => f,
        None => return false,
    };

    let c_func_ptr = get_function(arg);
    if c_func_ptr.is_null() {
        if let Some(err_clear) = api.err_clear {
            err_clear();
        }
        return false;
    }

    let addr = c_func_ptr as usize;

    // Single-lock: check + hook in one call
    attach_interceptor(addr, display_name, capture_stack)
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
// INTERCEPTOR CALLBACK
// =============================================================================

// Re-entrancy guard for interceptor callbacks (per-thread).
thread_local! {
    static IN_PY_C_HOOK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Interceptor on_enter callback for hooked C functions.
///
/// Fires for EVERY call to the hooked C function, whether from Python or C code.
/// The GIL is held during C→C calls within CPython, so PyEval_GetFrame is safe.
///
/// # Safety
/// Called by malwi-intercept with valid context.
unsafe extern "C" fn on_c_function_enter(_context: *mut InvocationContext, user_data: *mut c_void) {
    // Re-entrancy guard
    if IN_PY_C_HOOK.with(|h| h.get()) {
        return;
    }
    IN_PY_C_HOOK.with(|h| h.set(true));

    if !user_data.is_null() {
        let data = &*(user_data as *const HookData);

        let api = PYTHON_API.get();
        if let Some(api) = api {
            // Get the current Python frame for source location.
            // This is safe because GIL is held during C→C calls within CPython.
            let frame = match api.eval_get_frame {
                Some(eval_get_frame) => eval_get_frame(),
                None => std::ptr::null_mut(),
            };

            let runtime_stack = super::helpers::maybe_capture_stack(frame, data.capture_stack);
            let (source_file, source_line) = super::helpers::extract_frame_location(frame);

            let event = crate::tracing::event::python_enter(&data.display_name)
                .runtime_stack(runtime_stack)
                .source_location(source_file, source_line)
                .build();

            if super::helpers::send_trace_event(event).is_err() {
                // Can't raise PermissionError from interceptor context — the C function
                // is already being entered. Best effort: event was blocked.
            }
        }
    }

    IN_PY_C_HOOK.with(|h| h.set(false));
}
