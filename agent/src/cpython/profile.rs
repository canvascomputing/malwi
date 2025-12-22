//! Python profile hook registration and callback.
//!
//! Uses Python's PyEval_SetProfile / PyEval_SetProfileAllThreads (PEP 669) to trace
//! Python function calls. Requires proper GIL management for external threads.

use std::collections::HashSet;
use std::ffi::{c_int, c_void};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use log::{debug, error};
use malwi_protocol::RuntimeStack;
use malwi_intercept::CallListener;
use malwi_intercept::InvocationContext;

use crate::native;

use super::ffi::{
    init_python_api, Py_IsInitializedFn, PyEval_SetProfileAllThreadsFn, PyEval_SetProfileFn,
    PyGILState_EnsureFn, PyGILState_ReleaseFn, PYTRACE_CALL, PYTHON_API,
};
use super::filters::matches_filter;
use super::helpers::{extract_function_arguments, get_code_filename, get_qualified_function_name};
use super::stack::capture_python_stack;

// Dedup set for Python envvar names — reports each variable once per thread.
thread_local! {
    static PY_ENVVAR_SEEN: std::cell::RefCell<HashSet<String>> = std::cell::RefCell::new(HashSet::new());
}

/// Raise a Python PermissionError exception.
///
/// # Safety
/// Caller must ensure GIL is held.
unsafe fn raise_permission_error() {
    let Some(api) = PYTHON_API.get() else { return };
    let Some(err_set_string) = api.err_set_string else { return };
    if api.exc_permission_error.is_null() {
        return;
    }
    err_set_string(
        api.exc_permission_error,
        b"malwi-trace: blocked by user\0".as_ptr() as *const c_char,
    );
}

/// Whether profile hook is registered
pub static PROFILE_HOOK_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Flag set when we detect _thread.start_new_thread, triggers propagation on next profile event
static THREAD_CREATED: AtomicBool = AtomicBool::new(false);

/// Set the THREAD_CREATED flag (called from audit hook)
pub fn set_thread_created() {
    THREAD_CREATED.store(true, Ordering::Relaxed);
}

// =============================================================================
// THREAD STATE FIELD ACCESS
// =============================================================================
//
// PyThreadState struct offsets for c_profilefunc and c_profileobj fields.
// These offsets vary between Python versions due to struct layout changes.
//
// Python 3.9-3.11 (64-bit): offset 56 (func), 72 (obj)
// Python 3.12 (64-bit):     offset 64 (func), 80 (obj)
// Python 3.13+ (64-bit):    offset 80 (func), 96 (obj)

/// Cached profile offsets (c_profilefunc, c_profileobj) - detected once
static PROFILE_OFFSETS: OnceLock<(usize, usize)> = OnceLock::new();

/// Get offsets for c_profilefunc and c_profileobj based on Python version.
///
/// Offsets verified against py-spy bindings and CPython source:
/// - Python 3.10: (56, 72) - different struct layout than 3.11
/// - Python 3.11: (64, 80) - added more fields before cframe
/// - Python 3.12: (64, 80) - same as 3.11
/// - Python 3.13: (80, 96) - added eval_breaker and current_frame
fn get_profile_offsets() -> (usize, usize) {
    *PROFILE_OFFSETS.get_or_init(|| {
        let v = super::version::get().expect("Python version detection failed");
        if v.at_least(3, 13) {
            debug!("Python {} -> profile offsets (80, 96)", v);
            (80, 96)
        } else if v.at_least(3, 11) {
            // Python 3.11 and 3.12 have the same layout for these fields
            debug!("Python {} -> profile offsets (64, 80)", v);
            (64, 80)
        } else {
            // Python 3.10 and earlier
            debug!("Python {} -> profile offsets (56, 72)", v);
            (56, 72)
        }
    })
}

/// Cached cframe offset - detected once
static CFRAME_OFFSET: OnceLock<usize> = OnceLock::new();

/// Get offset of cframe field in PyThreadState based on Python version.
///
/// The cframe field contains use_tracing which must be set for Python < 3.12.
/// - Python 3.10: cframe at offset 48
/// - Python 3.11: cframe at offset 56
fn get_cframe_offset() -> usize {
    *CFRAME_OFFSET.get_or_init(|| {
        let v = super::version::get().expect("Python version detection failed");
        if v.at_least(3, 11) {
            debug!("Python {} -> cframe offset 56", v);
            56
        } else {
            debug!("Python {} -> cframe offset 48", v);
            48 // Python 3.10
        }
    })
}

/// Read c_profilefunc field from a PyThreadState pointer.
///
/// # Safety
/// - `tstate` must be a valid PyThreadState pointer
/// - GIL must be held
unsafe fn get_tstate_profilefunc(tstate: *mut c_void) -> *mut c_void {
    let (profilefunc_offset, _) = get_profile_offsets();
    *(tstate.byte_add(profilefunc_offset) as *const *mut c_void)
}

/// Set c_profilefunc, c_profileobj, and use_tracing fields on a PyThreadState.
///
/// For Python < 3.12, also sets the use_tracing flag in cframe, which is required
/// for the interpreter to actually call the profile hook. Python 3.12+ removed
/// this flag from cframe.
///
/// # Safety
/// - `tstate` must be a valid PyThreadState pointer
/// - GIL must be held
unsafe fn set_tstate_profile(
    tstate: *mut c_void,
    func: Option<super::ffi::Py_tracefunc>,
    obj: *mut c_void,
) {
    let version = super::version::get();
    let (profilefunc_offset, profileobj_offset) = get_profile_offsets();

    // Write function pointer
    let func_ptr = match func {
        Some(f) => f as *mut c_void,
        None => std::ptr::null_mut(),
    };
    *(tstate.byte_add(profilefunc_offset) as *mut *mut c_void) = func_ptr;
    // Write obj pointer
    *(tstate.byte_add(profileobj_offset) as *mut *mut c_void) = obj;

    // For Python < 3.12, must also set use_tracing flag in cframe.
    // Without this flag set, the interpreter never calls the profile hook!
    //
    // Python 3.10: use_tracing is int (4 bytes), non-zero = enabled
    // Python 3.11: use_tracing is uint8_t (1 byte), 0 or 255
    // Python 3.12+: use_tracing was REMOVED from cframe
    if !version.map_or(true, |v| v.at_least(3, 12)) && func.is_some() {
        let cframe_offset = get_cframe_offset();
        let cframe_ptr = *(tstate.byte_add(cframe_offset) as *const *mut c_void);

        if !cframe_ptr.is_null() {
            // use_tracing is at offset 0 in cframe struct
            // Write as u8 (255) - works for both int and uint8_t since it's
            // at offset 0 and x86/arm are little-endian
            let use_tracing_ptr = cframe_ptr as *mut u8;
            *use_tracing_ptr = 255;
        }
        // Note: If cframe is null (thread not yet in eval loop), that's OK -
        // when the thread enters the eval loop, it will initialize use_tracing
        // based on c_profilefunc which we've already set above.
    }
}

/// Whether profile hook registration is in progress (re-entry guard)
static PROFILE_HOOK_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

/// Scope guard to reset PROFILE_HOOK_IN_PROGRESS on drop
struct InProgressGuard;

impl Drop for InProgressGuard {
    fn drop(&mut self) {
        PROFILE_HOOK_IN_PROGRESS.store(false, Ordering::SeqCst);
    }
}

/// Profile hook callback - called for every Python call and return.
///
/// SAFETY: This is called by Python with GIL held.
unsafe extern "C" fn profile_hook(
    _obj: *mut c_void,
    frame: *mut c_void,
    what: c_int,
    _arg: *mut c_void,
) -> c_int {
    // After thread creation, propagate profile hook to new threads.
    // The THREAD_CREATED flag is set by:
    // - The audit hook when it sees _thread.start_new_thread (Python 3.12+)
    // - The thread_hook when PyThread_start_new_thread returns (Python < 3.12)
    //
    // We propagate on ANY Python event (CALL or RETURN) because:
    // - The new thread's PyThreadState might not exist immediately after creation
    // - We need to catch it as soon as possible before the new thread executes Python
    if THREAD_CREATED.swap(false, Ordering::Relaxed) {
        propagate_profile_to_threads();
    }

    // Only trace CALL events (enter)
    if what != PYTRACE_CALL {
        return 0;
    }

    // Get qualified function name (e.g., "os.spawn", "json.loads")
    let qualified_name = match get_qualified_function_name(frame) {
        Some(name) => name,
        None => return 0,
    };

    // Intercept envvar access: _Environ.__getitem__ is the funnel for all
    // os.environ['KEY'], os.environ.get('KEY'), and os.getenv('KEY') calls.
    if super::is_envvar_monitoring_enabled() && qualified_name.ends_with("_Environ.__getitem__") {
        return handle_envvar_access(frame);
    }

    // Check filter and get capture_stack setting
    let (matches, capture_stack) = matches_filter(&qualified_name);
    if !matches {
        return 0;
    }

    let mut arguments = extract_function_arguments(frame);

    // Apply Python-specific formatting for networking functions
    let network_info = super::format::format_python_arguments(&qualified_name, &mut arguments);

    // Capture Python stack if enabled
    let runtime_stack = if capture_stack {
        let frames = capture_python_stack(frame);
        if frames.is_empty() {
            None
        } else {
            Some(RuntimeStack::Python(frames))
        }
    } else {
        None
    };

    // Extract caller's source location from the parent frame
    let (caller_file, caller_line) = {
        let api = PYTHON_API.get();
        if let Some(api) = api {
            let back = (api.frame_get_back)(frame);
            if !back.is_null() {
                let code = (api.frame_get_code)(back);
                let file = if !code.is_null() {
                    let f = get_code_filename(code);
                    (api.py_decref)(code);
                    f
                } else {
                    None
                };
                let line = (api.frame_get_line_number)(back) as u32;
                (api.py_decref)(back);
                (file, if line > 0 { Some(line) } else { None })
            } else {
                (None, None)
            }
        } else {
            (None, None)
        }
    };

    // Build trace event using EventBuilder
    let event = crate::tracing::event::python_enter(&qualified_name)
        .arguments(arguments)
        .network_info(network_info)
        .runtime_stack(runtime_stack)
        .source_location(caller_file, caller_line)
        .build();

    // Send to CLI (handles review mode internally)
    if super::helpers::send_trace_event(event).is_err() {
        // User denied - raise PermissionError to abort the call
        raise_permission_error();
        return -1;
    }

    0
}

/// Handle envvar access from Python's _Environ.__getitem__(self, key).
///
/// Extracts the `key` argument (index 1 after self), checks deny filter,
/// and sends an EnvVar trace event.
///
/// # Safety
/// Caller must ensure frame is a valid PyFrameObject pointer and GIL is held.
unsafe fn handle_envvar_access(frame: *mut c_void) -> c_int {
    let api = match PYTHON_API.get() {
        Some(api) => api,
        None => return 0,
    };

    let (tuple_get_item, object_get_item) = match (api.tuple_get_item, api.object_get_item) {
        (Some(tgi), Some(ogi)) => (tgi, ogi),
        _ => return 0,
    };

    // Get code object from frame
    let code = (api.frame_get_code)(frame);
    if code.is_null() {
        return 0;
    }

    // Get co_varnames tuple to find the 'key' parameter (index 1, after 'self')
    let varnames = (api.get_attr_string)(code, b"co_varnames\0".as_ptr() as *const c_char);
    if varnames.is_null() {
        return 0;
    }

    // Get the parameter name object at index 1 ('key')
    let key_name_obj = tuple_get_item(varnames, 1);
    (api.py_decref)(varnames);
    if key_name_obj.is_null() {
        return 0;
    }

    // Get locals dict from frame
    let locals = if let Some(frame_get_locals) = api.frame_get_locals {
        frame_get_locals(frame)
    } else {
        (api.get_attr_string)(frame, b"f_locals\0".as_ptr() as *const c_char)
    };
    if locals.is_null() {
        if let Some(err_clear) = api.err_clear {
            err_clear();
        }
        return 0;
    }

    // Look up the key value from locals using the parameter name
    let key_obj = object_get_item(locals, key_name_obj);
    (api.py_decref)(locals);
    if key_obj.is_null() {
        if let Some(err_clear) = api.err_clear {
            err_clear();
        }
        return 0;
    }

    // Convert key to UTF-8 string
    let key_ptr = (api.unicode_as_utf8)(key_obj);
    let key_str = if !key_ptr.is_null() {
        super::helpers::cstr_to_string(key_ptr)
    } else {
        None
    };
    (api.py_decref)(key_obj);

    let key = match key_str {
        Some(k) => k,
        None => return 0,
    };

    // Skip agent-internal variables
    if key.starts_with("MALWI_") {
        return 0;
    }

    // Dedup: report each variable once per thread
    let is_new = PY_ENVVAR_SEEN.with(|set| set.borrow_mut().insert(key.clone()));
    if !is_new {
        return 0;
    }

    // Check agent-side deny filter
    let blocked = crate::envvar_filter::should_block(&key);

    // Build and send EnvVar trace event
    let event = crate::tracing::event::envvar_enter(&key).build();

    if let Some(agent) = crate::Agent::get() {
        if agent.is_review_mode() {
            let decision = agent.await_review_decision(event);
            if !decision.is_allowed() {
                raise_permission_error();
                return -1;
            }
            return 0;
        }

        let _ = agent.send_event(event);
    }

    if blocked {
        raise_permission_error();
        return -1;
    }

    0
}

/// Actually perform the profile hook registration (called from audit hook context).
/// GIL is already held when this is called.
pub fn do_register_profile_hook() -> bool {
    // Already registered?
    if PROFILE_HOOK_REGISTERED.load(Ordering::SeqCst) {
        return true;
    }

    // Guard against re-entry (SetProfile might trigger audit events)
    if PROFILE_HOOK_IN_PROGRESS
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return true; // Already in progress
    }

    // Scope guard ensures IN_PROGRESS is reset even on early return
    let _guard = InProgressGuard;

    // Find profile setter - prefer AllThreads variant (Python 3.12+)
    let set_profile_all: Option<PyEval_SetProfileAllThreadsFn> =
        native::find_export(None, "PyEval_SetProfileAllThreads")
            .ok()
            .map(|addr| unsafe { std::mem::transmute(addr) });

    let set_profile: Option<PyEval_SetProfileFn> = native::find_export(None, "PyEval_SetProfile")
        .ok()
        .map(|addr| unsafe { std::mem::transmute(addr) });

    if set_profile_all.is_none() && set_profile.is_none() {
        error!("Python profile API not found (PyEval_SetProfile)");
        return false;
    }

    // Initialize Python API cache
    if !init_python_api() {
        error!("Failed to resolve required Python API functions");
        return false;
    }

    // We're being called from an audit hook, so GIL is already held!
    // Just set the profile hook directly
    unsafe {
        if let Some(set_all) = set_profile_all {
            debug!("Registering profile hook with PyEval_SetProfileAllThreads");
            set_all(Some(profile_hook), std::ptr::null_mut());
        } else if let Some(set_one) = set_profile {
            debug!("Registering profile hook with PyEval_SetProfile");
            set_one(Some(profile_hook), std::ptr::null_mut());
        }
    }

    PROFILE_HOOK_REGISTERED.store(true, Ordering::SeqCst);
    debug!("Python profile hook registered successfully");

    // For Python < 3.12, install thread creation hook to detect new threads
    // Python 3.12+ has _thread.start_new_thread audit events and PyEval_SetProfileAllThreads
    let version = super::version::get();
    if !version.map_or(false, |v| v.at_least(3, 12)) {
        debug!(
            "Python < 3.12 detected ({:?}), installing thread creation hook",
            version
        );
        if !install_thread_creation_hook() {
            // Non-fatal: thread propagation won't work but single-threaded tracing will
            debug!("Thread creation hook installation failed - multi-threaded tracing may not work");
        }
    }

    true
}

/// Register profile hook with GIL acquisition.
/// Safe to call from any thread. Acquires GIL if needed.
///
/// NOTE: For Python < 3.12, this only works if PyEval_SetProfileAllThreads is available.
/// Otherwise, we must rely on the deferred audit hook approach (which runs on the main thread).
pub fn register_profile_hook_with_gil() -> bool {
    if PROFILE_HOOK_REGISTERED.load(Ordering::SeqCst) {
        return true;
    }

    // Check Python version - PyEval_SetProfileAllThreads requires Python 3.12+
    // If not available, we can't register from this thread - must use audit hook on main thread
    let version = super::version::get();
    if !version.map_or(false, |v| v.at_least(3, 12)) {
        debug!(
            "Python < 3.12 (detected: {:?}), deferring to audit hook for main thread registration",
            version
        );
        return false;
    }

    // Check if Python is fully initialized before acquiring GIL
    let py_is_initialized: Py_IsInitializedFn =
        match native::find_export(None, "Py_IsInitialized") {
            Ok(addr) => unsafe { std::mem::transmute(addr) },
            Err(e) => {
                error!("Failed to find Py_IsInitialized: {}", e);
                return false;
            }
        };

    if unsafe { py_is_initialized() } == 0 {
        debug!("Python not yet initialized, deferring profile hook registration");
        return false;
    }

    // Resolve GIL functions
    let gil_ensure: PyGILState_EnsureFn = match native::find_export(None, "PyGILState_Ensure") {
        Ok(addr) => unsafe { std::mem::transmute(addr) },
        Err(e) => {
            error!("Failed to find PyGILState_Ensure: {}", e);
            return false;
        }
    };

    let gil_release: PyGILState_ReleaseFn = match native::find_export(None, "PyGILState_Release") {
        Ok(addr) => unsafe { std::mem::transmute(addr) },
        Err(e) => {
            error!("Failed to find PyGILState_Release: {}", e);
            return false;
        }
    };

    debug!("Acquiring GIL for eager profile hook registration (using SetProfileAllThreads)");
    unsafe {
        let gil_state = gil_ensure();
        let result = do_register_profile_hook();
        gil_release(gil_state);
        result
    }
}

// =============================================================================
// THREAD PROFILE PROPAGATION
// =============================================================================

/// Propagate profile hook to all threads that don't have one set.
///
/// This is called from the profile hook when any Python call is traced.
/// When called, the GIL is held so we can safely iterate thread states.
///
/// # Safety
/// This function accesses internal PyThreadState structures. GIL must be held.
pub unsafe fn propagate_profile_to_threads() {
    let api = match PYTHON_API.get() {
        Some(api) => api,
        None => {
            debug!("propagate_profile_to_threads: PYTHON_API not initialized");
            return;
        }
    };

    // Get thread iteration functions (require Python 3.9+)
    let (thread_head, tstate_next, get_interp, tstate_get) = match (
        api.interp_thread_head,
        api.tstate_next,
        api.tstate_get_interp,
        api.tstate_unchecked_get,
    ) {
        (Some(h), Some(n), Some(i), Some(g)) => (h, n, i, g),
        _ => {
            debug!("Thread iteration APIs not available, skipping profile propagation");
            return;
        }
    };

    // Get current thread state
    let current = tstate_get();
    if current.is_null() {
        debug!("propagate_profile_to_threads: current tstate is null");
        return;
    }

    // Get interpreter using exported function (version-safe)
    let interp = get_interp(current);
    if interp.is_null() {
        debug!("propagate_profile_to_threads: interpreter is null");
        return;
    }

    // Iterate all threads in the interpreter
    let mut tstate = thread_head(interp);
    let mut propagated = 0;

    while !tstate.is_null() {
        // Check if this thread has a profile function set
        let profile_func = get_tstate_profilefunc(tstate);

        if profile_func.is_null() {
            // Set our profile hook on this thread
            set_tstate_profile(tstate, Some(profile_hook), std::ptr::null_mut());
            propagated += 1;
        }

        tstate = tstate_next(tstate);
    }

    if propagated > 0 {
        debug!("propagate_profile_to_threads: propagated to {} threads", propagated);
    }
}

// =============================================================================
// THREAD CREATION HOOK
// =============================================================================
//
// Hook for PyThread_start_new_thread to detect thread creation.
//
// For Python < 3.12, we hook the C function that creates threads
// and propagate the profile hook after each thread is created.
//
// This is necessary because:
// 1. Python < 3.12 does NOT emit `_thread.start_new_thread` audit events
// 2. PyEval_SetProfileAllThreads is only available in Python 3.12+
//
// By hooking PyThread_start_new_thread, we detect ALL thread creation
// (both threading.Thread and raw _thread.start_new_thread) and propagate
// our profile hook to the newly created thread.

/// Whether the thread creation hook is installed
static THREAD_HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Install hook on PyThread_start_new_thread.
///
/// When the hooked function returns (thread created), we propagate
/// the profile hook to all threads that don't have one set.
///
/// Returns true if hook was installed (or already installed), false on failure.
fn install_thread_creation_hook() -> bool {
    use log::warn;

    // Already installed?
    if THREAD_HOOK_INSTALLED.swap(true, Ordering::SeqCst) {
        return true;
    }

    // Find the symbol - try with and without underscore prefix
    // macOS uses underscore prefix, Linux typically doesn't
    let addr = match native::find_export(None, "PyThread_start_new_thread") {
        Ok(addr) => addr,
        Err(_) => match native::find_export(None, "_PyThread_start_new_thread") {
            Ok(addr) => addr,
            Err(e) => {
                warn!("PyThread_start_new_thread not found: {}", e);
                THREAD_HOOK_INSTALLED.store(false, Ordering::SeqCst);
                return false;
            }
        },
    };

    debug!(
        "Installing thread creation hook on PyThread_start_new_thread at {:#x}",
        addr
    );

    let interceptor = malwi_intercept::Interceptor::obtain();
    let listener = CallListener {
        on_enter: None,
        on_leave: Some(on_thread_created),
        user_data: std::ptr::null_mut(),
    };

    interceptor.begin_transaction();
    let attach_res = interceptor.attach(addr as *mut c_void, listener);
    interceptor.end_transaction();

    if let Err(e) = attach_res {
        warn!("Failed to attach thread creation hook: {:?}", e);
        THREAD_HOOK_INSTALLED.store(false, Ordering::SeqCst);
        return false;
    }

    debug!("Thread creation hook installed successfully");
    true
}

/// Callback when PyThread_start_new_thread returns.
///
/// At this point, the OS thread has been created but its PyThreadState might not
/// exist yet (it's created by the new thread in its bootstrap function).
///
/// We set a flag to trigger propagation on the next profile callback, AND try
/// to propagate immediately (in case the new thread is fast).
///
/// # Safety
/// Called by malwi-intercept with valid context. The main thread holds the GIL here because
/// it's still executing Python code (returning from threading.Thread.start() or
/// _thread.start_new_thread()).
unsafe extern "C" fn on_thread_created(
    _context: *mut InvocationContext,
    _user_data: *mut c_void,
) {
    debug!("Thread creation detected, flagging for propagation");

    // Set flag so profile hook propagates on next Python call (CALL or RETURN)
    // This handles the case where the new thread's PyThreadState doesn't exist yet
    THREAD_CREATED.store(true, Ordering::Relaxed);

    // Also try to propagate immediately - might catch threads that are already set up
    propagate_profile_to_threads();
}
