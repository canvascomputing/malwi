//! Python C API types and function pointers.
//!
//! Contains FFI type definitions for the Python C API and the PythonApi
//! struct that caches resolved function pointers.

// Allow non-camel-case types to match Python C API naming convention
#![allow(non_camel_case_types)]

use std::ffi::{c_int, c_void};
use std::os::raw::c_char;
use std::sync::OnceLock;

use log::debug;

use crate::native;

// =============================================================================
// PYTHON C API TYPES
// =============================================================================

pub type Py_tracefunc = unsafe extern "C" fn(
    obj: *mut c_void,   // User data (PyObject*)
    frame: *mut c_void, // PyFrameObject*
    what: c_int,        // Event type (PyTrace_CALL, etc.)
    arg: *mut c_void,   // Event-specific arg (PyObject*)
) -> c_int;

pub type PyEval_SetProfileAllThreadsFn =
    unsafe extern "C" fn(func: Option<Py_tracefunc>, obj: *mut c_void);

pub type PyEval_SetProfileFn = unsafe extern "C" fn(func: Option<Py_tracefunc>, obj: *mut c_void);

pub type PyFrame_GetCodeFn = unsafe extern "C" fn(frame: *mut c_void) -> *mut c_void;

pub type PyCode_GetNameFn = unsafe extern "C" fn(code: *mut c_void) -> *mut c_void;

pub type PyUnicode_AsUTF8Fn = unsafe extern "C" fn(obj: *mut c_void) -> *const c_char;

pub type Py_DecRefFn = unsafe extern "C" fn(obj: *mut c_void);

pub type PyObject_GetAttrStringFn =
    unsafe extern "C" fn(obj: *mut c_void, name: *const c_char) -> *mut c_void;

/// PyDict_GetItemString - get item from dict (borrowed reference, no decref needed!)
pub type PyDict_GetItemStringFn =
    unsafe extern "C" fn(dict: *mut c_void, key: *const c_char) -> *mut c_void;

/// PyFrame_GetBack - get parent frame (returns new reference)
pub type PyFrame_GetBackFn = unsafe extern "C" fn(frame: *mut c_void) -> *mut c_void;

/// PyFrame_GetLineNumber - get current line number
pub type PyFrame_GetLineNumberFn = unsafe extern "C" fn(frame: *mut c_void) -> c_int;

/// PyEval_GetFrame - get current frame (borrowed reference)
pub type PyEval_GetFrameFn = unsafe extern "C" fn() -> *mut c_void;

/// PyFrame_GetLocals - get frame's local variables dict (new reference in 3.11+, borrowed in earlier)
pub type PyFrame_GetLocalsFn = unsafe extern "C" fn(frame: *mut c_void) -> *mut c_void;

/// PyTuple_Size - get tuple length
pub type PyTuple_SizeFn = unsafe extern "C" fn(tuple: *mut c_void) -> isize;

/// PyTuple_GetItem - get tuple item at index (borrowed reference!)
pub type PyTuple_GetItemFn = unsafe extern "C" fn(tuple: *mut c_void, pos: isize) -> *mut c_void;

/// PyObject_GetItem - get item by key from any mapping (new reference, sets KeyError on miss)
pub type PyObject_GetItemFn =
    unsafe extern "C" fn(obj: *mut c_void, key: *mut c_void) -> *mut c_void;

/// PyObject_Repr - get string representation (new reference)
pub type PyObject_ReprFn = unsafe extern "C" fn(obj: *mut c_void) -> *mut c_void;

/// PyLong_AsLong - convert Python int to C long
pub type PyLong_AsLongFn = unsafe extern "C" fn(obj: *mut c_void) -> std::ffi::c_long;

/// PyErr_Clear - clear any pending Python exception
pub type PyErr_ClearFn = unsafe extern "C" fn();

/// PyErr_SetString - set a Python exception with message
pub type PyErr_SetStringFn = unsafe extern "C" fn(exc_type: *mut c_void, message: *const c_char);

/// GIL state type (opaque integer)
pub type PyGILState_STATE = c_int;

/// PyGILState_Ensure - acquire GIL, safe to call from any thread
pub type PyGILState_EnsureFn = unsafe extern "C" fn() -> PyGILState_STATE;

/// PyGILState_Release - release GIL acquired with Ensure
pub type PyGILState_ReleaseFn = unsafe extern "C" fn(state: PyGILState_STATE);

/// Py_IsInitialized - check if Python runtime is initialized
pub type Py_IsInitializedFn = unsafe extern "C" fn() -> c_int;

/// PyThread_start_new_thread - creates a new OS thread for Python
/// Returns thread ID on success, PYTHREAD_INVALID_THREAD_ID (-1) on failure
/// This is the low-level C function called by both threading.Thread and _thread.start_new_thread
#[allow(dead_code)] // Documented for reference; we hook by address not by type
pub type PyThread_start_new_threadFn =
    unsafe extern "C" fn(func: extern "C" fn(*mut c_void), arg: *mut c_void) -> std::ffi::c_ulong;

/// PyAuditHookFunction type for PySys_AddAuditHook
pub type PyAuditHookFunction =
    unsafe extern "C" fn(event: *const c_char, args: *mut c_void, user_data: *mut c_void) -> c_int;

/// PySys_AddAuditHook function type
pub type PySys_AddAuditHookFn =
    unsafe extern "C" fn(hook: PyAuditHookFunction, user_data: *mut c_void) -> c_int;

/// PyInterpreterState_ThreadHead - get first thread in interpreter
pub type PyInterpreterState_ThreadHeadFn = unsafe extern "C" fn(interp: *mut c_void) -> *mut c_void;

/// PyThreadState_Next - get next thread in list
pub type PyThreadState_NextFn = unsafe extern "C" fn(tstate: *mut c_void) -> *mut c_void;

/// PyThreadState_GetInterpreter - get interpreter from thread state (Python 3.9+)
pub type PyThreadState_GetInterpreterFn = unsafe extern "C" fn(tstate: *mut c_void) -> *mut c_void;

/// _PyThreadState_UncheckedGet - get current thread state (may be NULL)
pub type PyThreadState_UncheckedGetFn = unsafe extern "C" fn() -> *mut c_void;

// PyTrace event types
pub const PYTRACE_CALL: c_int = 0;

// =============================================================================
// PYTHON API STRUCT
// =============================================================================

/// Cached Python C API function pointers.
/// Initialized once during profile hook registration.
pub struct PythonApi {
    pub frame_get_code: PyFrame_GetCodeFn,
    pub unicode_as_utf8: PyUnicode_AsUTF8Fn,
    pub py_decref: Py_DecRefFn,
    pub get_attr_string: PyObject_GetAttrStringFn,
    pub dict_get_item_string: PyDict_GetItemStringFn,
    pub frame_get_back: PyFrame_GetBackFn,
    pub frame_get_line_number: PyFrame_GetLineNumberFn,
    pub eval_get_frame: PyEval_GetFrameFn,
    /// PyCode_GetName is optional (Python 3.11+ only)
    pub code_get_name: Option<PyCode_GetNameFn>,
    // Argument extraction APIs (some optional for older Python versions)
    pub frame_get_locals: Option<PyFrame_GetLocalsFn>, // Python 3.11+
    pub tuple_size: Option<PyTuple_SizeFn>,
    pub tuple_get_item: Option<PyTuple_GetItemFn>,
    pub object_get_item: Option<PyObject_GetItemFn>,
    pub object_repr: Option<PyObject_ReprFn>,
    pub long_as_long: Option<PyLong_AsLongFn>,
    pub err_clear: Option<PyErr_ClearFn>,
    pub err_set_string: Option<PyErr_SetStringFn>,
    pub exc_permission_error: *mut c_void,
    // Thread state iteration APIs (for propagating profile to new threads)
    pub interp_thread_head: Option<PyInterpreterState_ThreadHeadFn>,
    pub tstate_next: Option<PyThreadState_NextFn>,
    pub tstate_get_interp: Option<PyThreadState_GetInterpreterFn>,
    pub tstate_unchecked_get: Option<PyThreadState_UncheckedGetFn>,
}

// Safety: PythonApi function pointers and exc_permission_error are
// static Python objects that don't change after initialization
unsafe impl Send for PythonApi {}
unsafe impl Sync for PythonApi {}

/// Global Python API - initialized once, thread-safe access
pub static PYTHON_API: OnceLock<PythonApi> = OnceLock::new();

/// Resolve all required Python C API functions.
/// Returns None if any required function is missing.
pub fn resolve_python_api() -> Option<PythonApi> {
    let frame_get_code: PyFrame_GetCodeFn = native::find_export(None, "PyFrame_GetCode")
        .ok()
        .map(|addr| unsafe { std::mem::transmute(addr) })?;

    let unicode_as_utf8: PyUnicode_AsUTF8Fn = native::find_export(None, "PyUnicode_AsUTF8")
        .ok()
        .map(|addr| unsafe { std::mem::transmute(addr) })?;

    let py_decref: Py_DecRefFn = native::find_export(None, "Py_DecRef")
        .ok()
        .map(|addr| unsafe { std::mem::transmute(addr) })?;

    let get_attr_string: PyObject_GetAttrStringFn =
        native::find_export(None, "PyObject_GetAttrString")
            .ok()
            .map(|addr| unsafe { std::mem::transmute(addr) })?;

    let dict_get_item_string: PyDict_GetItemStringFn =
        native::find_export(None, "PyDict_GetItemString")
            .ok()
            .map(|addr| unsafe { std::mem::transmute(addr) })?;

    let frame_get_back: PyFrame_GetBackFn = native::find_export(None, "PyFrame_GetBack")
        .ok()
        .map(|addr| unsafe { std::mem::transmute(addr) })?;

    let frame_get_line_number: PyFrame_GetLineNumberFn =
        native::find_export(None, "PyFrame_GetLineNumber")
            .ok()
            .map(|addr| unsafe { std::mem::transmute(addr) })?;

    let eval_get_frame: PyEval_GetFrameFn = native::find_export(None, "PyEval_GetFrame")
        .ok()
        .map(|addr| unsafe { std::mem::transmute(addr) })?;

    // PyCode_GetName is optional (Python 3.11+)
    let code_get_name: Option<PyCode_GetNameFn> = native::find_export(None, "PyCode_GetName")
        .ok()
        .map(|addr| unsafe { std::mem::transmute(addr) });

    // Argument extraction APIs (optional - may not exist in older Python)
    let frame_get_locals: Option<PyFrame_GetLocalsFn> =
        native::find_export(None, "PyFrame_GetLocals")
            .ok()
            .map(|addr| unsafe { std::mem::transmute(addr) });

    let tuple_size: Option<PyTuple_SizeFn> = native::find_export(None, "PyTuple_Size")
        .ok()
        .map(|addr| unsafe { std::mem::transmute(addr) });

    let tuple_get_item: Option<PyTuple_GetItemFn> = native::find_export(None, "PyTuple_GetItem")
        .ok()
        .map(|addr| unsafe { std::mem::transmute(addr) });

    let object_get_item: Option<PyObject_GetItemFn> = native::find_export(None, "PyObject_GetItem")
        .ok()
        .map(|addr| unsafe { std::mem::transmute(addr) });

    let object_repr: Option<PyObject_ReprFn> = native::find_export(None, "PyObject_Repr")
        .ok()
        .map(|addr| unsafe { std::mem::transmute(addr) });

    let long_as_long: Option<PyLong_AsLongFn> = native::find_export(None, "PyLong_AsLong")
        .ok()
        .map(|addr| unsafe { std::mem::transmute(addr) });

    let err_clear: Option<PyErr_ClearFn> = native::find_export(None, "PyErr_Clear")
        .ok()
        .map(|addr| unsafe { std::mem::transmute(addr) });

    let err_set_string: Option<PyErr_SetStringFn> = native::find_export(None, "PyErr_SetString")
        .ok()
        .map(|addr| unsafe { std::mem::transmute(addr) });

    // PyExc_PermissionError is a global variable (pointer to PyObject)
    // The symbol is the address OF the pointer, so we dereference to get the PyObject*
    let exc_permission_error: *mut c_void = native::find_export(None, "PyExc_PermissionError")
        .ok()
        .map(|addr| unsafe { *(addr as *const *mut c_void) })
        .unwrap_or(std::ptr::null_mut());

    // Thread state iteration APIs (optional - for propagating profile to new threads)
    let interp_thread_head: Option<PyInterpreterState_ThreadHeadFn> =
        native::find_export(None, "PyInterpreterState_ThreadHead")
            .ok()
            .map(|addr| unsafe { std::mem::transmute(addr) });

    let tstate_next: Option<PyThreadState_NextFn> = native::find_export(None, "PyThreadState_Next")
        .ok()
        .map(|addr| unsafe { std::mem::transmute(addr) });

    let tstate_get_interp: Option<PyThreadState_GetInterpreterFn> =
        native::find_export(None, "PyThreadState_GetInterpreter")
            .ok()
            .map(|addr| unsafe { std::mem::transmute(addr) });

    // Try both symbol names:
    // - _PyThreadState_UncheckedGet (Python < 3.13, private API with underscore prefix)
    // - PyThreadState_GetUnchecked (Python 3.13+, now public without underscore)
    let tstate_unchecked_get: Option<PyThreadState_UncheckedGetFn> =
        native::find_export(None, "_PyThreadState_UncheckedGet")
            .or_else(|_| native::find_export(None, "PyThreadState_GetUnchecked"))
            .ok()
            .map(|addr| unsafe { std::mem::transmute(addr) });

    Some(PythonApi {
        frame_get_code,
        unicode_as_utf8,
        py_decref,
        get_attr_string,
        dict_get_item_string,
        frame_get_back,
        frame_get_line_number,
        eval_get_frame,
        code_get_name,
        frame_get_locals,
        tuple_size,
        tuple_get_item,
        object_get_item,
        object_repr,
        long_as_long,
        err_clear,
        err_set_string,
        exc_permission_error,
        interp_thread_head,
        tstate_next,
        tstate_get_interp,
        tstate_unchecked_get,
    })
}

/// Initialize the Python API cache.
/// Returns true if successful, false if already initialized or failed.
pub fn init_python_api() -> bool {
    if PYTHON_API.get().is_some() {
        return true;
    }

    match resolve_python_api() {
        Some(api) => {
            let has_code_get_name = api.code_get_name.is_some();
            let has_thread_iter = api.interp_thread_head.is_some()
                && api.tstate_next.is_some()
                && api.tstate_get_interp.is_some()
                && api.tstate_unchecked_get.is_some();
            if PYTHON_API.set(api).is_ok() {
                if has_code_get_name {
                    debug!("Python API initialized (using PyCode_GetName)");
                } else {
                    debug!("Python API initialized (using co_name fallback)");
                }
                if has_thread_iter {
                    debug!("Thread iteration APIs available for profile propagation");
                } else {
                    debug!("Thread iteration APIs NOT available (thread propagation disabled)");
                }
                true
            } else {
                false
            }
        }
        None => false,
    }
}
