//! Helper functions for Python introspection.
//!
//! Contains utilities for extracting information from Python objects
//! like frames and code objects.

use std::ffi::{c_void, CStr};
use std::os::raw::c_char;

use malwi_protocol::Argument;

use super::ffi::PYTHON_API;

// Re-export truncate_display from shared tracing utilities
pub use crate::tracing::format::truncate_display;

/// Safely convert C string pointer to Rust String.
///
/// # Safety
/// Caller must ensure ptr is either null or points to valid UTF-8 C string.
pub unsafe fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    CStr::from_ptr(ptr).to_str().ok().map(String::from)
}

/// Extract module name from frame's f_globals['__name__'].
///
/// # Safety
/// Caller must ensure frame is a valid PyFrameObject pointer and GIL is held.
pub unsafe fn get_module_name(frame: *mut c_void) -> Option<String> {
    let api = PYTHON_API.get()?;

    // Get f_globals from frame
    let f_globals = (api.get_attr_string)(frame, b"f_globals\0".as_ptr() as *const c_char);
    if f_globals.is_null() {
        return None;
    }

    // Get __name__ from globals dict (borrowed reference - no decref!)
    let name_obj =
        (api.dict_get_item_string)(f_globals, b"__name__\0".as_ptr() as *const c_char);
    let result = if !name_obj.is_null() {
        cstr_to_string((api.unicode_as_utf8)(name_obj))
    } else {
        None
    };

    // Decref f_globals (get_attr_string returns new reference)
    (api.py_decref)(f_globals);

    result
}

/// Get co_qualname from code object (Python 3.11+ for class methods).
///
/// # Safety
/// Caller must ensure code is a valid PyCodeObject pointer and GIL is held.
pub unsafe fn get_qualname(code: *mut c_void) -> Option<String> {
    let api = PYTHON_API.get()?;

    let qualname_obj = (api.get_attr_string)(code, b"co_qualname\0".as_ptr() as *const c_char);
    if qualname_obj.is_null() {
        // Clear the AttributeError from failed lookup (Python < 3.11)
        if let Some(err_clear) = api.err_clear {
            err_clear();
        }
        return None;
    }

    let result = cstr_to_string((api.unicode_as_utf8)(qualname_obj));
    (api.py_decref)(qualname_obj);
    result
}

/// Get simple function name from code object (co_name).
///
/// # Safety
/// Caller must ensure code is a valid PyCodeObject pointer and GIL is held.
pub unsafe fn get_simple_name(code: *mut c_void) -> Option<String> {
    let api = PYTHON_API.get()?;

    // Try PyCode_GetName first (Python 3.11+), fall back to co_name attribute
    let name_obj = if let Some(code_get_name) = api.code_get_name {
        code_get_name(code)
    } else {
        (api.get_attr_string)(code, b"co_name\0".as_ptr() as *const c_char)
    };

    if name_obj.is_null() {
        return None;
    }

    let result = cstr_to_string((api.unicode_as_utf8)(name_obj));
    (api.py_decref)(name_obj);
    result
}

/// Get the display string for a Python object via repr().
///
/// Handles null repr results and clears any Python exceptions.
/// Returns None if repr fails.
///
/// # Safety
/// Caller must ensure obj is a valid PyObject pointer and GIL is held.
unsafe fn get_object_display(
    obj: *mut c_void,
    api: &super::ffi::PythonApi,
    object_repr: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    max_len: usize,
) -> Option<String> {
    let repr_obj = object_repr(obj);
    if repr_obj.is_null() {
        if let Some(err_clear) = api.err_clear {
            err_clear();
        }
        return None;
    }
    let repr_str = cstr_to_string((api.unicode_as_utf8)(repr_obj));
    (api.py_decref)(repr_obj);
    repr_str.map(|s| simplify_object_repr(&truncate_display(&s, max_len)))
}

/// Get filename from code object (co_filename).
///
/// # Safety
/// Caller must ensure code is a valid PyCodeObject pointer and GIL is held.
pub unsafe fn get_code_filename(code: *mut c_void) -> Option<String> {
    let api = PYTHON_API.get()?;

    let filename_obj = (api.get_attr_string)(code, b"co_filename\0".as_ptr() as *const c_char);
    if filename_obj.is_null() {
        return None;
    }

    let result = cstr_to_string((api.unicode_as_utf8)(filename_obj));
    (api.py_decref)(filename_obj);
    result
}

/// Get co_argcount from code object (number of positional arguments).
///
/// # Safety
/// Caller must ensure code is a valid PyCodeObject pointer and GIL is held.
pub unsafe fn get_code_argcount(code: *mut c_void) -> usize {
    let api = match PYTHON_API.get() {
        Some(api) => api,
        None => return 0,
    };

    let long_as_long = match api.long_as_long {
        Some(f) => f,
        None => return 0,
    };

    let argcount_obj = (api.get_attr_string)(code, b"co_argcount\0".as_ptr() as *const c_char);
    if argcount_obj.is_null() {
        return 0;
    }

    let count = long_as_long(argcount_obj);
    (api.py_decref)(argcount_obj);

    if count < 0 {
        0
    } else {
        count as usize
    }
}

/// Reconstruct class name from `self`/`cls` parameter for Python < 3.11.
///
/// When `co_qualname` is unavailable, inspects the frame's locals to find the
/// first argument. If it's named `self` or `cls`, extracts the class's
/// `__qualname__` to reconstruct class method names like `"HTTPConnection.request"`.
///
/// # Safety
/// Caller must ensure frame and code are valid Python object pointers and GIL is held.
unsafe fn get_class_name_from_self(frame: *mut c_void, code: *mut c_void) -> Option<String> {
    let api = PYTHON_API.get()?;

    // Must have at least one argument
    if get_code_argcount(code) < 1 {
        return None;
    }

    // Need tuple access to check co_varnames[0]
    let (tuple_get_item, tuple_size) = match (api.tuple_get_item, api.tuple_size) {
        (Some(tgi), Some(ts)) => (tgi, ts),
        _ => return None,
    };

    // Get co_varnames tuple (new ref)
    let varnames = (api.get_attr_string)(code, b"co_varnames\0".as_ptr() as *const c_char);
    if varnames.is_null() {
        if let Some(err_clear) = api.err_clear {
            err_clear();
        }
        return None;
    }

    let varnames_len = tuple_size(varnames);
    if varnames_len < 1 {
        (api.py_decref)(varnames);
        return None;
    }

    // Check first parameter name (borrowed ref from tuple)
    let first_name_obj = tuple_get_item(varnames, 0);
    let first_name = if !first_name_obj.is_null() {
        cstr_to_string((api.unicode_as_utf8)(first_name_obj))
    } else {
        None
    };
    (api.py_decref)(varnames);

    let first_name = first_name?;
    let is_self = first_name == "self";
    let is_cls = first_name == "cls";
    if !is_self && !is_cls {
        return None;
    }

    // Get f_locals from frame (new ref — triggers FastToLocals on 3.10)
    let locals = (api.get_attr_string)(frame, b"f_locals\0".as_ptr() as *const c_char);
    if locals.is_null() {
        if let Some(err_clear) = api.err_clear {
            err_clear();
        }
        return None;
    }

    // Get the self/cls value from locals dict (borrowed ref)
    let key = if is_self {
        b"self\0".as_ptr()
    } else {
        b"cls\0".as_ptr()
    };
    let obj = (api.dict_get_item_string)(locals, key as *const c_char);
    if obj.is_null() {
        (api.py_decref)(locals);
        return None;
    }

    // For 'self': get __class__ first (new ref), then __qualname__ from class
    // For 'cls': get __qualname__ directly from the cls object
    let class_obj = if is_self {
        let cls = (api.get_attr_string)(obj, b"__class__\0".as_ptr() as *const c_char);
        if cls.is_null() {
            if let Some(err_clear) = api.err_clear {
                err_clear();
            }
            (api.py_decref)(locals);
            return None;
        }
        cls // new ref, must decref
    } else {
        // cls is already the class — but we have a borrowed ref from dict,
        // so we don't own it. We'll just use it without decref.
        obj
    };

    let qualname_obj =
        (api.get_attr_string)(class_obj, b"__qualname__\0".as_ptr() as *const c_char);
    let result = if !qualname_obj.is_null() {
        let s = cstr_to_string((api.unicode_as_utf8)(qualname_obj));
        (api.py_decref)(qualname_obj);
        s
    } else {
        if let Some(err_clear) = api.err_clear {
            err_clear();
        }
        None
    };

    // Clean up: decref class_obj only if we got it from get_attr_string (self case)
    if is_self {
        (api.py_decref)(class_obj);
    }
    (api.py_decref)(locals);

    result
}

/// Simplify Python object repr by extracting meaningful names from `<type name at 0x...>` format.
///
/// Simple values (strings, numbers, lists, dicts) pass through unchanged.
/// Object reprs have their memory addresses and internal info stripped:
/// - `<code object <module> at 0x109e62f50>` → `<module>`
/// - `<function my_func at 0x10abcdef0>` → `my_func`
/// - `<built-in function print>` → `print`
/// - `<module 'os' from '/usr/lib/...'>` → `os`
/// - `<class 'dict'>` → `dict`
/// - `<unknown_type at 0x...>` → `[Object]`
fn simplify_object_repr(s: &str) -> String {
    // Only process <...> repr format (objects with addresses/internal info)
    // Simple values like 'hello', 42, [1,2,3], {'k':'v'} pass through unchanged
    if !s.starts_with('<') || !s.ends_with('>') {
        return s.to_string();
    }
    let inner = &s[1..s.len() - 1]; // strip outer < >

    // <code object NAME at 0x...> or <code object NAME at 0x..., file "...">
    if let Some(rest) = inner.strip_prefix("code object ") {
        if let Some(name) = rest.split(" at 0x").next() {
            return name.to_string();
        }
    }
    // <function NAME at 0x...>
    if let Some(rest) = inner.strip_prefix("function ") {
        if let Some(name) = rest.split(" at 0x").next() {
            return name.to_string();
        }
    }
    // <built-in function NAME>
    if let Some(name) = inner.strip_prefix("built-in function ") {
        return name.to_string();
    }
    // <module 'NAME' from '...'>
    if let Some(rest) = inner.strip_prefix("module ") {
        if let Some(name) = rest.strip_prefix('\'').and_then(|s| s.split('\'').next()) {
            return name.to_string();
        }
    }
    // <class 'NAME'>
    if let Some(rest) = inner.strip_prefix("class ") {
        if let Some(name) = rest.strip_prefix('\'').and_then(|s| s.split('\'').next()) {
            return name.to_string();
        }
    }
    // Unrecognized <...> format
    "[Object]".to_string()
}

/// Extract fully qualified function name: "module.function" or "module.Class.method".
///
/// # Safety
/// Caller must ensure frame is a valid PyFrameObject pointer and GIL is held.
pub unsafe fn get_qualified_function_name(frame: *mut c_void) -> Option<String> {
    if frame.is_null() {
        return None;
    }

    let api = PYTHON_API.get()?;

    let code = (api.frame_get_code)(frame);
    if code.is_null() {
        return None;
    }

    // Get function name - prefer qualname for class methods (Python 3.11+),
    // fall back to reconstructing from self/cls on older versions
    let func_name = get_qualname(code).or_else(|| {
        let simple = get_simple_name(code)?;
        if let Some(class_name) = get_class_name_from_self(frame, code) {
            Some(format!("{}.{}", class_name, simple))
        } else {
            Some(simple)
        }
    })?;

    // Get module name
    let module_name = get_module_name(frame);

    // Construct qualified name
    match module_name {
        Some(ref module) if !module.is_empty() && module != "__main__" => {
            Some(format!("{}.{}", module, func_name))
        }
        _ => Some(func_name),
    }
}

/// Extract arguments from a Python tuple (used by audit hook).
///
/// The audit hook receives arguments as a tuple. This extracts
/// repr() of each element.
///
/// # Arguments
/// * `args_tuple` - Python tuple object (borrowed reference)
///
/// # Safety
/// Caller must ensure args_tuple is a valid PyObject pointer and GIL is held.
pub unsafe fn extract_tuple_arguments(args_tuple: *mut c_void) -> Vec<Argument> {
    const MAX_DISPLAY_LEN: usize = 200;
    let mut arguments = Vec::new();

    let api = match PYTHON_API.get() {
        Some(api) => api,
        None => return arguments,
    };

    // Need tuple_size, tuple_get_item, and object_repr
    let (tuple_size, tuple_get_item, object_repr) =
        match (api.tuple_size, api.tuple_get_item, api.object_repr) {
            (Some(ts), Some(tgi), Some(or)) => (ts, tgi, or),
            _ => return arguments,
        };

    if args_tuple.is_null() {
        return arguments;
    }

    let tuple_len = tuple_size(args_tuple);
    if tuple_len <= 0 {
        return arguments;
    }

    for i in 0..tuple_len as usize {
        // PyTuple_GetItem returns borrowed reference
        let item = tuple_get_item(args_tuple, i as isize);
        if item.is_null() {
            continue;
        }

        // Get repr() of item
        let display = get_object_display(item, api, object_repr, MAX_DISPLAY_LEN);

        arguments.push(Argument {
            raw_value: item as usize,
            display,
        });
    }

    arguments
}

/// Extract function arguments from Python frame.
///
/// Uses frame's locals dict and code object's co_varnames to get
/// all positional arguments. Returns their repr() strings.
///
/// # Arguments
/// * `frame` - Python frame object (borrowed reference)
///
/// # Safety
/// Caller must ensure frame is a valid PyFrameObject pointer and GIL is held.
pub unsafe fn extract_function_arguments(frame: *mut c_void) -> Vec<Argument> {
    const MAX_DISPLAY_LEN: usize = 200;
    let mut arguments = Vec::new();

    let api = match PYTHON_API.get() {
        Some(api) => api,
        None => return arguments,
    };

    // Need tuple_size, tuple_get_item, object_get_item, object_repr
    let (tuple_size, tuple_get_item, object_get_item, object_repr) =
        match (
            api.tuple_size,
            api.tuple_get_item,
            api.object_get_item,
            api.object_repr,
        ) {
            (Some(ts), Some(tgi), Some(ogi), Some(or)) => (ts, tgi, ogi, or),
            _ => return arguments,
        };

    if frame.is_null() {
        return arguments;
    }

    // Get code object from frame
    let code = (api.frame_get_code)(frame);
    if code.is_null() {
        return arguments;
    }

    // Get number of positional arguments from co_argcount
    let argcount = get_code_argcount(code);
    if argcount == 0 {
        return arguments;
    }

    // Get co_varnames tuple (contains parameter names first, then locals)
    let varnames = (api.get_attr_string)(code, b"co_varnames\0".as_ptr() as *const c_char);
    if varnames.is_null() {
        return arguments;
    }

    // Get locals dict from frame — prefer PyFrame_GetLocals (3.11+),
    // fall back to frame.f_locals attribute (triggers FastToLocals on 3.10)
    let locals = if let Some(frame_get_locals) = api.frame_get_locals {
        frame_get_locals(frame)
    } else {
        (api.get_attr_string)(frame, b"f_locals\0".as_ptr() as *const c_char)
    };
    if locals.is_null() {
        if let Some(err_clear) = api.err_clear {
            err_clear();
        }
        (api.py_decref)(varnames);
        return arguments;
    }

    // Get tuple size to avoid out-of-bounds
    let varnames_len = tuple_size(varnames);
    if varnames_len < 0 {
        (api.py_decref)(varnames);
        (api.py_decref)(locals);
        return arguments;
    }

    // Extract all arguments (argcount tells us exactly how many positional args)
    let capture_count = argcount.min(varnames_len as usize);

    for i in 0..capture_count {
        // Get parameter name from varnames tuple (borrowed reference!)
        let name_obj = tuple_get_item(varnames, i as isize);
        if name_obj.is_null() {
            continue;
        }

        // Get value from locals by name (new reference — works on dict and FrameLocalsProxy)
        let value_obj = object_get_item(locals, name_obj);
        if value_obj.is_null() {
            // PyObject_GetItem sets KeyError on miss — clear it
            if let Some(err_clear) = api.err_clear {
                err_clear();
            }
            continue;
        }

        // Get repr() of value
        let display = get_object_display(value_obj, api, object_repr, MAX_DISPLAY_LEN);

        // PyObject_GetItem returns a new reference — decref after use
        (api.py_decref)(value_obj);

        arguments.push(Argument {
            raw_value: value_obj as usize,
            display,
        });
    }

    // Clean up (varnames and locals are new references)
    (api.py_decref)(varnames);
    (api.py_decref)(locals);

    arguments
}

/// Send trace event, handling review mode if enabled.
///
/// Returns `Ok(())` if the event was allowed/sent, `Err(())` if blocked by user.
pub fn send_trace_event(event: malwi_protocol::TraceEvent) -> Result<(), ()> {
    let Some(agent) = crate::Agent::get() else {
        return Ok(());
    };
    if !agent.is_review_mode() {
        let _ = agent.send_event(event);
        return Ok(());
    }
    let decision = agent.await_review_decision(event.clone());
    if decision.is_allowed() {
        Ok(())
    } else {
        log::info!("BLOCKED: {}", event.function);
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simplify_repr_code_object() {
        assert_eq!(
            simplify_object_repr("<code object <module> at 0x109e62f50, file \"<string>\">"),
            "<module>"
        );
        assert_eq!(
            simplify_object_repr("<code object my_func at 0x10abcdef0>"),
            "my_func"
        );
    }

    #[test]
    fn test_simplify_repr_function() {
        assert_eq!(
            simplify_object_repr("<function my_func at 0x10abcdef0>"),
            "my_func"
        );
    }

    #[test]
    fn test_simplify_repr_builtin() {
        assert_eq!(
            simplify_object_repr("<built-in function print>"),
            "print"
        );
    }

    #[test]
    fn test_simplify_repr_module() {
        assert_eq!(
            simplify_object_repr("<module 'os' from '/usr/lib/python3.12/os.py'>"),
            "os"
        );
    }

    #[test]
    fn test_simplify_repr_class() {
        assert_eq!(
            simplify_object_repr("<class 'dict'>"),
            "dict"
        );
    }

    #[test]
    fn test_simplify_repr_unknown_object() {
        assert_eq!(
            simplify_object_repr("<foo at 0x12345>"),
            "[Object]"
        );
    }

    #[test]
    fn test_simplify_repr_simple_values() {
        // Simple values pass through unchanged
        assert_eq!(simplify_object_repr("'hello'"), "'hello'");
        assert_eq!(simplify_object_repr("42"), "42");
        assert_eq!(simplify_object_repr("[1, 2, 3]"), "[1, 2, 3]");
        assert_eq!(simplify_object_repr("{'k': 'v'}"), "{'k': 'v'}");
        assert_eq!(simplify_object_repr("None"), "None");
        assert_eq!(simplify_object_repr("True"), "True");
    }
}
