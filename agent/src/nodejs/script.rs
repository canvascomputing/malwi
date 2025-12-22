//! Node.js Script Execution API.
//!
//! This module provides functions to execute JavaScript code within
//! the current V8 context and retrieve results.

use std::ffi::{c_int, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use log::debug;

use super::ffi::{
    v8_Isolate, v8_String, v8_Value, IsolateGetCurrentContextFn, IsolateGetCurrentFn,
    ScriptCompileFn, ScriptRunFn, StringNewFromUtf8Fn, StringUtf8LengthFn, StringWriteUtf8Fn,
};
use super::symbols;
use crate::native;

// =============================================================================
// API STRUCT
// =============================================================================

/// Node.js Script Execution API - cached function pointers
struct NodejsScriptApi {
    isolate_get_current: IsolateGetCurrentFn,
    isolate_get_current_context: IsolateGetCurrentContextFn,
    string_new_from_utf8: StringNewFromUtf8Fn,
    script_compile: ScriptCompileFn,
    script_run: ScriptRunFn,
    string_utf8_length: StringUtf8LengthFn,
    string_write_utf8: StringWriteUtf8Fn,
}

/// Global Node.js Script API - initialized once
static NODEJS_SCRIPT_API: OnceLock<NodejsScriptApi> = OnceLock::new();

/// Flag to prevent repeated resolution attempts
static NODEJS_SCRIPT_API_RESOLUTION_ATTEMPTED: AtomicBool = AtomicBool::new(false);

// =============================================================================
// API RESOLUTION
// =============================================================================

/// Try to resolve Node.js Script Execution API functions.
fn resolve_nodejs_script_api() -> Option<NodejsScriptApi> {
    if NODEJS_SCRIPT_API_RESOLUTION_ATTEMPTED.load(Ordering::SeqCst) {
        return None;
    }
    NODEJS_SCRIPT_API_RESOLUTION_ATTEMPTED.store(true, Ordering::SeqCst);

    debug!("Attempting to resolve Node.js Script Execution API...");

    macro_rules! resolve {
        ($sym:expr) => {
            match native::find_export(None, $sym) {
                Ok(addr) => unsafe { std::mem::transmute(addr) },
                Err(e) => {
                    debug!("Failed to resolve {}: {}", $sym, e);
                    return None;
                }
            }
        };
    }

    let isolate_get_current: IsolateGetCurrentFn = resolve!(symbols::v8::ISOLATE_GET_CURRENT);
    let isolate_get_current_context: IsolateGetCurrentContextFn =
        resolve!(symbols::v8::ISOLATE_GET_CURRENT_CONTEXT);
    let string_new_from_utf8: StringNewFromUtf8Fn = resolve!(symbols::v8::STRING_NEW_FROM_UTF8);
    let script_compile: ScriptCompileFn = resolve!(symbols::v8::SCRIPT_COMPILE);
    let script_run: ScriptRunFn = resolve!(symbols::v8::SCRIPT_RUN);
    let string_utf8_length: StringUtf8LengthFn = resolve!(symbols::v8::STRING_UTF8_LENGTH);
    let string_write_utf8: StringWriteUtf8Fn = resolve!(symbols::v8::STRING_WRITE_UTF8);

    debug!("Node.js Script Execution API resolved successfully");

    Some(NodejsScriptApi {
        isolate_get_current,
        isolate_get_current_context,
        string_new_from_utf8,
        script_compile,
        script_run,
        string_utf8_length,
        string_write_utf8,
    })
}

/// Get or initialize the Node.js Script API.
fn get_script_api() -> Option<&'static NodejsScriptApi> {
    if let Some(api) = NODEJS_SCRIPT_API.get() {
        return Some(api);
    }

    if let Some(api) = resolve_nodejs_script_api() {
        let _ = NODEJS_SCRIPT_API.set(api);
        NODEJS_SCRIPT_API.get()
    } else {
        None
    }
}

// =============================================================================
// PUBLIC API
// =============================================================================

/// Execute JavaScript code in the current V8 context and return the result as a string.
///
/// # Safety
/// Must be called from within a V8 context (e.g., during a trace hook).
/// The code will be compiled and executed synchronously.
///
/// # Returns
/// - Some(string) with the result if successful
/// - None if execution failed or no V8 context
pub fn execute_js(code: &str) -> Option<String> {
    let api = get_script_api()?;

    unsafe {
        // Get current isolate
        let isolate = (api.isolate_get_current)();
        if isolate.is_null() {
            debug!("No current V8 isolate");
            return None;
        }

        // Get current context
        let context = (api.isolate_get_current_context)(isolate);
        if context.is_null() {
            debug!("No current V8 context");
            return None;
        }

        // Create source string
        let code_cstr = CString::new(code).ok()?;
        const NEW_STRING_TYPE_NORMAL: c_int = 0;
        let source = (api.string_new_from_utf8)(
            isolate,
            code_cstr.as_ptr(),
            NEW_STRING_TYPE_NORMAL,
            code.len() as c_int,
        );
        if source.is_null() {
            debug!("Failed to create V8 string from code");
            return None;
        }

        // Compile script (no ScriptOrigin)
        let script = (api.script_compile)(context, source, std::ptr::null());
        if script.is_null() {
            debug!("Failed to compile JavaScript code");
            return None;
        }

        // Run script
        let result = (api.script_run)(script, context);
        if result.is_null() {
            debug!("JavaScript execution returned empty result");
            return None;
        }

        // Try to convert result to string
        extract_v8_string(api, result, isolate)
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Extract a Rust String from a V8 Value (assumes it's a string type).
unsafe fn extract_v8_string(
    api: &NodejsScriptApi,
    value: v8_Value,
    isolate: v8_Isolate,
) -> Option<String> {
    let v8_str = value as v8_String;

    let len = (api.string_utf8_length)(v8_str, isolate);
    if len <= 0 {
        return Some(String::new());
    }

    let mut buffer = vec![0u8; len as usize + 1];
    let mut nchars: c_int = 0;
    const NO_OPTIONS: c_int = 0;

    (api.string_write_utf8)(
        v8_str,
        isolate,
        buffer.as_mut_ptr() as *mut c_char,
        len + 1,
        &mut nchars,
        NO_OPTIONS,
    );

    buffer.truncate(len as usize);
    String::from_utf8(buffer).ok()
}
