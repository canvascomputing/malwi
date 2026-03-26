//! JavaScript Function Tracing via V8 Internal Tracing.
//!
//! This module enables V8's built-in function tracing by:
//! 1. Calling `v8::V8::SetFlagsFromString("--trace")` to enable tracing
//! 2. Hooking `Runtime_TraceEnter` and `Runtime_TraceExit` to intercept trace events
//! 3. Suppressing V8's stdout output while preserving V8 internal behavior
//! 4. Using stack parser to detect parameter types from V8 stack frames
//!
//! We must call the original V8 functions because they manage internal state:
//! - `SealHandleScope` for GC safety
//! - Validation checks (`CHECK_UNLESS_FUZZING`)
//! - Return value passthrough (TraceExit returns args[0])

use std::cell::RefCell;
use std::ffi::{c_char, c_void, CString};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use log::{debug, error, info, warn};

use super::stack;
use super::state::BytecodePhase;
use crate::native;
use core::ptr;

// =============================================================================
// SHADOW STACK FOR --st SUPPORT
// =============================================================================

/// Whether any filter has capture_stack=true (set once, never unset).
/// When false, skip shadow stack maintenance for zero overhead.
static STACK_CAPTURE_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable shadow stack maintenance (called when a filter has capture_stack=true).
pub fn enable_stack_capture() {
    STACK_CAPTURE_ENABLED.store(true, Ordering::Release);
}

thread_local! {
    /// Shadow call stack: function names pushed on TraceEnter, popped on TraceExit.
    /// Only maintained when STACK_CAPTURE_ENABLED is true.
    static TRACED_JS_CALL_STACK: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

// =============================================================================
// V8 SYMBOL NAMES
// =============================================================================

/// v8::V8::SetFlagsFromString(const char*)
#[cfg(unix)]
const SET_FLAGS_FROM_STRING: &str = "_ZN2v82V818SetFlagsFromStringEPKc";

/// v8::internal::Runtime_TraceEnter(int, Address*, Isolate*)
#[cfg(unix)]
const RUNTIME_TRACE_ENTER: &str = "_ZN2v88internal18Runtime_TraceEnterEiPmPNS0_7IsolateE";

/// v8::internal::Runtime_TraceExit(int, Address*, Isolate*)
#[cfg(unix)]
const RUNTIME_TRACE_EXIT: &str = "_ZN2v88internal17Runtime_TraceExitEiPmPNS0_7IsolateE";

/// v8::internal::PrintF(const char*, ...) - outputs trace text to stdout
#[cfg(unix)]
const V8_PRINTF: &str = "_ZN2v88internal6PrintFEPKcz";

/// v8::internal::PrintF(FILE*, const char*, ...) - outputs trace text to a FILE*
/// macOS uses __sFILE, Linux uses _IO_FILE in the mangling.
#[cfg(target_os = "macos")]
const V8_PRINTF_FILE: &str = "_ZN2v88internal6PrintFEP7__sFILEPKcz";
#[cfg(target_os = "linux")]
const V8_PRINTF_FILE: &str = "_ZN2v88internal6PrintFEP8_IO_FILEPKcz";

// =============================================================================
// FUNCTION TYPES
// =============================================================================

/// v8::V8::SetFlagsFromString(const char*) -> void
type SetFlagsFromStringFn = unsafe extern "C" fn(*const c_char);

/// Original Runtime_TraceEnter function pointer (set during hook installation).
/// Written once with Release ordering during `install_trace_hooks()`, read with
/// Acquire ordering in the replacement callback on arbitrary V8 threads.
static ORIGINAL_TRACE_ENTER: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

/// Original Runtime_TraceExit function pointer (set during hook installation).
/// Written once with Release ordering during `install_trace_hooks()`, read with
/// Acquire ordering in the replacement callback on arbitrary V8 threads.
static ORIGINAL_TRACE_EXIT: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

// =============================================================================
// SKIP LOGIC FOR ADDON DEDUPLICATION
// =============================================================================

/// Check if we should skip tracing because the addon already handled this call.
///
/// Uses a per-call thread-local flag set by the addon callback. This avoids
/// the old process-wide flag which could suppress bytecode events for files
/// that the addon didn't actually trace (e.g. if the addon event was lost).
fn should_skip_for_addon(_isolate: *mut std::ffi::c_void) -> bool {
    super::addon::callback::take_addon_handled()
}

// =============================================================================
// V8 TRACING CONTROL
// =============================================================================

/// Enable V8's internal function tracing by calling SetFlagsFromString("--trace").
///
/// This must be called BEFORE V8 starts executing JavaScript code.
pub fn enable_v8_tracing() -> bool {
    if !BytecodePhase::advance(BytecodePhase::Uninitialized, BytecodePhase::TraceEnabled) {
        return BytecodePhase::current() >= BytecodePhase::TraceEnabled;
    }

    debug!("Enabling V8 internal tracing...");

    // Find v8::V8::SetFlagsFromString
    let set_flags_addr = match native::find_export(None, SET_FLAGS_FROM_STRING) {
        Ok(addr) => addr,
        Err(e) => {
            warn!("Failed to find SetFlagsFromString: {}", e);
            BytecodePhase::reset_to(BytecodePhase::TraceEnabled, BytecodePhase::Uninitialized);
            return false;
        }
    };

    let set_flags: SetFlagsFromStringFn =
        unsafe { std::mem::transmute::<usize, SetFlagsFromStringFn>(set_flags_addr) };

    // Enable --trace flag. This instruments the bytecode interpreter only.
    // Sparkplug/Maglev JIT tiers bypass trace calls, but we don't disable them:
    // short-lived code (eval, one-shot scripts) runs in the interpreter anyway
    // (JIT needs warmup), and long-running module functions are traced by the
    // N-API addon's require-hook wrapping. Disabling JIT tiers causes regressions
    // on older V8 versions (e.g. V8 11.8 / Node v21).
    let flags = CString::new("--trace").unwrap();
    unsafe { set_flags(flags.as_ptr()) };

    info!("V8 --trace flag enabled via SetFlagsFromString");
    true
}

/// Find the V8 module name from loaded modules.
fn find_v8_module() -> Option<String> {
    for module in native::enumerate_modules() {
        // Look for "node" binary (Node.js embeds V8)
        // Match: "node", "node.exe", "node-v24.13.0", etc.
        if module.name == "node"
            || module.name.starts_with("node.")
            || module.name.starts_with("node-")
        {
            return Some(module.name);
        }
        // Also check path for node binary
        // Match: "/path/to/node", "/path/to/node-v24.13.0", etc.
        if module.path.ends_with("/node")
            || module.path.contains("/node.")
            || module.path.contains("/node-")
        {
            return Some(module.name);
        }
    }
    None
}

/// Try to find a symbol, first as export, then as local symbol.
fn find_v8_symbol(module_name: &str, symbol: &str) -> Option<usize> {
    // First try exported symbols (fast path)
    if let Ok(addr) = native::find_export(None, symbol) {
        return Some(addr);
    }

    // Fall back to local symbol enumeration
    match native::find_symbol(module_name, symbol) {
        Ok(addr) => return Some(addr),
        Err(e) => debug!("find_symbol({}, {}) failed: {}", module_name, symbol, e),
    }

    None
}

/// Install hooks on V8 trace runtime functions.
///
/// This REPLACES Runtime_TraceEnter and Runtime_TraceExit to intercept
/// the trace events that V8 generates when --trace is enabled.
/// Using replace (not attach) suppresses V8's default stdout output.
pub fn install_trace_hooks() -> bool {
    if !BytecodePhase::advance(BytecodePhase::TraceEnabled, BytecodePhase::HooksInstalled) {
        return BytecodePhase::current() >= BytecodePhase::HooksInstalled;
    }

    debug!("Installing V8 trace hooks (replace mode)...");

    // Find V8 module for local symbol lookup
    let v8_module = match find_v8_module() {
        Some(name) => {
            debug!("Found V8 module: {}", name);
            name
        }
        None => {
            warn!("Could not find V8 module");
            BytecodePhase::reset_to(BytecodePhase::HooksInstalled, BytecodePhase::TraceEnabled);
            return false;
        }
    };

    let interceptor = crate::Interceptor::obtain();

    let mut hooks_installed = 0;

    interceptor.begin_transaction();

    // Replace Runtime_TraceEnter
    if let Some(addr) = find_v8_symbol(&v8_module, RUNTIME_TRACE_ENTER) {
        let mut original_ptr: *const c_void = ptr::null();
        let result = interceptor.replace(
            addr as *mut c_void,
            replacement_trace_enter as *const c_void,
            ptr::null_mut(),
            &mut original_ptr,
        );
        if result.is_ok() {
            ORIGINAL_TRACE_ENTER.store(original_ptr as *mut c_void, Ordering::Release);
            info!("Replaced Runtime_TraceEnter at {:#x}", addr);
            hooks_installed += 1;
        } else {
            warn!("Failed to replace Runtime_TraceEnter: {:?}", result.err());
            // Fallback: patch pointer tables in DATA segments
            let replacement = replacement_trace_enter as *const () as usize;
            match unsafe { crate::module::rebind_pointers_by_value(&v8_module, addr, replacement) }
            {
                Ok(n) => {
                    info!("Rebound {} pointer(s) for Runtime_TraceEnter", n);
                    hooks_installed += 1;
                }
                Err(e) => warn!("rebind_pointers_by_value failed for TraceEnter: {:?}", e),
            }
        }
    } else {
        debug!("Runtime_TraceEnter not found (tried export and local symbols)");
    }

    // Replace Runtime_TraceExit
    if let Some(addr) = find_v8_symbol(&v8_module, RUNTIME_TRACE_EXIT) {
        let mut original_ptr: *const c_void = ptr::null();
        let result = interceptor.replace(
            addr as *mut c_void,
            replacement_trace_exit as *const c_void,
            ptr::null_mut(),
            &mut original_ptr,
        );
        if result.is_ok() {
            ORIGINAL_TRACE_EXIT.store(original_ptr as *mut c_void, Ordering::Release);
            info!("Replaced Runtime_TraceExit at {:#x}", addr);
            hooks_installed += 1;
        } else {
            warn!("Failed to replace Runtime_TraceExit: {:?}", result.err());
            // Fallback: patch pointer tables in DATA segments
            let replacement = replacement_trace_exit as *const () as usize;
            match unsafe { crate::module::rebind_pointers_by_value(&v8_module, addr, replacement) }
            {
                Ok(n) => {
                    info!("Rebound {} pointer(s) for Runtime_TraceExit", n);
                    hooks_installed += 1;
                }
                Err(e) => warn!("rebind_pointers_by_value failed for TraceExit: {:?}", e),
            }
        }
    } else {
        debug!("Runtime_TraceExit not found (tried export and local symbols)");
    }

    // Replace v8::internal::PrintF to suppress V8's trace output.
    // The bytecode interpreter calls PrintF directly for trace output, not just
    // through Runtime_TraceEnter/Exit. Without this hook, trace spam floods stdout.
    // Note: console.log does NOT go through v8::internal::PrintF — it uses libuv.
    if let Some(addr) = find_v8_symbol(&v8_module, V8_PRINTF) {
        let result = interceptor.replace(
            addr as *mut c_void,
            replacement_printf as *const c_void,
            ptr::null_mut(),
            ptr::null_mut(),
        );
        if result.is_ok() {
            info!("Replaced v8::internal::PrintF at {:#x}", addr);
            hooks_installed += 1;
        } else {
            debug!("Failed to replace PrintF: {:?}", result.err());
            // Fallback: patch pointer tables in DATA segments
            let replacement = replacement_printf as *const () as usize;
            match unsafe { crate::module::rebind_pointers_by_value(&v8_module, addr, replacement) }
            {
                Ok(n) => {
                    info!("Rebound {} pointer(s) for PrintF", n);
                    hooks_installed += 1;
                }
                Err(e) => debug!("rebind_pointers_by_value failed for PrintF: {:?}", e),
            }
        }
    } else {
        debug!("v8::internal::PrintF not found");
    }

    // Also replace the FILE* variant: v8::internal::PrintF(FILE*, const char*, ...)
    if let Some(addr) = find_v8_symbol(&v8_module, V8_PRINTF_FILE) {
        let result = interceptor.replace(
            addr as *mut c_void,
            replacement_printf_file as *const c_void,
            ptr::null_mut(),
            ptr::null_mut(),
        );
        if result.is_ok() {
            info!("Replaced v8::internal::PrintF(FILE*) at {:#x}", addr);
            hooks_installed += 1;
        } else {
            debug!("Failed to replace PrintF(FILE*): {:?}", result.err());
            // Fallback: patch pointer tables in DATA segments
            let replacement = replacement_printf_file as *const () as usize;
            match unsafe { crate::module::rebind_pointers_by_value(&v8_module, addr, replacement) }
            {
                Ok(n) => {
                    info!("Rebound {} pointer(s) for PrintF(FILE*)", n);
                    hooks_installed += 1;
                }
                Err(e) => debug!("rebind_pointers_by_value failed for PrintF(FILE*): {:?}", e),
            }
        }
    } else {
        debug!("v8::internal::PrintF(FILE*) not found");
    }

    interceptor.end_transaction();

    if hooks_installed > 0 {
        info!(
            "V8 trace hooks installed ({} replacements)",
            hooks_installed
        );
        true
    } else {
        warn!("No V8 trace hooks could be installed");
        BytecodePhase::reset_to(BytecodePhase::HooksInstalled, BytecodePhase::TraceEnabled);
        false
    }
}

/// Initialize V8 JavaScript tracing.
///
/// This enables V8's --trace flag and installs hooks to intercept trace events.
/// Call this when Node.js is detected and JS filters are registered.
pub fn initialize() -> bool {
    info!("Initializing V8 JavaScript tracing...");

    // Step 1: Enable V8 tracing via --trace flag
    if !enable_v8_tracing() {
        error!("Failed to enable V8 tracing");
        return false;
    }

    // Step 2: Install hooks on Runtime_TraceEnter/TraceExit
    if !install_trace_hooks() {
        error!("Failed to install V8 trace hooks");
        return false;
    }

    // Note: Stack parser FFI loading is deferred until first trace call
    // because V8 isn't ready yet and we'd pick the wrong Node version addon.

    info!("V8 JavaScript tracing initialized successfully");
    true
}

// =============================================================================
// REPLACEMENT FUNCTIONS
// =============================================================================

/// Replacement for Runtime_TraceEnter.
///
/// We do NOT call the original function because V8's trace output cannot be
/// reliably suppressed on Node 24+ (it bypasses our fd redirection).
/// The original's internal state management (SealHandleScope) is not critical
/// for trace-only operations - it only affects handle allocation during trace
/// formatting, which we don't need since we extract info from the stack.
unsafe extern "C" fn replacement_trace_enter(
    _args_count: i32,
    _args_ptr: *const usize,
    isolate: *mut c_void,
) -> usize {
    // Lazy init of stack parser FFI - must happen after V8 is ready
    // so we detect the correct Node.js version for addon selection.
    // Retries until addon metadata is available (wrapper may not have run yet).
    stack::ensure_available();

    // Return undefined_value (0x11 is V8's undefined on arm64/x64)
    // We skip calling the original to avoid V8's trace output pollution.
    let result: usize = 0;

    // Extract function name from the V8 stack
    let function_name = extract_function_name(isolate);

    // Maintain shadow stack for --st support (only when any filter has capture_stack)
    let stack_enabled = STACK_CAPTURE_ENABLED.load(Ordering::Acquire);
    if stack_enabled {
        TRACED_JS_CALL_STACK.with(|stack| {
            stack.borrow_mut().push(function_name.clone());
        });
    }

    // Consume the addon-handled flag eagerly, before any early returns.
    // This prevents stale flags from JIT-compiled addon calls (which bypass
    // the bytecode path entirely) from leaking to the next bytecode call.
    let addon_handled = should_skip_for_addon(isolate);

    // If no js: filters are configured, skip all JS traces
    if !super::has_filters() {
        return result;
    }

    // Check if this function matches our filter
    let (matches, capture_stack) = super::check_filter(&function_name);
    if !matches {
        return result;
    }

    // Skip if addon already handled this specific call
    if addon_handled {
        return result;
    }

    // Capture JavaScript function parameter VALUES using stack parser
    let arguments: Vec<crate::Argument> = {
        if let Some(params) = stack::parse_parameters_from_isolate(isolate) {
            params
                .into_iter()
                .map(|p| crate::Argument {
                    raw_value: 0,
                    display: Some(p.to_string()), // Use Display impl for formatted values
                })
                .collect()
        } else {
            Vec::new()
        }
    };

    // Get caller source location via direct frame reading (GC-safe).
    // These V8 APIs (GetScriptOrigin, GetScriptLineNumber) read existing heap
    // data without allocating new V8 heap objects, unlike the parameter parsing
    // path which uses String::NewFromUtf8Literal (allocates → triggers GC).
    let (caller_file, caller_line, caller_column) =
        unsafe { stack::get_caller_source_location(isolate) };

    // Capture shadow stack as runtime_stack when --st flag is set.
    // This is GC-safe (pure Rust, no V8 API calls) unlike the removed
    // capture_stack_trace_safe() C++ FP-chain walker.
    let runtime_stack = if capture_stack {
        TRACED_JS_CALL_STACK.with(|stack| {
            let borrowed = stack.borrow();
            if borrowed.len() <= 1 {
                return None; // Only the current function, no callers
            }
            let frames: Vec<crate::NodejsFrame> = borrowed
                .iter()
                .rev()
                .map(|name| crate::NodejsFrame {
                    function: name.clone(),
                    script: String::new(),
                    line: 0,
                    column: 0,
                    is_user_javascript: true,
                })
                .collect();
            Some(crate::RuntimeStack::Nodejs(frames))
        })
    } else {
        None
    };

    // Emit trace event using EventBuilder
    let event = crate::tracing::event::js_enter(&function_name)
        .arguments(arguments)
        .runtime_stack(runtime_stack)
        .source_location(caller_file, caller_line, caller_column)
        .build();

    if let Some(agent) = crate::Agent::get() {
        // V8 bytecode tracing is always non-blocking: Runtime_TraceEnter fires
        // AFTER the function has already started, so we can't block it.
        // Always send as a normal event (non-blocking path).
        let _ = agent.send_event(event);
    }

    result
}

/// Replacement for Runtime_TraceExit.
///
/// We do NOT call the original function to avoid V8's trace output pollution.
/// The original returns args[0] (the JS function's return value), which we
/// extract directly from the args array.
unsafe extern "C" fn replacement_trace_exit(
    args_count: i32,
    args_ptr: *const usize,
    isolate: *mut c_void,
) -> usize {
    // Return args[0] directly - this is what the original function returns.
    // args_ptr points to an array of tagged V8 objects (addresses).
    // args[0] is the return value from the JS function being traced.
    let result = if args_count > 0 && !args_ptr.is_null() {
        *args_ptr // Return first argument (the function's return value)
    } else {
        0 // Fallback: undefined
    };

    // Extract function name
    let function_name = extract_function_name(isolate);

    // Pop shadow stack
    if STACK_CAPTURE_ENABLED.load(Ordering::Acquire) {
        TRACED_JS_CALL_STACK.with(|stack| {
            stack.borrow_mut().pop();
        });
    }

    // Consume the addon-handled flag eagerly (see replacement_trace_enter).
    let addon_handled = should_skip_for_addon(isolate);

    // If no js: filters are configured, skip all JS traces
    if !super::has_filters() {
        return result;
    }

    // Check if this function matches our filter
    let (matches, _capture_stack) = super::check_filter(&function_name);
    if !matches {
        return result;
    }

    // Skip if addon already handled this specific call
    if addon_handled {
        return result;
    }

    // Leave events don't need runtime_stack — only Enter events show the call chain.

    // Emit trace event using EventBuilder
    let event = crate::tracing::event::js_leave(&function_name, None).build();

    if let Some(agent) = crate::Agent::get() {
        // Leave events: just send normally (no blocking)
        let _ = agent.send_event(event);
    }

    result
}

// =============================================================================
// PRINTF SUPPRESSION
// =============================================================================

/// Replacement for v8::internal::PrintF(const char*, ...).
///
/// V8's bytecode interpreter calls this to output trace information when
/// --trace is enabled. We replace it with a no-op to suppress the trace
/// output while still allowing the trace machinery to run (which triggers
/// Runtime_TraceEnter/Exit where we do our actual tracing).
#[allow(unused_variables)]
unsafe extern "C" fn replacement_printf(_format: *const c_char) {
    // No-op: suppress V8 trace output
}

/// Replacement for v8::internal::PrintF(FILE*, const char*, ...).
///
/// Some V8 code paths use this variant instead of the stdout version.
#[allow(unused_variables)]
unsafe extern "C" fn replacement_printf_file(_file: *mut c_void, _format: *const c_char) {
    // No-op: suppress V8 trace output
}

// =============================================================================
// V8 OBJECT PARSING
// =============================================================================

/// Extract function name from V8 stack.
///
/// Uses V8's StackTrace API via the addon to get the current function name.
fn extract_function_name(isolate: *mut c_void) -> String {
    // Use the stack parser FFI to get the function name
    if let Some(name) = unsafe { stack::get_current_function_name(isolate) } {
        if !name.is_empty() {
            return name;
        }
    }

    // Fallback: just use a placeholder
    "<function>".to_string()
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytecode_phase_is_accessible() {
        let _phase = BytecodePhase::current();
    }
}
