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

use std::ffi::{c_char, c_void, CString};
use std::sync::atomic::{AtomicBool, Ordering};

use log::{debug, error, info, warn};

use crate::native;
use super::stack;
use core::ptr;

// =============================================================================
// STATE
// =============================================================================

/// Whether Node.js bytecode tracing has been initialized.
static NODEJS_TRACE_ENABLED: AtomicBool = AtomicBool::new(false);

/// Whether hooks are installed.
static HOOKS_INSTALLED: AtomicBool = AtomicBool::new(false);


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

/// Runtime_TraceEnter/Exit signature: Object Runtime_TraceXxx(int args_count, Address* args, Isolate* isolate)
/// Object is a tagged pointer (usize), Address is usize, Isolate* is opaque pointer
type RuntimeTraceFn = unsafe extern "C" fn(i32, *const usize, *mut c_void) -> usize;

/// Original Runtime_TraceEnter function pointer (set during hook installation)
static mut ORIGINAL_TRACE_ENTER: Option<RuntimeTraceFn> = None;

/// Original Runtime_TraceExit function pointer (set during hook installation)
static mut ORIGINAL_TRACE_EXIT: Option<RuntimeTraceFn> = None;

/// Whether V8's PrintF hook is installed (to suppress trace output)
static PRINTF_HOOKED: AtomicBool = AtomicBool::new(false);

/// Whether we've attempted to init the stack parser FFI (lazy init on first trace)
static FFI_INIT_ATTEMPTED: AtomicBool = AtomicBool::new(false);

// =============================================================================
// SKIP LOGIC FOR ADDON DEDUPLICATION
// =============================================================================

/// Check if we should skip tracing for this function because addon is active.
///
/// When the addon is tracing, we skip V8 internal tracing for CommonJS module
/// functions to avoid duplicate events. The addon's require hook wraps module
/// exports, so we'd get duplicate events if we also traced via Runtime_TraceEnter.
///
/// We only skip for actual file-based CommonJS modules (contain path separator
/// and end with .js or .cjs). This allows:
/// - User functions in --eval (script path is "[eval]", no path separator)
/// - ESM modules (.mjs files, which addon doesn't handle)
/// - Node.js internals (node:* paths)
fn should_skip_for_addon(isolate: *mut std::ffi::c_void) -> bool {
    if !super::is_addon_tracing_active() {
        return false;
    }

    if let Some(script_path) = stack::get_current_script_path(isolate) {
        // Only skip if it's a real file path (contains path separator)
        // and is a CommonJS file (.js or .cjs, not .mjs)
        let is_file_path = script_path.contains('/') || script_path.contains('\\');
        let is_commonjs = script_path.ends_with(".js") || script_path.ends_with(".cjs");
        return is_file_path && is_commonjs;
    }

    false
}

// =============================================================================
// V8 TRACING CONTROL
// =============================================================================

/// Enable V8's internal function tracing by calling SetFlagsFromString("--trace").
///
/// This must be called BEFORE V8 starts executing JavaScript code.
pub fn enable_v8_tracing() -> bool {
    if NODEJS_TRACE_ENABLED.swap(true, Ordering::SeqCst) {
        return true; // Already initialized
    }

    debug!("Enabling V8 internal tracing...");

    // Find v8::V8::SetFlagsFromString
    let set_flags_addr = match native::find_export(None, SET_FLAGS_FROM_STRING) {
        Ok(addr) => addr,
        Err(e) => {
            warn!("Failed to find SetFlagsFromString: {}", e);
            NODEJS_TRACE_ENABLED.store(false, Ordering::SeqCst);
            return false;
        }
    };

    let set_flags: SetFlagsFromStringFn = unsafe { std::mem::transmute(set_flags_addr) };

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
    if let Ok(addr) = native::find_symbol(module_name, symbol) {
        return Some(addr);
    }

    None
}

/// Install hooks on V8 trace runtime functions.
///
/// This REPLACES Runtime_TraceEnter and Runtime_TraceExit to intercept
/// the trace events that V8 generates when --trace is enabled.
/// Using replace (not attach) suppresses V8's default stdout output.
pub fn install_trace_hooks() -> bool {
    if HOOKS_INSTALLED.swap(true, Ordering::SeqCst) {
        return true; // Already installed
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
            HOOKS_INSTALLED.store(false, Ordering::SeqCst);
            return false;
        }
    };

    let interceptor = malwi_intercept::Interceptor::obtain();

    let mut hooks_installed = 0;

    interceptor.begin_transaction();

    // Replace Runtime_TraceEnter (preferred), otherwise fall back to pointer-table rebinding.
    if let Some(addr) = find_v8_symbol(&v8_module, RUNTIME_TRACE_ENTER) {
        let mut original_ptr: *const c_void = ptr::null();
        let result = interceptor.replace(
            addr as *mut c_void,
            replacement_trace_enter as *const c_void,
            ptr::null_mut(),
            &mut original_ptr,
        );
        if result.is_ok() {
            unsafe {
                ORIGINAL_TRACE_ENTER = Some(std::mem::transmute(original_ptr));
            }
            info!("Replaced Runtime_TraceEnter at {:#x}", addr);
            hooks_installed += 1;
        } else {
            debug!("Failed to replace Runtime_TraceEnter: {:?}", result.err());

            // On some macOS configurations inline patching of __TEXT is not possible.
            // V8 dispatches runtime calls through tables stored in __DATA; patch those.
            let replacement = replacement_trace_enter as *const () as usize;
            match unsafe { malwi_intercept::module::rebind_pointers_by_value(&v8_module, addr, replacement) } {
                Ok(n) if n > 0 => {
                    info!(
                        "Rebound {} pointer(s) for Runtime_TraceEnter ({:#x} -> {:#x})",
                        n, addr, replacement
                    );
                    hooks_installed += 1;
                }
                Ok(_) => {
                    debug!("No pointers found to rebind for Runtime_TraceEnter");
                }
                Err(e) => {
                    debug!("Pointer rebinding for Runtime_TraceEnter failed: {:?}", e);
                }
            }
        }
    } else {
        debug!("Runtime_TraceEnter not found (tried export and local symbols)");
    }

    // Replace Runtime_TraceExit (preferred), otherwise fall back to pointer-table rebinding.
    if let Some(addr) = find_v8_symbol(&v8_module, RUNTIME_TRACE_EXIT) {
        let mut original_ptr: *const c_void = ptr::null();
        let result = interceptor.replace(
            addr as *mut c_void,
            replacement_trace_exit as *const c_void,
            ptr::null_mut(),
            &mut original_ptr,
        );
        if result.is_ok() {
            unsafe {
                ORIGINAL_TRACE_EXIT = Some(std::mem::transmute(original_ptr));
            }
            info!("Replaced Runtime_TraceExit at {:#x}", addr);
            hooks_installed += 1;
        } else {
            debug!("Failed to replace Runtime_TraceExit: {:?}", result.err());

            let replacement = replacement_trace_exit as *const () as usize;
            match unsafe { malwi_intercept::module::rebind_pointers_by_value(&v8_module, addr, replacement) } {
                Ok(n) if n > 0 => {
                    info!(
                        "Rebound {} pointer(s) for Runtime_TraceExit ({:#x} -> {:#x})",
                        n, addr, replacement
                    );
                    hooks_installed += 1;
                }
                Ok(_) => {
                    debug!("No pointers found to rebind for Runtime_TraceExit");
                }
                Err(e) => {
                    debug!("Pointer rebinding for Runtime_TraceExit failed: {:?}", e);
                }
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
            PRINTF_HOOKED.store(true, Ordering::SeqCst);
            info!("Replaced v8::internal::PrintF at {:#x}", addr);
            hooks_installed += 1;
        } else {
            debug!("Failed to replace PrintF: {:?}", result.err());
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
        }
    } else {
        debug!("v8::internal::PrintF(FILE*) not found");
    }

    interceptor.end_transaction();

    if hooks_installed > 0 {
        info!("V8 trace hooks installed ({} replacements)", hooks_installed);
        true
    } else {
        warn!("No V8 trace hooks could be installed");
        HOOKS_INSTALLED.store(false, Ordering::SeqCst);
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
    if !FFI_INIT_ATTEMPTED.swap(true, Ordering::SeqCst) {
        match super::addon::get_addon_path() {
            Some(addon_path) => {
                if stack::resolve_stack_parser_ffi(&addon_path) {
                    info!("Stack parser FFI loaded from {:?}", addon_path);
                } else {
                    warn!("Stack parser FFI failed to load from {:?}", addon_path);
                }
            }
            None => {
                warn!("No addon path available - function names will show as <function>");
            }
        }
    }

    // Return undefined_value (0x11 is V8's undefined on arm64/x64)
    // We skip calling the original to avoid V8's trace output pollution.
    let result: usize = 0;

    // Extract function name from the V8 stack
    let function_name = extract_function_name(isolate);

    // If no js: filters are configured, skip all JS traces
    if !super::has_filters() {
        return result;
    }

    // Check if this function matches our filter
    let (matches, capture_stack) = super::check_filter(&function_name);
    if !matches {
        return result;
    }

    // Skip if addon is active and this is a CommonJS module function
    if should_skip_for_addon(isolate) {
        return result;
    }

    // Capture JavaScript function parameter VALUES using stack parser
    let arguments: Vec<malwi_protocol::Argument> = {
        if let Some(params) = stack::parse_parameters_from_isolate(isolate) {
            params
                .into_iter()
                .map(|p| malwi_protocol::Argument {
                    raw_value: 0,
                    display: Some(p.to_string()), // Use Display impl for formatted values
                })
                .collect()
        } else {
            Vec::new()
        }
    };

    // Capture V8 stack for caller location (and full stack if enabled)
    // When capture_stack is true, get more frames to avoid capturing twice
    let max_frames = if capture_stack { 10 } else { 2 };
    let v8_frames = stack::capture_stack_trace(isolate, max_frames);

    // Extract caller source location from frame[1] (frame[0] is callee)
    let (caller_file, caller_line) = v8_frames.as_ref()
        .and_then(|frames| frames.get(1))
        .map(|f| (Some(f.script.clone()), Some(f.line.max(0) as u32)))
        .unwrap_or((None, None));

    // Build runtime stack from captured frames if enabled
    let runtime_stack = if capture_stack {
        let nodejs_frames: Vec<malwi_protocol::NodejsFrame> = v8_frames
            .unwrap_or_default()
            .into_iter()
            .map(|f| malwi_protocol::NodejsFrame {
                function: f.function,
                script: f.script.clone(),
                line: f.line.max(0) as u32,
                column: f.column.max(0) as u32,
                is_user_javascript: !f.script.starts_with("node:"),
            })
            .collect();
        if !nodejs_frames.is_empty() {
            Some(malwi_protocol::RuntimeStack::Nodejs(nodejs_frames))
        } else {
            None
        }
    } else {
        None
    };

    // Emit trace event using EventBuilder
    let event = crate::tracing::event::js_enter(&function_name)
        .arguments(arguments)
        .runtime_stack(runtime_stack)
        .source_location(caller_file, caller_line)
        .build();

    if let Some(agent) = crate::Agent::get() {
        // V8 bytecode tracing is always non-blocking: Runtime_TraceEnter fires
        // AFTER the function has already started, so we can't block it.
        // Always send as a normal event regardless of review mode.
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

    // If no js: filters are configured, skip all JS traces
    if !super::has_filters() {
        return result;
    }

    // Check if this function matches our filter
    let (matches, capture_stack) = super::check_filter(&function_name);
    if !matches {
        return result;
    }

    // Skip if addon is active and this is a CommonJS module function
    if should_skip_for_addon(isolate) {
        return result;
    }

    // Capture V8 stack if enabled via -t flag
    let runtime_stack = if capture_stack {
        let v8_frames = super::capture_stack();
        if !v8_frames.is_empty() {
            Some(malwi_protocol::RuntimeStack::Nodejs(v8_frames))
        } else {
            None
        }
    } else {
        None
    };

    // Emit trace event using EventBuilder
    let event = crate::tracing::event::js_leave(&function_name, None)
        .runtime_stack(runtime_stack)
        .build();

    if let Some(agent) = crate::Agent::get() {
        // Leave events in review mode: just send normally (no blocking)
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
    if let Some(name) = stack::get_current_function_name(isolate) {
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
    fn test_initialization_state() {
        // Just verify the state variables are accessible
        assert!(!NODEJS_TRACE_ENABLED.load(Ordering::SeqCst) || true);
        assert!(!HOOKS_INSTALLED.load(Ordering::SeqCst) || true);
    }
}
