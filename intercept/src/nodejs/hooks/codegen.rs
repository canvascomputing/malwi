//! Synchronous Node.js code-generation gate for eval/function constructor.
//!
//! Hooks `node::ModifyCodeGenerationFromStrings`, which V8 calls before
//! compiling code from strings. Unlike bytecode tracing, this path is
//! synchronous and can block execution via policy.

use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use log::{debug, info, warn};

use crate::native;
use crate::nodejs::stack;

/// node::ModifyCodeGenerationFromStrings(Local<Context>, Local<Value>, bool)
#[cfg(unix)]
const MODIFY_CODEGEN_FROM_STRINGS: &str =
    "_ZN4node31ModifyCodeGenerationFromStringsEN2v85LocalINS0_7ContextEEENS1_INS0_5ValueEEEb";

/// Whether the codegen hook has been installed.
static CODEGEN_HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

/// C++ `v8::ModifyCodeGenerationFromStringsResult` ABI.
/// bool + padding + MaybeLocal<String> (pointer-sized).
#[repr(C)]
#[derive(Clone, Copy)]
struct CodegenResult {
    codegen_allowed: bool,
    _padding: [u8; 7],
    modified_source: usize,
}

type ModifyCodegenFn = unsafe extern "C" fn(*mut c_void, *mut c_void, bool) -> CodegenResult;

/// Original function pointer, stored with Release before `end_transaction()`,
/// read with Acquire in the replacement callback on arbitrary V8 threads.
static ORIGINAL_MODIFY_CODEGEN: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

#[inline]
fn deny_result() -> CodegenResult {
    CodegenResult {
        codegen_allowed: false,
        _padding: [0; 7],
        modified_source: 0,
    }
}

/// Try to find a symbol, first as export, then as local symbol.
fn find_symbol(module_name: &str, symbol: &str) -> Option<usize> {
    if let Ok(addr) = native::find_export(None, symbol) {
        return Some(addr);
    }
    native::find_symbol(module_name, symbol).ok()
}

/// Install the synchronous Node codegen hook.
pub fn initialize() -> bool {
    if CODEGEN_HOOK_INSTALLED.swap(true, Ordering::SeqCst) {
        return true;
    }

    // Resolve globally first - this works even very early in process init.
    let addr = if let Ok(a) = native::find_export(None, MODIFY_CODEGEN_FROM_STRINGS) {
        a
    } else {
        // Fallback: module-local symbol enumeration.
        let node_module = match super::find_node_module() {
            Some(name) => name,
            None => {
                warn!("Node module not found; skipping codegen gate hook");
                CODEGEN_HOOK_INSTALLED.store(false, Ordering::SeqCst);
                return false;
            }
        };
        match find_symbol(&node_module, MODIFY_CODEGEN_FROM_STRINGS) {
            Some(a) => a,
            None => {
                debug!("ModifyCodeGenerationFromStrings not found");
                CODEGEN_HOOK_INSTALLED.store(false, Ordering::SeqCst);
                return false;
            }
        }
    };

    let interceptor = crate::Interceptor::obtain();
    let mut original_ptr: *const c_void = ptr::null();

    interceptor.begin_transaction();
    let result = interceptor.replace(
        addr as *mut c_void,
        replacement_modify_codegen as *const c_void,
        ptr::null_mut(),
        &mut original_ptr,
    );

    if let Err(e) = result {
        interceptor.end_transaction();
        warn!("Failed to install Node codegen gate hook: {:?}", e);
        CODEGEN_HOOK_INSTALLED.store(false, Ordering::SeqCst);
        return false;
    }

    // Store the original BEFORE end_transaction() activates the hook.
    // The replacement reads this with Acquire ordering.
    ORIGINAL_MODIFY_CODEGEN.store(original_ptr as *mut c_void, Ordering::Release);
    interceptor.end_transaction();
    info!(
        "Installed Node codegen gate hook on ModifyCodeGenerationFromStrings at {:#x}",
        addr
    );
    true
}

unsafe extern "C" fn replacement_modify_codegen(
    context: *mut c_void,
    source: *mut c_void,
    is_code_like: bool,
) -> CodegenResult {
    let original_ptr = ORIGINAL_MODIFY_CODEGEN.load(Ordering::Acquire);
    if original_ptr.is_null() {
        return deny_result();
    }
    let original: ModifyCodegenFn = std::mem::transmute(original_ptr);

    if !crate::nodejs::has_filters() {
        return original(context, source, is_code_like);
    }

    // Normalize this edge to a stable JS pseudo-function so normal js: filters
    // and policy can gate it.
    let (matches, capture_stack) = crate::nodejs::check_filter("eval");
    if !matches {
        return original(context, source, is_code_like);
    }

    let (caller_file, caller_line, caller_column) =
        unsafe { stack::get_caller_source_location(std::ptr::null_mut()) };

    let runtime_stack = if capture_stack {
        crate::nodejs::capture_stack_from_isolate(std::ptr::null_mut())
    } else {
        None
    };

    let arguments = vec![
        crate::Argument {
            raw_value: source as usize,
            display: Some("<codegen_from_strings>".to_string()),
        },
        crate::Argument {
            raw_value: is_code_like as usize,
            display: Some(format!("is_code_like={}", is_code_like)),
        },
    ];

    let event = crate::tracing::event::js_enter("eval")
        .arguments(arguments)
        .runtime_stack(runtime_stack)
        .source_location(caller_file, caller_line, caller_column)
        .build();

    if let Some(agent) = crate::Agent::get() {
        // Agent-side policy: evaluate locally
        if let Some(decision) = agent.evaluate_policy(&event) {
            match decision {
                malwi_policy::Outcome::Block { .. } => {
                    let _ = agent.send_event(event);
                    info!("Blocked Node eval/codegen via agent policy");
                    return deny_result();
                }
                malwi_policy::Outcome::Hide | malwi_policy::Outcome::Suppress => {
                    // Don't send, allow execution
                }
                _ => {
                    let _ = agent.send_event(event);
                }
            }
        } else {
            let _ = agent.send_event(event);
        }
    }

    original(context, source, is_code_like)
}

// =============================================================================
// WASM CODE GENERATION GATE
// =============================================================================

/// node::AllowWasmCodeGenerationCallback(Local<Context>, Local<String>)
#[cfg(unix)]
const ALLOW_WASM_CODEGEN: &str =
    "_ZN4node31AllowWasmCodeGenerationCallbackEN2v85LocalINS0_7ContextEEENS1_INS0_6StringEEE";

static WASM_HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);
static ORIGINAL_ALLOW_WASM: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

type AllowWasmFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> bool;

/// Install the WebAssembly code generation gate hook.
pub fn initialize_wasm_gate() -> bool {
    if WASM_HOOK_INSTALLED.swap(true, Ordering::SeqCst) {
        return true;
    }

    let addr = match native::find_export(None, ALLOW_WASM_CODEGEN) {
        Ok(a) => a,
        Err(_) => {
            debug!("AllowWasmCodeGenerationCallback not found; skipping wasm gate");
            WASM_HOOK_INSTALLED.store(false, Ordering::SeqCst);
            return false;
        }
    };

    let interceptor = crate::Interceptor::obtain();
    let mut original_ptr: *const c_void = ptr::null();

    interceptor.begin_transaction();
    let result = interceptor.replace(
        addr as *mut c_void,
        replacement_allow_wasm as *const c_void,
        ptr::null_mut(),
        &mut original_ptr,
    );

    if let Err(e) = result {
        interceptor.end_transaction();
        debug!("Failed to install wasm gate hook: {:?}", e);
        WASM_HOOK_INSTALLED.store(false, Ordering::SeqCst);
        return false;
    }

    ORIGINAL_ALLOW_WASM.store(original_ptr as *mut c_void, Ordering::Release);
    interceptor.end_transaction();
    info!("Installed wasm code generation gate at {:#x}", addr);
    true
}

unsafe extern "C" fn replacement_allow_wasm(context: *mut c_void, source: *mut c_void) -> bool {
    let original_ptr = ORIGINAL_ALLOW_WASM.load(Ordering::Acquire);
    if original_ptr.is_null() {
        return false;
    }
    let original: AllowWasmFn = std::mem::transmute(original_ptr);

    // Emit a trace event for wasm compilation
    let event = crate::tracing::event::js_enter("WebAssembly.compile")
        .arguments(vec![crate::Argument {
            raw_value: 0,
            display: Some("<wasm_module>".to_string()),
        }])
        .build();

    if let Some(agent) = crate::Agent::get() {
        if let Some(decision) = agent.evaluate_policy(&event) {
            match decision {
                malwi_policy::Outcome::Block { .. } => {
                    let _ = agent.send_event(event);
                    info!("Blocked WebAssembly compilation via agent policy");
                    return false;
                }
                malwi_policy::Outcome::Hide | malwi_policy::Outcome::Suppress => {}
                _ => {
                    let _ = agent.send_event(event);
                }
            }
        } else {
            let _ = agent.send_event(event);
        }
    }

    original(context, source)
}
