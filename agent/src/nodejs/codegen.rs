//! Synchronous Node.js code-generation gate for eval/function constructor.
//!
//! Hooks `node::ModifyCodeGenerationFromStrings`, which V8 calls before
//! compiling code from strings. Unlike bytecode tracing, this path is
//! synchronous and can block execution in review mode.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};

use log::{debug, info, warn};

use super::stack;
use crate::native;

/// node::ModifyCodeGenerationFromStrings(Local<Context>, Local<Value>, bool)
#[cfg(unix)]
const MODIFY_CODEGEN_FROM_STRINGS: &str =
    "_ZN4node31ModifyCodeGenerationFromStringsEN2v85LocalINS0_7ContextEEENS1_INS0_5ValueEEEb";

/// Whether the codegen hook has been installed.
static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

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

static mut ORIGINAL_MODIFY_CODEGEN: Option<ModifyCodegenFn> = None;

#[inline]
fn deny_result() -> CodegenResult {
    CodegenResult {
        codegen_allowed: false,
        _padding: [0; 7],
        modified_source: 0,
    }
}

/// Find the Node module name from loaded modules.
fn find_node_module() -> Option<String> {
    for module in native::enumerate_modules() {
        if module.name == "node"
            || module.name.starts_with("node.")
            || module.name.starts_with("node-")
        {
            return Some(module.name);
        }
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
fn find_symbol(module_name: &str, symbol: &str) -> Option<usize> {
    if let Ok(addr) = native::find_export(None, symbol) {
        return Some(addr);
    }
    native::find_symbol(module_name, symbol).ok()
}

/// Install the synchronous Node codegen hook.
pub fn initialize() -> bool {
    if HOOK_INSTALLED.swap(true, Ordering::SeqCst) {
        return true;
    }

    // Resolve globally first - this works even very early in process init.
    let addr = if let Ok(a) = native::find_export(None, MODIFY_CODEGEN_FROM_STRINGS) {
        a
    } else {
        // Fallback: module-local symbol enumeration.
        let node_module = match find_node_module() {
            Some(name) => name,
            None => {
                warn!("Node module not found; skipping codegen gate hook");
                HOOK_INSTALLED.store(false, Ordering::SeqCst);
                return false;
            }
        };
        match find_symbol(&node_module, MODIFY_CODEGEN_FROM_STRINGS) {
            Some(a) => a,
            None => {
                debug!("ModifyCodeGenerationFromStrings not found");
                HOOK_INSTALLED.store(false, Ordering::SeqCst);
                return false;
            }
        }
    };

    let interceptor = malwi_intercept::Interceptor::obtain();
    let mut original_ptr: *const c_void = std::ptr::null();

    interceptor.begin_transaction();
    let result = interceptor.replace(
        addr as *mut c_void,
        replacement_modify_codegen as *const c_void,
        std::ptr::null_mut(),
        &mut original_ptr,
    );
    interceptor.end_transaction();

    if let Err(e) = result {
        warn!("Failed to install Node codegen gate hook: {:?}", e);
        HOOK_INSTALLED.store(false, Ordering::SeqCst);
        return false;
    }

    unsafe {
        ORIGINAL_MODIFY_CODEGEN = Some(std::mem::transmute::<*const c_void, ModifyCodegenFn>(
            original_ptr,
        ));
    }
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
    let Some(original) = ORIGINAL_MODIFY_CODEGEN else {
        return deny_result();
    };

    if !super::has_filters() {
        return original(context, source, is_code_like);
    }

    // Normalize this edge to a stable JS pseudo-function so normal js: filters
    // and review mode can gate it.
    let (matches, capture_stack) = super::check_filter("eval");
    if !matches {
        return original(context, source, is_code_like);
    }

    let (caller_file, caller_line) = stack::capture_stack_trace(std::ptr::null_mut(), 2)
        .and_then(|frames| {
            frames
                .get(1)
                .map(|f| (Some(f.script.clone()), Some(f.line.max(0) as u32)))
        })
        .unwrap_or((None, None));

    let runtime_stack = if capture_stack {
        let frames = super::capture_stack();
        if frames.is_empty() {
            None
        } else {
            Some(malwi_protocol::RuntimeStack::Nodejs(frames))
        }
    } else {
        None
    };

    let arguments = vec![
        malwi_protocol::Argument {
            raw_value: source as usize,
            display: Some("<codegen_from_strings>".to_string()),
        },
        malwi_protocol::Argument {
            raw_value: is_code_like as usize,
            display: Some(format!("is_code_like={}", is_code_like)),
        },
    ];

    let event = crate::tracing::event::js_enter("eval")
        .arguments(arguments)
        .runtime_stack(runtime_stack)
        .source_location(caller_file, caller_line)
        .build();

    if let Some(agent) = crate::Agent::get() {
        if agent.is_review_mode() && !agent.await_review_decision(event.clone()).is_allowed() {
            info!("Blocked Node eval/codegen via review mode");
            return deny_result();
        }
        let _ = agent.send_event(event);
    }

    original(context, source, is_code_like)
}
