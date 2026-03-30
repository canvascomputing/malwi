//! Node.js Tracing - Public API and Implementation.
//!
//! This module provides JavaScript function tracing for Node.js applications.
//!
//! ## Features
//!
//! - **Automatic addon detection**: Detects Node.js version and loads matching addon
//! - **Zero configuration**: No environment variables needed
//! - **Native binding tracing**: Traces fs.*, crypto.*, and other native modules
//! - **Stack capture**: JavaScript call stack capture via addon
//! - **Filter support**: Glob patterns to filter traced functions
//!
//! ## Architecture
//!
//! Node.js tracing uses a **hybrid approach** combining two tracing mechanisms:
//!
//! 1. **bytecode** (Runtime_TraceEnter hooks):
//!    - Catches user JavaScript bytecode functions
//!    - Works for synchronous `--eval` code that runs before module loading
//!    - Uses V8's internal --trace flag with hooks on Runtime_TraceEnter/TraceExit
//!
//! 2. **codegen** (ModifyCodeGenerationFromStrings hook):
//!    - Catches `eval()` / `Function()` / string-based code generation
//!    - Runs synchronously before compilation, so policy can block
//!
//! 3. **addon** (N-API function wrapping):
//!    - Catches native module functions (fs.*, crypto.*, etc.)
//!    - Extracts and loads the v8_introspect addon
//!    - Installs a require hook to intercept module loading
//!    - Wraps matching JavaScript functions at the JavaScript level
//!
//! Both mechanisms use the same filter list and emit events through the same
//! channel - they are complementary and together provide complete coverage.
//!
//! ## Module Structure
//!
//! - `addon/`: Addon embedding, extraction, callback, and FFI
//!   - `embed.rs`: Binary extraction per Node.js version
//!   - `callback.rs`: Trace event callback from addon
//!   - `ffi.rs`: FFI function resolution
//!   - `loader.rs`: Loading strategies (direct and NODE_OPTIONS)
//!
//! - `bytecode.rs`: Runtime_TraceEnter/Exit hooks for bytecode functions
//! - `codegen.rs`: Synchronous gate for eval/codegen-from-strings
//! - `filters.rs`: Filter management and coordination
//! - `ffi.rs`: FFI type definitions
//! - `script.rs`: JavaScript execution
//! - `stack.rs`: JavaScript stack frame parsing
//! - `symbols.rs`: Mangled symbol names

pub use crate::NodejsFrame;

// =============================================================================
// SUBMODULES
// =============================================================================

pub mod addon;
mod detect;
pub mod filters;
pub mod format;
pub mod hooks;
pub mod stack;
pub mod state;
pub mod symbols;

use crate::RuntimeStack;

// Re-export commonly used items from addon
pub use addon::embed::is_addon_loaded;

// Re-export from detect (standard runtime convention)
pub use detect::{detected_version, is_loaded};

// Re-export from filters (main coordination layer)
pub use filters::{add_filter, check_filter, get_thread_id, has_filters, initialize};

// Re-export state machines
pub use state::{AddonPhase, BytecodePhase};

// =============================================================================
// SHARED HELPERS
// =============================================================================
// PUBLIC API
// =============================================================================

/// Initialize V8 JavaScript tracing.
///
/// Three mechanisms work together via frida-gum hooks:
///
/// 1. **codegen gates** — hook `ModifyCodeGenerationFromStrings` (eval/Function
///    blocking) and `AllowWasmCodeGenerationCallback` (wasm compilation gate)
/// 2. **bytecode tracing** — set V8 `--trace` flag + hook `Runtime_TraceEnter/Exit`
///    to trace all interpreted JS functions
/// 3. **addon extraction** — extract V8 introspection addon for stack parser FFI
///    (function names, parameters, source locations via dlopen)
///
/// Native module C++ callback hooks (fs.*, dns.*, etc.) are installed separately
/// in `native_callbacks::install_hooks()` after agent configuration.
pub fn init_tracing() -> bool {
    // Step 1: Install synchronous eval/wasm codegen gate hooks.
    let codegen_ok = hooks::codegen::initialize();
    let wasm_ok = hooks::codegen::initialize_wasm_gate();

    // Step 2: Initialize bytecode-level tracing (V8 --trace flag).
    let bytecode_ok = hooks::bytecode::initialize();

    // Step 3: Extract addon for stack parser FFI (dlopen).
    let addon_ok = initialize();

    // Note: Native C++ callback hooks (fs.*, dns.*, etc.) are installed later,
    // after agent config provides the filter list. See agent/mod.rs.

    codegen_ok || wasm_ok || bytecode_ok || addon_ok
}

/// Capture the current JavaScript call stack.
///
/// Returns a vector of NodejsFrame representing the JavaScript call stack
/// at the point of invocation.
///
/// # Returns
/// - Vector of NodejsFrame with function name, script, line, column
/// - Empty vector if Node.js is not initialized or no frames available
///
/// # Note
/// This requires V8 to be in a valid state with an active Isolate.
/// Returns empty if called outside of V8 context.
/// Capture JS stack trace from a specific isolate, returning RuntimeStack.
/// Used by native callback hooks which have the isolate from FunctionCallbackInfo.
pub fn capture_stack_from_isolate(isolate: *mut std::ffi::c_void) -> Option<RuntimeStack> {
    let frames = unsafe { stack::capture_stack_trace(isolate, 10) }?;
    if frames.is_empty() {
        return None;
    }
    let nodejs_frames: Vec<NodejsFrame> = frames
        .into_iter()
        .map(|f| NodejsFrame {
            function: f.function,
            script: f.script.clone(),
            line: f.line.max(0) as u32,
            column: f.column.max(0) as u32,
            is_user_javascript: !f.script.starts_with("node:"),
        })
        .collect();
    Some(RuntimeStack::Nodejs(nodejs_frames))
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_loaded_when_not_loaded() {
        let result = is_loaded();
        println!("is_loaded: {}", result);
    }

    #[test]
    fn test_add_filter_enables_matching_and_rejects_non_matching() {
        add_filter("fs.*", true);
        assert!(has_filters());

        let (matches, capture) = check_filter("fs.readFile");
        assert!(matches);
        assert!(capture);

        let (matches, _) = check_filter("http.request");
        assert!(!matches);
    }
}
