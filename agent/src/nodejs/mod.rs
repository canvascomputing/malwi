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
//! 2. **addon** (N-API function wrapping):
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
//! - `filters.rs`: Filter management and coordination
//! - `ffi.rs`: FFI type definitions
//! - `script.rs`: JavaScript execution
//! - `stack.rs`: JavaScript stack frame parsing
//! - `symbols.rs`: Mangled symbol names

pub use malwi_protocol::NodejsFrame;

use std::sync::atomic::{AtomicBool, Ordering};

use crate::native;

/// Whether Node.js envvar monitoring is enabled.
static NODEJS_ENVVAR_MONITORING: AtomicBool = AtomicBool::new(false);

// =============================================================================
// SUBMODULES
// =============================================================================

pub mod addon;
pub mod bytecode;
pub mod ffi;
pub mod filters;
pub mod script;
pub mod stack;
pub mod symbols;

// Re-export commonly used items from addon
pub use addon::embed::{is_addon_loaded, load_addon};

// Re-export from filters (main coordination layer)
pub use filters::{
    add_filter, check_filter, get_thread_id, has_filters, initialize, is_addon_tracing_active,
};

// =============================================================================
// PUBLIC API
// =============================================================================

/// Check if Node.js runtime is loaded in the process.
///
/// Detection is based on the presence of well-known exports:
/// - `node_module_register` (Node.js)
/// - `uv_version` (libuv, bundled with Node.js)
/// - V8 Isolate symbols
pub fn is_loaded() -> bool {
    // Check for Node.js-specific symbol
    if native::find_export(None, symbols::NODE_MODULE_REGISTER).is_ok() {
        return true;
    }

    // Check for libuv (bundled with Node.js)
    if native::find_export(None, symbols::UV_VERSION).is_ok() {
        return true;
    }

    // Check for V8 Isolate
    if native::find_export(None, symbols::v8::ISOLATE_GET_CURRENT).is_ok() {
        return true;
    }

    false
}

/// Initialize V8 JavaScript tracing.
///
/// This function uses a **hybrid approach** combining two tracing mechanisms:
///
/// 1. **bytecode** (Runtime_TraceEnter hooks):
///    - Catches user JavaScript bytecode functions
///    - Works for synchronous `--eval` code that runs before module loading
///    - Uses V8's internal --trace flag with hooks on Runtime_TraceEnter/TraceExit
///    - Can be disabled via `MALWI_NO_BYTECODE=1` for apps with sensitive init
///
/// 2. **addon** (N-API function wrapping):
///    - Catches native module functions (fs.*, crypto.*, etc.)
///    - Extracts and loads the v8_introspect addon
///    - Installs a require hook to intercept module loading
///    - Wraps matching JavaScript functions at the JavaScript level
///
/// Both mechanisms use the same filter list and emit events through the same
/// channel - they are complementary and together provide complete coverage.
///
/// Call this after checking `is_v8_loaded()` and adding filters.
///
/// # Returns
/// - true if at least one tracing mechanism initialized successfully
/// - false if V8 tracing could not be enabled
pub fn init_tracing() -> bool {
    // Check if bytecode tracing should be skipped.
    // Set `MALWI_NO_BYTECODE=1` to disable.
    let skip_bytecode = std::env::var("MALWI_NO_BYTECODE")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);

    // Check if all JS tracing should be skipped (for debugging)
    let skip_all_js = std::env::var("MALWI_NO_JS")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);

    if skip_all_js {
        log::info!("All JS tracing disabled via MALWI_NO_JS");
        return false;
    }

    // Step 1: Initialize bytecode-level tracing (unless explicitly disabled)
    // This catches user JS functions in --eval, ESM, dynamic imports, etc.
    let bytecode_ok = if skip_bytecode {
        log::info!("Bytecode tracing disabled via MALWI_NO_BYTECODE");
        false
    } else {
        bytecode::initialize()
    };

    // Step 2: Initialize wrapper-based addon tracing
    // This catches native module functions (fs.*, etc.)
    let addon_ok = initialize();

    // Success if at least one approach initialized
    bytecode_ok || addon_ok
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
pub fn capture_stack() -> Vec<NodejsFrame> {
    // Use null isolate to let the stack parser get the current isolate
    let frames = match stack::capture_stack_trace(std::ptr::null_mut(), 10) {
        Some(frames) => frames,
        None => return Vec::new(),
    };

    // Convert internal stack frame to NodejsFrame (malwi_protocol type)
    frames
        .into_iter()
        .map(|f| NodejsFrame {
            function: f.function,
            script: f.script.clone(),
            line: f.line.max(0) as u32,
            column: f.column.max(0) as u32,
            // User JavaScript is anything not from node: internals
            is_user_javascript: !f.script.starts_with("node:"),
        })
        .collect()
}

/// Enable Node.js envvar monitoring.
///
/// Sets a flag so the JS wrapper installs a `process.env` Proxy
/// (the Proxy checks `addon.checkEnvVar` at load time; this flag
/// is for the native getenv hook to skip when Node.js handles it).
pub fn enable_envvar_monitoring() {
    NODEJS_ENVVAR_MONITORING.store(true, Ordering::SeqCst);
}

/// Check if Node.js envvar monitoring is enabled.
pub fn is_envvar_monitoring_enabled() -> bool {
    NODEJS_ENVVAR_MONITORING.load(Ordering::SeqCst)
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
    fn test_add_filter() {
        add_filter("fs.*", true);
        assert!(has_filters());

        let (matches, capture) = check_filter("fs.readFile");
        assert!(matches);
        assert!(capture);

        let (matches, _) = check_filter("http.request");
        assert!(!matches);
    }
}
