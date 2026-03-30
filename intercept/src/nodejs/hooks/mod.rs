//! Node.js hook mechanisms.
//!
//! Three complementary frida-gum hook mechanisms for JavaScript tracing:
//! - `bytecode`: V8 `--trace` flag + `Runtime_TraceEnter/Exit` hooks
//! - `codegen`: `ModifyCodeGenerationFromStrings` + wasm gate for eval/Function blocking
//! - `native`: Direct C++ callback hooks on node::fs::*, node::dns::*, etc.

pub mod bytecode;
pub mod codegen;
pub mod native;

pub use native::has_native_hook;

// =============================================================================
// SHARED UTILITIES
// =============================================================================

/// Find the Node.js binary module name from loaded modules.
/// Checks both module name and path for patterns like "node", "node.exe", "node-v24".
pub fn find_node_module() -> Option<String> {
    for module in crate::native::enumerate_modules() {
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

// =============================================================================
// NATIVE HOOK DEDUPLICATION
// =============================================================================

// Per-call flag: when a native C++ callback hook handles a trace event,
// the bytecode hook should skip the duplicate. Set by native::on_enter,
// consumed (cleared) by the bytecode hook on each trace entry/exit.
thread_local! {
    static NATIVE_HOOK_HANDLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Mark that the current call was handled by a native C++ callback hook.
pub fn mark_native_hook_handled() {
    NATIVE_HOOK_HANDLED.with(|c| c.set(true));
}

/// Check and clear the native-hook-handled flag.
pub fn take_native_hook_handled() -> bool {
    NATIVE_HOOK_HANDLED.with(|c| c.replace(false))
}
