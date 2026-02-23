//! Node.js process detection and version querying.

use crate::native;

use super::symbols;

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

/// Get the detected Node.js major version, if any.
///
/// Delegates to [`super::addon::detect_node_version()`] which caches the result.
pub fn detected_version() -> Option<u32> {
    super::addon::detect_node_version()
}
