//! V8 Addon Embedding and Extraction.
//!
//! Embeds prebuilt V8 introspection addon binaries and extracts them at runtime
//! for stack parser FFI access via dlopen. No N-API wrapping or NODE_OPTIONS.

pub mod embed;

pub use embed::{
    detect_node_version, extract_addon_for_ffi, extract_all_addons, get_addon_path, is_addon_loaded,
};
