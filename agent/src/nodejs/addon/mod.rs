//! Node.js Addon Management.
//!
//! This module handles:
//! - Addon binary embedding and extraction (embed.rs)
//! - Trace event callback from addon (callback.rs)
//! - FFI function resolution (ffi.rs)
//! - Loading strategies: direct and NODE_OPTIONS (loader.rs)

pub mod callback;
pub mod embed;
pub mod ffi;
pub mod loader;

// Re-export commonly used items
pub use callback::malwi_nodejs_trace_callback;
pub use embed::{detect_node_version, extract_all_addons, get_addon_path};
pub use ffi::{resolve_addon_ffi, AddonFfi, ADDON_FFI};
pub use loader::{
    activate_addon_tracing, direct_initialize, forward_filters_to_addon, is_addon_tracing_active,
    node_options_initialize, set_addon_tracing_active,
};
