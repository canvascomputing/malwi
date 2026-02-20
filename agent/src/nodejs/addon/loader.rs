//! Addon Loading.
//!
//! This module handles loading the V8 introspection addon.
//!
//! ## Wrapper-Centric Approach
//!
//! For NODE_OPTIONS mode, we use a wrapper-centric approach:
//! 1. Rust extracts ALL addon versions to a stable directory
//! 2. Rust writes a JS wrapper and sets NODE_OPTIONS
//! 3. The JS wrapper (loaded via --require) does version detection
//!    and loads the correct addon for the Node.js version
//!
//! This avoids timing issues with version detection during early init.

use std::ffi::CString;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use log::{debug, info, warn};

use super::{malwi_nodejs_trace_callback, resolve_addon_ffi, AddonFfi, ADDON_FFI};

// =============================================================================
// SHARED STATE
// =============================================================================

/// Whether addon-based tracing is active.
static ADDON_TRACING_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Check if addon-based tracing is currently active.
///
/// Returns true if the addon has been loaded and tracing is enabled.
/// This is used by bytecode tracing to avoid duplicate events for module functions
/// that are already being traced by the addon's require hook.
pub fn is_addon_tracing_active() -> bool {
    ADDON_TRACING_ACTIVE.load(Ordering::SeqCst)
}

/// Set addon tracing as active.
pub fn set_addon_tracing_active(active: bool) {
    ADDON_TRACING_ACTIVE.store(active, Ordering::SeqCst);
}

/// Forward existing filters to the addon.
pub fn forward_filters_to_addon(ffi: &AddonFfi, filters: &[crate::tracing::Filter]) {
    let mut total_wrapped = 0;
    for filter in filters {
        if let Ok(c_pattern) = CString::new(filter.pattern.as_str()) {
            let count = unsafe { (ffi.add_filter)(c_pattern.as_ptr(), filter.capture_stack) };
            log::debug!("Filter '{}': {} functions wrapped", filter.pattern, count);
            total_wrapped += count;
        }
    }
    if !filters.is_empty() {
        info!(
            "Forwarded {} filters to addon: {} total functions wrapped",
            filters.len(),
            total_wrapped
        );
    }
}

/// Activate addon tracing with FFI resolution and filter forwarding.
///
/// Returns true on success.
pub fn activate_addon_tracing(addon_path: &Path) -> bool {
    let ffi = match resolve_addon_ffi(addon_path) {
        Some(f) => f,
        None => {
            warn!("Failed to resolve addon FFI");
            return false;
        }
    };

    let success = unsafe { (ffi.enable_tracing)(malwi_nodejs_trace_callback) };
    if !success {
        warn!("Addon failed to enable tracing");
        return false;
    }

    let _ = ADDON_FFI.set(ffi);
    set_addon_tracing_active(true);

    // Forward existing filters
    if let Some(stored_ffi) = ADDON_FFI.get() {
        let filters = crate::nodejs::filters::get_filters();
        forward_filters_to_addon(stored_ffi, &filters);
    }

    true
}

// =============================================================================
// NODE_OPTIONS LOADING (WRAPPER-CENTRIC APPROACH)
// =============================================================================

/// Generate the JS wrapper script content.
///
/// This script is loaded via --require and handles:
/// - Version detection using process.versions.node
/// - Loading the correct addon for the Node.js version
/// - Installing the require hook
/// - Getting and applying filters from the agent via FFI
fn generate_wrapper_script(addon_dir: &Path) -> String {
    let addon_dir_str = addon_dir.to_string_lossy().replace('\\', "\\\\");

    format!(
        r#"// Malwi V8 tracing wrapper - auto-generated
(function() {{
    'use strict';

    const path = require('path');
    const Module = require('module');

    // Detect Node.js major version
    const major = parseInt(process.versions.node.split('.')[0], 10);

    // Map version to bucket (must match embed.rs version_bucket())
    const bucket = major >= 25 ? 'node25'
                 : major >= 24 ? 'node24'
                 : major >= 23 ? 'node23'
                 : major >= 22 ? 'node22'
                 : major >= 21 ? 'node21'
                 : null;  // Unsupported versions

    if (!bucket) {{
        if (process.env.MALWI_DEBUG) {{
            console.error('[malwi] Node.js', major, 'is not supported (requires Node 21+)');
        }}
        return;
    }}

    // Build addon path
    const addonPath = path.join('{addon_dir}', bucket, 'v8_introspect.node');

    try {{
        // Load the native addon
        const addon = require(addonPath);

        // Enable tracing FIRST - connects the trace callback from Rust agent
        if (addon.enableTracing) {{
            addon.enableTracing();
        }}

        // Install require hook only when JS filters are configured.
        // Filters are set by the CLI via --js flag and passed through Rust agent state.
        // Without this guard, the require hook breaks npm's module loading.
        if (addon.getFilters) {{
            const filters = addon.getFilters();
            if (filters.length > 0) {{
                if (addon.installRequireHook) {{
                    addon.installRequireHook(Module);
                }}
                for (const f of filters) {{
                    if (addon.addFilter) {{
                        addon.addFilter(f.pattern, f.captureStack);
                    }}
                }}
            }}
        }}

        // Envvar monitoring: wrap process.env with a Proxy that calls checkEnvVar
        if (addon.checkEnvVar) {{
            const _envChecked = new Map();
            const _origEnv = process.env;
            process.env = new Proxy(_origEnv, {{
                get(target, prop, receiver) {{
                    if (typeof prop === 'string' && !prop.startsWith('MALWI_')) {{
                        if (!_envChecked.has(prop)) {{
                            const result = addon.checkEnvVar(prop);
                            _envChecked.set(prop, result === 1);
                        }}
                        if (!_envChecked.get(prop)) return undefined;
                    }}
                    return Reflect.get(target, prop, receiver);
                }},
                set(target, prop, value, receiver) {{
                    return Reflect.set(target, prop, value, receiver);
                }},
                has(target, prop) {{ return Reflect.has(target, prop); }},
                deleteProperty(target, prop) {{ return Reflect.deleteProperty(target, prop); }},
                ownKeys(target) {{ return Reflect.ownKeys(target); }},
                getOwnPropertyDescriptor(target, prop) {{
                    return Reflect.getOwnPropertyDescriptor(target, prop);
                }}
            }});
        }}

        // Debug output if requested
        if (process.env.MALWI_DEBUG) {{
            console.error('[malwi] Addon loaded: Node', major, '(' + bucket + ')');
        }}
    }} catch (e) {{
        // Fallback: bytecode tracing still works
        if (process.env.MALWI_DEBUG) {{
            console.error('[malwi] Addon load failed:', e.message);
        }}
    }}
}})();
"#,
        addon_dir = addon_dir_str
    )
}

/// Initialize V8 tracing via NODE_OPTIONS.
///
/// This function uses the wrapper-centric approach:
/// 1. Extracts ALL addon versions to a stable directory
/// 2. Writes a JS wrapper that does version detection and addon loading
/// 3. Sets NODE_OPTIONS to preload the wrapper
///
/// No version detection or addon loading happens in Rust - the JS wrapper
/// handles all of that when Node.js is fully initialized.
///
/// **Important:** If NODE_OPTIONS was already set by the CLI (before spawn),
/// we skip this initialization to avoid the timing issue where NODE_OPTIONS
/// is set after Node.js has already read it.
pub fn node_options_initialize() -> bool {
    // Check if NODE_OPTIONS was already set by the CLI (contains our wrapper)
    // This happens when the CLI calls malwi_prepare_node_options() before spawn
    if let Ok(existing) = std::env::var("NODE_OPTIONS") {
        if existing.contains("malwi-wrapper-") {
            info!("NODE_OPTIONS already configured by CLI (wrapper present)");
            // Mark addon tracing as potentially active
            // The actual activation happens when the wrapper loads the addon
            return true;
        }
    }

    info!("Initializing V8 JavaScript tracing via NODE_OPTIONS...");

    // Step 1: Extract all addons to stable directory
    let addon_dir = match super::embed::extract_all_addons() {
        Some(dir) => dir,
        None => {
            warn!("Failed to extract addons");
            return false;
        }
    };

    // Step 2: Generate and write the JS wrapper
    let wrapper_js = generate_wrapper_script(&addon_dir);

    // Use socket hash for stable wrapper path (works for child processes)
    let socket = std::env::var("MALWI_URL").unwrap_or_default();
    let hash = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        socket.hash(&mut hasher);
        format!("{:08x}", hasher.finish() as u32)
    };

    let wrapper_path = std::env::temp_dir().join(format!("malwi-wrapper-{}.js", hash));

    // Only write if file doesn't exist or content differs
    let should_write = if wrapper_path.exists() {
        match std::fs::read_to_string(&wrapper_path) {
            Ok(existing) => existing != wrapper_js,
            Err(_) => true,
        }
    } else {
        true
    };

    if should_write {
        if let Err(e) = std::fs::write(&wrapper_path, &wrapper_js) {
            warn!("Failed to write JS wrapper: {}", e);
            return false;
        }
        debug!("Wrote JS wrapper to {:?}", wrapper_path);
    }

    // Step 3: Set NODE_OPTIONS to preload the wrapper
    // NOTE: This is a fallback for when CLI didn't prepare NODE_OPTIONS.
    // Setting it here is too late for the current process (Node.js already read it),
    // but it will work for child Node.js processes.
    let wrapper_path_str = wrapper_path.to_string_lossy();
    let require_opt = format!("--require={}", wrapper_path_str);

    // Get existing NODE_OPTIONS and append our require
    let node_options = match std::env::var("NODE_OPTIONS") {
        Ok(existing) => format!("{} {}", existing, require_opt),
        Err(_) => require_opt,
    };

    debug!("Setting NODE_OPTIONS={}", node_options);
    std::env::set_var("NODE_OPTIONS", &node_options);

    info!("V8 tracing configured via NODE_OPTIONS (wrapper-centric mode)");
    true
}
