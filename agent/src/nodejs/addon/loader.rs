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

use std::ffi::c_void;
use std::ffi::CString;
use std::path::Path;
use std::ptr;
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
    // Check env var set by JS wrapper (preferred) or internal state
    if std::env::var("MALWI_ADDON_READY").is_ok() {
        return true;
    }
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
/// This is the shared implementation used by direct loading.
/// For NODE_OPTIONS mode, activation happens in the JS wrapper.
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

        // Install require hook only when JS function tracing is requested.
        // The CLI sets MALWI_JS_ADDON=1 when --js flag is used.
        // Without this guard, the require hook breaks npm's module loading.
        if (process.env.MALWI_JS_ADDON === '1') {{
            if (addon.installRequireHook) {{
                addon.installRequireHook(Module);
            }}

            // Get filters from agent via FFI and apply them
            if (addon.getFilters) {{
                const filters = addon.getFilters();
                for (const f of filters) {{
                    if (addon.addFilter) {{
                        addon.addFilter(f.pattern, f.captureStack);
                    }}
                }}
            }}
        }}

        // Signal that addon is ready (for bytecode deduplication)
        process.env.MALWI_ADDON_READY = '1';

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

    // Set MALWI_ADDON_DIR for child processes and the wrapper
    std::env::set_var("MALWI_ADDON_DIR", addon_dir.to_string_lossy().as_ref());

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

// =============================================================================
// DIRECT LOADING (DEPRECATED - kept for MALWI_DIRECT_LOAD=1)
// =============================================================================
use std::sync::OnceLock;

use crate::native;
use crate::nodejs::ffi::{
    IsolateGetCurrentFn, NapiAddonRegisterFunc, NapiModuleRegisterBySymbolFn, ObjectNewFn,
    ScriptRunMethodFn, V8Context, V8Value,
};
use crate::nodejs::symbols;

/// Addon directory for deferred direct loading (contains all version subdirs).
static DEFERRED_DIRECT_ADDON_DIR: OnceLock<std::path::PathBuf> = OnceLock::new();

/// Original Script::Run function pointer.
static ORIGINAL_SCRIPT_RUN: OnceLock<ScriptRunMethodFn> = OnceLock::new();

/// Whether the Script::Run hook has been installed.
static SCRIPT_RUN_HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Direct loading API - cached function pointers.
struct DirectLoadApi {
    isolate_get_current: IsolateGetCurrentFn,
    object_new: ObjectNewFn,
    napi_register: NapiModuleRegisterBySymbolFn,
}

/// Cached direct load API.
static DIRECT_LOAD_API: OnceLock<DirectLoadApi> = OnceLock::new();

/// Resolve direct load API functions.
fn resolve_direct_load_api() -> Option<DirectLoadApi> {
    debug!("Resolving direct load API symbols...");

    macro_rules! resolve {
        ($sym:expr, $ty:ty) => {
            match native::find_export(None, $sym) {
                Ok(addr) => unsafe { std::mem::transmute::<usize, $ty>(addr) },
                Err(e) => {
                    debug!("Failed to resolve {}: {}", $sym, e);
                    return None;
                }
            }
        };
    }

    let isolate_get_current: IsolateGetCurrentFn =
        resolve!(symbols::v8::ISOLATE_GET_CURRENT, IsolateGetCurrentFn);
    let object_new: ObjectNewFn = resolve!(symbols::v8::OBJECT_NEW, ObjectNewFn);
    let napi_register: NapiModuleRegisterBySymbolFn = resolve!(
        symbols::napi::MODULE_REGISTER_BY_SYMBOL,
        NapiModuleRegisterBySymbolFn
    );

    debug!("Direct load API symbols resolved successfully");

    Some(DirectLoadApi {
        isolate_get_current,
        object_new,
        napi_register,
    })
}

/// Get or initialize the direct load API.
fn get_direct_load_api() -> Option<&'static DirectLoadApi> {
    if let Some(api) = DIRECT_LOAD_API.get() {
        return Some(api);
    }

    if let Some(api) = resolve_direct_load_api() {
        let _ = DIRECT_LOAD_API.set(api);
        DIRECT_LOAD_API.get()
    } else {
        None
    }
}

/// Load our addon using an already-valid V8 context.
#[cfg(unix)]
unsafe fn load_addon_with_context(addon_path: &Path, context: V8Context) -> bool {
    use std::ffi::CStr;

    // Already initialized?
    if ADDON_FFI.get().is_some() {
        return true;
    }

    debug!("Loading addon from {:?} using existing context", addon_path);

    let api = match get_direct_load_api() {
        Some(a) => a,
        None => {
            warn!("Failed to resolve direct load API");
            return false;
        }
    };

    // Get isolate from current context
    let isolate = (api.isolate_get_current)();
    if isolate.is_null() {
        warn!("Failed to get current isolate");
        return false;
    }

    // Create fresh exports and module objects for our addon
    let our_exports = (api.object_new)(isolate);
    let our_module = (api.object_new)(isolate);

    if our_exports.is_null() || our_module.is_null() {
        warn!("Failed to create V8 objects for our addon");
        return false;
    }

    // Load our addon via dlopen
    let path_cstr = match CString::new(addon_path.to_string_lossy().as_bytes()) {
        Ok(s) => s,
        Err(e) => {
            warn!("Invalid addon path: {}", e);
            return false;
        }
    };

    let handle = libc::dlopen(path_cstr.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
    if handle.is_null() {
        let err = CStr::from_ptr(libc::dlerror());
        warn!("Failed to dlopen addon: {:?}", err);
        return false;
    }

    // Get our addon's init function
    let init_sym = CString::new("napi_register_module_v1").unwrap();
    let init_ptr = libc::dlsym(handle, init_sym.as_ptr());
    if init_ptr.is_null() {
        warn!("Our addon missing napi_register_module_v1 symbol");
        libc::dlclose(handle);
        return false;
    }

    let our_init: NapiAddonRegisterFunc =
        std::mem::transmute::<*mut libc::c_void, NapiAddonRegisterFunc>(init_ptr);

    // Register our addon with N-API
    debug!("Calling napi_module_register_by_symbol for our addon...");
    (api.napi_register)(our_exports, our_module as V8Value, context, our_init, 9);

    debug!("Our addon loaded successfully");

    // Activate tracing
    if !activate_addon_tracing(addon_path) {
        warn!("Failed to activate addon tracing");
        return false;
    }

    info!("V8 tracing initialized via Script::Run hook");
    true
}

#[cfg(not(unix))]
unsafe fn load_addon_with_context(_addon_path: &Path, _context: V8Context) -> bool {
    warn!("Direct addon loading not implemented for this platform");
    false
}

/// Hooked v8::Script::Run - loads our addon on first script execution.
unsafe extern "C" fn hooked_script_run(script: *mut c_void, context: V8Context) -> V8Value {
    // Try to inject our addon on first call (if not already done)
    if ADDON_FFI.get().is_none() {
        if let Some(addon_dir) = DEFERRED_DIRECT_ADDON_DIR.get() {
            debug!("Script::Run hook triggered - detecting version and loading addon");

            // Now that Node.js is running, we can detect the version
            if let Some(major) = super::embed::detect_node_version() {
                // Map version to bucket
                let bucket = match major {
                    21 => "node21",
                    22 => "node22",
                    23 => "node23",
                    24 => "node24",
                    25.. => "node25",
                    _ => {
                        warn!("Unsupported Node.js version {} for direct loading", major);
                        // Call original and return
                        return if let Some(original) = ORIGINAL_SCRIPT_RUN.get() {
                            original(script, context)
                        } else {
                            ptr::null_mut()
                        };
                    }
                };

                let addon_path = addon_dir.join(bucket).join("v8_introspect.node");
                if addon_path.exists() {
                    info!("Loading addon for Node.js {} from {:?}", major, addon_path);
                    load_addon_with_context(&addon_path, context);
                } else {
                    warn!("Addon not found at {:?}", addon_path);
                }
            } else {
                warn!("Failed to detect Node.js version in Script::Run hook");
            }
        }
    }

    // Always call original
    if let Some(original) = ORIGINAL_SCRIPT_RUN.get() {
        original(script, context)
    } else {
        ptr::null_mut()
    }
}

/// Install the v8::Script::Run hook for direct addon loading.
fn install_script_run_hook() -> bool {
    if SCRIPT_RUN_HOOK_INSTALLED.swap(true, Ordering::SeqCst) {
        return true; // Already installed
    }

    debug!("Installing v8::Script::Run hook...");

    // Find Script::Run address
    let script_run_addr = match native::find_export(None, symbols::v8::SCRIPT_RUN_WITH_CONTEXT) {
        Ok(addr) => addr,
        Err(e) => {
            warn!("Failed to find Script::Run symbol: {}", e);
            SCRIPT_RUN_HOOK_INSTALLED.store(false, Ordering::SeqCst);
            return false;
        }
    };

    debug!("Found Script::Run at {:#x}", script_run_addr);

    let interceptor = malwi_intercept::Interceptor::obtain();
    interceptor.begin_transaction();
    let mut original_ptr: *const c_void = ptr::null();
    let result = interceptor.replace(
        script_run_addr as *mut c_void,
        hooked_script_run as *const c_void,
        ptr::null_mut(),
        &mut original_ptr,
    );
    interceptor.end_transaction();

    if let Err(e) = result {
        warn!("Failed to hook Script::Run: {:?}", e);
        SCRIPT_RUN_HOOK_INSTALLED.store(false, Ordering::SeqCst);
        return false;
    }

    // Store trampoline pointer so the hook can call original behavior.
    let original_fn: ScriptRunMethodFn =
        unsafe { std::mem::transmute::<*const c_void, ScriptRunMethodFn>(original_ptr) };
    let _ = ORIGINAL_SCRIPT_RUN.set(original_fn);

    info!("v8::Script::Run hook installed");
    true
}

/// Initialize V8 tracing via direct addon loading (no NODE_OPTIONS).
///
/// This approach installs a v8::Script::Run hook and loads the addon
/// when Node.js first executes a script. This avoids NODE_OPTIONS timing issues.
///
/// Used when MALWI_DIRECT_LOAD=1 is set.
pub fn direct_initialize() -> bool {
    info!("Initializing V8 JavaScript tracing via direct loading (no NODE_OPTIONS)...");

    // Extract ALL addons upfront - we'll detect the version later in the hook
    // This is necessary because version detection fails at library load time
    // (Node.js metadata isn't initialized yet)
    let addon_dir = match super::embed::extract_all_addons() {
        Some(dir) => dir,
        None => {
            warn!("Failed to extract addons for direct loading");
            return false;
        }
    };

    // Store addon directory for deferred version detection and loading
    if DEFERRED_DIRECT_ADDON_DIR.set(addon_dir).is_err() {
        warn!("Direct load addon directory already set");
        return false;
    }

    // Install the v8::Script::Run hook
    if !install_script_run_hook() {
        warn!("Failed to install Script::Run hook for direct loading");
        return false;
    }

    info!("V8 tracing will initialize on first script execution (Script::Run hook)");
    true
}
