//! malwi-intercept: Native function interception and agent runtime for malwi-trace.

use std::sync::atomic::{AtomicBool, Ordering};

// Re-export protocol types from malwi-protocol crate.
// Preserves all existing import paths (malwi_intercept::TraceEvent, malwi_intercept::glob::*, etc.)
// Note: protocol::exec is not re-exported as a module (name collision with intercept's exec).
// Use malwi_protocol::exec:: directly for protocol exec utilities.
pub use malwi_protocol::*;
pub use malwi_protocol::{event, glob, message, platform, protocol, wire};

pub(crate) mod ffi;

pub mod backtrace;
mod gum;
pub mod interceptor;
pub mod module;
pub mod types;

// Re-exports for convenience (flattened imports)
pub use gum::query_ptrauth_support;
pub use gum::strip_code_ptr;
pub use interceptor::invocation;
pub use interceptor::listener::CallListener;
pub use interceptor::Interceptor;
pub use types::InvocationContext;

// Agent runtime modules
pub mod agent;
pub mod bash;
pub mod exec;
pub mod http_client;
pub mod native;
pub mod nodejs;
pub mod python;
pub mod tracing;

#[cfg(test)]
mod test_utils;

pub use agent::{
    agent_debug_enabled, malwi_agent_init, malwi_prepare_node_options, Agent,
    CONFIGURATION_COMPLETE,
};
pub use tracing::{StackCapturer, StackFrame};

/// Whether hook debug output is enabled (from MALWI_HOOK_DEBUG env var at init).
static HOOK_DEBUG: AtomicBool = AtomicBool::new(false);

/// Check if hook debug output is enabled.
pub fn hook_debug_enabled() -> bool {
    HOOK_DEBUG.load(Ordering::Relaxed)
}

/// Initialize the intercept subsystem.
///
/// Reads the `MALWI_HOOK_DEBUG` env var once and caches the result.
/// Also initializes the interception runtime.
pub fn init() {
    HOOK_DEBUG.store(
        std::env::var_os("MALWI_HOOK_DEBUG").is_some(),
        Ordering::Relaxed,
    );
    gum::init_runtime();
}

/// Process-global lock for tests that modify executable code (interceptor + patcher).
///
/// All tests that patch libc or main-executable functions must hold this lock to prevent
/// SIGSEGV from concurrent patching of the same function.
#[cfg(test)]
pub(crate) fn lock_hook_tests() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}
