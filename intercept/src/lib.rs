//! malwi-intercept: Native function interception for malwi-trace.

use std::sync::atomic::{AtomicBool, Ordering};

pub mod arch;
pub mod backtrace;
pub mod code;
pub mod interceptor;
pub mod module;
pub mod types;

// Re-exports for convenience (flattened imports)
pub use code::ptrauth::query_ptrauth_support;
pub use interceptor::invocation;
pub use interceptor::listener::CallListener;
pub use interceptor::Interceptor;
pub use types::InvocationContext;

/// Whether hook debug output is enabled (from MALWI_HOOK_DEBUG env var at init).
static HOOK_DEBUG: AtomicBool = AtomicBool::new(false);

/// Check if hook debug output is enabled.
pub fn hook_debug_enabled() -> bool {
    HOOK_DEBUG.load(Ordering::Relaxed)
}

/// Initialize the intercept subsystem.
///
/// Reads the `MALWI_HOOK_DEBUG` env var once and caches the result.
pub fn init() {
    HOOK_DEBUG.store(
        std::env::var_os("MALWI_HOOK_DEBUG").is_some(),
        Ordering::Relaxed,
    );
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
