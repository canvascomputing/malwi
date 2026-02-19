//! malwi-intercept: Native function interception for malwi-trace.

pub mod arch;
pub mod backtrace;
pub mod code;
pub mod interceptor;
pub mod module;
pub mod types;

// Re-exports for convenience (flattened imports)
pub use interceptor::invocation;
pub use interceptor::listener::CallListener;
pub use interceptor::Interceptor;
pub use types::InvocationContext;

/// Initialize the intercept subsystem.
///
/// Uses Rust-managed state, so this is a no-op today but kept for
/// API compatibility with the agent integration.
pub fn init() {}

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
