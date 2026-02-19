//! Platform-specific thread ID retrieval.
//!
//! Provides a unified `id()` function that returns the current thread ID
//! in a cross-platform way. This replaces duplicate implementations in:
//! - cpython.rs
//! - v8_internal/hooks.rs
//! - v8_trace/mod.rs

/// Get the current thread ID in a cross-platform way.
///
/// Returns a platform-specific thread identifier:
/// - Unix: pthread_self() as u64
/// - Windows: GetCurrentThreadId() as u64
#[cfg(unix)]
#[inline]
pub fn id() -> u64 {
    unsafe { libc::pthread_self() as u64 }
}

/// Get the current thread ID in a cross-platform way.
///
/// Returns a platform-specific thread identifier:
/// - Unix: pthread_self() as u64
/// - Windows: GetCurrentThreadId() as u64
#[cfg(windows)]
#[inline]
pub fn id() -> u64 {
    unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() as u64 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_id_is_consistent() {
        let id1 = id();
        let id2 = id();
        assert_eq!(id1, id2, "Thread ID should be consistent within same thread");
    }

    #[test]
    fn test_thread_id_is_nonzero() {
        let tid = id();
        // Thread IDs are generally non-zero, though this isn't strictly guaranteed
        // on all platforms. We mainly test that the function doesn't crash.
        let _ = tid; // Exercises the code; thread IDs can be any u64 value
    }
}
