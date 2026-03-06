//! Fork-safe mutex wrapper.
//!
//! After `fork()`, any `Mutex` that was locked by a now-dead thread remains
//! locked forever — blocking `lock()` would deadlock. `ForkSafeMutex<T>`
//! switches to `try_lock` after [`mark_forked()`] is called, returning an
//! error instead of deadlocking.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use anyhow::Result;

/// A `Mutex<T>` that becomes non-blocking after `fork()`.
///
/// In normal (pre-fork) operation, `lock()` blocks.  After `mark_forked()`,
/// `lock()` uses `try_lock` — returning `Err` if the mutex is held by a
/// thread that died at fork time, instead of deadlocking.
pub struct ForkSafeMutex<T> {
    inner: Mutex<T>,
    forked: AtomicBool,
}

impl<T> ForkSafeMutex<T> {
    /// Create a new fork-safe mutex wrapping `value`.
    pub fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
            forked: AtomicBool::new(false),
        }
    }

    /// Acquire the lock, using a fork-safe strategy when appropriate.
    ///
    /// - Pre-fork: blocking `lock()` (handles poisoning).
    /// - Post-fork: `try_lock()` to avoid deadlock from dead threads.
    pub fn lock(&self) -> Result<MutexGuard<'_, T>> {
        if self.forked.load(Ordering::Relaxed) {
            match self.inner.try_lock() {
                Ok(guard) => Ok(guard),
                Err(std::sync::TryLockError::WouldBlock) => {
                    Err(anyhow::anyhow!("mutex held by dead thread (post-fork)"))
                }
                Err(std::sync::TryLockError::Poisoned(e)) => Ok(e.into_inner()),
            }
        } else {
            Ok(self.inner.lock().unwrap_or_else(|e| e.into_inner()))
        }
    }

    /// Mark this mutex as living in a forked child process.
    ///
    /// After this call, `lock()` uses `try_lock` to avoid deadlock.
    /// Resets the wrapped value to `Default` — if the mutex was held by a
    /// now-dead thread, reinitializes the mutex entirely. This is safe
    /// because only one thread exists in the child after fork.
    pub fn mark_forked(&self)
    where
        T: Default,
    {
        self.forked.store(true, Ordering::SeqCst);
        match self.inner.try_lock() {
            Ok(mut guard) => {
                *guard = T::default();
            }
            Err(_) => {
                // Mutex was held by a thread that died at fork time.
                // Only one thread exists in the child, so we can safely
                // reinitialize the mutex in place. The old Mutex (and its
                // locked pthread_mutex_t) is intentionally leaked — its
                // state is invalid post-fork anyway.
                unsafe {
                    let ptr = &self.inner as *const Mutex<T> as *mut Mutex<T>;
                    ptr.write(Mutex::new(T::default()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_succeeds_before_mark_forked() {
        let m = ForkSafeMutex::new(Some(42u32));
        let guard = m.lock().unwrap();
        assert_eq!(*guard, Some(42));
    }

    #[test]
    fn mark_forked_resets_value_to_default() {
        let m = ForkSafeMutex::new(Some(42u32));
        m.mark_forked();
        let guard = m.lock().unwrap();
        assert_eq!(*guard, None);
    }

    #[test]
    fn lock_succeeds_after_mark_forked() {
        let m = ForkSafeMutex::new(Some(42u32));
        m.mark_forked();
        // Post-fork lock uses try_lock path
        let guard = m.lock().unwrap();
        assert_eq!(*guard, None);
        drop(guard);
        // Second lock also works
        let guard2 = m.lock().unwrap();
        assert_eq!(*guard2, None);
    }

    #[test]
    fn mark_forked_reinitializes_stuck_mutex() {
        let m = ForkSafeMutex::new(Some(42u32));
        // Simulate a dead thread holding the lock: lock and intentionally
        // leak the guard so the mutex stays permanently locked.
        let guard = m.inner.lock().unwrap();
        std::mem::forget(guard);
        // Now the mutex is permanently locked — simulates fork with
        // a thread that held the lock at fork time.

        // mark_forked should reinitialize the mutex via ptr::write
        m.mark_forked();

        // lock() should now succeed with the default value
        let val = m.lock().unwrap();
        assert_eq!(*val, None);
    }

    #[test]
    fn lock_returns_err_when_stuck_without_mark_forked() {
        let m = ForkSafeMutex::new(Some(42u32));
        // Leak the guard to simulate a dead thread holding the lock
        let guard = m.inner.lock().unwrap();
        std::mem::forget(guard);
        // Set forked flag manually WITHOUT calling mark_forked()
        // (so the mutex is NOT reinitialised)
        m.forked.store(true, Ordering::SeqCst);

        // lock() should return Err — the "mutex held by dead thread" path
        assert!(m.lock().is_err());
    }
}
