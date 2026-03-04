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
    /// Also attempts to drop the current value via `try_lock` — safe even
    /// if the mutex was held at fork time.
    pub fn mark_forked(&self)
    where
        T: Default,
    {
        self.forked.store(true, Ordering::SeqCst);
        if let Ok(mut guard) = self.inner.try_lock() {
            *guard = T::default();
        }
    }
}
