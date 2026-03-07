//! Node.js tracing state machines.
//!
//! Two parallel tracks — bytecode and addon initialize independently:
//!
//! ```text
//! BytecodePhase:  Uninitialized ──> TraceEnabled ──> HooksInstalled
//! AddonPhase:     Uninitialized ──> Initializing ──> Active
//! ```
//!
//! Replaces 7 scattered `AtomicBool` statics with 2 `AtomicU8` values
//! plus 3 outright deletions (`PRINTF_HOOKED`, `CALLBACK_SEEN`, `ADDON_LOADED`).

use std::sync::atomic::{AtomicU8, Ordering};

// =============================================================================
// BYTECODE PHASE
// =============================================================================

/// V8 bytecode tracing phase.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BytecodePhase {
    /// Not yet initialized.
    Uninitialized = 0,
    /// V8 --trace flag set via SetFlagsFromString. Replaces `NODEJS_TRACE_ENABLED`.
    TraceEnabled = 1,
    /// Runtime_TraceEnter/Exit hooks installed. Replaces `HOOKS_INSTALLED`.
    HooksInstalled = 2,
}

static BYTECODE_PHASE: AtomicU8 = AtomicU8::new(BytecodePhase::Uninitialized as u8);

impl BytecodePhase {
    /// Read the current phase.
    #[inline]
    pub fn current() -> Self {
        Self::from_u8(BYTECODE_PHASE.load(Ordering::Acquire))
    }

    /// Attempt a CAS transition. Returns `true` if this caller won.
    pub fn advance(expected: Self, next: Self) -> bool {
        BYTECODE_PHASE
            .compare_exchange(
                expected as u8,
                next as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Reset to a previous phase on failure. Only valid for rollback
    /// (next < current), and only if current matches `expected`.
    pub fn reset_to(expected: Self, rollback: Self) -> bool {
        BYTECODE_PHASE
            .compare_exchange(
                expected as u8,
                rollback as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    #[inline]
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Uninitialized,
            1 => Self::TraceEnabled,
            _ => Self::HooksInstalled,
        }
    }
}

// =============================================================================
// ADDON PHASE
// =============================================================================

/// N-API addon tracing phase.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AddonPhase {
    /// Not yet initialized.
    Uninitialized = 0,
    /// `filters::initialize()` called, NODE_OPTIONS set up. Replaces `NODEJS_TRACING_INITIALIZED`.
    Initializing = 1,
    /// Addon loaded and tracing callback connected. Replaces `ADDON_TRACING_ACTIVE`.
    Active = 2,
}

static ADDON_PHASE: AtomicU8 = AtomicU8::new(AddonPhase::Uninitialized as u8);

impl AddonPhase {
    /// Read the current phase.
    #[inline]
    pub fn current() -> Self {
        Self::from_u8(ADDON_PHASE.load(Ordering::Acquire))
    }

    /// Attempt a CAS transition. Returns `true` if this caller won.
    pub fn advance(expected: Self, next: Self) -> bool {
        ADDON_PHASE
            .compare_exchange(
                expected as u8,
                next as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Reset to a previous phase on failure.
    pub fn reset_to(expected: Self, rollback: Self) -> bool {
        ADDON_PHASE
            .compare_exchange(
                expected as u8,
                rollback as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Check if addon-based tracing is active.
    #[inline]
    pub fn is_active() -> bool {
        Self::current() >= Self::Active
    }

    #[inline]
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Uninitialized,
            1 => Self::Initializing,
            _ => Self::Active,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier, Mutex};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn with_phase_reset(f: impl FnOnce()) {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        BYTECODE_PHASE.store(BytecodePhase::Uninitialized as u8, Ordering::SeqCst);
        ADDON_PHASE.store(AddonPhase::Uninitialized as u8, Ordering::SeqCst);
        f();
        BYTECODE_PHASE.store(BytecodePhase::Uninitialized as u8, Ordering::SeqCst);
        ADDON_PHASE.store(AddonPhase::Uninitialized as u8, Ordering::SeqCst);
    }

    // --- Existing tests, wrapped ---

    #[test]
    fn test_bytecode_phase_sequential_advance() {
        with_phase_reset(|| {
            assert!(BytecodePhase::advance(
                BytecodePhase::Uninitialized,
                BytecodePhase::TraceEnabled
            ));
            assert_eq!(BytecodePhase::current(), BytecodePhase::TraceEnabled);

            assert!(BytecodePhase::advance(
                BytecodePhase::TraceEnabled,
                BytecodePhase::HooksInstalled
            ));
            assert_eq!(BytecodePhase::current(), BytecodePhase::HooksInstalled);
        });
    }

    #[test]
    fn test_bytecode_phase_duplicate_advance_fails() {
        with_phase_reset(|| {
            BYTECODE_PHASE.store(BytecodePhase::TraceEnabled as u8, Ordering::SeqCst);

            // Already at TraceEnabled, so advancing from Uninitialized should fail
            assert!(!BytecodePhase::advance(
                BytecodePhase::Uninitialized,
                BytecodePhase::TraceEnabled
            ));
        });
    }

    #[test]
    fn test_bytecode_phase_reset_on_failure() {
        with_phase_reset(|| {
            BYTECODE_PHASE.store(BytecodePhase::TraceEnabled as u8, Ordering::SeqCst);

            assert!(BytecodePhase::reset_to(
                BytecodePhase::TraceEnabled,
                BytecodePhase::Uninitialized
            ));
            assert_eq!(BytecodePhase::current(), BytecodePhase::Uninitialized);
        });
    }

    #[test]
    fn test_addon_phase_sequential_advance() {
        with_phase_reset(|| {
            assert!(AddonPhase::advance(
                AddonPhase::Uninitialized,
                AddonPhase::Initializing
            ));
            assert!(!AddonPhase::is_active());

            assert!(AddonPhase::advance(
                AddonPhase::Initializing,
                AddonPhase::Active
            ));
            assert!(AddonPhase::is_active());
        });
    }

    // --- Concurrency tests ---

    #[test]
    fn test_bytecode_phase_advance_concurrent_exactly_one_winner() {
        with_phase_reset(|| {
            const N: usize = 32;
            let barrier = Arc::new(Barrier::new(N));
            let winners: Arc<std::sync::atomic::AtomicUsize> =
                Arc::new(std::sync::atomic::AtomicUsize::new(0));

            let handles: Vec<_> = (0..N)
                .map(|_| {
                    let b = Arc::clone(&barrier);
                    let w = Arc::clone(&winners);
                    std::thread::spawn(move || {
                        b.wait();
                        if BytecodePhase::advance(
                            BytecodePhase::Uninitialized,
                            BytecodePhase::TraceEnabled,
                        ) {
                            w.fetch_add(1, Ordering::SeqCst);
                        }
                    })
                })
                .collect();

            for h in handles {
                h.join().unwrap();
            }

            assert_eq!(winners.load(Ordering::SeqCst), 1);
            assert_eq!(BytecodePhase::current(), BytecodePhase::TraceEnabled);
        });
    }

    #[test]
    fn test_addon_phase_advance_concurrent_exactly_one_winner() {
        with_phase_reset(|| {
            const N: usize = 32;
            let barrier = Arc::new(Barrier::new(N));
            let winners: Arc<std::sync::atomic::AtomicUsize> =
                Arc::new(std::sync::atomic::AtomicUsize::new(0));

            let handles: Vec<_> = (0..N)
                .map(|_| {
                    let b = Arc::clone(&barrier);
                    let w = Arc::clone(&winners);
                    std::thread::spawn(move || {
                        b.wait();
                        if AddonPhase::advance(AddonPhase::Uninitialized, AddonPhase::Initializing)
                        {
                            w.fetch_add(1, Ordering::SeqCst);
                        }
                    })
                })
                .collect();

            for h in handles {
                h.join().unwrap();
            }

            assert_eq!(winners.load(Ordering::SeqCst), 1);
            assert_eq!(AddonPhase::current(), AddonPhase::Initializing);
        });
    }

    #[test]
    fn test_bytecode_phase_reset_concurrent_advance_and_reset_no_corruption() {
        with_phase_reset(|| {
            // Advance to TraceEnabled first
            assert!(BytecodePhase::advance(
                BytecodePhase::Uninitialized,
                BytecodePhase::TraceEnabled
            ));

            const N: usize = 32;
            let barrier = Arc::new(Barrier::new(N));

            let handles: Vec<_> = (0..N)
                .map(|i| {
                    let b = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        b.wait();
                        if i % 2 == 0 {
                            // Half try to advance
                            BytecodePhase::advance(
                                BytecodePhase::TraceEnabled,
                                BytecodePhase::HooksInstalled,
                            );
                        } else {
                            // Half try to reset
                            BytecodePhase::reset_to(
                                BytecodePhase::TraceEnabled,
                                BytecodePhase::Uninitialized,
                            );
                        }
                    })
                })
                .collect();

            for h in handles {
                h.join().unwrap();
            }

            // Must be one of the valid states — no corruption
            let current = BytecodePhase::current();
            assert!(
                current == BytecodePhase::Uninitialized || current == BytecodePhase::HooksInstalled,
                "unexpected phase: {:?}",
                current
            );
        });
    }

    #[test]
    fn test_addon_phase_is_active_only_when_active() {
        with_phase_reset(|| {
            let phases = [
                AddonPhase::Uninitialized,
                AddonPhase::Initializing,
                AddonPhase::Active,
            ];

            for &phase in &phases {
                ADDON_PHASE.store(phase as u8, Ordering::SeqCst);

                assert_eq!(
                    AddonPhase::is_active(),
                    phase == AddonPhase::Active,
                    "is_active() wrong at {:?}",
                    phase
                );
            }
        });
    }

    #[test]
    fn test_bytecode_phase_from_u8_saturates_invalid() {
        // No global state needed — from_u8 is pure
        assert_eq!(BytecodePhase::from_u8(3), BytecodePhase::HooksInstalled);
        assert_eq!(BytecodePhase::from_u8(100), BytecodePhase::HooksInstalled);
        assert_eq!(
            BytecodePhase::from_u8(u8::MAX),
            BytecodePhase::HooksInstalled
        );
    }

    #[test]
    fn test_addon_phase_full_lifecycle_with_reset() {
        with_phase_reset(|| {
            // Full advance
            assert!(AddonPhase::advance(
                AddonPhase::Uninitialized,
                AddonPhase::Initializing
            ));
            assert!(AddonPhase::advance(
                AddonPhase::Initializing,
                AddonPhase::Active
            ));
            assert!(AddonPhase::is_active());

            // Reset back
            assert!(AddonPhase::reset_to(
                AddonPhase::Active,
                AddonPhase::Uninitialized
            ));
            assert!(!AddonPhase::is_active());
            assert_eq!(AddonPhase::current(), AddonPhase::Uninitialized);

            // Re-advance
            assert!(AddonPhase::advance(
                AddonPhase::Uninitialized,
                AddonPhase::Initializing
            ));
            assert!(AddonPhase::advance(
                AddonPhase::Initializing,
                AddonPhase::Active
            ));
            assert!(AddonPhase::is_active());
        });
    }
}
