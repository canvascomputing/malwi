//! Agent lifecycle state machine.
//!
//! Replaces 4 scattered `AtomicBool` statics with a single monotonic `AtomicU8`.
//! Invalid state transitions are structurally impossible: `advance()` uses
//! `compare_exchange` so exactly one caller wins each transition.
//!
//! ```text
//! Uninitialized ──> Configuring ──> Ready ──> ShuttingDown ──> Flushed ──> ShutdownSent
//! ```

use std::sync::atomic::{AtomicU8, Ordering};

/// Agent lifecycle phase. Advances monotonically via CAS.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AgentPhase {
    /// Library loaded, no agent created yet.
    Uninitialized = 0,
    /// Agent created, waiting for hook configuration from CLI.
    Configuring = 1,
    /// Configuration complete, hooks installed, main() may proceed.
    /// Replaces `CONFIGURATION_COMPLETE`.
    Ready = 2,
    /// atexit handler fired, flush thread should drain and exit.
    /// Replaces `SHUTDOWN_REQUESTED`.
    ShuttingDown = 3,
    /// Flush thread has drained all pending events.
    /// Replaces `FLUSH_COMPLETE`.
    Flushed = 4,
    /// /shutdown message sent to CLI (exactly once).
    /// Replaces `SHUTDOWN_SENT`.
    ShutdownSent = 5,
}

static PHASE: AtomicU8 = AtomicU8::new(AgentPhase::Uninitialized as u8);

impl AgentPhase {
    /// Read the current phase.
    #[inline]
    pub fn current() -> Self {
        Self::from_u8(PHASE.load(Ordering::Acquire))
    }

    /// Attempt a monotonic CAS transition. Returns `true` if this caller won.
    ///
    /// Enforces forward-only progression: `next` must be `expected + 1`.
    /// Multiple threads racing for the same transition get exactly one winner.
    pub fn advance(expected: Self, next: Self) -> bool {
        debug_assert!(
            (next as u8) == (expected as u8) + 1,
            "AgentPhase::advance must be sequential"
        );
        PHASE
            .compare_exchange(
                expected as u8,
                next as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Force-advance to `ShuttingDown` from any phase < `ShuttingDown`.
    ///
    /// Used by the atexit handler which can fire at any point.
    /// Returns `true` if this caller initiated the shutdown.
    pub fn request_shutdown() -> bool {
        loop {
            let current = PHASE.load(Ordering::Acquire);
            if current >= Self::ShuttingDown as u8 {
                return false; // Already shutting down
            }
            if PHASE
                .compare_exchange(
                    current,
                    Self::ShuttingDown as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return true;
            }
            // Retry on spurious CAS failure
        }
    }

    /// Configuration is complete (hooks installed, main() may proceed).
    #[inline]
    pub fn is_configured() -> bool {
        Self::current() >= Self::Ready
    }

    /// Shutdown has been requested (atexit fired).
    #[inline]
    pub fn is_shutting_down() -> bool {
        Self::current() >= Self::ShuttingDown
    }

    /// Flush thread has drained all pending events.
    #[inline]
    pub fn is_flushed() -> bool {
        Self::current() >= Self::Flushed
    }

    #[inline]
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Uninitialized,
            1 => Self::Configuring,
            2 => Self::Ready,
            3 => Self::ShuttingDown,
            4 => Self::Flushed,
            5 => Self::ShutdownSent,
            _ => Self::ShutdownSent, // saturate
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
        PHASE.store(AgentPhase::Uninitialized as u8, Ordering::SeqCst);
        f();
        PHASE.store(AgentPhase::Uninitialized as u8, Ordering::SeqCst);
    }

    #[test]
    fn test_agent_phase_advance_sequential_transitions_succeed() {
        with_phase_reset(|| {
            assert!(AgentPhase::advance(
                AgentPhase::Uninitialized,
                AgentPhase::Configuring
            ));
            assert_eq!(AgentPhase::current(), AgentPhase::Configuring);

            assert!(AgentPhase::advance(
                AgentPhase::Configuring,
                AgentPhase::Ready
            ));
            assert!(AgentPhase::is_configured());
        });
    }

    #[test]
    fn test_agent_phase_advance_wrong_expected_fails() {
        with_phase_reset(|| {
            PHASE.store(AgentPhase::Ready as u8, Ordering::SeqCst);

            // Trying to advance from Configuring when we're at Ready should fail
            assert!(!AgentPhase::advance(
                AgentPhase::Configuring,
                AgentPhase::Ready
            ));
        });
    }

    #[test]
    fn test_agent_phase_request_shutdown_from_ready() {
        with_phase_reset(|| {
            PHASE.store(AgentPhase::Ready as u8, Ordering::SeqCst);

            assert!(AgentPhase::request_shutdown());
            assert!(AgentPhase::is_shutting_down());
            assert_eq!(AgentPhase::current(), AgentPhase::ShuttingDown);

            // Second call is a no-op
            assert!(!AgentPhase::request_shutdown());
        });
    }

    #[test]
    fn test_agent_phase_full_lifecycle() {
        with_phase_reset(|| {
            assert!(AgentPhase::advance(
                AgentPhase::Uninitialized,
                AgentPhase::Configuring
            ));
            assert!(AgentPhase::advance(
                AgentPhase::Configuring,
                AgentPhase::Ready
            ));
            assert!(AgentPhase::request_shutdown());
            assert!(AgentPhase::advance(
                AgentPhase::ShuttingDown,
                AgentPhase::Flushed
            ));
            assert!(AgentPhase::is_flushed());
            assert!(AgentPhase::advance(
                AgentPhase::Flushed,
                AgentPhase::ShutdownSent
            ));
            assert_eq!(AgentPhase::current(), AgentPhase::ShutdownSent);
        });
    }

    // --- Concurrency tests ---

    #[test]
    fn test_agent_phase_advance_concurrent_exactly_one_winner() {
        with_phase_reset(|| {
            PHASE.store(AgentPhase::Ready as u8, Ordering::SeqCst);

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
                        if AgentPhase::advance(AgentPhase::Ready, AgentPhase::ShuttingDown) {
                            w.fetch_add(1, Ordering::SeqCst);
                        }
                    })
                })
                .collect();

            for h in handles {
                h.join().unwrap();
            }

            assert_eq!(winners.load(Ordering::SeqCst), 1);
            assert_eq!(AgentPhase::current(), AgentPhase::ShuttingDown);
        });
    }

    #[test]
    fn test_agent_phase_request_shutdown_concurrent_exactly_one_winner() {
        with_phase_reset(|| {
            PHASE.store(AgentPhase::Ready as u8, Ordering::SeqCst);

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
                        if AgentPhase::request_shutdown() {
                            w.fetch_add(1, Ordering::SeqCst);
                        }
                    })
                })
                .collect();

            for h in handles {
                h.join().unwrap();
            }

            assert_eq!(winners.load(Ordering::SeqCst), 1);
            assert_eq!(AgentPhase::current(), AgentPhase::ShuttingDown);
        });
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "AgentPhase::advance must be sequential")]
    fn test_agent_phase_advance_skip_state_panics() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        PHASE.store(AgentPhase::Uninitialized as u8, Ordering::SeqCst);

        // Skip Configuring — should panic in debug
        AgentPhase::advance(AgentPhase::Uninitialized, AgentPhase::Ready);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "AgentPhase::advance must be sequential")]
    fn test_agent_phase_advance_backward_panics() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        PHASE.store(AgentPhase::Ready as u8, Ordering::SeqCst);

        // Backward transition — should panic in debug
        AgentPhase::advance(AgentPhase::Ready, AgentPhase::Configuring);
    }

    #[test]
    fn test_agent_phase_from_u8_saturates_invalid() {
        // No global state needed — from_u8 is pure
        assert_eq!(AgentPhase::from_u8(6), AgentPhase::ShutdownSent);
        assert_eq!(AgentPhase::from_u8(100), AgentPhase::ShutdownSent);
        assert_eq!(AgentPhase::from_u8(u8::MAX), AgentPhase::ShutdownSent);
    }

    #[test]
    fn test_agent_phase_query_helpers_at_each_state() {
        with_phase_reset(|| {
            let phases = [
                AgentPhase::Uninitialized,
                AgentPhase::Configuring,
                AgentPhase::Ready,
                AgentPhase::ShuttingDown,
                AgentPhase::Flushed,
                AgentPhase::ShutdownSent,
            ];

            for &phase in &phases {
                PHASE.store(phase as u8, Ordering::SeqCst);

                assert_eq!(
                    AgentPhase::is_configured(),
                    phase >= AgentPhase::Ready,
                    "is_configured() wrong at {:?}",
                    phase
                );
                assert_eq!(
                    AgentPhase::is_shutting_down(),
                    phase >= AgentPhase::ShuttingDown,
                    "is_shutting_down() wrong at {:?}",
                    phase
                );
                assert_eq!(
                    AgentPhase::is_flushed(),
                    phase >= AgentPhase::Flushed,
                    "is_flushed() wrong at {:?}",
                    phase
                );
            }
        });
    }

    #[test]
    fn test_agent_phase_request_shutdown_from_uninitialized() {
        with_phase_reset(|| {
            // Shutdown should work from any phase < ShuttingDown
            assert!(AgentPhase::request_shutdown());
            assert_eq!(AgentPhase::current(), AgentPhase::ShuttingDown);
        });
    }

    #[test]
    fn test_agent_phase_flushed_to_shutdown_sent_concurrent_exactly_one_winner() {
        with_phase_reset(|| {
            PHASE.store(AgentPhase::Flushed as u8, Ordering::SeqCst);

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
                        if AgentPhase::advance(AgentPhase::Flushed, AgentPhase::ShutdownSent) {
                            w.fetch_add(1, Ordering::SeqCst);
                        }
                    })
                })
                .collect();

            for h in handles {
                h.join().unwrap();
            }

            assert_eq!(winners.load(Ordering::SeqCst), 1);
            assert_eq!(AgentPhase::current(), AgentPhase::ShutdownSent);
        });
    }
}
