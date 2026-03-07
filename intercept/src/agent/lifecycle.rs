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

    #[test]
    fn test_agent_phase_advance_sequential_transitions_succeed() {
        // Reset to known state for test (not safe in production, fine in single-threaded test)
        PHASE.store(AgentPhase::Uninitialized as u8, Ordering::SeqCst);

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
    }

    #[test]
    fn test_agent_phase_advance_wrong_expected_fails() {
        PHASE.store(AgentPhase::Ready as u8, Ordering::SeqCst);

        // Trying to advance from Configuring when we're at Ready should fail
        assert!(!AgentPhase::advance(
            AgentPhase::Configuring,
            AgentPhase::Ready
        ));
    }

    #[test]
    fn test_agent_phase_request_shutdown_from_ready() {
        PHASE.store(AgentPhase::Ready as u8, Ordering::SeqCst);

        assert!(AgentPhase::request_shutdown());
        assert!(AgentPhase::is_shutting_down());
        assert_eq!(AgentPhase::current(), AgentPhase::ShuttingDown);

        // Second call is a no-op
        assert!(!AgentPhase::request_shutdown());
    }

    #[test]
    fn test_agent_phase_full_lifecycle() {
        PHASE.store(AgentPhase::Uninitialized as u8, Ordering::SeqCst);

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
    }
}
