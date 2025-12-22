//! Timestamp management for trace events.
//!
//! Provides a shared trace start time and elapsed nanosecond calculation.
//! This ensures consistent timestamp handling across all tracing modules.

use std::sync::LazyLock;
use std::time::Instant;

/// Trace start time - initialized on first access.
///
/// All trace events use timestamps relative to this instant,
/// allowing correlation of events across different tracing mechanisms.
pub static TRACE_START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Get elapsed nanoseconds since trace start.
///
/// Returns the number of nanoseconds that have elapsed since the
/// first call to any tracing function. This provides a consistent
/// timeline for all trace events.
#[inline]
pub fn elapsed_ns() -> u64 {
    TRACE_START.elapsed().as_nanos() as u64
}

/// Initialize the trace start time.
///
/// Call this early in the agent initialization to ensure consistent
/// timestamps from the very beginning of tracing.
///
/// This is automatically called on first access to `elapsed_ns()`,
/// but explicit initialization allows for more precise control.
#[inline]
pub fn init() {
    // Force initialization by accessing TRACE_START
    let _ = *TRACE_START;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_elapsed_ns_increases() {
        let t1 = elapsed_ns();
        thread::sleep(Duration::from_millis(1));
        let t2 = elapsed_ns();
        assert!(t2 > t1, "Elapsed time should increase");
    }

    #[test]
    fn test_trace_start_is_consistent() {
        let start1 = *TRACE_START;
        let start2 = *TRACE_START;
        assert_eq!(start1, start2, "TRACE_START should be consistent");
    }
}
