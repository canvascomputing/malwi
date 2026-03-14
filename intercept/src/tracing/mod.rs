//! Shared tracing utilities used by both Python and V8 tracing.
//!
//! This module provides common functionality that is duplicated across
//! different runtime tracing implementations:
//!
//! - `thread`: Platform-specific thread ID retrieval
//! - `time`: Timestamp management (trace start time, elapsed nanoseconds)
//! - `filter`: Generic filter matching with glob patterns
//! - `event`: TraceEvent builder for consistent event creation
//! - `format`: Shared string formatting utilities (truncation, display)

pub mod dns;
pub mod event;
pub mod filter;
pub mod fork_mutex;
pub mod format;
pub mod stack;
pub mod thread;
pub mod time;

// Re-export commonly used items
pub use dns::dns_tracker;
pub use event::EventBuilder;
pub use filter::{check_filter, Filter, FilterManager};
pub use fork_mutex::ForkSafeMutex;
pub use stack::{StackCapturer, StackFrame};
pub use thread::id as thread_id;
pub use time::elapsed_ns;
