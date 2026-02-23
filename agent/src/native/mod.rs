//! Native code utilities for symbol resolution, argument formatting, and hook management.

mod format;
pub mod hooks;
mod symbol;

pub use format::format_native_arguments;
pub use hooks::{
    capture_backtrace, is_in_hook, set_in_hook, suppress_hooks_on_current_thread, HookManager,
    HookSuppressGuard,
};
pub use symbol::*;
