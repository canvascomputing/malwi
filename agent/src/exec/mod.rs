//! Child process monitoring: spawn/exec/fork hooks, command filtering, envvar deny.

pub mod envvar;
pub mod filter;
#[cfg(unix)]
pub mod fork;
pub mod spawn;

// Re-export public items
pub use filter::{add_filter, check_filter, has_filters};
#[cfg(unix)]
pub use fork::{ForkHandler, ForkMonitor};
pub use spawn::{
    detected_bash_version, enable_envvar_monitoring, is_envvar_monitoring_enabled, SpawnHandler,
    SpawnInfo, SpawnMonitor,
};
