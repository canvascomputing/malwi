//! Bash tracing: shell hooks for builtins, external commands, eval, source.
//!
//! Detects bash processes via `dist_version` global variable and hooks
//! bash execution functions to trace all command invocations.

pub(crate) mod detect;
pub(crate) mod hooks;
pub(crate) mod structs;

pub use detect::detected_bash_version;

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) use detect::{enable_envvar_hook, setup_bash_hooks, BashHookListeners};
