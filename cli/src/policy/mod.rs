//! CLI policy subsystem — evaluation, detection, configuration, and templates.

mod active;
mod analysis;
mod commands;
pub(crate) mod config;
mod detect;
mod files;
mod network;
pub(crate) mod taxonomy;
mod templates;

pub use active::{ActivePolicy, EventDisposition};
pub(crate) use config::{
    default_policy_path, ensure_default_policy, list_policies, reset_policies, write_policy,
};
pub(crate) use detect::{detect_policy, ensure_auto_policy};
pub(crate) use templates::embedded_policy;
