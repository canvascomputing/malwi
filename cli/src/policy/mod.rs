//! CLI policy subsystem — evaluation, detection, configuration, and display.
//!
//! The compiler, templates, and core evaluator live in the `malwi_policy` crate.
//! This module provides CLI-specific functionality: event enrichment (extracting
//! network info from args, path normalization), command analysis, policy
//! auto-detection, and config file management.

// CLI-specific modules
mod active;
mod analysis;
mod commands;
pub(crate) mod config;
mod detect;
mod files;
mod network;

// Re-export compiler types from malwi_policy (single source of truth)
pub(self) use malwi_policy::compiler::compiled::{Category, EnforcementMode, Runtime, SectionKey};
pub(self) use malwi_policy::compiler::engine::PolicyEngine;

// Re-export CLI policy types
pub use active::{ActivePolicy, EventDisposition};
pub(crate) use config::{
    default_policy_path, ensure_default_policy, list_policies, reset_policies, write_policy,
};
pub(crate) use detect::{detect_policy, ensure_auto_policy};
pub(crate) use malwi_policy::templates::embedded_policy;
