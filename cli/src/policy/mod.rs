//! CLI policy subsystem — engine, evaluation, detection, configuration, and templates.

// Policy engine modules (absorbed from malwi-policy crate)
#[allow(dead_code)]
pub(super) mod compiled;
#[allow(dead_code)]
pub(super) mod compiler;
#[allow(dead_code)]
pub(super) mod engine;
#[allow(dead_code)]
pub(super) mod error;
#[allow(dead_code)]
pub(super) mod parser;
#[allow(dead_code)]
pub(super) mod pattern;
#[allow(dead_code)]
pub(super) mod validate;
#[allow(dead_code)]
pub(super) mod yaml;

#[cfg(test)]
mod engine_tests;

// CLI policy evaluation modules
mod active;
mod analysis;
mod commands;
pub(crate) mod config;
mod detect;
mod files;
mod network;
pub(crate) mod taxonomy;
mod templates;

// Module-internal re-exports for sibling access via crate::policy::X
pub(self) use compiled::{Category, EnforcementMode, Runtime, SectionKey};
pub(self) use engine::{HookSpecKind, PolicyDecision, PolicyEngine, PolicyHookSpec};
pub(self) use yaml::{parse as parse_yaml, YamlValue};

// Re-export CLI policy types
pub use active::{ActivePolicy, EventDisposition};
pub(crate) use config::{
    default_policy_path, ensure_default_policy, list_policies, reset_policies, write_policy,
};
pub(crate) use detect::{detect_policy, ensure_auto_policy};
pub(crate) use templates::embedded_policy;
