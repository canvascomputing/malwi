//! malwi-policy: The single policy engine for malwi.
//!
//! This crate provides the **only** policy evaluator, used by both the CLI
//! (for display rendering) and the agent (for in-process enforcement).
//!
//! # Architecture
//!
//! The policy compiler resolves all allow/deny/warn/hide conflicts at compile
//! time using pattern specificity, producing priority-ordered rule lists. The
//! evaluator then does a simple first-match scan — no runtime specificity
//! computation, no cascade ordering. Both CLI and agent use the same evaluator,
//! guaranteeing identical decisions by construction.
//!
//! Network rules are the exception: they require multi-representation matching
//! (URL × domain × endpoint) with runtime specificity, so they use a dedicated
//! `NetworkRuleSet` instead of the pre-sorted `RuleSet`.
//!
//! ```text
//! YAML → compile_policy() → Policy → check_event() (shared)
//!                                        ↑           ↑
//!                                     Agent         CLI
//! ```

pub mod compiler;
pub mod config;
pub mod decision;
pub mod eval;
pub mod glob;
pub mod resolved;
pub mod templates;
mod util;

// Re-export core types
pub use config::AgentConfig;
pub use decision::Outcome;
pub use resolved::{Decision, NetworkRule, NetworkRuleSet, Policy, Rule, RuleSet};

// Re-export compiler types and functions
pub use compiler::{
    compile_policy, compile_policy_with_includes, compile_policy_yaml,
    compile_policy_yaml_with_includes, prioritize_and_resolve, Category, CompiledPolicy,
    EnforcementMode, PolicyAction, PolicyDecision, PolicyEngine, PolicyError, Runtime, SectionKey,
    ValidationError,
};

// Re-export glob for shared use
pub use glob::{matches_glob, matches_glob_ci};
