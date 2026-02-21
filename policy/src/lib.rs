//! Policy engine for malwi function tracing.
//!
//! This crate provides policy parsing, compilation, and evaluation for controlling
//! which operations are allowed, denied, or require review during function tracing.
//!
//! # Example
//!
//! ```
//! use malwi_policy::{PolicyEngine, Runtime, PolicyAction};
//!
//! let yaml = r#"
//! version: 1
//! python:
//!   deny:
//!     - eval
//!     - exec
//!   allow:
//!     - json.*
//! "#;
//!
//! let engine = PolicyEngine::from_yaml(yaml).unwrap();
//!
//! // Evaluate a function call
//! let decision = engine.evaluate_function(Runtime::Python, "eval", &[]);
//! assert_eq!(decision.action, PolicyAction::Deny);
//!
//! let decision = engine.evaluate_function(Runtime::Python, "json.loads", &[]);
//! assert_eq!(decision.action, PolicyAction::Allow);
//! ```

mod compiled;
mod compiler;
mod engine;
mod error;
mod parser;
mod pattern;
mod validate;
mod yaml;

#[cfg(test)]
mod tests;

// Re-export public types
pub use compiled::{
    Category, CompiledPolicy, CompiledRule, CompiledSection, Constraint, ConstraintKind,
    EnforcementMode, Operation, Runtime, SectionKey,
};
pub use compiler::{compile_policy, compile_policy_yaml, compile_policy_yaml_with_includes, resolve_includes};
pub use engine::{
    EvalContext, HookSpecKind, PolicyAction, PolicyDecision, PolicyEngine, PolicyHookSpec,
};
pub use error::{PatternError, PolicyError, ValidationError};
pub use parser::{
    parse_policy, parse_section_name, AllowDenySection, ParsedSectionName, PolicyFile, Rule,
    SectionValue,
};
pub use pattern::{
    compile_pattern, compile_pattern_case_insensitive, compile_url_pattern, CompiledPattern,
};
pub use validate::validate_policy;
pub use yaml::{parse as parse_yaml, YamlValue};
