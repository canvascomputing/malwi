//! Policy compiler: parse, validate, compile, and resolve YAML policies.
//!
//! The compiler transforms YAML policy files into `CompiledPolicy` (the
//! intermediate representation) and then resolves them into `Policy`
//! (the final, priority-ordered rule lists used by the evaluator).
//!
//! ```text
//! YAML → compile_policy_yaml() → CompiledPolicy → prioritize_and_resolve() → Policy
//! ```

pub mod compile;
pub mod compiled;
pub mod engine;
pub mod error;
pub mod parser;
pub mod pattern;
pub mod resolve;
pub mod validate;
mod yaml;

// Re-export key types
pub use compile::{compile_policy_yaml, compile_policy_yaml_with_includes};
pub use compiled::{
    Category, CompiledPolicy, CompiledSection, EnforcementMode, Runtime, SectionKey,
};
pub use engine::{PolicyAction, PolicyDecision, PolicyEngine};
pub use error::{PatternError, PolicyError, Result, ValidationError};
pub use parser::PolicyFile;
pub use pattern::CompiledPattern;
pub use resolve::prioritize_and_resolve;

use crate::resolved::Policy;

/// Compile a YAML policy string into a ready-to-evaluate Policy.
pub fn compile_policy(yaml: &str) -> Result<Policy> {
    let compiled = compile_policy_yaml(yaml)?;
    Ok(prioritize_and_resolve(&compiled))
}

/// Compile a YAML policy string with includes resolution into a Policy.
pub fn compile_policy_with_includes(
    yaml: &str,
    resolver: &dyn Fn(&str) -> Option<String>,
) -> Result<Policy> {
    let compiled = compile_policy_yaml_with_includes(yaml, resolver)?;
    Ok(prioritize_and_resolve(&compiled))
}
