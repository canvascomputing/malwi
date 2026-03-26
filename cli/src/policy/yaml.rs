//! Re-export YAML parser from protocol crate.
//!
//! The canonical implementation lives in `malwi-protocol::yaml`. This module
//! re-exports it so existing `super::yaml::` paths in sibling modules continue
//! to work without changes.

pub use malwi_intercept::yaml::*;
