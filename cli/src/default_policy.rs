//! Embedded default security policy YAML.
//!
//! Observe-mode policy: nothing is blocked. Uses `warn:` for credential/secret
//! access and `log:` for general network/command visibility.

pub const DEFAULT_SECURITY_YAML: &str = include_str!("policies/default.yaml");
