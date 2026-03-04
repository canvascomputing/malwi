//! Environment variable deny filter for agent-side blocking.
//!
//! When the policy has Block-mode deny rules in the `envvars:` section,
//! the CLI sends individual deny patterns to the agent. This module stores
//! those patterns and provides synchronous matching in the find_variable
//! hook callback — no HTTP round-trip needed.

use std::sync::LazyLock;

use crate::tracing::filter::FilterManager;

/// Global filter manager for envvar deny patterns.
static ENVVAR_DENY_FILTERS: LazyLock<FilterManager> =
    LazyLock::new(|| FilterManager::new("EnvVar"));

/// Add an envvar deny pattern (e.g. "AWS_*", "*SECRET*").
pub fn add_deny_pattern(pattern: &str) {
    ENVVAR_DENY_FILTERS.add(pattern, false);
}

/// Check if a variable name matches any registered deny pattern.
pub fn should_block(name: &str) -> bool {
    ENVVAR_DENY_FILTERS.check(name).0
}

/// Check if any deny patterns are registered.
pub fn has_deny_patterns() -> bool {
    ENVVAR_DENY_FILTERS.has_any()
}

#[cfg(test)]
mod tests {
    use crate::tracing::filter::FilterManager;

    #[test]
    fn test_envvar_deny_exact_match() {
        let filters = FilterManager::new("Test");
        filters.add("AWS_SECRET_ACCESS_KEY", false);

        assert_eq!(filters.check("AWS_SECRET_ACCESS_KEY"), (true, false));
        assert_eq!(filters.check("HOME"), (false, false));
    }

    #[test]
    fn test_envvar_deny_glob_prefix() {
        let filters = FilterManager::new("Test");
        filters.add("AWS_*", false);

        assert_eq!(filters.check("AWS_SECRET_ACCESS_KEY"), (true, false));
        assert_eq!(filters.check("AWS_ACCESS_KEY_ID"), (true, false));
        assert_eq!(filters.check("HOME"), (false, false));
    }

    #[test]
    fn test_envvar_deny_glob_contains() {
        let filters = FilterManager::new("Test");
        filters.add("*SECRET*", false);

        assert_eq!(filters.check("AWS_SECRET_ACCESS_KEY"), (true, false));
        assert_eq!(filters.check("MY_SECRET"), (true, false));
        assert_eq!(filters.check("HOME"), (false, false));
    }

    #[test]
    fn test_envvar_deny_wildcard_all() {
        let filters = FilterManager::new("Test");
        filters.add("*", false);

        assert_eq!(filters.check("AWS_SECRET_ACCESS_KEY"), (true, false));
        assert_eq!(filters.check("HOME"), (true, false));
    }

    #[test]
    fn test_envvar_deny_has_any() {
        let filters = FilterManager::new("Test");
        assert!(!filters.has_any());

        filters.add("AWS_*", false);
        assert!(filters.has_any());
    }
}
