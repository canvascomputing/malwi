//! Environment variable allow/deny filter for agent-side blocking.
//!
//! When the policy has Block-mode deny rules in the `envvars:` section,
//! the CLI sends individual deny patterns to the agent. Allow patterns
//! (from `envvars: allow:`) are sent separately and take precedence:
//! a variable matching any allow pattern bypasses deny checks.

use std::sync::LazyLock;

use crate::tracing::filter::FilterManager;

/// Global filter manager for envvar deny patterns.
static ENVVAR_DENY_FILTERS: LazyLock<FilterManager> =
    LazyLock::new(|| FilterManager::new("EnvVar"));

/// Global filter manager for envvar allow patterns.
static ENVVAR_ALLOW_FILTERS: LazyLock<FilterManager> =
    LazyLock::new(|| FilterManager::new("EnvVarAllow"));

/// Add an envvar deny pattern (e.g. "AWS_*", "*SECRET*").
pub fn add_deny_pattern(pattern: &str) {
    ENVVAR_DENY_FILTERS.add(pattern, false);
}

/// Add an envvar allow pattern (e.g. "HF_HUB_*").
/// Variables matching allow patterns bypass deny checks.
pub fn add_allow_pattern(pattern: &str) {
    ENVVAR_ALLOW_FILTERS.add(pattern, false);
}

/// Check if a variable name should be blocked.
/// Returns false if any allow pattern matches (regardless of deny).
pub fn should_block(name: &str) -> bool {
    // Allow takes precedence over deny
    if ENVVAR_ALLOW_FILTERS.has_any() && ENVVAR_ALLOW_FILTERS.check(name).0 {
        return false;
    }
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

    #[test]
    fn test_envvar_allow_overrides_deny() {
        let deny = FilterManager::new("Deny");
        let allow = FilterManager::new("Allow");

        deny.add("*TOKEN*", false);
        allow.add("HF_HUB_*", false);

        // HF_HUB_DISABLE_IMPLICIT_TOKEN matches *TOKEN* deny but also HF_HUB_* allow
        assert!(deny.check("HF_HUB_DISABLE_IMPLICIT_TOKEN").0);
        assert!(allow.check("HF_HUB_DISABLE_IMPLICIT_TOKEN").0);

        // Simulating should_block logic: allow takes precedence
        let should_block = |name: &str| -> bool {
            if allow.has_any() && allow.check(name).0 {
                return false;
            }
            deny.check(name).0
        };

        assert!(
            !should_block("HF_HUB_DISABLE_IMPLICIT_TOKEN"),
            "HF_HUB_* allow should override *TOKEN* deny"
        );
        assert!(
            should_block("GITHUB_TOKEN"),
            "GITHUB_TOKEN has no allow override"
        );
        assert!(!should_block("HOME"), "HOME matches neither allow nor deny");
    }
}
