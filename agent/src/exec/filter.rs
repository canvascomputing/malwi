//! Exec command filter management.
//!
//! Filters for executed commands (spawned child processes) using the `ex:` prefix.
//! Uses the shared FilterManager for pattern matching.

use std::sync::LazyLock;

use crate::tracing::filter::FilterManager;

/// Global filter manager for exec command filtering.
static EXEC_FILTERS: LazyLock<FilterManager> = LazyLock::new(|| FilterManager::new("Exec"));

/// Add an exec command filter pattern.
pub fn add_filter(pattern: &str, capture_stack: bool) {
    EXEC_FILTERS.add(pattern, capture_stack);
}

/// Check if a command name matches any registered filter.
/// Returns (matches, capture_stack).
pub fn check_filter(command: &str) -> (bool, bool) {
    EXEC_FILTERS.check(command)
}

/// Check if any exec filters are registered.
pub fn has_filters() -> bool {
    EXEC_FILTERS.has_any()
}

#[cfg(test)]
mod tests {
    use crate::tracing::filter::FilterManager;

    #[test]
    fn test_exec_filter_matches_exact_command_name() {
        let filters = FilterManager::new("Test");
        filters.add("curl", false);

        assert_eq!(filters.check("curl"), (true, false));
        assert_eq!(filters.check("wget"), (false, false));
    }

    #[test]
    fn test_exec_filter_star_matches_any_command() {
        let filters = FilterManager::new("Test");
        filters.add("*", false);

        assert_eq!(filters.check("curl"), (true, false));
        assert_eq!(filters.check("wget"), (true, false));
        assert_eq!(filters.check("ls"), (true, false));
    }

    #[test]
    fn test_exec_filter_glob_matches_command_prefix() {
        let filters = FilterManager::new("Test");
        filters.add("curl*", false);

        assert_eq!(filters.check("curl"), (true, false));
        assert_eq!(filters.check("curl-config"), (true, false));
        assert_eq!(filters.check("wget"), (false, false));
    }

    #[test]
    fn test_exec_filter_glob_matches_command_suffix() {
        let filters = FilterManager::new("Test");
        filters.add("*grep", false);

        assert_eq!(filters.check("grep"), (true, false));
        assert_eq!(filters.check("egrep"), (true, false));
        assert_eq!(filters.check("fgrep"), (true, false));
        assert_eq!(filters.check("ls"), (false, false));
    }

    #[test]
    fn test_exec_filter_respects_stack_capture_setting() {
        let filters = FilterManager::new("Test");
        filters.add("curl", true);

        assert_eq!(filters.check("curl"), (true, true));
    }

    #[test]
    fn test_exec_filter_has_any_returns_true_when_filters_exist() {
        let filters = FilterManager::new("Test");
        assert!(!filters.has_any());

        filters.add("curl", false);
        assert!(filters.has_any());
    }

    #[test]
    fn test_exec_filter_checks_all_patterns_in_order() {
        let filters = FilterManager::new("Test");
        filters.add("curl", false);
        filters.add("wget", true);

        assert_eq!(filters.check("curl"), (true, false));
        assert_eq!(filters.check("wget"), (true, true));
        assert_eq!(filters.check("ls"), (false, false));
    }
}
