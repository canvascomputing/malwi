//! Generic filter management for function tracing.
//!
//! Provides a unified filter system used by both Python and V8 tracing.
//! Supports glob patterns for flexible function matching.

use std::sync::{Arc, RwLock};

use log::{debug, error};

use crate::glob::matches_glob;

/// A filter entry with pattern and capture settings.
///
/// This struct is used by both Python and V8 tracing to store
/// filter patterns and their associated settings.
#[derive(Debug, Clone)]
pub struct Filter {
    /// Glob pattern to match function names (e.g., "fs.*", "os.path.*")
    pub pattern: String,
    /// Whether to capture the runtime call stack for matched functions
    pub capture_stack: bool,
}

impl Filter {
    /// Create a new filter with the given pattern and capture setting.
    pub fn new(pattern: impl Into<String>, capture_stack: bool) -> Self {
        Self {
            pattern: pattern.into(),
            capture_stack,
        }
    }
}

/// Check if a function name matches any filter in the list.
///
/// # Arguments
/// * `filters` - Slice of filters to check against
/// * `name` - The function name to check
///
/// # Returns
/// Tuple of (matches, capture_stack)
pub fn check_filter(filters: &[Filter], name: &str) -> (bool, bool) {
    for filter in filters {
        if matches_glob(&filter.pattern, name) {
            return (true, filter.capture_stack);
        }
    }
    (false, false)
}

// =============================================================================
// FILTER MANAGER
// =============================================================================

/// Callback type for filter add notifications.
pub type FilterAddCallback = Box<dyn Fn(&str, bool) + Send + Sync>;

/// Unified filter manager for runtime tracing (Python, V8).
///
/// Encapsulates filter storage and common operations, with optional
/// callback support for forwarding filters to external systems (e.g., V8 addon).
pub struct FilterManager {
    /// Runtime name for logging (e.g., "Python", "V8")
    name: &'static str,
    /// Stored filters behind Arc for lock-free snapshot reads.
    filters: RwLock<Arc<Vec<Filter>>>,
    /// Optional callback when filters are added
    on_add: Option<FilterAddCallback>,
}

impl FilterManager {
    /// Create a new filter manager with the given name.
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            filters: RwLock::new(Arc::new(Vec::new())),
            on_add: None,
        }
    }

    /// Create a new filter manager with a callback for filter additions.
    pub fn with_callback(name: &'static str, callback: FilterAddCallback) -> Self {
        Self {
            name,
            filters: RwLock::new(Arc::new(Vec::new())),
            on_add: Some(callback),
        }
    }

    /// Add a filter pattern.
    pub fn add(&self, pattern: &str, capture_stack: bool) {
        match self.filters.write() {
            Ok(mut arc) => {
                let mut new_vec = (**arc).clone();
                new_vec.push(Filter::new(pattern, capture_stack));
                *arc = Arc::new(new_vec);
                debug!(
                    "Added {} filter: {} (stack: {})",
                    self.name, pattern, capture_stack
                );

                // Invoke callback if registered
                if let Some(ref callback) = self.on_add {
                    callback(pattern, capture_stack);
                }
            }
            Err(e) => {
                error!("Failed to add {} filter '{}': {}", self.name, pattern, e);
            }
        }
    }

    /// Check if a function name matches any registered filter.
    /// Returns (matches, capture_stack).
    ///
    /// Takes a snapshot of the Arc (one atomic increment), releases the lock,
    /// then iterates outside the lock. The lock is held only for nanoseconds.
    pub fn check(&self, name: &str) -> (bool, bool) {
        let snapshot = self
            .filters
            .read()
            .map(|guard| Arc::clone(&*guard))
            .unwrap_or_else(|_| Arc::new(Vec::new()));
        check_filter(&snapshot, name)
    }

    /// Check if any filters are registered.
    pub fn has_any(&self) -> bool {
        self.filters
            .read()
            .map(|f| !f.is_empty())
            .unwrap_or(false)
    }

    /// Get a copy of all registered filters.
    pub fn get_all(&self) -> Vec<Filter> {
        self.filters
            .read()
            .map(|arc| (**arc).clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_new_creates_empty_filter_list() {
        let filter = Filter::new("fs.*", true);
        assert_eq!(filter.pattern, "fs.*");
        assert!(filter.capture_stack);
    }

    #[test]
    fn test_filter_matches_function_against_glob_pattern() {
        let filters = vec![
            Filter::new("fs.*", true),
            Filter::new("http.*", false),
        ];

        assert_eq!(check_filter(&filters, "fs.readFile"), (true, true));
        assert_eq!(check_filter(&filters, "http.request"), (true, false));
        assert_eq!(check_filter(&filters, "crypto.hash"), (false, false));
    }

    #[test]
    fn test_filter_with_no_patterns_matches_nothing() {
        let filters: Vec<Filter> = vec![];
        assert_eq!(check_filter(&filters, "fs.readFile"), (false, false));
    }

    #[test]
    fn test_filter_returns_first_matching_pattern_settings() {
        let filters = vec![
            Filter::new("fs.*", true),
            Filter::new("http.*", false),
        ];

        // fs.* should capture stack
        assert_eq!(check_filter(&filters, "fs.readFile"), (true, true));

        // http.* should NOT capture stack
        assert_eq!(check_filter(&filters, "http.request"), (true, false));

        // Unknown should not match
        assert_eq!(check_filter(&filters, "crypto.hash"), (false, false));
    }
}
