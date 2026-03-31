//! Glob pattern matching for policy rules.
//!
//! This is the single source of truth for glob matching, used by the
//! evaluator in both agent and CLI contexts.

/// Check if a name matches a glob pattern.
/// Supports `*` as wildcard matching any sequence of characters.
pub fn matches_glob(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();

    if parts.len() == 1 {
        // No wildcards — exact match
        return pattern == name;
    }

    // Handle pattern that is just "*" or "**" etc.
    if parts.iter().all(|p| p.is_empty()) {
        return true;
    }

    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }

        if i == 0 {
            // First part must match at start
            if !name.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if i == parts.len() - 1 {
            // Last part must match at end
            if !name[pos..].ends_with(part) {
                return false;
            }
        } else {
            // Middle parts: find anywhere after current position
            match name[pos..].find(part) {
                Some(idx) => pos += idx + part.len(),
                None => return false,
            }
        }
    }
    true
}

/// Case-insensitive glob matching.
/// Useful for DNS hostnames and URLs where case doesn't matter.
pub fn matches_glob_ci(pattern: &str, name: &str) -> bool {
    matches_glob(&pattern.to_lowercase(), &name.to_lowercase())
}

/// Check if a pattern contains glob wildcards.
pub fn is_glob_pattern(pattern: &str) -> bool {
    pattern.contains('*')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert!(matches_glob("malloc", "malloc"));
        assert!(!matches_glob("malloc", "free"));
    }

    #[test]
    fn test_star_prefix() {
        assert!(matches_glob("*alloc", "malloc"));
        assert!(matches_glob("*alloc", "calloc"));
        assert!(!matches_glob("*alloc", "free"));
    }

    #[test]
    fn test_star_suffix() {
        assert!(matches_glob("fs.*", "fs.readFileSync"));
        assert!(!matches_glob("fs.*", "path.join"));
    }

    #[test]
    fn test_star_middle() {
        assert!(matches_glob("*alloc*", "malloc"));
        assert!(matches_glob("*alloc*", "realloc_zone"));
        assert!(!matches_glob("*alloc*", "free"));
    }

    #[test]
    fn test_single_star() {
        assert!(matches_glob("*", "anything"));
        assert!(matches_glob("*", ""));
    }

    #[test]
    fn test_multiple_stars() {
        assert!(matches_glob("py*load*", "pyload"));
        assert!(matches_glob("py*load*", "python_load_module"));
        assert!(!matches_glob("py*load*", "load_python"));
    }

    #[test]
    fn test_case_insensitive() {
        assert!(matches_glob_ci("*.pypi.org", "files.PyPI.org"));
        assert!(matches_glob_ci("PyPI.org", "pypi.org"));
        assert!(!matches_glob_ci("*.pypi.org", "evil-pypi.org"));
    }

    #[test]
    fn test_is_glob_pattern() {
        assert!(is_glob_pattern("fs.*"));
        assert!(is_glob_pattern("*"));
        assert!(!is_glob_pattern("malloc"));
    }
}
