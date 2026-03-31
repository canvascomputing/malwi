//! File path utilities for policy evaluation.
//!
//! Path normalization and transformation used by the command analysis engine.
//! Actual file policy evaluation happens in `Policy::check_event()`.

/// Normalize a file path by collapsing `.` and `..` segments.
/// Prevents traversal bypasses like `/tmp/../../home/.ssh/id_rsa`.
pub(crate) fn normalize_path(path: &str) -> String {
    let mut components: Vec<&str> = Vec::new();
    let is_absolute = path.starts_with('/');

    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if !components.is_empty() && components.last() != Some(&"..") {
                    components.pop();
                } else if !is_absolute {
                    components.push("..");
                }
            }
            _ => components.push(part),
        }
    }

    let joined = components.join("/");
    if is_absolute {
        format!("/{}", joined)
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_removes_dotdot() {
        assert_eq!(normalize_path("/tmp/../../etc/passwd"), "/etc/passwd");
    }

    #[test]
    fn test_normalize_absolute() {
        assert_eq!(normalize_path("/usr/local/bin"), "/usr/local/bin");
    }

    #[test]
    fn test_normalize_dots() {
        assert_eq!(normalize_path("/usr/./local/../bin"), "/usr/bin");
    }
}
