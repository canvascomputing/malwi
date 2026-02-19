use regex::Regex;

use crate::error::{PatternError, PatternResult};

/// A compiled pattern ready for matching.
#[derive(Debug, Clone)]
pub enum CompiledPattern {
    /// Exact string match (no wildcards).
    Exact(String),
    /// Glob pattern compiled to regex.
    Glob { original: String, regex: Regex },
    /// Explicit regex pattern (prefixed with "regex:" in YAML).
    Regex { original: String, regex: Regex },
}

impl CompiledPattern {
    /// Check if the pattern matches the input string.
    pub fn matches(&self, input: &str) -> bool {
        match self {
            CompiledPattern::Exact(s) => s == input,
            CompiledPattern::Glob { regex, .. } => regex.is_match(input),
            CompiledPattern::Regex { regex, .. } => regex.is_match(input),
        }
    }

    /// Check if the pattern matches the input string case-insensitively.
    pub fn matches_ignore_case(&self, input: &str) -> bool {
        match self {
            CompiledPattern::Exact(s) => s.eq_ignore_ascii_case(input),
            CompiledPattern::Glob { regex, .. } => {
                // The regex should already have (?i) if case-insensitive matching was needed.
                // For now, just use the regex as-is since we compile separate patterns.
                regex.is_match(input)
            }
            CompiledPattern::Regex { regex, .. } => regex.is_match(input),
        }
    }

    /// Get the original pattern string.
    pub fn original(&self) -> &str {
        match self {
            CompiledPattern::Exact(s) => s,
            CompiledPattern::Glob { original, .. } => original,
            CompiledPattern::Regex { original, .. } => original,
        }
    }
}

/// Compile a pattern string into a CompiledPattern.
///
/// Pattern syntax:
/// - `regex:...` - Explicit regex pattern
/// - Contains `*` or `?` - Glob pattern
/// - Otherwise - Exact match
pub fn compile_pattern(pattern: &str) -> PatternResult<CompiledPattern> {
    compile_pattern_with_options(pattern, false, false)
}

/// Compile a pattern with case-insensitive option.
pub fn compile_pattern_case_insensitive(pattern: &str) -> PatternResult<CompiledPattern> {
    compile_pattern_with_options(pattern, true, false)
}

/// Compile a URL pattern where `*` never crosses `/` (path-aware).
/// Used for `http:` URL pattern rules where `*` matches within a path segment
/// and `**` crosses path separators.
pub fn compile_url_pattern(pattern: &str) -> PatternResult<CompiledPattern> {
    compile_pattern_with_options(pattern, true, true)
}

fn compile_pattern_with_options(
    pattern: &str,
    case_insensitive: bool,
    force_path_mode: bool,
) -> PatternResult<CompiledPattern> {
    // Check for explicit regex prefix
    if let Some(regex_str) = pattern.strip_prefix("regex:") {
        let regex_pattern = if case_insensitive {
            format!("(?i){}", regex_str)
        } else {
            regex_str.to_string()
        };
        let regex = Regex::new(&regex_pattern).map_err(|e| PatternError::InvalidRegex {
            pattern: pattern.to_string(),
            reason: e.to_string(),
        })?;
        return Ok(CompiledPattern::Regex {
            original: pattern.to_string(),
            regex,
        });
    }

    // Check if it's a glob pattern (contains * or ?)
    if pattern.contains('*') || pattern.contains('?') {
        let regex = glob_to_regex(pattern, case_insensitive, force_path_mode)?;
        return Ok(CompiledPattern::Glob {
            original: pattern.to_string(),
            regex,
        });
    }

    // Exact match
    let exact = if case_insensitive {
        pattern.to_lowercase()
    } else {
        pattern.to_string()
    };
    Ok(CompiledPattern::Exact(exact))
}

/// Convert a glob pattern to a regex.
///
/// Glob syntax:
/// - `*` matches any sequence of characters (excludes `/` only for path patterns)
/// - `**` matches any sequence of characters including path separators
/// - `**/` matches zero or more path segments
/// - `?` matches any single character
/// - All other characters are escaped for literal matching
fn glob_to_regex(
    glob: &str,
    case_insensitive: bool,
    force_path_mode: bool,
) -> PatternResult<Regex> {
    let mut regex = String::new();

    if case_insensitive {
        regex.push_str("(?i)");
    }

    regex.push('^');

    let chars: Vec<char> = glob.chars().collect();
    let mut i = 0;

    // Determine if this is a path pattern (starts with / or ~, or force_path_mode for URLs)
    // For path patterns, single * doesn't match /
    let is_path_pattern = force_path_mode || glob.starts_with('/') || glob.starts_with('~');

    while i < chars.len() {
        let c = chars[i];

        if c == '*' {
            // Check for **
            if i + 1 < chars.len() && chars[i + 1] == '*' {
                // Check if followed by /
                if i + 2 < chars.len() && chars[i + 2] == '/' {
                    // **/ matches zero or more path segments (including trailing /)
                    regex.push_str("(.*/)?");
                    i += 3;
                } else {
                    // ** matches anything including path separators
                    regex.push_str(".*");
                    i += 2;
                }
            } else {
                // Single * - behavior depends on context
                if is_path_pattern {
                    // For path patterns, * doesn't cross path separators
                    regex.push_str("[^/]*");
                } else {
                    // For non-path patterns (like *sudo*), * matches anything
                    regex.push_str(".*");
                }
                i += 1;
            }
        } else if c == '?' {
            // ? matches any single character
            regex.push('.');
            i += 1;
        } else {
            // Escape regex metacharacters
            if is_regex_metachar(c) {
                regex.push('\\');
            }
            regex.push(c);
            i += 1;
        }
    }

    regex.push('$');

    Regex::new(&regex).map_err(|e| PatternError::InvalidRegex {
        pattern: glob.to_string(),
        reason: e.to_string(),
    })
}

fn is_regex_metachar(c: char) -> bool {
    matches!(
        c,
        '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$' | '\\'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_pattern() {
        let p = compile_pattern("eval").unwrap();
        assert!(p.matches("eval"));
        assert!(!p.matches("evaluate"));
        assert!(!p.matches("myeval"));
        assert!(!p.matches("Eval"));
    }

    #[test]
    fn test_glob_star() {
        let p = compile_pattern("fs.*").unwrap();
        assert!(p.matches("fs.readFile"));
        assert!(p.matches("fs.writeFile"));
        assert!(p.matches("fs."));
        assert!(!p.matches("http.request"));
        assert!(!p.matches("fs"));
    }

    #[test]
    fn test_glob_double_star() {
        let p = compile_pattern("/app/**/*.py").unwrap();
        assert!(p.matches("/app/src/main.py"));
        assert!(p.matches("/app/src/lib/util.py"));
        assert!(p.matches("/app/test.py"));
        assert!(!p.matches("/other/test.py"));
    }

    #[test]
    fn test_glob_question_mark() {
        let p = compile_pattern("file?.txt").unwrap();
        assert!(p.matches("file1.txt"));
        assert!(p.matches("fileA.txt"));
        assert!(!p.matches("file12.txt"));
        assert!(!p.matches("file.txt"));
    }

    #[test]
    fn test_regex_pattern() {
        let p = compile_pattern("regex:^AWS_").unwrap();
        assert!(p.matches("AWS_ACCESS_KEY"));
        assert!(p.matches("AWS_SECRET"));
        assert!(!p.matches("MY_AWS_KEY"));
    }

    #[test]
    fn test_case_insensitive_exact() {
        let p = compile_pattern_case_insensitive("ONION").unwrap();
        assert!(p.matches_ignore_case("onion"));
        assert!(p.matches_ignore_case("ONION"));
        assert!(p.matches_ignore_case("Onion"));
    }

    #[test]
    fn test_case_insensitive_glob() {
        let p = compile_pattern_case_insensitive("*.ONION").unwrap();
        assert!(p.matches("test.onion"));
        assert!(p.matches("TEST.ONION"));
        assert!(p.matches("Test.Onion"));
    }

    #[test]
    fn test_endpoint_patterns() {
        let p1 = compile_pattern("127.0.0.1:*").unwrap();
        assert!(p1.matches("127.0.0.1:8080"));
        assert!(p1.matches("127.0.0.1:443"));
        assert!(!p1.matches("192.168.1.1:8080"));

        let p2 = compile_pattern("*:443").unwrap();
        assert!(p2.matches("example.com:443"));
        assert!(!p2.matches("example.com:80"));
    }

    #[test]
    fn test_invalid_regex() {
        let result = compile_pattern("regex:[invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_special_chars_escaped() {
        let p = compile_pattern("os.path.join").unwrap();
        assert!(p.matches("os.path.join"));
        assert!(!p.matches("os_path_join"));
    }
}
