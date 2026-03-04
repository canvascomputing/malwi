//! Shared formatting utilities for tracing output.
//!
//! Provides common string truncation and display formatting functions
//! used by native, Python, and V8 argument formatters.

/// Truncate a string to max length, appending "..." if truncated.
///
/// # Arguments
/// * `s` - The string to truncate
/// * `max` - Maximum length (including the "..." suffix)
///
/// # Returns
/// The original string if <= max, otherwise truncated with "..." suffix.
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

/// Truncate a string with a custom suffix.
///
/// # Arguments
/// * `s` - The string to truncate
/// * `max` - Maximum total length (including suffix)
/// * `suffix` - The suffix to append if truncated (default: "...")
pub fn truncate_with_suffix(s: &str, max: usize, suffix: &str) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let content_len = max.saturating_sub(suffix.len());
        format!("{}{}", &s[..content_len], suffix)
    }
}

/// Truncate display string, preserving quotes if present.
///
/// Useful for truncating Python/JS repr strings that have quotes.
///
/// # Arguments
/// * `s` - The string to truncate
/// * `max` - Maximum length (including any quotes and "..." suffix)
pub fn truncate_display(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

/// Truncate URL for display.
///
/// Cleans up surrounding quotes and truncates if needed.
pub fn truncate_url(url: &str, max: usize) -> String {
    let clean = url.trim_matches('\'').trim_matches('"');
    if clean.len() > max {
        format!("'{}'...", &clean[..max.saturating_sub(5)])
    } else {
        url.to_string()
    }
}

/// Truncate data/bytes preview for display.
pub fn truncate_data_preview(data: &str, max: usize) -> String {
    if data.len() > max {
        format!("{}...", &data[..max])
    } else {
        data.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_short_string() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_long_string() {
        assert_eq!(truncate("hello world", 8), "hello...");
        assert_eq!(truncate("abcdefghij", 7), "abcd...");
    }

    #[test]
    fn test_truncate_with_suffix() {
        assert_eq!(truncate_with_suffix("hello", 10, "..."), "hello");
        assert_eq!(truncate_with_suffix("hello world", 8, "..."), "hello...");
        assert_eq!(
            truncate_with_suffix("hello world", 10, "[truncated]"),
            "[truncated]"
        );
    }

    #[test]
    fn test_truncate_url() {
        assert_eq!(
            truncate_url("'https://example.com'", 100),
            "'https://example.com'"
        );
        // max=25, overhead=5 ('...'), content=20 chars
        assert_eq!(
            truncate_url("'https://example.com/very/long/path'", 25),
            "'https://example.com/'..."
        );
    }
}
