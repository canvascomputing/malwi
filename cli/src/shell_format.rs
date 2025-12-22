//! Shell command formatting utilities.
//!
//! Converts argv arrays to human-readable shell command lines with proper quoting.

/// Characters that require quoting in shell arguments.
const SHELL_SPECIAL_CHARS: &[char] = &[
    ' ', '\t', '\n', '"', '\'', '\\', '$', '`', '!', '*', '?', '[', ']', '#', '~', '=', '%', '|',
    '&', ';', '<', '>', '(', ')', '{', '}', '^',
];

/// Format an argv array as a shell command line with proper quoting.
///
/// # Arguments
/// * `args` - The argument vector to format
/// * `max_length` - Maximum length before truncation
///
/// # Returns
/// A string representation of the command suitable for display.
pub fn format_shell_command(args: &[String], max_length: usize) -> String {
    if args.is_empty() {
        return String::new();
    }

    let parts: Vec<String> = args.iter().map(|arg| quote_shell_arg(arg)).collect();
    let full = parts.join(" ");

    if full.len() > max_length {
        format!("{}...", &full[..max_length.saturating_sub(3)])
    } else {
        full
    }
}

/// Quote a single shell argument if needed.
///
/// Rules:
/// - Empty string → ''
/// - No special chars → use as-is
/// - Contains spaces/special but no single quotes → wrap in single quotes
/// - Contains single quotes → use double quotes with escaping
fn quote_shell_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }

    // Check if quoting is needed
    let needs_quoting = arg.chars().any(|c| SHELL_SPECIAL_CHARS.contains(&c));

    if !needs_quoting {
        return arg.to_string();
    }

    // Prefer single quotes if the argument doesn't contain them
    if !arg.contains('\'') {
        return format!("'{}'", arg);
    }

    // Use double quotes with escaping for special characters
    let escaped: String = arg
        .chars()
        .map(|c| match c {
            '"' | '\\' | '$' | '`' => format!("\\{}", c),
            _ => c.to_string(),
        })
        .collect();

    format!("\"{}\"", escaped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quote_shell_arg_simple() {
        assert_eq!(quote_shell_arg("curl"), "curl");
        assert_eq!(quote_shell_arg("--version"), "--version");
        assert_eq!(quote_shell_arg("-X"), "-X");
    }

    #[test]
    fn test_quote_shell_arg_with_spaces() {
        assert_eq!(quote_shell_arg("hello world"), "'hello world'");
        assert_eq!(quote_shell_arg("foo bar baz"), "'foo bar baz'");
    }

    #[test]
    fn test_quote_shell_arg_with_special_chars() {
        assert_eq!(quote_shell_arg("$HOME"), "'$HOME'");
        assert_eq!(quote_shell_arg("*.txt"), "'*.txt'");
        assert_eq!(quote_shell_arg("a=b"), "'a=b'");
    }

    #[test]
    fn test_quote_shell_arg_with_single_quotes() {
        assert_eq!(quote_shell_arg("it's"), "\"it's\"");
        assert_eq!(quote_shell_arg("don't"), "\"don't\"");
    }

    #[test]
    fn test_quote_shell_arg_with_double_quotes() {
        assert_eq!(quote_shell_arg(r#"say "hello""#), r#"'say "hello"'"#);
    }

    #[test]
    fn test_quote_shell_arg_json() {
        assert_eq!(
            quote_shell_arg(r#"{"key": "value"}"#),
            r#"'{"key": "value"}'"#
        );
    }

    #[test]
    fn test_quote_shell_arg_empty() {
        assert_eq!(quote_shell_arg(""), "''");
    }

    #[test]
    fn test_format_shell_command_simple() {
        let args: Vec<String> = vec!["curl".into(), "--version".into()];
        assert_eq!(format_shell_command(&args, 200), "curl --version");
    }

    #[test]
    fn test_format_shell_command_with_args() {
        let args: Vec<String> = vec![
            "curl".into(),
            "-X".into(),
            "POST".into(),
            "https://example.com".into(),
            "--data".into(),
            r#"{"key": "value"}"#.into(),
        ];
        assert_eq!(
            format_shell_command(&args, 200),
            "curl -X POST https://example.com --data '{\"key\": \"value\"}'"
        );
    }

    #[test]
    fn test_format_shell_command_truncation() {
        let args: Vec<String> = vec![
            "curl".into(),
            "-X".into(),
            "POST".into(),
            "https://very-long-domain-name-example.com/api/v1/endpoint".into(),
        ];
        let result = format_shell_command(&args, 30);
        assert!(result.len() <= 30);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_format_shell_command_empty() {
        let args: Vec<String> = vec![];
        assert_eq!(format_shell_command(&args, 200), "");
    }
}
