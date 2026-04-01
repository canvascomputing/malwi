//! Shared utilities for policy evaluation.

use malwi_protocol::event::TraceEvent;

/// Networking native symbols that should be deferred from the functions
/// phase to the network phase when network policy rules exist.
///
/// This prevents socket() (which has no destination info yet) from being
/// blocked by a functions deny-all, while letting connect() be blocked
/// by the network phase using actual destination info.
pub const NETWORKING_SYMBOLS: &[&str] = &[
    "socket",
    "connect",
    "sendto",
    "send",
    "bind",
    "listen",
    "accept",
    "accept4",
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname2",
];

/// Check if a native function name is a networking symbol.
pub fn is_networking_symbol(name: &str) -> bool {
    NETWORKING_SYMBOLS.contains(&name)
}

/// Extract a file path from a trace event's first argument.
/// Strips surrounding quotes from native hook argument formatting.
pub fn extract_file_path(event: &TraceEvent) -> Option<String> {
    event
        .arguments
        .first()
        .and_then(|a| a.display.as_deref())
        .map(|s| s.trim_matches('"').trim_matches('\'').to_string())
}

/// Convert an absolute path to tilde notation (e.g. /Users/mav/.ssh → ~/.ssh).
/// Returns None if HOME is not set or the path is not under HOME.
pub fn to_tilde_path(path: &str) -> Option<String> {
    use std::sync::OnceLock;
    static HOME: OnceLock<Option<String>> = OnceLock::new();
    let home = HOME.get_or_init(|| std::env::var("HOME").ok());
    let home = home.as_deref()?;
    path.strip_prefix(home).map(|rest| format!("~{rest}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_networking_symbol() {
        assert!(is_networking_symbol("connect"));
        assert!(is_networking_symbol("socket"));
        assert!(is_networking_symbol("getaddrinfo"));
        assert!(!is_networking_symbol("open"));
        assert!(!is_networking_symbol("malloc"));
    }

    #[test]
    fn test_to_tilde_path() {
        let home = std::env::var("HOME").unwrap();
        let path = format!("{home}/.ssh/id_rsa");
        assert_eq!(to_tilde_path(&path), Some("~/.ssh/id_rsa".into()));
        assert_eq!(to_tilde_path("/tmp/foo"), None);
    }
}
