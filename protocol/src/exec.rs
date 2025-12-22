//! Utilities for exec command analysis.

/// Known shell basenames that wrap commands via `-c`.
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh"];

/// If argv represents a shell wrapper (e.g. `["sh", "-c", "curl ..."]`),
/// return the underlying command name. Otherwise return `None`.
pub fn unwrap_shell_command(argv: &[String]) -> Option<&str> {
    let basename = std::path::Path::new(&argv[0]).file_name()?.to_str()?;
    if !SHELLS.contains(&basename) {
        return None;
    }
    // Find "-c" flag; the command string follows it
    let c_idx = argv.iter().position(|a| a == "-c")?;
    let cmd_str = argv.get(c_idx + 1)?;
    // First word of the -c argument is the command
    let cmd = cmd_str.split_whitespace().next()?;
    // Return basename in case it's a path like /usr/bin/curl
    std::path::Path::new(cmd).file_name()?.to_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unwrap_sh_c_curl() {
        let argv: Vec<String> = vec!["sh".into(), "-c".into(), "curl -s https://example.com".into()];
        assert_eq!(unwrap_shell_command(&argv), Some("curl"));
    }

    #[test]
    fn test_unwrap_bash_c_full_path() {
        let argv: Vec<String> = vec![
            "/bin/bash".into(),
            "-c".into(),
            "/usr/bin/curl -s https://example.com".into(),
        ];
        assert_eq!(unwrap_shell_command(&argv), Some("curl"));
    }

    #[test]
    fn test_no_unwrap_direct_command() {
        let argv: Vec<String> = vec!["curl".into(), "-s".into(), "https://example.com".into()];
        assert_eq!(unwrap_shell_command(&argv), None);
    }

    #[test]
    fn test_no_unwrap_interactive_shell() {
        let argv: Vec<String> = vec!["sh".into()];
        assert_eq!(unwrap_shell_command(&argv), None);
    }

    #[test]
    fn test_unwrap_zsh_c() {
        let argv: Vec<String> = vec!["zsh".into(), "-c".into(), "wget http://example.com".into()];
        assert_eq!(unwrap_shell_command(&argv), Some("wget"));
    }

    #[test]
    fn test_unwrap_dash_c() {
        let argv: Vec<String> = vec!["/bin/dash".into(), "-c".into(), "ls -la".into()];
        assert_eq!(unwrap_shell_command(&argv), Some("ls"));
    }

    #[test]
    fn test_no_unwrap_shell_without_c_flag() {
        let argv: Vec<String> = vec!["bash".into(), "--login".into()];
        assert_eq!(unwrap_shell_command(&argv), None);
    }

    #[test]
    fn test_unwrap_empty_c_arg() {
        let argv: Vec<String> = vec!["sh".into(), "-c".into(), "".into()];
        assert_eq!(unwrap_shell_command(&argv), None);
    }

    #[test]
    fn test_unwrap_c_missing_value() {
        let argv: Vec<String> = vec!["sh".into(), "-c".into()];
        assert_eq!(unwrap_shell_command(&argv), None);
    }
}
