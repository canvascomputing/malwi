//! Command taxonomy — single source of truth for command classification.
//!
//! Parses per-category command files (embedded at compile time) into a cached
//! `Taxonomy` struct. Provides `lookup()` for command category queries.
//!
//! Each category has a shared file and optional OS-specific files
//! (`_macos.yaml`, `_linux.yaml`) compiled in via `#[cfg(target_os)]`.

use std::collections::HashMap;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Primary behavioral category (determines triage engine routing).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Category {
    Safe,
    Build,
    Text,
    Package,
    FileOperation,
    Threat,
}

/// Node.js file function prefix (not worth a YAML file for a single value).
pub const NODEJS_FILE_PREFIX: &str = "fs.";

/// Parsed taxonomy data (shared + current-OS commands merged).
pub struct Taxonomy {
    commands: HashMap<String, Category>,
}

impl Taxonomy {
    /// Look up a command by basename.
    pub fn lookup(&self, name: &str) -> Option<&Category> {
        self.commands.get(name)
    }
}

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

static TAXONOMY: OnceLock<Taxonomy> = OnceLock::new();

/// Get the parsed taxonomy (lazy-initialized on first call).
pub fn get() -> &'static Taxonomy {
    TAXONOMY.get_or_init(build_taxonomy)
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

fn unquote(s: &str) -> String {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Parse a flat command list. Skips empty lines and comments.
fn parse_command_list(raw: &str) -> Vec<String> {
    raw.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.strip_prefix("- "))
        .map(|l| unquote(l.trim()))
        .filter(|l| !l.is_empty())
        .collect()
}

/// Build the taxonomy from per-category flat files.
fn build_taxonomy() -> Taxonomy {
    let mut commands = HashMap::new();

    let mut sources: Vec<(Category, &str)> = vec![
        (Category::Safe, include_str!("commands_safe.yaml")),
        (Category::Build, include_str!("commands_build.yaml")),
        (Category::Text, include_str!("commands_text.yaml")),
        (Category::Package, include_str!("commands_package.yaml")),
        (
            Category::FileOperation,
            include_str!("commands_file_operation.yaml"),
        ),
        (Category::Threat, include_str!("commands_threat.yaml")),
    ];

    #[cfg(target_os = "macos")]
    sources.extend([
        (Category::Safe, include_str!("commands_safe_macos.yaml")),
        (Category::Build, include_str!("commands_build_macos.yaml")),
        (
            Category::Package,
            include_str!("commands_package_macos.yaml"),
        ),
        (
            Category::FileOperation,
            include_str!("commands_file_operation_macos.yaml"),
        ),
        (Category::Threat, include_str!("commands_threat_macos.yaml")),
    ]);

    #[cfg(target_os = "linux")]
    sources.extend([
        (Category::Safe, include_str!("commands_safe_linux.yaml")),
        (
            Category::Package,
            include_str!("commands_package_linux.yaml"),
        ),
        (Category::Threat, include_str!("commands_threat_linux.yaml")),
    ]);

    for (category, raw) in &sources {
        for cmd in parse_command_list(raw) {
            commands.insert(cmd, *category);
        }
    }

    Taxonomy { commands }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_parses_clean() {
        let _tax = get();
    }

    #[test]
    fn lookup_safe_commands() {
        let tax = get();
        assert_eq!(tax.lookup("echo").unwrap(), &Category::Safe);
        assert_eq!(tax.lookup("ls").unwrap(), &Category::Safe);
        assert_eq!(tax.lookup("whoami").unwrap(), &Category::Safe);
    }

    #[test]
    fn lookup_build_commands() {
        let tax = get();
        assert_eq!(tax.lookup("make").unwrap(), &Category::Build);
        assert_eq!(tax.lookup("gcc").unwrap(), &Category::Build);
        assert_eq!(tax.lookup("rustc").unwrap(), &Category::Build);
    }

    #[test]
    fn lookup_text_commands() {
        let tax = get();
        assert_eq!(tax.lookup("grep").unwrap(), &Category::Text);
        assert_eq!(tax.lookup("sed").unwrap(), &Category::Text);
        assert_eq!(tax.lookup("jq").unwrap(), &Category::Text);
    }

    #[test]
    fn lookup_package_commands() {
        let tax = get();
        assert_eq!(tax.lookup("git").unwrap(), &Category::Package);
        assert_eq!(tax.lookup("npm").unwrap(), &Category::Package);
        assert_eq!(tax.lookup("cargo").unwrap(), &Category::Package);
    }

    #[test]
    fn lookup_file_operation_commands() {
        let tax = get();
        assert_eq!(tax.lookup("cat").unwrap(), &Category::FileOperation);
        assert_eq!(tax.lookup("cp").unwrap(), &Category::FileOperation);
        assert_eq!(tax.lookup("tar").unwrap(), &Category::FileOperation);
    }

    #[test]
    fn lookup_threat_commands() {
        let tax = get();
        assert_eq!(tax.lookup("curl").unwrap(), &Category::Threat);
        assert_eq!(tax.lookup("python").unwrap(), &Category::Threat);
        assert_eq!(tax.lookup("sudo").unwrap(), &Category::Threat);
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let tax = get();
        assert!(tax.lookup("nonexistent_command_xyz").is_none());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_commands_merged() {
        let tax = get();
        assert_eq!(tax.lookup("sw_vers").unwrap(), &Category::Safe);
        assert_eq!(tax.lookup("osascript").unwrap(), &Category::Threat);
        assert_eq!(tax.lookup("brew").unwrap(), &Category::Package);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_commands_merged() {
        let tax = get();
        assert_eq!(tax.lookup("lsb_release").unwrap(), &Category::Safe);
        assert_eq!(tax.lookup("systemctl").unwrap(), &Category::Threat);
        assert_eq!(tax.lookup("apt").unwrap(), &Category::Package);
    }

    #[test]
    fn no_duplicate_names() {
        // Verify no command appears in multiple category files.
        // Include ALL OS variants unconditionally for this check.
        let all_sources: &[(&str, &str)] = &[
            ("safe", include_str!("commands_safe.yaml")),
            ("safe", include_str!("commands_safe_macos.yaml")),
            ("safe", include_str!("commands_safe_linux.yaml")),
            ("build", include_str!("commands_build.yaml")),
            ("build", include_str!("commands_build_macos.yaml")),
            ("text", include_str!("commands_text.yaml")),
            ("package", include_str!("commands_package.yaml")),
            ("package", include_str!("commands_package_macos.yaml")),
            ("package", include_str!("commands_package_linux.yaml")),
            (
                "file_operation",
                include_str!("commands_file_operation.yaml"),
            ),
            (
                "file_operation",
                include_str!("commands_file_operation_macos.yaml"),
            ),
            ("threat", include_str!("commands_threat.yaml")),
            ("threat", include_str!("commands_threat_macos.yaml")),
            ("threat", include_str!("commands_threat_linux.yaml")),
        ];

        let mut seen: HashMap<String, &str> = HashMap::new();
        for (cat_name, raw) in all_sources {
            for cmd in parse_command_list(raw) {
                if let Some(existing_cat) = seen.get(&cmd) {
                    if existing_cat != cat_name {
                        panic!(
                            "command '{}' appears in both '{}' and '{}'",
                            cmd, existing_cat, cat_name
                        );
                    }
                }
                seen.insert(cmd, cat_name);
            }
        }
    }

    #[test]
    fn http_functions_present() {
        let py = super::super::http_functions_python();
        assert!(py.contains(&"requests.get".to_string()));
        assert!(py.contains(&"urllib.request.urlopen".to_string()));
        let js = super::super::http_functions_nodejs();
        assert!(js.contains(&"http.request".to_string()));
        assert!(js.contains(&"fetch".to_string()));
    }

    #[test]
    fn file_functions_present() {
        let py = super::super::file_functions_python();
        assert!(py.contains(&"open".to_string()));
        assert!(py.contains(&"builtins.open".to_string()));
        assert!(py.contains(&"io.open".to_string()));
        assert_eq!(NODEJS_FILE_PREFIX, "fs.");
        let native = super::super::file_functions_native();
        assert!(native.contains(&"open".to_string()));
        assert!(native.contains(&"openat".to_string()));
    }

    #[test]
    fn parse_command_list_skips_comments() {
        let raw = "# header comment\n- cmd_a\n# another comment\n- cmd_b\n";
        let result = parse_command_list(raw);
        assert_eq!(result, vec!["cmd_a", "cmd_b"]);
    }

    #[test]
    fn parse_command_list_unquotes() {
        let raw = "- \"true\"\n- '['\n- plain\n";
        let result = parse_command_list(raw);
        assert_eq!(result, vec!["true", "[", "plain"]);
    }
}
