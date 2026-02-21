//! Auto-detection of command-specific policies.
//!
//! When the user runs a known package-management command (e.g. `npm install`,
//! `pip install`), this module detects it from argv and ensures the
//! corresponding policy template exists on disk.

use std::path::{Path, PathBuf};

use anyhow::Result;

/// A path-based confirmation pattern.
enum PathPattern {
    /// Any argv arg's full path contains this substring (case-insensitive).
    Contains(&'static str),
    /// The first `.py` arg has this file in the same directory.
    Sibling(&'static str),
}

/// A rule that matches a program + argument combination to a policy.
struct DetectionRule {
    /// Basename(s) to match in argv (e.g. "npm", "pip").
    programs: &'static [&'static str],
    /// Additional arg basenames that must appear (e.g. "install", "comfy").
    /// Empty means the program alone is sufficient.
    command_patterns: &'static [&'static str],
    /// Path-based confirmation. When non-empty, takes priority over `command_patterns`:
    /// if any pattern matches the rule succeeds; if none match the rule is skipped.
    path_patterns: &'static [PathPattern],
    /// Optional extra check run after program + command_patterns match.
    /// Return true to accept the match, false to skip this rule.
    extra_check: Option<fn(&[String]) -> bool>,
    /// Policy filename stem (e.g. "npm-install").
    policy_name: &'static str,
}

static RULES: &[DetectionRule] = &[
    DetectionRule {
        programs: &["npm"],
        command_patterns: &["install", "add", "ci"],
        path_patterns: &[],
        extra_check: None,
        policy_name: "npm-install",
    },
    DetectionRule {
        programs: &["pip", "pip3"],
        command_patterns: &["install"],
        path_patterns: &[],
        extra_check: None,
        policy_name: "pip-install",
    },
    // ComfyUI via python — confirmed by path keyword or sibling file
    DetectionRule {
        programs: &["python", "python3"],
        command_patterns: &[],
        path_patterns: &[
            PathPattern::Contains("comfyui"),
            PathPattern::Sibling("comfyui_version.py"),
        ],
        extra_check: None,
        policy_name: "comfyui",
    },
    // ComfyUI via `python -m comfy`
    DetectionRule {
        programs: &["python", "python3"],
        command_patterns: &["comfy"],
        path_patterns: &[],
        extra_check: None,
        policy_name: "comfyui",
    },
    // ComfyUI standalone binary
    DetectionRule {
        programs: &["comfyui"],
        command_patterns: &[],
        path_patterns: &[],
        extra_check: None,
        policy_name: "comfyui",
    },
    // openclaw — direct binary invocation
    DetectionRule {
        programs: &["openclaw"],
        command_patterns: &[],
        path_patterns: &[],
        extra_check: None,
        policy_name: "openclaw",
    },
    // openclaw via node — confirmed by path keyword
    DetectionRule {
        programs: &["node"],
        command_patterns: &[],
        path_patterns: &[PathPattern::Contains("openclaw")],
        extra_check: None,
        policy_name: "openclaw",
    },
    // openclaw.mjs — direct script invocation
    DetectionRule {
        programs: &["openclaw.mjs"],
        command_patterns: &[],
        path_patterns: &[],
        extra_check: None,
        policy_name: "openclaw",
    },
    // bash/sh — install scripts only (not interactive shells).
    // Matches: bash -c "...", bash script.sh, piped stdin.
    // Does NOT match bare `bash` or `bash -i` (interactive REPL).
    // Placed last so more specific rules (npm, pip, comfyui) match first.
    DetectionRule {
        programs: &["bash", "sh"],
        command_patterns: &[],
        path_patterns: &[],
        extra_check: Some(is_bash_non_interactive),
        policy_name: "bash-install",
    },
];

/// Scan the full argv and return the first matching policy name, or None.
pub(crate) fn detect_policy(program: &[String]) -> Option<&'static str> {
    // Compute basenames once.
    let basenames: Vec<&str> = program
        .iter()
        .map(|arg| {
            Path::new(arg)
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or(arg)
        })
        .collect();

    for rule in RULES {
        let has_program = basenames.iter().any(|b| rule.programs.contains(b));
        if !has_program {
            continue;
        }

        // Path patterns take priority: if specified, they alone decide the match.
        if !rule.path_patterns.is_empty() {
            if check_path_patterns(program, rule.path_patterns) {
                return Some(rule.policy_name);
            }
            continue;
        }

        // Otherwise match on arg basenames.
        let has_args = rule.command_patterns.is_empty()
            || basenames.iter().any(|b| rule.command_patterns.contains(b));
        if !has_args {
            continue;
        }

        // Run extra check if specified.
        if let Some(check) = rule.extra_check {
            if !check(program) {
                continue;
            }
        }

        return Some(rule.policy_name);
    }
    None
}

/// Check whether bash/sh is being run non-interactively (i.e. running a script).
/// Returns true for: `bash -c "..."`, `bash script.sh`, piped stdin.
/// Returns false for: bare `bash` (TTY), `bash -i`, `bash --norc` (interactive REPL).
fn is_bash_non_interactive(argv: &[String]) -> bool {
    // Skip argv[0] (the bash binary itself).
    let args = if argv.len() > 1 { &argv[1..] } else { &[] };

    // Has `-c` flag → inline script
    if args.iter().any(|a| a == "-c") {
        return true;
    }

    // Has a non-flag argument → script file
    for arg in args {
        if arg == "--" {
            // `--` ends options; anything after is a script name
            return true;
        }
        if !arg.starts_with('-') {
            return true;
        }
    }

    // Explicit `-i` flag → interactive shell, even if stdin is piped
    if args.iter().any(|a| a == "-i") {
        return false;
    }

    // Stdin is piped → script via stdin (e.g. curl ... | malwi x bash)
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return true;
    }

    false
}

/// Ensure the auto-policy YAML file exists on disk and return its path.
///
/// On first detection the embedded template is written to
/// `~/.config/malwi/policies/<name>.yaml`. Subsequent runs reuse the
/// file (the user may have customised it).
pub(crate) fn ensure_auto_policy(name: &str) -> Result<PathBuf> {
    let dir = super::config::policies_dir()?;
    let path = dir.join(format!("{}.yaml", name));

    if !path.exists() {
        let yaml = super::templates::embedded_policy(name)
            .ok_or_else(|| anyhow::anyhow!("No embedded policy template for '{}'", name))?;
        std::fs::write(&path, &yaml)?;
    }

    Ok(path)
}

/// Check whether any path pattern matches against argv.
fn check_path_patterns(argv: &[String], patterns: &[PathPattern]) -> bool {
    patterns.iter().any(|p| p.matches(argv))
}

impl PathPattern {
    fn matches(&self, argv: &[String]) -> bool {
        match self {
            PathPattern::Contains(keyword) => argv
                .iter()
                .any(|arg| arg.to_ascii_lowercase().contains(keyword)),
            PathPattern::Sibling(filename) => argv.iter().any(|arg| {
                let dir = Path::new(arg).parent().unwrap_or(Path::new("."));
                let dir = if dir.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    dir
                };
                dir.join(filename).exists()
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::templates::embedded_policy;
    use super::*;

    #[test]
    fn test_detect_npm_install() {
        assert_eq!(
            detect_policy(&strs(&["npm", "install", "react"])),
            Some("npm-install"),
        );
    }

    #[test]
    fn test_detect_npm_add() {
        assert_eq!(
            detect_policy(&strs(&["npm", "add", "lodash"])),
            Some("npm-install"),
        );
    }

    #[test]
    fn test_detect_npm_ci() {
        assert_eq!(detect_policy(&strs(&["npm", "ci"])), Some("npm-install"),);
    }

    #[test]
    fn test_detect_pip_install() {
        assert_eq!(
            detect_policy(&strs(&["pip", "install", "flask"])),
            Some("pip-install"),
        );
    }

    #[test]
    fn test_detect_pip3_install() {
        assert_eq!(
            detect_policy(&strs(&["/usr/bin/pip3", "install", "flask"])),
            Some("pip-install"),
        );
    }

    #[test]
    fn test_detect_python_m_pip_install() {
        assert_eq!(
            detect_policy(&strs(&["python3", "-m", "pip", "install", "six"])),
            Some("pip-install"),
        );
    }

    #[test]
    fn test_detect_no_match() {
        assert_eq!(detect_policy(&strs(&["node", "server.js"])), None);
    }

    #[test]
    fn test_detect_npm_run_no_match() {
        assert_eq!(detect_policy(&strs(&["npm", "run", "build"])), None);
    }

    #[test]
    fn test_detect_pip_without_subcommand() {
        assert_eq!(detect_policy(&strs(&["pip", "freeze"])), None);
    }

    #[test]
    fn test_detect_empty_argv() {
        assert_eq!(detect_policy(&strs(&[])), None);
    }

    fn test_tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("malwi_test_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_detect_comfyui_python_main_py() {
        let dir = test_tempdir("comfyui_main");
        std::fs::write(dir.join("main.py"), "").unwrap();
        std::fs::write(dir.join("comfyui_version.py"), "").unwrap();
        let main_py = dir.join("main.py").to_str().unwrap().to_string();
        assert_eq!(
            detect_policy(&[String::from("python"), main_py]),
            Some("comfyui"),
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_detect_python_main_no_siblings() {
        let dir = test_tempdir("no_siblings");
        std::fs::write(dir.join("main.py"), "").unwrap();
        let main_py = dir.join("main.py").to_str().unwrap().to_string();
        assert_eq!(detect_policy(&[String::from("python"), main_py]), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_detect_comfyui_python_m_comfy() {
        assert_eq!(
            detect_policy(&strs(&["python3", "-m", "comfy", "--port", "8188"])),
            Some("comfyui"),
        );
    }

    #[test]
    fn test_detect_comfyui_standalone() {
        assert_eq!(
            detect_policy(&strs(&["comfyui", "--listen"])),
            Some("comfyui"),
        );
    }

    #[test]
    fn test_pip_install_comfyui_matches_pip() {
        assert_eq!(
            detect_policy(&strs(&["pip", "install", "comfyui"])),
            Some("pip-install"),
        );
    }

    #[test]
    fn test_detect_comfyui_path_keyword() {
        assert_eq!(
            detect_policy(&[String::from("python"), String::from("/tmp/ComfyUI/main.py"),]),
            Some("comfyui"),
        );
    }

    #[test]
    fn test_detect_comfyui_path_keyword_case_insensitive() {
        assert_eq!(
            detect_policy(&[
                String::from("python"),
                String::from("/home/user/comfyui/run.py"),
            ]),
            Some("comfyui"),
        );
    }

    #[test]
    fn test_detect_no_false_positive_path() {
        assert_eq!(
            detect_policy(&[String::from("python"), String::from("/tmp/other/main.py"),]),
            None,
        );
    }

    /// Helper to convert &[&str] to Vec<String>.
    fn strs(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    // =====================================================================
    // bash-install detection tests
    // =====================================================================

    #[test]
    fn test_detect_bash_install_bare_bash_depends_on_stdin() {
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() {
            assert_eq!(detect_policy(&strs(&["bash"])), None);
        } else {
            assert_eq!(detect_policy(&strs(&["bash"])), Some("bash-install"));
        }
    }

    #[test]
    fn test_detect_bash_install_bare_sh_depends_on_stdin() {
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() {
            assert_eq!(detect_policy(&strs(&["sh"])), None);
        } else {
            assert_eq!(detect_policy(&strs(&["sh"])), Some("bash-install"));
        }
    }

    #[test]
    fn test_detect_bash_install_with_script() {
        assert_eq!(
            detect_policy(&strs(&["bash", "install.sh"])),
            Some("bash-install"),
        );
    }

    #[test]
    fn test_detect_bash_install_with_c_flag() {
        assert_eq!(
            detect_policy(&strs(&["bash", "-c", "echo test"])),
            Some("bash-install"),
        );
    }

    #[test]
    fn test_detect_bash_install_with_flags_and_script() {
        assert_eq!(
            detect_policy(&strs(&["bash", "--norc", "install.sh"])),
            Some("bash-install"),
        );
    }

    #[test]
    fn test_detect_bash_interactive_flag_only() {
        assert_eq!(detect_policy(&strs(&["bash", "-i"])), None);
    }

    // =====================================================================
    // openclaw detection tests
    // =====================================================================

    #[test]
    fn test_detect_openclaw_direct_binary() {
        assert_eq!(
            detect_policy(&strs(&["openclaw", "gateway"])),
            Some("openclaw"),
        );
    }

    #[test]
    fn test_detect_openclaw_mjs() {
        assert_eq!(
            detect_policy(&strs(&["openclaw.mjs", "doctor"])),
            Some("openclaw"),
        );
    }

    #[test]
    fn test_detect_openclaw_node_with_path() {
        assert_eq!(
            detect_policy(&[
                String::from("node"),
                String::from("/usr/local/lib/node_modules/openclaw/dist/openclaw.mjs"),
            ]),
            Some("openclaw"),
        );
    }

    #[test]
    fn test_detect_openclaw_npm_install_priority() {
        assert_eq!(
            detect_policy(&strs(&["npm", "install", "openclaw"])),
            Some("npm-install"),
        );
    }

    #[test]
    fn test_detect_openclaw_no_false_positive() {
        assert_eq!(detect_policy(&strs(&["node", "server.js"])), None,);
    }
}
