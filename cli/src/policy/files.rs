//! File access policy evaluation — checks file paths against the `files:` policy section.

use super::active::{decision_to_disposition, pick_stricter, ActivePolicy, EventDisposition};
use crate::policy::{Category, SectionKey};
use malwi_intercept::{HookType, TraceEvent};

/// Check if a Python or Node.js function is a known file-access function.
/// Sources from `file_functions_python.yaml` and `NODEJS_FILE_PREFIX`.
fn is_runtime_file_func(hook_type: &HookType, function: &str) -> bool {
    match *hook_type {
        HookType::Python => super::templates::file_functions_python()
            .iter()
            .any(|f| f == function),
        HookType::Nodejs => function.starts_with(super::templates::taxonomy::NODEJS_FILE_PREFIX),
        _ => false,
    }
}

/// Convert absolute path to ~/... form if under user's home directory.
fn to_tilde_path(path: &str) -> Option<String> {
    static HOME: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    let home = HOME.get_or_init(|| std::env::var("HOME").ok());
    let home = home.as_deref()?;
    path.strip_prefix(home).map(|rest| format!("~{rest}"))
}

impl ActivePolicy {
    /// Evaluate file access against the `files:` policy section.
    ///
    /// Three paths:
    /// - Exec/Bash events: check command arguments for file paths
    /// - Native open/openat: extract the path from the call arguments
    /// - Python/Node.js: check known file functions for path in first argument
    pub(super) fn evaluate_file_phase(
        &self,
        event: &TraceEvent,
        disp: EventDisposition,
    ) -> EventDisposition {
        match event.hook_type {
            HookType::Exec | HookType::Bash => self.evaluate_file_args_from_exec(event, disp),
            HookType::Native => self.evaluate_file_from_native(event, disp),
            HookType::Python | HookType::Nodejs => self.evaluate_file_from_runtime(event, disp),
            _ => disp,
        }
    }

    /// Evaluate a file path against the files: policy section.
    /// Checks both the normalized path and the ~/... form.
    fn check_file_path(&self, path: &str) -> EventDisposition {
        let normalized = normalize_path(path);
        let decision = self.engine.evaluate_file(&normalized);
        let disp = decision_to_disposition(decision);
        if disp.should_display() {
            return disp;
        }
        if let Some(tilde) = to_tilde_path(&normalized) {
            let decision = self.engine.evaluate_file(&tilde);
            let d = decision_to_disposition(decision);
            if d.should_display() {
                return d;
            }
        }
        disp
    }

    /// Check command arguments for file paths (covers SIP-protected binaries).
    fn evaluate_file_args_from_exec(
        &self,
        event: &TraceEvent,
        disp: EventDisposition,
    ) -> EventDisposition {
        let args: Vec<&str> = event
            .arguments
            .iter()
            .filter_map(|a| a.display.as_deref())
            .collect();

        let mut strictest = disp;
        for arg in args.iter().skip(1) {
            // skip argv[0]
            if arg.starts_with('-') || arg.is_empty() {
                continue;
            }
            let file_disp = self.check_file_path(arg);
            if file_disp.should_display() {
                strictest = pick_stricter(strictest, file_disp);
                if strictest.is_blocked() {
                    return strictest;
                }
            }
        }
        strictest
    }

    /// Extract path from open()/openat() args and evaluate against files: policy.
    fn evaluate_file_from_native(
        &self,
        event: &TraceEvent,
        disp: EventDisposition,
    ) -> EventDisposition {
        // Normalize _open → open (macOS underscore-prefixed aliases)
        let func = event.function.trim_start_matches('_');
        if !super::templates::file_functions_native()
            .iter()
            .any(|f| f == func)
        {
            return disp;
        }
        let args: Vec<&str> = event
            .arguments
            .iter()
            .filter_map(|a| a.display.as_deref())
            .collect();

        // Arg extraction stays in code — position depends on the specific syscall
        debug_assert!(
            matches!(func, "open" | "openat"),
            "native file function '{}' in taxonomy but missing from extraction match",
            func
        );
        let path_str = match func {
            "open" => args.first().map(|a| strip_any_quotes(a)),
            "openat" => args.get(1).map(|a| strip_any_quotes(a)),
            _ => return disp,
        };

        if let Some(path) = path_str {
            let file_disp = self.check_file_path(path);
            if file_disp.should_display() {
                return pick_stricter(disp, file_disp);
            }
        }
        disp
    }

    /// Extract path from known Python/Node.js file functions and evaluate.
    fn evaluate_file_from_runtime(
        &self,
        event: &TraceEvent,
        disp: EventDisposition,
    ) -> EventDisposition {
        let is_file_func = is_runtime_file_func(&event.hook_type, &event.function);
        if !is_file_func {
            return disp;
        }
        // First arg is the file path
        let path_str = event
            .arguments
            .first()
            .and_then(|a| a.display.as_deref())
            .map(strip_any_quotes);
        if let Some(path) = path_str {
            let file_disp = self.check_file_path(path);
            if file_disp.should_display() {
                return pick_stricter(disp, file_disp);
            }
        }
        disp
    }

    /// Collect file deny/warn/log patterns from the `files:` policy section.
    pub(super) fn file_deny_patterns(&self) -> Vec<&str> {
        let key = SectionKey::global(Category::Files);
        self.engine
            .policy()
            .get_section(&key)
            .map(|s| s.deny_rules.iter().map(|r| r.pattern.original()).collect())
            .unwrap_or_default()
    }
}

/// Normalize a file path by collapsing `.` and `..` segments.
/// Prevents traversal bypasses like `/tmp/../../home/.ssh/id_rsa`.
pub(crate) fn normalize_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    let joined = parts.join("/");
    if path.starts_with('/') {
        format!("/{}", joined)
    } else {
        joined
    }
}

/// Remove surrounding quotes (single or double) from a display string.
fn strip_any_quotes(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| s.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::super::active::test_helpers::*;
    use super::*;
    use crate::policy::PolicyEngine;

    #[test]
    fn test_exec_cat_ssh_key_blocked_by_files() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\ncommands:\n  allow:\n    - cat\nfiles:\n  deny:\n    - \"*/.ssh/**\"\n",
        )
        .unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_exec_event("cat", &["~/.ssh/id_rsa"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "cat ~/.ssh/id_rsa should be blocked by files: deny"
        );
    }

    #[test]
    fn test_exec_cat_safe_file_allowed() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\ncommands:\n  allow:\n    - cat\nfiles:\n  deny:\n    - \"*/.ssh/**\"\n",
        )
        .unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_exec_event("cat", &["/tmp/ok.txt"]);
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "cat /tmp/ok.txt should be allowed");
    }

    #[test]
    fn test_native_open_ssh_key_blocked() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\nfiles:\n  deny:\n    - \"*/.ssh/**\"\n    - \"*id_rsa*\"\n",
        )
        .unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(
            HookType::Native,
            "open",
            &["\"/Users/mav/.ssh/id_rsa\"", "O_RDONLY"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.is_blocked());
    }

    #[test]
    fn test_native_openat_denied_file() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nfiles:\n  deny:\n    - \"*.pem\"\n").unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(
            HookType::Native,
            "openat",
            &["-100", "\"/tmp/server.pem\"", "O_RDONLY"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.is_blocked());
    }

    #[test]
    fn test_native_open_safe_file_suppressed() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nfiles:\n  deny:\n    - \"*/.ssh/**\"\n").unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(HookType::Native, "open", &["\"/tmp/ok.txt\"", "O_RDONLY"]);
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display());
    }

    #[test]
    fn test_normalize_path_collapses_dotdot() {
        assert_eq!(
            normalize_path("/tmp/../../home/.ssh/id_rsa"),
            "/home/.ssh/id_rsa"
        );
    }

    #[test]
    fn test_normalize_path_preserves_absolute() {
        assert_eq!(
            normalize_path("/Users/mav/.ssh/id_rsa"),
            "/Users/mav/.ssh/id_rsa"
        );
    }

    #[test]
    fn test_normalize_path_relative() {
        assert_eq!(normalize_path("foo/./bar/../baz"), "foo/baz");
    }

    #[test]
    fn test_strip_any_quotes_removes_double_quotes() {
        assert_eq!(strip_any_quotes("\"/tmp/file\""), "/tmp/file");
    }

    #[test]
    fn test_strip_any_quotes_removes_single_quotes() {
        assert_eq!(strip_any_quotes("'/tmp/file'"), "/tmp/file");
    }

    #[test]
    fn test_strip_any_quotes_passes_through_unquoted() {
        assert_eq!(strip_any_quotes("/tmp/file"), "/tmp/file");
    }

    #[test]
    fn test_exec_skips_flags_in_file_check() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\ncommands:\n  allow:\n    - cat\nfiles:\n  deny:\n    - \"*/.ssh/**\"\n",
        )
        .unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_exec_event("cat", &["-n", "/tmp/ok.txt"]);
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display());
    }

    #[test]
    fn test_exec_dotdot_traversal_blocked() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\ncommands:\n  allow:\n    - cat\nfiles:\n  deny:\n    - \"*/.ssh/**\"\n",
        )
        .unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_exec_event("cat", &["/tmp/../../home/user/.ssh/id_rsa"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "path traversal to .ssh should be blocked"
        );
    }

    #[test]
    fn test_file_phase_blocks_python_open_to_denied_path() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nfiles:\n  deny:\n    - \"*/.ssh/**\"\n").unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(HookType::Python, "open", &["'~/.ssh/id_rsa'"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "Python open to .ssh should be blocked by files: deny"
        );
    }

    #[test]
    fn test_native_open_absolute_path_matches_tilde_pattern() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nfiles:\n  deny:\n    - \"~/.zshrc\"\n").unwrap();
        let policy = ActivePolicy::new(engine);

        let home = std::env::var("HOME").unwrap();
        let abs_path = format!("\"{}/.zshrc\"", home);
        let event = make_trace_event(HookType::Native, "open", &[&abs_path, "O_WRONLY"]);
        let disp = policy.evaluate_trace(&event);
        assert!(disp.is_blocked(), "absolute path should match ~/ pattern");
    }

    #[test]
    fn test_nodejs_fs_write_to_denied_path_blocked() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nfiles:\n  deny:\n    - \"*/.ssh/**\"\n").unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(
            HookType::Nodejs,
            "fs.writeFileSync",
            &["'/home/user/.ssh/authorized_keys'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.is_blocked());
    }

    #[test]
    fn test_python_non_file_func_skipped() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nfiles:\n  deny:\n    - \"*/.ssh/**\"\n").unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(HookType::Python, "json.loads", &["'{\"key\": \"value\"}'"]);
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display());
    }

    // =====================================================================
    // Cache-hit regression: file phase must run even on 2nd+ call
    // =====================================================================

    #[test]
    fn test_native_open_cache_hit_still_evaluates_file_policy() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\nsymbols:\n  warn:\n    - open\nfiles:\n  deny:\n    - \"~/.ssh/**\"\n",
        )
        .unwrap();
        let policy = ActivePolicy::new(engine);

        // 1st call: safe path — triggers warn from symbols warn, caches function-level
        let event = make_trace_event(HookType::Native, "open", &["/lib/libc.so"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            matches!(disp, EventDisposition::Warn { .. }),
            "1st open (safe path) should be warned by symbols warn"
        );

        // 2nd call: sensitive path — cache hit for function-level, but file phase must still run
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
        let sensitive = format!("{}/.ssh/id_rsa", home);
        let event = make_trace_event(HookType::Native, "open", &[&sensitive]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "2nd open (~/.ssh/id_rsa) must be blocked even on cache hit"
        );
    }

    #[test]
    fn test_python_open_cache_hit_still_evaluates_file_policy() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\npython:\n  warn:\n    - open\nfiles:\n  deny:\n    - \"~/.ssh/**\"\n",
        )
        .unwrap();
        let policy = ActivePolicy::new(engine);

        // 1st call: safe path
        let event = make_trace_event(HookType::Python, "open", &["'/tmp/safe.txt'"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            matches!(disp, EventDisposition::Warn { .. }),
            "1st Python open (safe path) should be warned"
        );

        // 2nd call: sensitive path — must still evaluate file phase
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
        let sensitive = format!("'{}/{}'", home, ".ssh/id_rsa");
        let event = make_trace_event(HookType::Python, "open", &[&sensitive]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "2nd Python open (~/.ssh/id_rsa) must be blocked even on cache hit"
        );
    }

    #[test]
    fn test_nodejs_fs_cache_hit_still_evaluates_file_policy() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\nnodejs:\n  warn:\n    - fs.readFileSync\nfiles:\n  deny:\n    - \"~/.ssh/**\"\n",
        )
        .unwrap();
        let policy = ActivePolicy::new(engine);

        // 1st call: safe path
        let event = make_trace_event(HookType::Nodejs, "fs.readFileSync", &["'/tmp/safe.txt'"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            matches!(disp, EventDisposition::Warn { .. }),
            "1st fs.readFileSync (safe path) should be warned"
        );

        // 2nd call: sensitive path — must still evaluate file phase
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
        let sensitive = format!("'{}/{}'", home, ".ssh/id_rsa");
        let event = make_trace_event(HookType::Nodejs, "fs.readFileSync", &[&sensitive]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "2nd fs.readFileSync (~/.ssh/id_rsa) must be blocked even on cache hit"
        );
    }
}
