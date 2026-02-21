//! File access policy evaluation — checks file paths against the `files:` policy section.

use super::active::{decision_to_disposition, pick_stricter, ActivePolicy, EventDisposition};
use malwi_policy::{Category, Operation, SectionKey};
use malwi_protocol::{HookType, TraceEvent};

impl ActivePolicy {
    /// Evaluate file access against the `files:` policy section.
    ///
    /// Two paths:
    /// - Exec events: check command arguments for file paths
    /// - Native open/openat: extract the path from the call arguments
    pub(super) fn evaluate_file_phase(
        &self,
        event: &TraceEvent,
        disp: EventDisposition,
    ) -> EventDisposition {
        match event.hook_type {
            HookType::Exec => self.evaluate_file_args_from_exec(event, disp),
            HookType::Native => self.evaluate_file_from_native(event, disp),
            _ => disp,
        }
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
            let normalized = normalize_path(arg);
            let decision = self.engine.evaluate_file(&normalized, Operation::Read);
            let file_disp = decision_to_disposition(decision);
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
        let func = &event.function;
        let args: Vec<&str> = event
            .arguments
            .iter()
            .filter_map(|a| a.display.as_deref())
            .collect();

        // Extract file path based on function
        let path_str = match func.as_str() {
            "open" | "_open" => args.first().and_then(|a| strip_quotes(a)),
            "openat" | "_openat" => args.get(1).and_then(|a| strip_quotes(a)),
            _ => return disp,
        };

        if let Some(path) = path_str {
            let normalized = normalize_path(path);
            let operation = detect_operation_from_flags(&args, func);
            let decision = self.engine.evaluate_file(&normalized, operation);
            let file_disp = decision_to_disposition(decision);
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

/// Remove surrounding double quotes from a formatted display string.
fn strip_quotes(s: &str) -> Option<&str> {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or(Some(s))
}

/// Determine Read vs Write operation from open() flags argument.
fn detect_operation_from_flags(args: &[&str], func: &str) -> Operation {
    let flags_str = match func {
        "open" | "_open" => args.get(1),
        "openat" | "_openat" => args.get(2),
        _ => None,
    };
    if let Some(flags) = flags_str {
        if flags.contains("O_WRONLY") || flags.contains("O_RDWR") || flags.contains("O_CREAT") {
            return Operation::Write;
        }
    }
    Operation::Read
}

#[cfg(test)]
mod tests {
    use super::super::active::test_helpers::*;
    use super::*;
    use malwi_policy::PolicyEngine;

    #[test]
    fn test_exec_cat_ssh_key_blocked_by_files() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\ncommands:\n  allow:\n    - cat\nfiles:\n  deny:\n    - \"*/.ssh/**\"\n",
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
    fn test_detect_operation_write() {
        let args = vec!["\"/tmp/out\"", "O_WRONLY|O_CREAT"];
        assert!(matches!(
            detect_operation_from_flags(&args, "open"),
            Operation::Write
        ));
    }

    #[test]
    fn test_detect_operation_read() {
        let args = vec!["\"/tmp/in\"", "O_RDONLY"];
        assert!(matches!(
            detect_operation_from_flags(&args, "open"),
            Operation::Read
        ));
    }

    #[test]
    fn test_strip_quotes_removes_double_quotes() {
        assert_eq!(strip_quotes("\"/tmp/file\""), Some("/tmp/file"));
    }

    #[test]
    fn test_strip_quotes_passes_through_unquoted() {
        assert_eq!(strip_quotes("/tmp/file"), Some("/tmp/file"));
    }

    #[test]
    fn test_exec_skips_flags_in_file_check() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\ncommands:\n  allow:\n    - cat\nfiles:\n  deny:\n    - \"*/.ssh/**\"\n",
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let event = make_exec_event("cat", &["/tmp/../../home/user/.ssh/id_rsa"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "path traversal to .ssh should be blocked"
        );
    }

    #[test]
    fn test_file_phase_skips_non_exec_non_native() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nfiles:\n  deny:\n    - \"*/.ssh/**\"\n").unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let event = make_trace_event(HookType::Python, "open", &["~/.ssh/id_rsa"]);
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display());
    }
}
