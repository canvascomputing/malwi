//! Command triage — integrates the deterministic command analysis engine.

use super::active::{pick_stricter, ActivePolicy, EventDisposition};
use malwi_policy::{Category, SectionKey};
use malwi_protocol::{HookType, TraceEvent};

impl ActivePolicy {
    /// Collect command deny/warn/log patterns from the `commands:` policy section.
    pub(super) fn command_deny_patterns(&self) -> Vec<&str> {
        let key = SectionKey::global(Category::Execution);
        self.engine
            .policy()
            .get_section(&key)
            .map(|s| s.deny_rules.iter().map(|r| r.pattern.original()).collect())
            .unwrap_or_default()
    }

    /// Run the deterministic command triage layer on exec events.
    ///
    /// If suspicious, escalates the disposition to at least Warn.
    pub(super) fn evaluate_command_phase(
        &self,
        event: &TraceEvent,
        disp: EventDisposition,
    ) -> EventDisposition {
        if event.hook_type != HookType::Exec || disp.is_blocked() {
            return disp;
        }
        let args: Vec<&str> = event
            .arguments
            .iter()
            .filter_map(|a| a.display.as_deref())
            .collect();
        let file_patterns = self.file_deny_patterns();
        let cmd_patterns = self.command_deny_patterns();
        match super::analysis::analyze_command(
            &event.function,
            &args,
            &file_patterns,
            &cmd_patterns,
        ) {
            Some(analysis) => pick_stricter(
                disp,
                EventDisposition::Warn {
                    rule: analysis.reason,
                    section: "analysis".to_string(),
                },
            ),
            None => disp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::active::test_helpers::*;
    use super::super::active::{ActivePolicy, EventDisposition};
    use malwi_policy::PolicyEngine;

    #[test]
    fn test_command_analysis_ln_sensitive_warns() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\ncommands:\n  allow:\n    - ln\nfiles:\n  warn:\n    - \"*/.ssh/**\"\n",
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let event = make_exec_event("ln", &["-s", "~/.ssh", "/tmp/x"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "ln -s ~/.ssh /tmp/x should be warned by command analysis"
        );
    }

    #[test]
    fn test_command_analysis_blocked_stays_blocked() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\ncommands:\n  deny:\n    - curl\nfiles:\n  warn:\n    - \"*/.ssh/**\"\n",
        )
        .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let event = make_exec_event("curl", &["file:///etc/passwd"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "blocked curl should stay blocked even with suspicious args"
        );
    }

    #[test]
    fn test_command_analysis_curl_file_protocol_warns() {
        let engine =
            PolicyEngine::from_yaml("version: 1\ncommands:\n  log:\n    - curl\n").unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let event = make_exec_event("curl", &["file:///etc/passwd"]);
        let disp = policy.evaluate_trace(&event);
        assert!(
            matches!(disp, EventDisposition::Warn { .. }),
            "curl file:///etc/passwd should be warned by analysis"
        );
    }
}
