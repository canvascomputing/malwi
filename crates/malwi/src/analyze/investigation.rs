//! The finding lifecycle: what a result means, what it opens, and what stops
//! the run. An investigation is a second analysis task on the same code, so
//! what tells the two apart lives here rather than in either of the modules
//! that read them back.

use agentwerk::{Task, Werk};
use serde_json::Value;

use crate::analyze::discovery::ANALYSIS_LABEL;
use crate::types::{self, typed_schema, Type};

/// The least-severe verdict that stops the run and makes it exit `2`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailureThreshold {
    Malicious,
    Exploitable,
}

/// True when a schema-validated finding carries `verdict: "malicious"`.
pub(crate) fn is_malicious_verdict(result: &Value) -> bool {
    result.get("verdict").and_then(|v| v.as_str()) == Some("malicious")
}

/// Whether a verdict reaches the selected failure threshold. Every exploitable
/// verdict reaches the exploitable threshold; a typed malicious finding
/// still gets its focused follow-up before it can stop the run.
pub(crate) fn is_failure_verdict(
    werk: &Werk,
    task: &Task,
    result: &Value,
    threshold: FailureThreshold,
) -> bool {
    if result.get("verdict").and_then(Value::as_str) == Some("exploitable") {
        return threshold == FailureThreshold::Exploitable;
    }
    if is_investigation(werk, task) {
        return is_malicious_verdict(result);
    }
    if !is_malicious_verdict(result) {
        return false;
    }

    let finding_type = result
        .get("type")
        .and_then(Value::as_str)
        .and_then(types::find);
    !matches!(finding_type, Some(finding_type) if finding_type.verdict() == "malicious")
}

/// True when a result carries a non-benign verdict (`malicious` or
/// `exploitable`): the analyst reached an actual finding, not a dismissal.
pub(crate) fn is_finding_verdict(result: &Value) -> bool {
    matches!(
        result.get("verdict").and_then(|v| v.as_str()),
        Some("malicious") | Some("exploitable")
    )
}

/// True for a task an analyst verdict opened. A task carries one label, so
/// an investigation reads `security_analysis` like the verdict it answers; the
/// parent tells them apart, since a plain analysis task is handed over by a
/// Tracer and an investigation by an Analyst.
pub(crate) fn is_investigation(werk: &Werk, task: &Task) -> bool {
    task.get_parent()
        .and_then(|id| werk.get_task(id))
        .is_some_and(|parent| parent.get_label() == Some(ANALYSIS_LABEL))
}

/// The type an investigation is testing, read off the finding that opened it.
pub(crate) fn investigated_type(werk: &Werk, task: &Task) -> Option<&'static dyn Type> {
    let opener = werk.get_task(task.get_parent()?)?;
    types::find(opener.get_result()?.get("type")?.as_str()?)
}

/// The investigation a finished finding opens when its verdict and registered
/// type agree. A finding without a type opens nothing.
pub(crate) fn investigation(werk: &Werk, done: &Task, result: &Value) -> Option<Task> {
    if is_investigation(werk, done) || done.get_label() != Some(ANALYSIS_LABEL) {
        return None;
    }
    let verdict = result.get("verdict").and_then(Value::as_str)?;
    let finding_type = types::find(result.get("type").and_then(|v| v.as_str())?)?;
    if finding_type.verdict() != verdict {
        return None;
    }
    // The analysis label gets it claimed by an Analyst, the type's schema rides
    // on the task, and the parent is what marks it an investigation: a task
    // carries one label, and the pool that answers it already owns that one.
    Some(
        Task::new(finding_type.body(result))
            .label(ANALYSIS_LABEL)
            .schema(typed_schema(finding_type))
            .parent(done.get_id()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use serde_json::json;

    #[test]
    fn malicious_verdict_reads_verdict_from_validated_finding() {
        assert!(is_malicious_verdict(
            &json!({"verdict": "malicious", "path": "a.py"})
        ));
        assert!(!is_malicious_verdict(&json!({"verdict": "benign"})));
        assert!(!is_malicious_verdict(&json!({"path": "a.py"})));
        assert!(!is_malicious_verdict(&json!("a plain summary")));
    }
    /// Every exploitable verdict reaches the exploitable threshold, whether or
    /// not it names a registered type. Neither reaches the malicious
    /// threshold, while a malicious verdict reaches both.
    #[test]
    fn failure_thresholds_select_the_verdicts_that_stop_the_run() {
        let finding_type = types::find("side-loading").expect("side-loading is registered");
        let (werk, analysis, investigation) = opened_investigation("failure_threshold");
        let established = json!({
            "verdict": "exploitable", "path": "install.js", "type": finding_type.name(),
        });

        assert!(is_failure_verdict(
            &werk,
            &investigation,
            &established,
            FailureThreshold::Exploitable,
        ));
        assert!(!is_failure_verdict(
            &werk,
            &investigation,
            &established,
            FailureThreshold::Malicious,
        ));
        assert!(is_failure_verdict(
            &werk,
            &analysis,
            &established,
            FailureThreshold::Exploitable,
        ));
        let untyped = json!({"verdict": "exploitable", "path": "model.py"});
        assert!(is_failure_verdict(
            &werk,
            &analysis,
            &untyped,
            FailureThreshold::Exploitable,
        ));
        assert!(!is_failure_verdict(
            &werk,
            &analysis,
            &untyped,
            FailureThreshold::Malicious,
        ));
        let malicious = json!({"verdict": "malicious", "path": "a.py"});
        assert!(is_failure_verdict(
            &werk,
            &analysis,
            &malicious,
            FailureThreshold::Malicious,
        ));
        assert!(is_failure_verdict(
            &werk,
            &analysis,
            &malicious,
            FailureThreshold::Exploitable,
        ));
        // Ruling out one type does not erase the exploitable verdict.
        assert!(is_failure_verdict(
            &werk,
            &investigation,
            &json!({"verdict": "exploitable", "path": "a.py"}),
            FailureThreshold::Exploitable,
        ));
        let benign = json!({"verdict": "benign", "path": "a.py"});
        for threshold in [FailureThreshold::Malicious, FailureThreshold::Exploitable] {
            assert!(!is_failure_verdict(
                &werk,
                &investigation,
                &benign,
                threshold,
            ));
        }
        assert!(!is_failure_verdict(
            &werk,
            &analysis,
            &json!("a plain summary"),
            FailureThreshold::Exploitable,
        ));
    }
    #[test]
    fn finding_verdict_matches_malicious_and_exploitable_but_not_benign() {
        assert!(is_finding_verdict(
            &json!({"verdict": "malicious", "path": "a.py"})
        ));
        assert!(is_finding_verdict(
            &json!({"verdict": "exploitable", "path": "a.py"})
        ));
        assert!(!is_finding_verdict(&json!({"verdict": "benign"})));
        assert!(!is_finding_verdict(&json!({"path": "a.py"})));
        assert!(!is_finding_verdict(&json!("a plain summary")));
    }
    #[test]
    fn a_typed_exploitable_finding_opens_its_investigation() {
        let (werk, analysis, opened) = opened_investigation("opens");

        // The analysis label is what gets an Analyst to claim it; the type's
        // schema rides on the task, and the parent is what marks it.
        assert!(opened.get_label() == Some(ANALYSIS_LABEL));
        assert!(
            opened.get_schema().is_some(),
            "the type's schema rides along"
        );
        assert_eq!(opened.get_parent(), Some(analysis.get_id()));
        assert!(is_investigation(&werk, &opened));
        assert!(!is_investigation(&werk, &analysis));
        let body = opened.get_task().as_str().expect("the body is text");
        assert!(body.contains("# Side-Loading Investigation"), "{body}");
        assert!(body.contains("<finding_under_investigation>"), "{body}");
        assert!(body.contains("scripts/install.js"), "{body}");
        assert!(body.contains("downloads and runs a setup script"), "{body}");
    }
    /// A finding without a registered type opens no follow-up.
    #[test]
    fn an_exploitable_finding_without_a_registered_type_opens_nothing() {
        let (werk, done) = werk_with_analysis_task("no_type");
        for finding_type in [json!("none"), json!("an-unregistered-type"), Value::Null] {
            let mut finding = json!({"verdict": "exploitable", "path": "a.py", "description": "x"});
            if !finding_type.is_null() {
                finding["type"] = finding_type.clone();
            }
            assert!(
                investigation(&werk, &done, &finding).is_none(),
                "{finding_type}"
            );
        }
    }
    #[test]
    fn every_registered_type_opens_its_declared_investigation() {
        let finding_type = types::find("side-loading").expect("side-loading is registered");
        let (werk, done) = werk_with_analysis_task("declared_verdict");
        for verdict in ["malicious", "benign"] {
            let finding = json!({
                "verdict": verdict, "path": "a.py", "description": "x", "type": finding_type.name(),
            });
            assert!(investigation(&werk, &done, &finding).is_none(), "{verdict}");
        }

        let malicious = types::find("obfuscation").expect("obfuscation is registered");
        let finding = json!({
            "verdict": "malicious", "path": "a.py", "description": "x", "type": malicious.name(),
        });
        let opened =
            investigation(&werk, &done, &finding).expect("a malicious type opens its follow-up");
        assert_eq!(opened.get_parent(), Some(done.get_id()));
        assert!(opened.get_schema().is_some());
        assert!(investigation(&werk, &done, &json!("a plain summary")).is_none());
    }

    #[test]
    fn a_failure_threshold_waits_for_a_typed_malicious_follow_up() {
        let finding_type = types::find("obfuscation").expect("obfuscation is registered");
        let (werk, analysis) = werk_with_analysis_task("malicious_follow_up");
        let finding = json!({
            "verdict": "malicious", "path": "loader.py", "description": "decodes into exec",
            "type": finding_type.name(),
        });
        let opened = investigation(&werk, &analysis, &finding)
            .expect("the typed malicious finding opens a follow-up");
        let id = werk.add_task(opened);
        let opened = werk.get_task(&id).expect("the follow-up was filed");

        assert!(!is_failure_verdict(
            &werk,
            &analysis,
            &finding,
            FailureThreshold::Malicious,
        ));
        assert!(is_failure_verdict(
            &werk,
            &opened,
            &json!({"verdict": "malicious", "path": "loader.py"}),
            FailureThreshold::Malicious,
        ));
        assert!(investigation(&werk, &opened, &finding).is_none());
    }
    /// The loop guard: an investigation returns an `exploitable` verdict of its
    /// own, and opening a second one on that would never stop.
    #[test]
    fn an_investigation_never_opens_another_investigation() {
        let (werk, _, opened) = opened_investigation("loop_guard");
        assert!(investigation(&werk, &opened, &typed_finding()).is_none());
    }
    /// A queue holding one plain analysis task. Whether a task is an
    /// investigation is answered from its parent, so the queue has to be real.
    fn werk_with_analysis_task(dir: &str) -> (Arc<Werk>, Task) {
        let dir = std::env::temp_dir().join(format!("malwi_{dir}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let werk = Werk::new();
        werk.set_dir(&dir);
        let id = werk.add_task(Task::new("the evidence").label(ANALYSIS_LABEL));
        let analysis = werk.get_task(&id).expect("the task was filed");
        (werk, analysis)
    }
    /// The side-loading finding that opens its investigation.
    fn typed_finding() -> Value {
        json!({
            "verdict": "exploitable", "path": "scripts/install.js", "line": 12,
            "type": types::find("side-loading").expect("side-loading is registered").name(),
            "description": "downloads and runs a setup script",
        })
    }
    /// That queue, plus the investigation the finding opened on its task.
    fn opened_investigation(dir: &str) -> (Arc<Werk>, Task, Task) {
        let (werk, analysis) = werk_with_analysis_task(dir);
        let opened =
            investigation(&werk, &analysis, &typed_finding()).expect("an investigation opens");
        let id = werk.add_task(opened);
        let opened = werk.get_task(&id).expect("the investigation was filed");
        (werk, analysis, opened)
    }
    /// Three runs in a row lost the one investigation that would have carried a
    /// side-loading finding, because `--max-time` cut it mid-read. It carries
    /// the analysis label the stop calls off, so only being named out spares it.
    #[test]
    fn a_policy_stop_leaves_an_investigation_to_finish() {
        let (werk, analysis, opened) = opened_investigation("policy_stop");

        crate::analyze::cancel_for_policy_stop(&werk);

        assert!(!opened.is_cancelled(), "the investigation is spared");
        assert!(
            werk.get_task(analysis.get_id())
                .is_some_and(|task| task.is_cancelled()),
            "the pool is called off"
        );
    }
    /// Every seam a type has to be wired into, so adding one is an
    /// entry in the table rather than a checklist someone remembers.
    #[test]
    fn a_type_is_wired_into_every_seam() {
        for finding_type in types::TYPES {
            assert!(
                !finding_type.task().trim().is_empty(),
                "{}",
                finding_type.name()
            );
            assert!(
                !finding_type.summary().trim().is_empty(),
                "{}",
                finding_type.name()
            );
            assert!(
                !types::field_names(finding_type).is_empty(),
                "{}",
                finding_type.name()
            );
        }
    }
}
