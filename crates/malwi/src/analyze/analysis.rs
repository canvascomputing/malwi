//! Turns the analysis tasks into the findings JSON, and renders those
//! findings as the body the Reporter phrases. The schemas the scan's own
//! handovers are held to sit here too: a hit, a trace, and the Reporter's
//! prose are contracts between this command's agents and nobody else.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use agentwerk::schemas::Schema;
use agentwerk::Werk;
use serde_json::{json, Value};

use crate::analyze::discovery::ANALYSIS_LABEL;
use crate::analyze::investigation::is_investigation;
use crate::types;

/// One reportable finding and the exact parent it resolves, if any.
#[derive(Clone)]
struct Candidate {
    task_id: String,
    parent: Option<String>,
    finding: Value,
}

/// Every finding the report reads: an investigation carries the analysis label
/// like the finding it answers, and a task still `Todo` is a backlog a stop
/// left unclaimed rather than a result.
fn analysis_task_query() -> String {
    format!("{ANALYSIS_LABEL} AND status != Todo")
}

/// Build the analysis JSON from completed analyst tasks. Top-level
/// `verdict` is the worst across findings (`malicious` > `exploitable`
/// > `benign`).
pub(crate) fn build_analysis(werk: &Werk, scan_dir: &Path, total_files: usize) -> Value {
    let mut collected: Vec<Candidate> = Vec::new();
    let mut unparsed: usize = 0;
    let type_keys = types::keys();

    // An investigation returns the same finding object under the same label, so
    // one loop covers both; where it came from decides which one dedup keeps.
    //
    // A task still `Todo` is a backlog a stop left unclaimed, not a result the
    // run could not parse; a failed one is kept, since it was claimed and paid for.
    for task in werk.find_tasks(analysis_task_query()) {
        let parent = is_investigation(werk, &task)
            .then(|| task.get_parent().map(str::to_string))
            .flatten();
        let Some(attached) = task.get_result() else {
            unparsed += 1;
            continue;
        };
        let Some(obj) = attached.as_object() else {
            unparsed += 1;
            continue;
        };
        let verdict = match obj.get("verdict").and_then(|v| v.as_str()) {
            Some(s) if s == "malicious" || s == "exploitable" || s == "benign" => s.to_string(),
            _ => {
                unparsed += 1;
                continue;
            }
        };
        let path_raw = obj.get("path").and_then(|v| v.as_str()).unwrap_or("");
        let path = relative_path(path_raw, scan_dir);
        let line = obj.get("line").and_then(|v| v.as_u64());
        let column = obj.get("column").and_then(|v| v.as_u64());
        let description = obj
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let mut finding = json!({
            "verdict": verdict,
            "path": path,
            "line": line,
            "column": column,
            "description": description,
        });
        for name in &type_keys {
            if let Some(value) = obj.get(name) {
                finding[name.as_str()] = value.clone();
            }
        }
        collected.push(Candidate {
            task_id: task.get_id().to_string(),
            parent,
            finding,
        });
    }
    let findings = dedup_findings(collected);

    // Counts and the touched-file set come from the deduped findings.
    let mut count_malicious: usize = 0;
    let mut count_exploitable: usize = 0;
    let mut count_benign: usize = 0;
    let mut files_seen: HashSet<String> = HashSet::new();
    for f in &findings {
        files_seen.insert(f["path"].as_str().unwrap_or("").to_string());
        match f["verdict"].as_str() {
            Some("malicious") => count_malicious += 1,
            Some("exploitable") => count_exploitable += 1,
            _ => count_benign += 1,
        }
    }

    // Worst verdict across all findings.
    let verdict = if count_malicious > 0 {
        "malicious"
    } else if count_exploitable > 0 {
        "exploitable"
    } else {
        "benign"
    };

    // Human-readable summary.
    let mut parts: Vec<String> = Vec::new();
    if count_malicious > 0 {
        parts.push(format!("{count_malicious} malicious"));
    }
    if count_exploitable > 0 {
        parts.push(format!("{count_exploitable} exploitable"));
    }
    if count_benign > 0 {
        parts.push(format!("{count_benign} benign"));
    }
    let tally = if parts.is_empty() {
        format!(
            "0 findings across {total_files} file{}",
            if total_files == 1 { "" } else { "s" },
        )
    } else {
        format!(
            "{} finding{} across {} of {} file{}",
            parts.join(", "),
            if findings.len() == 1 { "" } else { "s" },
            files_seen.len(),
            total_files,
            if total_files == 1 { "" } else { "s" },
        )
    };
    let summary = if unparsed > 0 {
        format!("{tally}; {unparsed} unparsed")
    } else {
        tally
    };

    json!({
        "verdict": verdict,
        "summary": summary,
        "findings": findings,
    })
}

/// Render the findings array as a Reporter task body. `partial_coverage`
/// tells the Reporter the pools were called off early, so an all-clear must
/// stay scoped to the parts examined.
pub(crate) fn verdict_language(verdict: &str) -> &'static str {
    match verdict {
        "malicious" => "Malicious — deliberately harmful behavior is present.",
        "exploitable" => "Exploitable — no deliberate harm was established, but the code creates a path an attacker or compromised third party can abuse.",
        "benign" => "Benign — no malicious or exploitable behavior was established in the examined code.",
        _ => "Unknown — no recognized security verdict was produced.",
    }
}

pub(crate) const PARTIAL_COVERAGE_LANGUAGE: &str =
    "The review ended before all files were examined.";

/// Keep the model's explanation while making the two fixed parts of a summary
/// deterministic. Models occasionally return plain text wrapped in quotes or
/// repeat a required suffix even when the task says to copy it once.
pub(crate) fn normalize_reporter_summary(
    reported: &str,
    verdict: &str,
    partial_coverage: bool,
) -> String {
    let trimmed = reported.trim();
    let unquoted = trimmed
        .strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
        .unwrap_or(trimmed)
        .trim();
    let opening = verdict_language(verdict);
    let middle = unquoted
        .strip_prefix(opening)
        .unwrap_or(unquoted)
        .replace(PARTIAL_COVERAGE_LANGUAGE, "");
    let middle = middle.trim().trim_matches('"').trim();

    let mut summary = opening.to_string();
    if !middle.is_empty() {
        summary.push(' ');
        summary.push_str(middle);
    }
    if partial_coverage {
        summary.push(' ');
        summary.push_str(PARTIAL_COVERAGE_LANGUAGE);
    }
    summary
}

pub(crate) fn render_findings_table(analysis: &Value, partial_coverage: bool) -> String {
    let verdict = analysis["verdict"].as_str().unwrap_or("unknown");
    let empty: Vec<Value> = Vec::new();
    let findings = analysis["findings"].as_array().unwrap_or(&empty);
    let coverage = if partial_coverage { "partial" } else { "full" };
    let mut body = String::from("<report_input>\n");
    body.push_str(&format!(
        "Overall verdict: {verdict}\nRequired summary opening: {}\nFinding count: {}\nCoverage: {coverage}\n",
        verdict_language(verdict),
        findings.len()
    ));
    if partial_coverage {
        body.push_str(&format!(
            "Required summary ending: {PARTIAL_COVERAGE_LANGUAGE}\n"
        ));
    }
    // What an investigation established leads: it is the subject of the report,
    // not one entry among the rest. The sort is stable, so everything else keeps
    // the order discovery found it in.
    let mut ordered: Vec<&Value> = findings.iter().collect();
    ordered.sort_by_key(|f| !leads_the_report(f));
    for (i, f) in ordered.into_iter().enumerate() {
        body.push_str(&format!(
            "\n<finding index=\"{}\">\nFinding verdict: {}\nFinding verdict wording: {}\nPath: {}\nLine: {}\nColumn: {}\n",
            i + 1,
            f["verdict"].as_str().unwrap_or(""),
            verdict_language(f["verdict"].as_str().unwrap_or("")),
            f["path"].as_str().unwrap_or(""),
            f["line"]
                .as_u64()
                .map(|n| n.to_string())
                .unwrap_or_default(),
            f["column"]
                .as_u64()
                .map(|n| n.to_string())
                .unwrap_or_default(),
        ));
        body.push_str(&render_analysis(f));
        body.push_str(&format!(
            "Description:\n{}\n</finding>\n",
            f["description"].as_str().unwrap_or("")
        ));
    }
    body.push_str("</report_input>");
    body
}

/// First replace the exact verdict tasks answered by parent-linked follow-ups,
/// then collapse unrelated results to one finding per `(path, line)` by
/// severity. An affirmative-consent answer can therefore lower its own parent
/// to benign without weakening a separate malicious finding at the same site.
///
/// The key holds no `column`: an investigation restates the verdict it was
/// opened on, and one analyst naming a column where another left it null would
/// otherwise split one finding into two, the second stripped of the detail the
/// run paid for. Two distinct findings on one line of one file do not occur.
fn dedup_findings(collected: Vec<Candidate>) -> Vec<Value> {
    let resolved: HashSet<String> = collected
        .iter()
        .filter_map(|candidate| candidate.parent.clone())
        .collect();
    let mut findings: Vec<Candidate> = Vec::new();
    let mut index: HashMap<(String, Option<u64>), usize> = HashMap::new();
    for candidate in collected {
        if resolved.contains(&candidate.task_id) {
            continue;
        }
        let finding = &candidate.finding;
        let key = (
            finding["path"].as_str().unwrap_or("").to_string(),
            finding["line"].as_u64(),
        );
        let new_severity = severity(finding["verdict"].as_str().unwrap_or(""));
        match index.get(&key) {
            Some(&i) => {
                let held = severity(findings[i].finding["verdict"].as_str().unwrap_or(""));
                let equally_severe_follow_up = new_severity == held
                    && candidate.parent.is_some()
                    && findings[i].parent.is_none();
                if new_severity > held || equally_severe_follow_up {
                    findings[i] = candidate;
                }
            }
            None => {
                index.insert(key, findings.len());
                findings.push(candidate);
            }
        }
    }
    findings
        .into_iter()
        .map(|candidate| candidate.finding)
        .collect()
}

/// True for a finding an investigation established and did not dismiss.
fn leads_the_report(finding: &Value) -> bool {
    types::established(finding).is_some() && finding["verdict"].as_str() != Some("benign")
}

/// What the investigation established, in the words of the type that
/// established it. A finding no investigation reached renders nothing: its
/// type-specific fields are absent.
fn render_analysis(finding: &Value) -> String {
    if !leads_the_report(finding) {
        return String::new();
    }
    types::established(finding)
        .map(|finding_type| {
            format!(
                "Focused behavior: {}\nEstablished facts: {}\n",
                finding_type.report_phrase(),
                finding_type.render(finding)
            )
        })
        .unwrap_or_default()
}

/// Result schema for a Seeker task: the hit it hands to the Tracer, or that
/// the pass came back empty.
///
/// `outcome` gates the rest because both ends validate here, a `finish` without
/// a handover included, and an empty pass has no location to name. The hit
/// carries the `path` / `line` / `column` triple discovery hands over too, so the
/// Tracer copies a location rather than reading one out of prose.
pub(crate) fn seeker_result_schema_json() -> Value {
    json!({
        "type": "object",
        "properties": {
            "outcome": {
                "type": "string",
                "enum": ["hit", "nothing"],
                "description": "Use \"hit\" for a content match worth tracing. Use \"nothing\" after the complete assigned search finds none.",
            },
            "pattern": {
                "type": "string",
                "minLength": 1,
                "description": "The query that produced the hit, or the final attempted query for an empty pass.",
            },
            "path": {"type": "string", "minLength": 1, "description": "File containing the hit, copied from the search result."},
            "line": {"type": "integer", "description": "Line of the hit when the search result supplies one."},
            "column": {"type": "integer", "description": "Column of the hit when the search result supplies one."},
            "match": {
                "type": "string",
                "minLength": 1,
                "description": "The matched code quoted from the search result.",
            },
            "why": {
                "type": "string",
                "minLength": 1,
                "description": "Why the code merits tracing, stated as observed behavior without a verdict.",
            },
        },
        "required": ["outcome", "pattern"],
        "allOf": [{
            "if": {"properties": {"outcome": {"const": "hit"}}, "required": ["outcome"]},
            "then": {"required": ["path", "match", "why"]},
        }],
    })
}

/// Result schema for a Tracer task: the hit's location, what was found there,
/// and the chain that reaches it. The location is the same `path` / `line` /
/// `column` triple grep and the finding use, so the Analyst copies it rather
/// than re-deriving it from prose.
///
/// `trace` is an array because a reachability chain is a list of located steps.
/// An empty one is the dead end, which is why `trigger` and `boundary` are not
/// required: nothing reached the hit, so nothing sets it off.
pub(crate) fn trace_result_schema_json() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "minLength": 1, "description": "File containing the match, copied from the task."},
            "line": {"type": "integer", "description": "Line of the hit."},
            "column": {"type": "integer", "description": "Column of the hit, when you know it."},
            "evidence": {
                "type": "string",
                "minLength": 1,
                "description": "The relevant code quoted exactly, with the supplied reason for tracing it.",
            },
            "trace": {
                "type": "array",
                "description": "The demonstrated path from entry point to hit. Use an empty array when no in-tree caller reaches it.",
                "items": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "minLength": 1, "description": "File this step is in."},
                        "line": {"type": "integer", "description": "Line of the call, registration, or definition."},
                        "column": {"type": "integer", "description": "Column, when you know it."},
                        "step": {"type": "string", "minLength": 1, "description": "What this step does: what wires it, what invokes it, or that it is the sink."},
                    },
                    "required": ["path", "step"],
                },
            },
            "trigger": {"type": "string", "description": "What causes the entry point to run and whether the operator explicitly selects it."},
            "boundary": {"type": "string", "description": "The demonstrated trust transition: what lower-trust input crosses into which privileged operation."},
        },
        "required": ["path", "evidence", "trace"],
    })
}

/// Result schema for the Reporter task: an object carrying the lay-reader
/// `summary` and the three-paragraph technical `details`. Attaching it makes
/// `finish` reject a malformed or partial result and force a retry,
/// the same guard the Analyst finding relies on. The length floors and limits
/// sit outside the targets the prompt states, so a compliant result is never
/// rejected while a skimped or runaway one is.
pub(crate) fn reporter_result_schema() -> Schema {
    Schema::new(json!({
        "type": "object",
        "properties": {
            "summary": {"type": "string", "minLength": 150, "maxLength": 650, "description": "A 200-500 character reader-facing paragraph beginning with the supplied required opening."},
            "details": {"type": "string", "minLength": 500, "maxLength": 4500, "description": "A 700-3500 character engineering report with Evidence, Mechanism, and Impact sections."},
        },
        "required": ["summary", "details"],
    }))
    .expect("reporter result schema is a valid document")
}

/// Verdict ordering for dedup: `malicious` (2) > `exploitable` (1) > `benign` (0).
fn severity(verdict: &str) -> u8 {
    match verdict {
        "malicious" => 2,
        "exploitable" => 1,
        _ => 0,
    }
}

/// Strip `scan_dir` prefix from a source path to produce a relative display path.
fn relative_path(source: &str, scan_dir: &Path) -> String {
    let path = Path::new(source);
    path.strip_prefix(scan_dir)
        .map(|rel| rel.display().to_string())
        .unwrap_or_else(|_| source.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentwerk::{Query, Task};
    use serde_json::json;
    use std::fs;

    /// The finding an investigation returns, whole.
    fn side_loading_finding() -> Value {
        json!({
            "verdict": "exploitable",
            "path": "scripts/install.js",
            "line": 12,
            "description": "downloads and runs a setup script",
            "type": "side-loading",
            "source": "https://cdn.example.test/setup.sh",
            "control": "static",
            "user_consent": false,
            "trigger": {
                "phase": "installation",
                "location": {"path": "package.json", "line": 4},
                "execution_condition": "always, on every install",
            },
        })
    }

    fn obfuscation_finding() -> Value {
        json!({
            "verdict": "malicious",
            "path": "src/bootstrap.py",
            "line": 8,
            "description": "decodes and executes a concealed credential stealer",
            "type": "obfuscation",
            "payload": "ZXhlYygnc3RlYWwoKScp at src/bootstrap.py:4",
            "transform": "base64.b64decode at src/bootstrap.py:8",
            "sink": "exec at src/bootstrap.py:8",
            "trigger": {
                "phase": "runtime",
                "location": {"path": "src/bootstrap.py", "line": 8},
                "execution_condition": "when bootstrap() is invoked",
            },
        })
    }

    fn telemetry_finding() -> Value {
        json!({
            "verdict": "exploitable",
            "path": "src/events.py",
            "line": 18,
            "description": "sends host and command data on startup",
            "type": "telemetry",
            "provider": "Segment",
            "destination": "https://api.segment.io/v1/track at src/events.py:18",
            "data": ["hostname from platform.node() at src/events.py:12"],
            "user_consent": false,
            "trigger": {
                "phase": "startup",
                "location": {"path": "src/events.py", "line": 18},
                "execution_condition": "whenever the module is imported",
                "cadence": "once per process start",
            },
        })
    }
    /// The trace the Analyst copies its location out of.
    fn trace_result() -> Value {
        json!({
            "path": "scripts/install.js",
            "line": 13,
            "column": 5,
            "evidence": "`https.request(url)` writing to a path it then chmods",
            "trace": [
                {"path": "package.json", "line": 7, "step": "postinstall runs scripts/install.js"},
                {"path": "scripts/install.js", "line": 22, "step": "fetchHelper() at module load"},
                {"path": "scripts/install.js", "line": 13, "step": "the sink"},
            ],
            "trigger": "every npm install",
            "boundary": "an installer reaching the network",
        })
    }
    /// The hit a Seeker hands the Tracer.
    fn seeker_hit() -> Value {
        json!({
            "outcome": "hit",
            "pattern": "eval($DEC(...))",
            "path": "lib/telemetry.js",
            "line": 42,
            "match": "eval(atob(payload))",
            "why": "decodes a blob and evaluates it at module load",
        })
    }
    fn candidate(id: &str, parent: Option<&str>, finding: Value) -> Candidate {
        Candidate {
            task_id: id.to_string(),
            parent: parent.map(str::to_string),
            finding,
        }
    }
    /// AQL is checked when it runs, so the query the report reads every finding
    /// through is compiled here rather than on a live run.
    #[test]
    fn every_query_the_report_builds_compiles() {
        let query = analysis_task_query();
        Query::<Task>::new(&query).unwrap_or_else(|e| panic!("{query}: {e}"));
    }

    #[test]
    fn every_verdict_has_exact_reader_facing_language() {
        assert_eq!(
            verdict_language("malicious"),
            "Malicious — deliberately harmful behavior is present."
        );
        assert_eq!(
            verdict_language("exploitable"),
            "Exploitable — no deliberate harm was established, but the code creates a path an attacker or compromised third party can abuse."
        );
        assert_eq!(
            verdict_language("benign"),
            "Benign — no malicious or exploitable behavior was established in the examined code."
        );
    }

    #[test]
    fn normalizes_fixed_summary_language_without_rewriting_the_explanation() {
        let reported = format!(
            " \"{} The package sends usage data only after opt-in. {} {}\" ",
            verdict_language("benign"),
            PARTIAL_COVERAGE_LANGUAGE,
            PARTIAL_COVERAGE_LANGUAGE,
        );
        assert_eq!(
            normalize_reporter_summary(&reported, "benign", true),
            format!(
                "{} The package sends usage data only after opt-in. {}",
                verdict_language("benign"),
                PARTIAL_COVERAGE_LANGUAGE,
            )
        );
        assert_eq!(
            normalize_reporter_summary(
                "The loader executes a credential stealer.",
                "malicious",
                false
            ),
            format!(
                "{} The loader executes a credential stealer.",
                verdict_language("malicious")
            )
        );
    }

    #[test]
    fn renders_findings_table_with_per_finding_blocks() {
        let analysis = json!({
            "verdict": "malicious",
            "findings": [
                {
                    "verdict": "malicious",
                    "path": "requests/__init__.py",
                    "line": 189,
                    "description": "Backdoor exfiltrates Chrome credentials."
                },
                {
                    "verdict": "benign",
                    "path": "requests/utils.py",
                    "line": 280,
                    "description": "Standard zipfile usage; package as a whole is poisoned."
                }
            ],
        });
        let body = render_findings_table(&analysis, false);
        assert!(body.starts_with(
            "<report_input>\nOverall verdict: malicious\nRequired summary opening: Malicious — deliberately harmful behavior is present.\nFinding count: 2\nCoverage: full\n"
        ));
        assert!(body.contains("<finding index=\"1\">"));
        assert!(body.contains("<finding index=\"2\">"));
        assert!(body.contains("Finding verdict: malicious"));
        assert!(body.contains(
            "Finding verdict wording: Malicious — deliberately harmful behavior is present."
        ));
        assert!(body.contains("Path: requests/__init__.py"));
        assert!(body.contains("Line: 189"));
        assert!(body.contains("Backdoor exfiltrates Chrome credentials."));
        assert_eq!(
            body.matches("Backdoor exfiltrates Chrome credentials.")
                .count(),
            1
        );
        assert!(body.contains("Path: requests/utils.py"));
        assert!(body.ends_with("</report_input>"));
    }
    #[test]
    fn renders_findings_table_with_empty_findings_array() {
        let analysis = json!({"verdict": "benign", "findings": []});
        let body = render_findings_table(&analysis, false);
        assert_eq!(
            body,
            "<report_input>\nOverall verdict: benign\nRequired summary opening: Benign — no malicious or exploitable behavior was established in the examined code.\nFinding count: 0\nCoverage: full\n</report_input>"
        );
    }
    #[test]
    fn renders_findings_table_marks_partial_coverage() {
        let analysis = json!({"verdict": "benign", "findings": []});
        let body = render_findings_table(&analysis, true);
        assert!(body.contains("Coverage: partial"));
        assert!(body.contains(&format!(
            "Required summary ending: {PARTIAL_COVERAGE_LANGUAGE}"
        )));
        assert!(!render_findings_table(&analysis, false).contains("Required summary ending:"));
    }

    #[test]
    fn unreachable_malicious_code_keeps_its_verdict_and_exposure_context() {
        let analysis = json!({
            "verdict": "malicious",
            "findings": [{
                "verdict": "malicious",
                "path": "stealer.py",
                "line": 6,
                "description": "The payload implements credential theft. No in-tree caller reaches it, so its current exposure is limited."
            }],
        });
        let body = render_findings_table(&analysis, false);
        assert!(body.contains(
            "Finding verdict wording: Malicious — deliberately harmful behavior is present."
        ));
        assert!(body.contains("No in-tree caller reaches it, so its current exposure is limited."));
    }
    /// The investigation restates the finding it was opened on, and analysts
    /// disagree about the column. Keyed on the column the two never collide, and
    /// the report carries the same code twice, the second copy stripped of what
    /// the investigation established. The parent now names the same type, so
    /// only provenance can tell them apart.
    #[test]
    fn an_investigation_and_its_parent_are_one_finding_though_the_columns_differ() {
        let parent = json!({
            "verdict": "exploitable", "path": "scripts/install.js", "line": 13,
            "column": null, "type": "side-loading", "description": "downloads a binary",
        });
        let mut investigated = side_loading_finding();
        investigated["path"] = json!("scripts/install.js");
        investigated["line"] = json!(13);
        investigated["column"] = json!(5);

        for pair in [
            vec![
                candidate("question", None, parent.clone()),
                candidate("answer", Some("question"), investigated.clone()),
            ],
            vec![
                candidate("answer", Some("question"), investigated.clone()),
                candidate("question", None, parent.clone()),
            ],
        ] {
            let findings = dedup_findings(pair);
            assert_eq!(findings.len(), 1, "{findings:?}");
            assert_eq!(
                findings[0]["source"],
                json!("https://cdn.example.test/setup.sh"),
                "{findings:?}"
            );
        }
    }
    /// An investigation that ruled its type out must still replace its parent.
    #[test]
    fn an_investigation_that_ruled_its_type_out_still_takes_the_entry() {
        let findings = dedup_findings(vec![
            candidate(
                "question",
                None,
                json!({"verdict": "exploitable", "path": "a.py", "line": 3, "type": "side-loading", "description": "x"}),
            ),
            candidate(
                "answer",
                Some("question"),
                json!({"verdict": "exploitable", "path": "a.py", "line": 3, "description": "x"}),
            ),
        ]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].get("type").is_none());
    }

    #[test]
    fn a_benign_investigation_replaces_the_exploitable_question_it_resolved() {
        let question = candidate(
            "question",
            None,
            json!({
                "verdict": "exploitable", "path": "telemetry.py", "line": 3,
                "type": "telemetry", "description": "analytics client",
            }),
        );
        let answer = candidate(
            "answer",
            Some("question"),
            json!({
                "verdict": "benign", "path": "telemetry.py", "line": 3,
                "description": "transmission requires --share-usage",
            }),
        );

        for pair in [
            vec![question.clone(), answer.clone()],
            vec![answer.clone(), question.clone()],
        ] {
            let findings = dedup_findings(pair);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0]["verdict"], json!("benign"));
            assert!(findings[0].get("type").is_none());
        }
    }

    #[test]
    fn an_unrelated_malicious_finding_survives_a_benign_follow_up_at_the_same_site() {
        let findings = dedup_findings(vec![
            candidate(
                "question",
                None,
                json!({
                    "verdict": "exploitable", "path": "telemetry.py", "line": 3,
                    "type": "telemetry", "description": "analytics client",
                }),
            ),
            candidate(
                "unrelated",
                None,
                json!({
                    "verdict": "malicious", "path": "telemetry.py", "line": 3,
                    "description": "steals an API key",
                }),
            ),
            candidate(
                "answer",
                Some("question"),
                json!({
                    "verdict": "benign", "path": "telemetry.py", "line": 3,
                    "description": "transmission requires --share-usage",
                }),
            ),
        ]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["verdict"], json!("malicious"));
        assert_eq!(findings[0]["description"], json!("steals an API key"));
    }
    /// A stop leaves analysis tasks no Analyst ever claimed. Counting them
    /// names a failure that never happened.
    #[test]
    fn a_task_no_analyst_ever_claimed_is_not_an_unparsed_result() {
        let dir = std::env::temp_dir().join(format!("malwi_backlog_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let werk = agentwerk::Werk::new();
        werk.set_dir(&dir);
        for _ in 0..2 {
            werk.add_task(agentwerk::Task::new("the evidence").label(ANALYSIS_LABEL));
        }

        let analysis = build_analysis(&werk, &dir, 3);

        assert_eq!(analysis["summary"], json!("0 findings across 3 files"));
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn two_hits_on_different_lines_of_one_file_stay_apart() {
        let at = |line: u64| {
            candidate(
                &format!("line-{line}"),
                None,
                json!({"verdict": "benign", "path": "a.py", "line": line, "description": "x"}),
            )
        };
        assert_eq!(dedup_findings(vec![at(3), at(9)]).len(), 2);
    }
    /// The Reporter reads the blocks in order, so what a package pulls in from
    /// outside itself is the first thing it sees, whatever discovery found first.
    #[test]
    fn a_side_loading_finding_leads_the_findings_table() {
        let analysis = json!({
            "verdict": "exploitable",
            "findings": [
                {"verdict": "benign", "path": "first.py", "description": "ordinary"},
                {"verdict": "exploitable", "path": "second.py", "description": "weak secret"},
                side_loading_finding(),
            ],
        });
        let body = render_findings_table(&analysis, false);
        let lead = body
            .split("<finding index=\"2\">")
            .next()
            .expect("a first block");
        assert!(lead.contains("scripts/install.js"), "{body}");
        assert!(lead.contains("downloads and runs a setup script"), "{body}");
        // The order the Reporter reads is the only signal; the blocks themselves
        // are unchanged, so an ordinary finding still renders as it always did.
        assert!(body.contains("first.py"), "{body}");
        assert!(body.contains("second.py"), "{body}");
    }
    /// The Reporter never sees the finding object, so what the investigation
    /// established reaches the report through this sentence or not at all.
    #[test]
    fn the_table_carries_what_the_investigation_established() {
        let analysis = json!({"verdict": "exploitable", "findings": [side_loading_finding()]});
        let body = render_findings_table(&analysis, false);
        assert!(
            body.contains(
                "Focused behavior: execution of code fetched from an external source\n\
                 Established facts: This code fetches https://cdn.example.test/setup.sh and executes the result, from a static source, \
                 without the operator's consent. The fetch fires at package.json:4, during \
                 installation, always, on every install."
            ),
            "{body}"
        );
        assert!(!body.contains("side-loading"), "{body}");
        assert!(body.contains("downloads and runs a setup script"), "{body}");
    }

    #[test]
    fn every_established_type_reaches_the_report_in_plain_language() {
        for (finding, phrase) in [
            (obfuscation_finding(), "runtime execution of concealed code"),
            (
                side_loading_finding(),
                "execution of code fetched from an external source",
            ),
            (
                telemetry_finding(),
                "external data transmission without affirmative opt-in",
            ),
        ] {
            let internal_name = finding["type"].as_str().unwrap();
            let verdict = finding["verdict"].clone();
            let body =
                render_findings_table(&json!({"verdict": verdict, "findings": [finding]}), false);
            assert!(
                body.contains(&format!("Focused behavior: {phrase}")),
                "{body}"
            );
            assert!(!body.contains(internal_name), "{body}");
            assert!(!body.contains("type:"), "{body}");
        }
    }
    #[test]
    fn a_finding_no_investigation_reached_carries_no_sentence() {
        let analysis = json!({
            "verdict": "benign",
            "findings": [{"verdict": "benign", "path": "a.py", "description": "ordinary"}],
        });
        let body = render_findings_table(&analysis, false);
        assert!(!body.contains("Focused behavior:"), "{body}");
        assert!(!body.contains("Established facts:"), "{body}");
    }
    /// A type awaiting investigation must not be treated as established. One a policy stop cut off before the
    /// investigation answered it must not lead the table, nor print a sentence
    /// assembled from fields nobody established.
    #[test]
    fn a_type_no_investigation_confirmed_does_not_lead() {
        let analysis = json!({"verdict": "exploitable", "findings": [
            {"verdict": "benign", "path": "first.py", "description": "ordinary"},
            {
                "verdict": "exploitable", "path": "second.py",
                "type": "side-loading", "description": "typed, never investigated",
            },
        ]});
        let body = render_findings_table(&analysis, false);
        let lead = body
            .split("<finding index=\"2\">")
            .next()
            .expect("a first block");
        assert!(lead.contains("first.py"), "{body}");
        assert!(!body.contains("side-loads"), "{body}");
    }
    /// A finding no investigation reached must not be promoted over one that
    /// was, and a dismissed side-loading finding is the subject of nothing.
    #[test]
    fn a_dismissed_side_loading_finding_does_not_lead() {
        let mut dismissed = side_loading_finding();
        dismissed["verdict"] = json!("benign");
        let analysis = json!({"verdict": "benign", "findings": [
            {"verdict": "benign", "path": "first.py", "description": "ordinary"},
            dismissed,
        ]});
        let body = render_findings_table(&analysis, false);
        let lead = body
            .split("<finding index=\"2\">")
            .next()
            .expect("a first block");
        assert!(lead.contains("first.py"), "{body}");
    }
    #[test]
    fn a_seeker_hit_carries_the_location_the_trace_starts_at() {
        let schema = Schema::new(seeker_result_schema_json()).expect("a valid document");
        assert!(schema.validate(seeker_hit()).is_ok());
        // The old shape: the location buried in one sentence.
        assert!(schema
            .validate(json!(
                "lib/telemetry.js:42, eval(atob(payload)), worth tracing"
            ))
            .is_err());
        for missing in ["path", "match", "why"] {
            let mut hit = seeker_hit();
            hit.as_object_mut().expect("an object").remove(missing);
            assert!(schema.validate(hit).is_err(), "{missing}");
        }
    }
    /// An empty pass ends the same task with no location to name, and a
    /// `finish` without a handover carries the label's contract all the same.
    #[test]
    fn an_empty_seeker_pass_names_its_pattern_and_nothing_else() {
        let schema = Schema::new(seeker_result_schema_json()).expect("a valid document");
        assert!(schema
            .validate(json!({"outcome": "nothing", "pattern": "curl -fsSL"}))
            .is_ok());
        // The pattern is what a refilled task reads to avoid repeating it.
        assert!(schema.validate(json!({"outcome": "nothing"})).is_err());
        assert!(schema.validate(json!({"pattern": "curl -fsSL"})).is_err());
    }
    #[test]
    fn a_trace_carries_the_location_and_the_chain() {
        let schema = Schema::new(trace_result_schema_json()).expect("a valid document");
        assert!(schema.validate(trace_result()).is_ok());
        // The old shape: one markdown document.
        assert!(schema.validate(json!("## Finding\n`a.js:1`")).is_err());
        for missing in ["path", "evidence", "trace"] {
            let mut result = trace_result();
            result.as_object_mut().expect("an object").remove(missing);
            assert!(schema.validate(result).is_err(), "{missing}");
        }
    }
    /// Nothing reaches the hit: a finished trace, not a failed one. No flag says
    /// so, the empty chain does.
    #[test]
    fn an_empty_trace_is_the_dead_end() {
        let schema = Schema::new(trace_result_schema_json()).expect("a valid document");
        let mut result = trace_result();
        result["trace"] = json!([]);
        result.as_object_mut().expect("an object").remove("trigger");
        result
            .as_object_mut()
            .expect("an object")
            .remove("boundary");
        assert!(schema.validate(result).is_ok());
    }
    #[test]
    fn a_trace_step_without_a_location_is_rejected() {
        let schema = Schema::new(trace_result_schema_json()).expect("a valid document");
        let mut result = trace_result();
        result["trace"] = json!([{"step": "something calls it"}]);
        assert!(schema.validate(result).is_err());
    }
    #[test]
    fn reporter_schema_requires_summary_and_details() {
        let schema = reporter_result_schema();
        let summary = "s".repeat(200);
        let details = "d".repeat(1200);
        // Both fields present and within their length bounds validates.
        assert!(schema
            .validate(json!({"summary": summary, "details": details}))
            .is_ok());
        // A bare string is the old shape, now rejected.
        assert!(schema.validate(json!("safe to use")).is_err());
        // A missing field is rejected.
        assert!(schema.validate(json!({"summary": summary})).is_err());
        // A field below its length floor is rejected.
        assert!(schema
            .validate(json!({"summary": summary, "details": "no risky calls found"}))
            .is_err());
        assert!(schema
            .validate(json!({"summary": "safe to use", "details": details}))
            .is_err());
    }
}
