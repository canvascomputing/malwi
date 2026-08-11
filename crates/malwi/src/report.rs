//! Turns finished tickets into the analysis JSON, renders the agents' work as
//! it streams, and prints the run summary.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use agentwerk::event::{Event, EventKind, EventName, PolicyKind};
use agentwerk::schemas::Schema;
use agentwerk::{Stats, TicketQueue};
use serde_json::{json, Value};

use crate::analyze::REPORTER_LABEL;
use crate::discovery::{ScanTree, ANALYSIS_LABEL, EXPLORER_LABEL, SEEKER_LABEL, TRACER_LABEL};
use crate::download::CATEGORIZATION_LABEL;
use crate::osint::{CURATION_LABEL, EDITING_LABEL, SCOUTING_LABEL, VERIFICATION_LABEL};

/// Build the analysis JSON from completed analyst tickets. Top-level
/// `status` is the worst across findings (`malicious` > `exploitable`
/// > `benign`).
pub(crate) fn build_analysis(tickets: &TicketQueue, scan_dir: &Path, total_files: usize) -> Value {
    let mut findings: Vec<Value> = Vec::new();
    let mut index: HashMap<(String, Option<u64>, Option<u64>), usize> = HashMap::new();
    let mut unparsed: usize = 0;

    for ticket in tickets.find_tickets(|t| t.has_label(ANALYSIS_LABEL)) {
        let Some(attached) = ticket.result.as_ref() else {
            unparsed += 1;
            continue;
        };
        let Some(obj) = attached.as_object() else {
            unparsed += 1;
            continue;
        };
        let status = match obj.get("status").and_then(|v| v.as_str()) {
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

        // A refilled Seeker can re-hand the same hit; keep one finding per
        // (path, line, column), upgrading to the more severe status if it recurs.
        let new_severity = severity(&status);
        let key = (path.clone(), line, column);
        let finding = json!({
            "status": status,
            "path": path,
            "line": line,
            "column": column,
            "description": description,
        });
        match index.get(&key) {
            Some(&i) => {
                if new_severity > severity(findings[i]["status"].as_str().unwrap_or("")) {
                    findings[i] = finding;
                }
            }
            None => {
                index.insert(key, findings.len());
                findings.push(finding);
            }
        }
    }

    // Counts and the touched-file set come from the deduped findings.
    let mut count_malicious: usize = 0;
    let mut count_exploitable: usize = 0;
    let mut count_benign: usize = 0;
    let mut files_seen: HashSet<String> = HashSet::new();
    for f in &findings {
        files_seen.insert(f["path"].as_str().unwrap_or("").to_string());
        match f["status"].as_str() {
            Some("malicious") => count_malicious += 1,
            Some("exploitable") => count_exploitable += 1,
            _ => count_benign += 1,
        }
    }

    // Worst status across all findings.
    let worst = if count_malicious > 0 {
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
        "status": worst,
        "summary": summary,
        "findings": findings,
    })
}

/// Render the findings array as a Reporter ticket body. `partial_coverage`
/// tells the Reporter the pools were called off early, so an all-clear must
/// stay scoped to the parts examined.
pub(crate) fn render_findings_table(analysis: &Value, partial_coverage: bool) -> String {
    let worst = analysis["status"].as_str().unwrap_or("unknown");
    let empty: Vec<Value> = Vec::new();
    let findings = analysis["findings"].as_array().unwrap_or(&empty);
    let coverage = if partial_coverage {
        "partial, the examination was stopped before it finished"
    } else {
        "full"
    };
    let mut body = String::new();
    body.push_str(&format!(
        "worst_status: {worst}\nfindings: {}\ncoverage: {coverage}\n",
        findings.len()
    ));
    for (i, f) in findings.iter().enumerate() {
        body.push_str(&format!(
            "\n--- Finding {} ---\nstatus: {}\npath: {}\nline: {}\n{}\n",
            i + 1,
            f["status"].as_str().unwrap_or(""),
            f["path"].as_str().unwrap_or(""),
            f["line"]
                .as_u64()
                .map(|n| n.to_string())
                .unwrap_or_default(),
            f["description"].as_str().unwrap_or(""),
        ));
    }
    body
}

/// The Analyst verdict shape, as a plain JSON document.
pub(crate) fn analyst_result_schema_json() -> Value {
    json!({
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["malicious", "exploitable", "benign"]},
            "path": {"type": "string", "minLength": 1},
            "line": {"type": "integer"},
            "column": {"type": "integer"},
            "description": {"type": "string", "minLength": 1},
        },
        // `path` is required so the finding always carries a file the Reporter
        // can read to quote the offending line; a verdict without one is retried.
        "required": ["status", "path", "description"],
    })
}

/// The verdict document above, compiled. The run binds the document itself to
/// the analysis label, so only the test that guards the shape needs a `Schema`.
#[cfg(test)]
fn analyst_result_schema() -> Schema {
    Schema::new(analyst_result_schema_json()).expect("analyst result schema is a valid document")
}

/// Result schema for the Reporter ticket: an object carrying the lay-reader
/// `summary` and the three-paragraph technical `details`. Attaching it makes
/// `finish` reject a malformed or partial result and force a retry,
/// the same guard the analyst verdict relies on. The length floors and limits
/// sit outside the targets the prompt states, so a compliant result is never
/// rejected while a skimped or runaway one is.
pub(crate) fn reporter_result_schema() -> Schema {
    Schema::new(json!({
        "type": "object",
        "properties": {
            "summary": {"type": "string", "minLength": 150, "maxLength": 650},
            "details": {"type": "string", "minLength": 500, "maxLength": 4500},
        },
        "required": ["summary", "details"],
    }))
    .expect("reporter result schema is a valid document")
}

/// Verdict ordering for dedup: `malicious` (2) > `exploitable` (1) > `benign` (0).
fn severity(status: &str) -> u8 {
    match status {
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

pub(crate) fn print_summary(
    tickets: &TicketQueue,
    report_tickets: Option<&TicketQueue>,
    analysis: &Value,
    report_file: &Path,
    scan: &ScanTree,
    scan_dir: &Path,
) {
    let status = analysis["status"].as_str().unwrap_or("unknown");
    let findings = analysis["summary"].as_str().unwrap_or("");
    let scan_stats = tickets.stats();
    // The Reporter runs on its own queue after the scan; fold its counters
    // into the totals so the tally covers the whole run.
    let report_stats = report_tickets.map(|queue| queue.stats());
    let with_report = |count: &dyn Fn(&Stats) -> u64| {
        count(&scan_stats) + report_stats.as_ref().map_or(0, |report| count(report))
    };
    let report_secs = report_stats
        .as_ref()
        .and_then(|report| report.execution_duration())
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let secs = scan_stats
        .execution_duration()
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
        + report_secs;
    let time = if secs >= 60 {
        format!("{} min {} sec", secs / 60, secs % 60)
    } else {
        format!("{secs} sec")
    };

    let marker = match status {
        "malicious" => "\u{1f479} MALICIOUS",
        "exploitable" => "\u{26a0}\u{fe0f}  EXPLOITABLE",
        "benign" => "\u{2705} BENIGN",
        _ => "? UNKNOWN",
    };

    headline("Summary");
    if !findings.is_empty() {
        eprintln!();
        eprintln!("{findings}");
    }
    // Debug view of the Reporter's three-paragraph details, normally read
    // from the report file.
    if let Some(details) = analysis["details"].as_str().filter(|text| !text.is_empty()) {
        eprintln!();
        eprintln!("{details}");
    }
    eprintln!();
    eprintln!("  {marker} · {time}");
    eprintln!();

    eprintln!("  {}", rule("pipeline"));
    let display_labels: &[(&str, &str)] = &[
        (EXPLORER_LABEL, "exploring"),
        (SEEKER_LABEL, "seeking"),
        (TRACER_LABEL, "tracing"),
        (ANALYSIS_LABEL, "analysis"),
    ];
    for (label, display) in display_labels {
        let slice = scan_stats.stats_for_label(label);
        if slice.event_count(EventName::TicketCreated) == 0 {
            continue;
        }
        let done = slice.event_count(EventName::TicketFinished);
        let total = slice.event_count(EventName::TicketCreated);
        eprintln!(
            "  {display:<11}{}  {done}/{total} · {:>2} req",
            progress_bar(done, total),
            slice.event_count(EventName::RequestFinished),
        );
    }

    eprintln!("  {}", rule("run"));
    eprintln!(
        "  {}/{} tickets · {} failed · {} req · {} tools · {}k↑ {}k↓",
        with_report(&|stats: &Stats| stats.event_count(EventName::TicketFinished)),
        with_report(&|stats: &Stats| stats.event_count(EventName::TicketCreated)),
        with_report(&|stats: &Stats| stats.event_count(EventName::TicketFailed)),
        with_report(&|stats: &Stats| stats.event_count(EventName::RequestFinished)),
        with_report(&|stats: &Stats| stats.event_count(EventName::ToolCallStarted)),
        with_report(&Stats::input_tokens) / 1000,
        with_report(&Stats::output_tokens) / 1000,
    );

    // I/O: coverage plus the per-tool failure rollup on one line. A tool failing
    // often points at its prompt or input schema, not the model. Coverage folds
    // the Reporter's opens in the way `with_report` folds its counters.
    let mut opened_paths: Vec<String> = scan_stats.file_stats().into_keys().collect();
    if let Some(report) = report_stats.as_ref() {
        opened_paths.extend(report.file_stats().into_keys());
    }
    let candidate_paths = scan.files_by_ext.values().flatten().map(String::as_str);
    let (opened, scannable) = file_coverage(
        scan_dir,
        candidate_paths,
        opened_paths.iter().map(String::as_str),
    );
    let mut io_parts: Vec<String> = Vec::new();
    if scannable > 0 {
        io_parts.push(format!("{opened}/{scannable} files"));
    }
    let failing_tools = scan_stats.tool_stats();
    for (name, tool) in failing_tools.iter().filter(|(_, tool)| tool.errors() > 0) {
        let rate = tool
            .error_rate()
            .map(|share| (share * 100.0).round() as u64)
            .unwrap_or(0);
        io_parts.push(format!("{name} {}/{} ({rate}%)", tool.errors(), tool.calls));
    }
    if !io_parts.is_empty() {
        eprintln!("  {}", rule("i/o"));
        eprintln!("  {}", io_parts.join(" · "));
    }

    let display_path = std::env::current_dir()
        .ok()
        .and_then(|cwd| report_file.strip_prefix(&cwd).ok().map(Path::to_path_buf))
        .unwrap_or_else(|| report_file.to_path_buf());
    eprintln!();
    eprintln!("  report → {}", display_path.display());
}

/// A section divider: `── {label} ` padded with box-drawing dashes to a fixed
/// width, so the dashboard's groups read as distinct bands.
fn rule(label: &str) -> String {
    const WIDTH: usize = 46;
    let head = format!("── {label} ");
    format!(
        "{head}{}",
        "─".repeat(WIDTH.saturating_sub(head.chars().count()))
    )
}

/// A ten-cell bar filled proportionally to `done / total`, rounded to the
/// nearest cell. Empty when `total` is zero.
fn progress_bar(done: u64, total: u64) -> String {
    const WIDTH: u64 = 10;
    let filled = if total == 0 {
        0
    } else {
        ((done * WIDTH + total / 2) / total).min(WIDTH)
    } as usize;
    format!(
        "{}{}",
        "█".repeat(filled),
        "░".repeat(WIDTH as usize - filled)
    )
}

/// Count scannable files the run opened, as `(opened, scannable)`. Candidate
/// paths are relative to `scan_dir`; opened paths arrive in mixed forms
/// (relative from the Tracer's file map, absolute from the analyst ticket), so
/// both sides are canonicalized to one absolute key before intersecting.
fn file_coverage<'a>(
    scan_dir: &Path,
    candidate_paths: impl Iterator<Item = &'a str>,
    opened_paths: impl Iterator<Item = &'a str>,
) -> (usize, usize) {
    let scannable: HashSet<PathBuf> = candidate_paths
        .filter_map(|relative| fs::canonicalize(scan_dir.join(relative)).ok())
        .collect();
    let opened: HashSet<PathBuf> = opened_paths
        .filter_map(|path| {
            let path = Path::new(path);
            let absolute = if path.is_absolute() {
                path.to_path_buf()
            } else {
                scan_dir.join(path)
            };
            fs::canonicalize(absolute).ok()
        })
        .collect();
    (scannable.intersection(&opened).count(), scannable.len())
}

/// True when a limit bounding the whole run was breached. `MaxSchemaRetries` is
/// excluded: it's a per-ticket budget, so tripping it stops one ticket, not the run.
pub(crate) fn is_run_wide_policy_stop(event: &Event) -> bool {
    matches!(
        event.kind,
        EventKind::PolicyViolated {
            policy: PolicyKind::Time
                | PolicyKind::Turns
                | PolicyKind::InputTokens
                | PolicyKind::OutputTokens,
            ..
        }
    )
}

pub(crate) fn log_event(event: &Event, tickets: &TicketQueue) {
    let agent = agent_display(&event.agent_id);
    let color = agent_color(&event.agent_id);
    let reset = "\x1b[0m";
    match &event.kind {
        EventKind::TicketStarted => {
            let verb = match label_of(&event.agent_id) {
                SEEKER_LABEL => "searching for threats...",
                TRACER_LABEL => "tracing callers...",
                EXPLORER_LABEL => "exploring project...",
                CURATION_LABEL => "auditing the knowledge base...",
                SCOUTING_LABEL => "hunting public sources...",
                EDITING_LABEL => "drafting a page...",
                VERIFICATION_LABEL => "checking a page against its sources...",
                _ => "investigating...",
            };
            eprintln!("{color}[{agent}]{reset} {verb}");
        }
        // The completion line reads the schema-validated stored result, not the
        // raw finish input the analyst may have JSON-encoded as a string.
        EventKind::TicketFinished => {
            if let Some(result) = tickets.get_ticket(&event.ticket_key).and_then(|t| t.result) {
                eprintln!("{color}[{agent}]{reset} {}", finish_summary(&result));
            }
        }
        EventKind::TicketFailed => {
            eprintln!("{color}[{agent}]{reset} ✗ failed {}", event.ticket_key)
        }
        // Suppress "thinking...": the tool-call lines show activity.
        EventKind::RequestStarted { .. } => {}
        EventKind::ToolCallStarted {
            tool_name, input, ..
        } => {
            // A plain finish is reported at TicketFinished from the stored
            // result; a handover still prints, since it names who picks it up.
            if tool_name != "finish" || handover_label(input).is_some() {
                eprintln!(
                    "{color}[{agent}]{reset} {}",
                    tool_call_summary(tool_name, input)
                );
            }
        }
        EventKind::ToolCallFailed {
            tool_name,
            message,
            reason,
            ..
        } => eprintln!(
            "{color}[{agent}]{reset} ✗ {tool_name} ({reason:?}): {}",
            truncate(message, 200)
        ),
        EventKind::RequestFailed {
            reason, message, ..
        } => eprintln!(
            "{color}[{agent}]{reset} ✗ request failed ({reason:?}): {}",
            truncate(message, 200)
        ),
        EventKind::RequestRetried {
            attempt,
            max_attempts,
            reason,
            message,
            ..
        } => eprintln!(
            "{color}[{agent}]{reset} ⟳ retry {attempt}/{max_attempts} ({reason:?}): {}",
            truncate(message, 200)
        ),
        EventKind::SchemaRetried {
            attempt,
            max_attempts,
            message,
        } => eprintln!(
            "{color}[{agent}]{reset} ⟳ retry {attempt}/{max_attempts}: {}",
            truncate(message, 200)
        ),
        EventKind::PolicyViolated { policy, limit } => {
            eprintln!("{color}[{agent}]{reset} ✗ policy violated: {policy:?} limit={limit}")
        }
        _ => {}
    }
}

/// The label a `finish` call hands its child ticket to, when it chains one.
fn handover_label(input: &Value) -> Option<&str> {
    input.get("handover").and_then(|v| v.as_str())
}

fn tool_call_summary(tool_name: &str, input: &Value) -> String {
    match tool_name {
        "glob" => {
            let pattern = input.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
            let path = input.get("path").and_then(|v| v.as_str());
            let mut out = format!("glob {}", truncate(pattern, 60));
            if let Some(p) = path {
                out.push_str(&format!(" in {p}"));
            }
            out
        }
        "grep" => {
            let pattern = input.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
            let mut out = format!("grep {}", truncate(pattern, 60));
            if let Some(glob) = input.get("glob").and_then(|v| v.as_str()) {
                out.push_str(&format!(" glob={glob}"));
            }
            if let Some(path) = input.get("path").and_then(|v| v.as_str()) {
                out.push_str(&format!(" in {path}"));
            }
            if let Some(mode) = input.get("output_mode").and_then(|v| v.as_str()) {
                out.push_str(&format!(" mode={mode}"));
            }
            out
        }
        "read_tickets" => {
            let action = input.get("action").and_then(|v| v.as_str()).unwrap_or("?");
            match action {
                "get" => {
                    let key = input
                        .get("key")
                        .and_then(|v| v.as_str())
                        .unwrap_or("current");
                    format!("reading ticket {key}")
                }
                "list" => {
                    let label = input.get("label").and_then(|v| v.as_str()).unwrap_or("any");
                    let status = input
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("any");
                    format!("listing tickets label={label} status={status}")
                }
                "search" => {
                    let query = input.get("query").and_then(|v| v.as_str()).unwrap_or("");
                    format!("searching tickets for {}", truncate(query, 60))
                }
                other => other.into(),
            }
        }
        "read_file" => {
            let path = input
                .get("path")
                .and_then(|v| v.as_str())
                .map(|s| truncate(s, 80))
                .unwrap_or_default();
            format!("read_file {path}")
        }
        "list_directory" => {
            let path = input
                .get("path")
                .and_then(|v| v.as_str())
                .map(|s| truncate(s, 80))
                .unwrap_or_default();
            format!("list_directory {path}")
        }
        "write_file" => {
            let path = input
                .get("path")
                .and_then(|v| v.as_str())
                .map(|s| truncate(s, 80))
                .unwrap_or_default();
            format!("write_file {path}")
        }
        "manage_tickets" => {
            let action = input.get("action").and_then(|v| v.as_str()).unwrap_or("?");
            match action {
                "create" => {
                    let task_preview = input
                        .get("task")
                        .map(|v| match v {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        })
                        .unwrap_or_default();
                    format!("flagging: {}", truncate(&task_preview, 80))
                }
                other => other.into(),
            }
        }
        "finish" => {
            let to = handover_label(input).unwrap_or("?");
            let result = match input.get("result") {
                Some(Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
                None => String::new(),
            };
            format!("→ handover to {to}: {}", truncate(&result, 80))
        }
        "brave_search" => {
            let query = input.get("query").and_then(|v| v.as_str()).unwrap_or("");
            format!("searching the web for {}", truncate(query, 90))
        }
        "fetch_url" => {
            let url = input.get("url").and_then(|v| v.as_str()).unwrap_or("");
            format!("opening {}", truncate(url, 90))
        }
        "manage_knowledge" => {
            let action = input.get("action").and_then(|v| v.as_str()).unwrap_or("?");
            let slug = input.get("slug").and_then(|v| v.as_str()).unwrap_or("");
            match action {
                // `description` is what the tool names the field; `summary` is
                // kept as a fallback so an older payload still reads as a line.
                "write" => {
                    let summary = input
                        .get("description")
                        .or_else(|| input.get("summary"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if summary.is_empty() {
                        format!("noting {slug}")
                    } else {
                        format!("noting {slug}: {}", truncate(summary, 60))
                    }
                }
                "read" => format!("recalling {slug}"),
                "remove" => format!("removing {slug}"),
                "list" => "listing knowledge".into(),
                other => format!("{other} {slug}"),
            }
        }
        _ => truncate(&serde_json::to_string(input).unwrap_or_default(), 80),
    }
}

/// Render the `→` completion line from a ticket's stored result: the Security
/// Analyst verdict object `{ status, path, description }`, the Curator's gap
/// list, the Verifier's `{ slug, verdict, reason }`, or a plain summary string
/// from other agents. Every schema-carrying result gets a shape of its own,
/// since the fallback prints the whole object and a gap list dumped as JSON
/// buries the run's own log. The result is already schema-validated, so a
/// verdict the analyst JSON-encoded as a string arrives here decoded.
fn finish_summary(result: &Value) -> String {
    if let Some(gaps) = result.get("gaps").and_then(|v| v.as_array()) {
        let topics: Vec<&str> = gaps
            .iter()
            .filter_map(|gap| gap.get("topic").and_then(|v| v.as_str()))
            .collect();
        return format!(
            "→ {} gap(s): {}",
            gaps.len(),
            truncate(&topics.join("; "), 140)
        );
    }
    if let Some(verdict) = result.get("verdict").and_then(|v| v.as_str()) {
        let slug = result.get("slug").and_then(|v| v.as_str()).unwrap_or("");
        let reason = result.get("reason").and_then(|v| v.as_str()).unwrap_or("");
        return format!("→ {verdict} {slug}: {}", truncate(reason, 100));
    }
    if let Some(verdict) = result.get("status").and_then(|v| v.as_str()) {
        let mut out = format!("→ {verdict}");
        if let Some(p) = result.get("path").and_then(|v| v.as_str()) {
            out.push_str(&format!(" {p}"));
        }
        if verdict != "benign" {
            if let Some(d) = result.get("description").and_then(|v| v.as_str()) {
                out.push_str(&format!(": {}", truncate(d, 80)));
            }
        }
        return out;
    }
    let preview = match result {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    format!("→ {}", truncate(&preview, 80))
}

/// The pool each ticket label routes to. agentwerk names an agent after the
/// label it serves, and the labels are what the roles hand over by; the run is
/// read in pool names, so the two are mapped here rather than renaming either.
const POOL_NAMES: [(&str, &str); 10] = [
    (EXPLORER_LABEL, "Explorer"),
    (SEEKER_LABEL, "Seeker"),
    (TRACER_LABEL, "Tracer"),
    (ANALYSIS_LABEL, "Analyst"),
    (REPORTER_LABEL, "Reporter"),
    (CURATION_LABEL, "Curator"),
    (SCOUTING_LABEL, "Scout"),
    (EDITING_LABEL, "Editor"),
    (VERIFICATION_LABEL, "Verifier"),
    (CATEGORIZATION_LABEL, "Categorizer"),
];

/// The label an agent id was built from. agentwerk numbers each label's agents
/// `<label>-<n>`, and no label carries a `-`, so the last one splits the two.
fn label_of(agent_id: &str) -> &str {
    agent_id
        .rsplit_once('-')
        .map_or(agent_id, |(label, _)| label)
}

/// The pool and member number an agent id names: `security_analysis-2` reads as
/// `Analyst 2`. An id from a label no pool covers is shown as it stands, so a
/// new agent is still attributed.
fn agent_display(agent_id: &str) -> String {
    let Some((label, number)) = agent_id.rsplit_once('-') else {
        return agent_id.to_string();
    };
    POOL_NAMES.iter().find(|(l, _)| *l == label).map_or_else(
        || agent_id.to_string(),
        |(_, pool)| format!("{pool} {number}"),
    )
}

/// ANSI color code for an agent. Each pool gets its own color so interleaved
/// output is easy to follow, keyed on what the pool does: the pool that hunts is
/// one color in both commands, the pool that writes another.
fn agent_color(agent_id: &str) -> &'static str {
    match label_of(agent_id) {
        SEEKER_LABEL | SCOUTING_LABEL => "\x1b[35m", // magenta (hunting)
        TRACER_LABEL | EDITING_LABEL => "\x1b[36m",  // cyan (following a thread, writing it up)
        EXPLORER_LABEL | CURATION_LABEL => "\x1b[34m", // blue (surveying)
        _ => "\x1b[32m", // green (Analyst / Verifier / default: judging)
    }
}

pub(crate) fn headline(text: &str) {
    eprintln!("\n\x1b[1;36m=== {text} ===\x1b[0m");
}

/// Yellow `[Scanner]`-prefixed log line for the file-discovery /
/// indicator-scan phase. Matches the agent tag format so the catalogue
/// scanner reads as just another actor in the interleaved output.
pub(crate) fn scanner(msg: impl std::fmt::Display) {
    eprintln!("\x1b[33m[Scanner]\x1b[0m {msg}");
}

pub(crate) fn truncate(s: &str, max: usize) -> String {
    let s = s.replace('\n', " ");
    if s.chars().count() <= max {
        return s;
    }
    let cut: String = s.chars().take(max).collect();
    format!("{cut}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_findings_table_with_per_finding_blocks() {
        let analysis = json!({
            "status": "malicious",
            "findings": [
                {
                    "status": "malicious",
                    "path": "requests/__init__.py",
                    "line": 189,
                    "description": "Backdoor exfiltrates Chrome credentials."
                },
                {
                    "status": "benign",
                    "path": "requests/utils.py",
                    "line": 280,
                    "description": "Standard zipfile usage; package as a whole is poisoned."
                }
            ],
        });
        let body = render_findings_table(&analysis, false);
        assert!(body.starts_with("worst_status: malicious\nfindings: 2\ncoverage: full\n"));
        assert!(body.contains("--- Finding 1 ---"));
        assert!(body.contains("--- Finding 2 ---"));
        assert!(body.contains("status: malicious"));
        assert!(body.contains("path: requests/__init__.py"));
        assert!(body.contains("line: 189"));
        assert!(body.contains("Backdoor exfiltrates Chrome credentials."));
        assert!(body.contains("path: requests/utils.py"));
    }

    #[test]
    fn renders_findings_table_with_empty_findings_array() {
        let analysis = json!({"status": "benign", "findings": []});
        let body = render_findings_table(&analysis, false);
        assert_eq!(body, "worst_status: benign\nfindings: 0\ncoverage: full\n");
    }

    #[test]
    fn renders_findings_table_marks_partial_coverage() {
        let analysis = json!({"status": "benign", "findings": []});
        let body = render_findings_table(&analysis, true);
        assert!(body.contains("coverage: partial"));
    }

    #[test]
    fn analyst_schema_requires_a_well_formed_verdict() {
        let schema = analyst_result_schema();
        // Missing the verdict, or a status outside the enum, is rejected.
        assert!(schema.validate(json!({"description": "x"})).is_err());
        assert!(schema
            .validate(json!({"status": "sketchy", "description": "x"}))
            .is_err());
        // The documented analyst verdict validates.
        assert!(schema
            .validate(json!({
                "status": "malicious", "path": "a.py", "line": 3, "column": 1,
                "description": "decode-then-exec backdoor",
            }))
            .is_ok());
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

    #[test]
    fn finish_summary_keeps_verdict_and_plain_paths() {
        assert_eq!(
            finish_summary(&json!({"status": "benign", "path": "a.go"})),
            "→ benign a.go"
        );
        assert_eq!(finish_summary(&json!("all clear")), "→ all clear");
    }

    /// Guards the research log: the audit's own result is the longest object
    /// the run produces, and the fallback would print all of it as JSON.
    #[test]
    fn a_gap_list_logs_its_topics_rather_than_its_json() {
        let gaps = json!({"gaps": [
            {"topic": "source-build-only payloads", "why": "no page", "query": "a search"},
            {"topic": "container base-layer tampering", "why": "no page", "query": "a search"},
        ]});

        let line = finish_summary(&gaps);

        assert_eq!(
            line,
            "→ 2 gap(s): source-build-only payloads; container base-layer tampering"
        );
    }

    #[test]
    fn a_verdict_logs_the_page_it_judged_and_why() {
        let verdict = json!({
            "slug": "a-new-campaign",
            "verdict": "rejected",
            "reason": "the detectable signal describes a behaviour, not a string",
        });

        let line = finish_summary(&verdict);

        assert_eq!(
            line,
            "→ rejected a-new-campaign: the detectable signal describes a behaviour, not a string"
        );
    }

    #[test]
    fn a_web_search_logs_its_query_rather_than_the_tool_arguments() {
        let call = json!({"query": "PyPI sdist build hook malware 2026", "count": 5});

        let line = tool_call_summary("brave_search", &call);

        assert_eq!(
            line,
            "searching the web for PyPI sdist build hook malware 2026"
        );
    }

    #[test]
    fn a_fetch_logs_the_url_it_opened() {
        let call = json!({"url": "https://example.test/advisory"});

        assert_eq!(
            tool_call_summary("fetch_url", &call),
            "opening https://example.test/advisory"
        );
    }

    #[test]
    fn coverage_counts_files_opened_by_relative_or_absolute_path() {
        // The Tracer opens files by relative path; the analyst opens the same
        // tree by absolute path. Both forms must count against the relative
        // candidate list. Absolute-only matching regressed this to 0.
        let dir = std::env::temp_dir().join(format!("coverage_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("pkg")).unwrap();
        for relative in ["a.py", "pkg/b.py", "c.py"] {
            std::fs::write(dir.join(relative), b"x").unwrap();
        }
        let scan_dir = std::fs::canonicalize(&dir).unwrap();

        let candidates = ["a.py", "pkg/b.py", "c.py"];
        let opened = [
            "a.py".to_string(),
            scan_dir.join("pkg/b.py").to_string_lossy().into_owned(),
        ];
        let coverage = file_coverage(
            &scan_dir,
            candidates.iter().copied(),
            opened.iter().map(String::as_str),
        );

        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            coverage,
            (2, 3),
            "relative + absolute opens match; c.py untouched"
        );
    }

    #[test]
    fn an_agent_id_reads_as_the_pool_and_the_member_it_names() {
        assert_eq!(agent_display("security_analysis-2"), "Analyst 2");
        assert_eq!(agent_display("seeking-1"), "Seeker 1");
        assert_eq!(agent_display("verification-3"), "Verifier 3");
    }

    #[test]
    fn an_agent_id_of_no_known_pool_is_shown_as_it_stands() {
        assert_eq!(agent_display("triage-1"), "triage-1");
        assert_eq!(agent_display("unnumbered"), "unnumbered");
    }

    #[test]
    fn a_pool_is_colored_by_what_it_does_not_by_the_command_it_runs_in() {
        assert_eq!(agent_color("seeking-1"), agent_color("scouting-1"));
        assert_ne!(agent_color("seeking-1"), agent_color("tracing-1"));
        assert_ne!(agent_color("tracing-1"), agent_color("security_analysis-1"));
    }

    #[test]
    fn progress_bar_fills_proportionally_and_survives_zero_total() {
        assert_eq!(progress_bar(0, 2), "░░░░░░░░░░");
        assert_eq!(progress_bar(1, 2), "█████░░░░░");
        assert_eq!(progress_bar(1, 1), "██████████");
        assert_eq!(progress_bar(0, 0), "░░░░░░░░░░");
    }
}
