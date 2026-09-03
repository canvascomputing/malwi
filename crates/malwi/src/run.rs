//! What the operator is told about a run: the event stream as it arrives, the
//! counters folded out of the log, and the summary printed at the end. Every
//! command writes through it, which is why it belongs to none of them.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use agentwerk::{Event, Werk};
use serde::{Serialize, Serializer};
use serde_json::Value;

use crate::analyze::discovery::{
    ScanTree, ANALYSIS_LABEL, EXPLORER_LABEL, SEEKER_LABEL, TRACER_LABEL,
};
use crate::analyze::investigation::{investigated_type, is_investigation};
use crate::analyze::REPORTER_LABEL;
use crate::download::CATEGORIZATION_LABEL;
use crate::osint::{CURATION_LABEL, EDITING_LABEL, SCOUTING_LABEL, VERIFICATION_LABEL};
use crate::types::Type;

/// What a run spent, folded from the events its Werk logged.
///
/// agentwerk keeps its own counters to itself, so every figure the summary line
/// and `analysis.json` carry is folded here. The log is one file per working
/// directory, so a second Werk using the same directory, as the report
/// phase does in the scan's, is covered by the same fold.
#[derive(Debug, Default, Serialize)]
pub(crate) struct RunStats {
    pub(crate) input_tokens: u64,
    pub(crate) output_tokens: u64,
    /// From the first logged event to the last, so it spans every Werk that
    /// wrote to the log.
    #[serde(rename = "execution_duration_secs", serialize_with = "as_secs")]
    pub(crate) execution_duration: Duration,
    /// One count per event name.
    pub(crate) events: BTreeMap<String, u64>,
    /// Calls and failures per tool.
    pub(crate) tools: BTreeMap<String, ToolCalls>,
    /// The same counts again, split by the label of the task the event
    /// concerns. They draw the pipeline bars.
    pub(crate) labels: BTreeMap<String, BTreeMap<String, u64>>,
    /// Every file path a tool opened, which the coverage figure intersects with
    /// the scannable tree. Kept out of the JSON: it is one entry per file read.
    #[serde(skip)]
    opened_paths: HashSet<String>,
}

/// One tool's calls and how many of them failed.
#[derive(Debug, Default, Serialize)]
pub(crate) struct ToolCalls {
    pub(crate) calls: u64,
    pub(crate) errors: u64,
}

impl ToolCalls {
    /// The share of calls that failed, in whole percent. Zero when the tool was
    /// never called.
    fn error_rate(&self) -> u64 {
        match self.calls {
            0 => 0,
            calls => (self.errors * 100 + calls / 2) / calls,
        }
    }
}

impl RunStats {
    /// Fold everything the Werk's log holds. Reads the log from disk, so it
    /// answers for a finished run as readily as one still working.
    pub(crate) fn fold(werk: &Werk) -> Self {
        let mut stats = RunStats::default();
        let mut earliest: Option<u64> = None;
        let mut latest: u64 = 0;
        for event in werk.find_events(|_: &Event| true) {
            let name = event.get_name().to_string();
            *stats.events.entry(name.clone()).or_default() += 1;
            if let Some(label) = event.get_label() {
                *stats
                    .labels
                    .entry(label.to_string())
                    .or_default()
                    .entry(name.clone())
                    .or_default() += 1;
            }
            let created_at = event.get_created_at();
            earliest = Some(earliest.map_or(created_at, |first| first.min(created_at)));
            latest = latest.max(created_at);
            let data = event.get_data();
            match event.get_name() {
                Event::REQUEST_FINISHED => {
                    stats.input_tokens += data["usage"]["input_tokens"].as_u64().unwrap_or(0);
                    stats.output_tokens += data["usage"]["output_tokens"].as_u64().unwrap_or(0);
                }
                Event::TOOL_CALL_STARTED => {
                    let tool_name = data["tool_name"].as_str().unwrap_or_default();
                    stats.tools.entry(tool_name.to_string()).or_default().calls += 1;
                    if tool_name == "read_file" {
                        if let Some(path) = data["input"]["path"].as_str() {
                            stats.opened_paths.insert(path.to_string());
                        }
                    }
                }
                Event::TOOL_CALL_FAILED => {
                    let tool_name = data["tool_name"].as_str().unwrap_or_default();
                    stats.tools.entry(tool_name.to_string()).or_default().errors += 1;
                }
                _ => {}
            }
        }
        stats.execution_duration =
            Duration::from_millis(latest.saturating_sub(earliest.unwrap_or(latest)));
        stats
    }

    /// How often an event happened across the run.
    pub(crate) fn count(&self, event: &str) -> u64 {
        self.events.get(event).copied().unwrap_or(0)
    }

    /// How often an event happened on the tasks one label owns.
    pub(crate) fn label_count(&self, label: &str, event: &str) -> u64 {
        self.labels
            .get(label)
            .and_then(|counts| counts.get(event))
            .copied()
            .unwrap_or(0)
    }
}

/// Durations reach the JSON as whole seconds; `Duration` is the in-memory type.
fn as_secs<S: Serializer>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_u64(duration.as_secs())
}

pub(crate) fn print_summary(
    stats: &RunStats,
    analysis: &Value,
    report_file: &Path,
    scan: &ScanTree,
    scan_dir: &Path,
) {
    let verdict = analysis["verdict"].as_str().unwrap_or("unknown");
    let findings = analysis["summary"].as_str().unwrap_or("");
    let secs = stats.execution_duration.as_secs();
    let time = if secs >= 60 {
        format!("{} min {} sec", secs / 60, secs % 60)
    } else {
        format!("{secs} sec")
    };

    let marker = match verdict {
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
        let total = stats.label_count(label, Event::TASK_CREATED);
        if total == 0 {
            continue;
        }
        let done = stats.label_count(label, Event::TASK_FINISHED);
        eprintln!(
            "  {display:<11}{}  {done}/{total} · {:>2} req",
            progress_bar(done, total),
            stats.label_count(label, Event::REQUEST_FINISHED),
        );
    }

    eprintln!("  {}", rule("run"));
    eprintln!(
        "  {}/{} tasks · {} failed · {} req · {} tools · {}k↑ {}k↓",
        stats.count(Event::TASK_FINISHED),
        stats.count(Event::TASK_CREATED),
        stats.count(Event::TASK_FAILED),
        stats.count(Event::REQUEST_FINISHED),
        stats.count(Event::TOOL_CALL_STARTED),
        stats.input_tokens / 1000,
        stats.output_tokens / 1000,
    );

    // I/O: coverage plus the per-tool failure rollup on one line. A tool failing
    // often points at its prompt or input schema, not the model.
    let candidate_paths = scan.files_by_ext.values().flatten().map(String::as_str);
    let (opened, scannable) = file_coverage(
        scan_dir,
        candidate_paths,
        stats.opened_paths.iter().map(String::as_str),
    );
    let mut io_parts: Vec<String> = Vec::new();
    if scannable > 0 {
        io_parts.push(format!("{opened}/{scannable} files"));
    }
    for (name, tool) in stats.tools.iter().filter(|(_, tool)| tool.errors > 0) {
        io_parts.push(format!(
            "{name} {}/{} ({}%)",
            tool.errors,
            tool.calls,
            tool.error_rate()
        ));
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
/// paths are relative to `scan_dir`; opened paths arrive in mixed forms from
/// task bodies and agent calls, so
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
/// excluded: it's a per-task budget, so tripping it stops one task, not the run.
pub(crate) fn is_run_wide_policy_stop(event: &Event) -> bool {
    event.get_name() == Event::POLICY_VIOLATED
        && matches!(
            event.get_data()["policy"].as_str(),
            Some("time" | "turns" | "input_tokens" | "output_tokens")
        )
}

pub(crate) fn log_event(event: &Event, werk: &Werk) {
    let agent_id = event.get_agent_id();
    let agent = agent_display(agent_id);
    let color = agent_color(agent_id);
    let reset = "\x1b[0m";
    let data = event.get_data();
    match event.get_name() {
        Event::TASK_STARTED => {
            let verb = match label_of(agent_id) {
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
        Event::TASK_FINISHED => {
            if let Some(task) = werk.get_task(event.get_task_id()) {
                let investigating = is_investigation(werk, &task)
                    .then(|| investigated_type(werk, &task))
                    .flatten();
                if let Some(result) = task.get_result() {
                    eprintln!(
                        "{color}[{agent}]{reset} {}",
                        finish_summary(result, investigating)
                    );
                }
            }
        }
        Event::TASK_FAILED => {
            eprintln!("{color}[{agent}]{reset} ✗ failed {}", event.get_task_id())
        }
        // Suppress "thinking...": the tool-call lines show activity.
        Event::REQUEST_STARTED => {}
        Event::TOOL_CALL_STARTED => {
            let tool_name = data["tool_name"].as_str().unwrap_or_default();
            let input = &data["input"];
            // A finish is reported from the stored, validated result when the
            // task-finished event arrives.
            if tool_name != "finish" {
                eprintln!(
                    "{color}[{agent}]{reset} {}",
                    tool_call_summary(tool_name, input)
                );
            }
        }
        Event::TOOL_CALL_FAILED => eprintln!(
            "{color}[{agent}]{reset} ✗ {tool_name} ({reason:?}): {}",
            truncate(data["message"].as_str().unwrap_or_default(), 200),
            tool_name = data["tool_name"].as_str().unwrap_or_default(),
            reason = data["kind"],
        ),
        Event::REQUEST_FAILED => eprintln!(
            "{color}[{agent}]{reset} ✗ request failed ({reason:?}): {}",
            truncate(data["message"].as_str().unwrap_or_default(), 200),
            reason = data["kind"],
        ),
        Event::REQUEST_RETRIED => eprintln!(
            "{color}[{agent}]{reset} ⟳ retry {attempt}/{max_attempts} ({reason:?}): {}",
            truncate(data["message"].as_str().unwrap_or_default(), 200),
            attempt = data["attempt"],
            max_attempts = data["max_attempts"],
            reason = data["kind"],
        ),
        Event::SCHEMA_RETRIED => eprintln!(
            "{color}[{agent}]{reset} ⟳ retry {attempt}/{max_attempts}: {}",
            truncate(data["message"].as_str().unwrap_or_default(), 200),
            attempt = data["attempt"],
            max_attempts = data["max_attempts"],
        ),
        Event::POLICY_VIOLATED => {
            eprintln!(
                "{color}[{agent}]{reset} ✗ limit reached: {} limit={}",
                data["policy"], data["limit"]
            )
        }
        _ => {}
    }
}

/// The label a `finish` call hands its child task to, when it chains one.
fn handover_label(input: &Value) -> Option<&str> {
    input.get("handover").and_then(|handover| {
        handover
            .as_str()
            .or_else(|| handover.get("label").and_then(Value::as_str))
    })
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
        "task" => {
            let action = input.get("action").and_then(|v| v.as_str()).unwrap_or("?");
            match action {
                "task" | "result" => {
                    let id = input
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("current");
                    format!("reading task {id}")
                }
                "list" => {
                    let aql = input.get("aql").and_then(|v| v.as_str()).unwrap_or("all");
                    format!("listing tasks: {}", truncate(aql, 60))
                }
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
        // Configured handovers are reported from the task completion event.
        "finish" => {
            let to = handover_label(input).unwrap_or("?");
            match input.get("result") {
                Some(Value::String(s)) => format!("→ handover to {to}: {}", truncate(s, 80)),
                Some(other) => format!("→ handover to {to}: {}", truncate(&other.to_string(), 80)),
                None => format!("→ handover to {to}"),
            }
        }
        "brave_search" => {
            let query = input.get("query").and_then(|v| v.as_str()).unwrap_or("");
            format!("searching the web for {}", truncate(query, 90))
        }
        "fetch" => {
            let url = input.get("url").and_then(|v| v.as_str()).unwrap_or("");
            format!("opening {}", truncate(url, 90))
        }
        "knowledge" => {
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

/// Render the `→` completion line from a task's stored result: the Security
/// Analyst finding `{ verdict, path, description }`, the Curator's gap list,
/// the Verifier's `{ status, reason }`, or a plain summary string from other
/// agents. Every schema-carrying result gets a branch of its own,
/// since the fallback prints the whole object and a gap list dumped as JSON
/// buries the run's own log.
fn finish_summary(result: &Value, investigating: Option<&dyn Type>) -> String {
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
    // A Scout's dossier, whose sections would otherwise print as raw JSON.
    if let Some(signal) = result.get("signal") {
        return format!(
            "→ dossier: {} ({} sources)",
            truncate(result["incident"]["text"].as_str().unwrap_or(""), 100),
            signal["sources"].as_array().map_or(0, Vec::len),
        );
    }
    if let Some(status) = result.get("status").and_then(|v| v.as_str()) {
        let reason = result.get("reason").and_then(|v| v.as_str()).unwrap_or("");
        return format!("→ {status}: {}", truncate(reason, 100));
    }
    if let Some(outcome) = result.get("outcome").and_then(|v| v.as_str()) {
        if outcome != "hit" {
            let pattern = result.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
            return format!("→ nothing for {}", truncate(pattern, 80));
        }
        let why = result.get("why").and_then(|v| v.as_str()).unwrap_or("");
        return format!("→ hit {}: {}", location_of(result), truncate(why, 80));
    }
    // A trace, whose fields would otherwise print as raw JSON through the
    // fallback. An empty chain is the dead end.
    if let Some(steps) = result.get("trace").and_then(|v| v.as_array()) {
        let at = location_of(result);
        return match steps.len() {
            0 => format!("→ no caller reaches {at}"),
            1 => format!("→ traced {at}: 1 step"),
            n => format!("→ traced {at}: {n} steps"),
        };
    }
    if let Some(verdict) = result.get("verdict").and_then(|v| v.as_str()) {
        let mut out = format!("→ {verdict}");
        // The bracket is what an investigation answered, so the opening
        // finding prints no type: that is the question, not the answer.
        if let Some(finding_type) = investigating {
            match result.get("type").and_then(|v| v.as_str()) {
                Some(name) if name == finding_type.name() => out.push_str(&format!(" [{name}]")),
                _ => out.push_str(&format!(" [{} ruled out]", finding_type.name())),
            }
        }
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

/// A `path`, `line`, `column` triple as `path:line`, for one log line.
fn location_of(result: &Value) -> String {
    let path = result["path"].as_str().unwrap_or("");
    match result["line"].as_u64() {
        Some(line) => format!("{path}:{line}"),
        None => path.to_string(),
    }
}

/// The pool each task label routes to. agentwerk names an agent after the
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
    use crate::types;
    use serde_json::json;

    /// The trace a Tracer hands the Analyst.
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

    #[test]
    fn a_seeker_logs_the_hit_it_handed_over_or_the_pattern_that_came_back_empty() {
        assert_eq!(
            finish_summary(&seeker_hit(), None),
            "→ hit lib/telemetry.js:42: decodes a blob and evaluates it at module load"
        );
        assert_eq!(
            finish_summary(
                &json!({"outcome": "nothing", "pattern": "curl -fsSL"}),
                None
            ),
            "→ nothing for curl -fsSL"
        );
    }

    #[test]
    fn finish_summary_keeps_verdict_and_plain_paths() {
        assert_eq!(
            finish_summary(&json!({"verdict": "benign", "path": "a.go"}), None),
            "→ benign a.go"
        );
        assert_eq!(finish_summary(&json!("all clear"), None), "→ all clear");
    }

    /// The bracket is the investigation's answer. The Analyst's own
    /// opening finding carries the same `type` and must print none, or the stream
    /// reads as two findings on one piece of code.
    #[test]
    fn an_investigation_logs_what_it_established() {
        let finding_type = types::find("side-loading").expect("side-loading is registered");
        let established = json!({
            "verdict": "exploitable", "path": "a.py", "type": finding_type.name(),
            "description": "fetched at import time",
        });
        assert_eq!(
            finish_summary(&established, Some(finding_type)),
            "→ exploitable [side-loading] a.py: fetched at import time"
        );
        assert_eq!(
            finish_summary(&established, None),
            "→ exploitable a.py: fetched at import time"
        );
        let ruled_out = json!({
            "verdict": "exploitable", "path": "a.py",
            "description": "the artefact ships with the repository",
        });
        assert_eq!(
            finish_summary(&ruled_out, Some(finding_type)),
            "→ exploitable [side-loading ruled out] a.py: the artefact ships with the repository"
        );
    }

    /// Guards the research log: the audit's own result is the longest object
    /// the run produces, and the fallback would print all of it as JSON.
    #[test]
    fn a_gap_list_logs_its_topics_rather_than_its_json() {
        let gaps = json!({"gaps": [
            {"topic": "source-build-only payloads", "why": "no page", "query": "a search"},
            {"topic": "container base-layer tampering", "why": "no page", "query": "a search"},
        ]});

        let line = finish_summary(&gaps, None);

        assert_eq!(
            line,
            "→ 2 gap(s): source-build-only payloads; container base-layer tampering"
        );
    }

    #[test]
    fn a_trace_logs_where_it_landed_and_how_far_it_got() {
        assert_eq!(
            finish_summary(&trace_result(), None),
            "→ traced scripts/install.js:13: 3 steps"
        );
        let mut dead_end = trace_result();
        dead_end["trace"] = json!([]);
        assert_eq!(
            finish_summary(&dead_end, None),
            "→ no caller reaches scripts/install.js:13"
        );
    }

    /// The status names no slug: the Editor's task carries it, so the
    /// Verifier never retypes a key the install looks the page up by.
    #[test]
    fn a_verification_status_logs_why_it_was_rejected() {
        let result = json!({
            "status": "rejected",
            "reason": "the detectable signal describes a behaviour, not a string",
        });

        let line = finish_summary(&result, None);

        assert_eq!(
            line,
            "→ rejected: the detectable signal describes a behaviour, not a string"
        );
    }

    /// An inline handover names its receiver from v0.1.29's handover object and
    /// previews a result only when the call carries one.
    #[test]
    fn a_handover_names_its_receiver_and_previews_a_result_only_when_there_is_one() {
        assert_eq!(
            tool_call_summary(
                "finish",
                &json!({"handover": {"label": "tracing", "task": "trace it"}})
            ),
            "→ handover to tracing"
        );
        assert_eq!(
            tool_call_summary(
                "finish",
                &json!({
                    "handover": {"label": "tracing", "task": "trace it"},
                    "result": "a lead",
                })
            ),
            "→ handover to tracing: a lead"
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
            tool_call_summary("fetch", &call),
            "opening https://example.test/advisory"
        );
    }

    #[test]
    fn coverage_counts_files_opened_by_relative_or_absolute_path() {
        // Agent calls use both forms. Both must count against the relative
        // candidate list because absolute-only matching regressed this to 0.
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
