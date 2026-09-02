//! The `analyze` command: finds IoC matches and routes each through reachability
//! analysis to an Analyst. Curated extensions scan against their
//! catalogues and hand their matches to a Tracer. In parallel, Seekers search
//! the tree in a bounded series of regex `grep` passes; result hooks route each
//! interesting hit to a Tracer. The Tracer establishes how the flagged code could be
//! reached and hands that analysis to an Analyst for a finding; an
//! `exploitable` or `malicious` finding with a registered type opens one
//! focused investigation. A pool of
//! Explorers captures the project's intent alongside, so analysis has that context.
//! Explorers, Seekers, Tracers, and Analysts share one `Werk`; once the
//! pools drain, the Reporter phrases the verdict on its own uncapped queue, so
//! a `--max-time` stop never cuts the summary.

pub(crate) mod analysis;
pub(crate) mod discovery;
pub(crate) mod investigation;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentwerk::agents::Trajectory;
use agentwerk::providers::{Model, Provider};
use agentwerk::tools::{GlobTool, GrepTool, ListDirectoryTool, ReadFileTool, Tool};
use agentwerk::{Agent, Knowledge, Policy, Schema, Task, Werk};
use serde_json::{json, Value};

use crate::cli::{
    additional_focus, agent_name, default_model, parse_duration, rejected, resolve_models,
    verify_models, CliExit, ModelTable,
};
use crate::run::{is_run_wide_policy_stop, log_event, print_summary, RunStats};
use crate::types::finding_schema_json;
use analysis::{
    build_analysis, normalize_reporter_summary, render_findings_table, reporter_result_schema,
    seeker_result_schema_json, trace_result_schema_json,
};
use discovery::{ScanTree, Scanner, ANALYSIS_LABEL, EXPLORER_LABEL, SEEKER_LABEL, TRACER_LABEL};
use investigation::{
    investigation, is_failure_verdict, is_finding_verdict, is_investigation, FailureThreshold,
};

const SEEKER_AGENT: &str = include_str!("analyze/agents/seeker.md");
const ANALYST_AGENT: &str = include_str!("analyze/agents/analyst.md");
const ANALYST_VERDICTS: &str = include_str!("analyze/agents/verdicts.md");
const TRACER_AGENT: &str = include_str!("analyze/agents/tracer.md");
const EXPLORER_AGENT: &str = include_str!("analyze/agents/explorer.md");
const REPORTER_AGENT: &str = include_str!("analyze/agents/reporter.md");
const ANALYST_HANDOVER: &str = "<trace_evidence>\n{parent_result}\n</trace_evidence>";
const EXPLORATION_BODY: &str = concat!(
    "<overview_assignment>\n",
    "- Describe the scanned project from file-map-01.\n",
    "- Read at most three high-level files.\n",
    "- Save project-overview and return one line.\n",
    "</overview_assignment>"
);
const SEARCH_BODY: &str = concat!(
    "<search_assignment>\n",
    "- Choose one untested suspicious pattern supported by the file map.\n",
    "- Search for it in file contents.\n",
    "- Save every query and return one match or `nothing`.\n",
    "</search_assignment>"
);
pub(crate) const REPORTER_LABEL: &str = "reporter";
const REPORTER_NAME: &str = "Reporter";

/// Pool name and the label its tasks carry, shared by the built agents and
/// the `--models` roster so the two cannot disagree.
const POOLS: [(&str, &str); 4] = [
    ("Analyst", ANALYSIS_LABEL),
    ("Seeker", SEEKER_LABEL),
    ("Tracer", TRACER_LABEL),
    ("Explorer", EXPLORER_LABEL),
];

/// What a policy stop calls off, sparing the investigations already open. An
/// empty `IN ()` list does not parse, so no spared ID means no exclusion.
fn policy_stop_query(spared: &[String]) -> String {
    let pools = format!(
        "pending = true AND label IN ({})",
        POLICY_STOP_LABELS.join(", ")
    );
    match spared.is_empty() {
        true => pools,
        false => format!("{pools} AND id NOT IN ({})", spared.join(", ")),
    }
}

/// What a selected failure threshold calls off. The analysis label covers
/// investigations too.
fn failure_query() -> String {
    format!("pending = true AND label IN ({SEEKER_LABEL}, {TRACER_LABEL}, {ANALYSIS_LABEL})")
}

/// What a first ctrl-c calls off, leaving the backlog to drain into a report.
fn wind_down_query() -> String {
    format!("pending = true AND label IN ({EXPLORER_LABEL}, {SEEKER_LABEL})")
}

/// Shared `finish` calling convention, substituted into every agent
/// whose task carries a `Schema`. One source of truth instead of each
/// agent's `Output` section hand-writing its own wording, since a model
/// that leaves a field JSON-encoded as a string (rather than emitting it as
/// a native array or object) fails schema validation.
const OUTPUT_CONTRACT: &str = include_str!("output_contract.md");

/// Templates every agent is given, whatever its own role names: a role whose
/// builder forgot one ships the `{placeholder}` to the model as literal text.
fn shared_templates(additional_focus: &str) -> [(&'static str, &str); 2] {
    [
        ("additional_focus", additional_focus),
        ("output_contract", OUTPUT_CONTRACT.trim()),
    ]
}

/// The tools each pool is given. Named once so a role's `Tools:` list and the
/// builder cannot drift: a role naming a tool it was not given spends a turn on
/// `ToolNotFound`, and one omitting a tool it has never reaches for it. Every
/// agent also gets `knowledge` from its store and `finish` by default, which is
/// why neither is listed here.
fn analyst_tools() -> Vec<Tool> {
    vec![
        ReadFileTool.into(),
        ListDirectoryTool.into(),
        GlobTool.into(),
        GrepTool.into(),
    ]
}

fn seeker_tools() -> Vec<Tool> {
    vec![GrepTool.into()]
}

fn tracer_tools() -> Vec<Tool> {
    vec![
        ReadFileTool.into(),
        ListDirectoryTool.into(),
        GlobTool.into(),
        GrepTool.into(),
    ]
}

fn explorer_tools() -> Vec<Tool> {
    vec![
        ReadFileTool.into(),
        ListDirectoryTool.into(),
        GlobTool.into(),
    ]
}

fn reporter_tools() -> Vec<Tool> {
    vec![ReadFileTool.into()]
}

/// Distinct searches a Seeker aims for per task before the pool refills it.
/// Injected into the prompt so the target lives in one place.
const SEARCHES_PER_TASK: u32 = 10;

/// Maximum number of Seeker passes in one analysis run.
const SEEKER_PASSES: usize = 20;

/// What a policy stop calls off. A type investigation is spared by ID: an
/// investigation in flight is the detail the run paid an Analyst for, and with
/// the analysis label off it opens nothing new.
const POLICY_STOP_LABELS: [&str; 4] = [EXPLORER_LABEL, SEEKER_LABEL, TRACER_LABEL, ANALYSIS_LABEL];

/// The scanner's working folder: task state, knowledge stores, and the analysis
/// output all live here. Named for the project and wiped at the start of every
/// run so nothing carries over from a prior scan.
const WORK_DIR: &str = ".malwi";

/// Where a single-file target is copied so the scan still walks a tree. Inside
/// [`WORK_DIR`], so the next run's wipe takes the copy with it, which is why the
/// target is staged after that wipe rather than before.
const INPUT_DIR: &str = ".malwi/input";

/// What the operator named as the thing to analyze.
pub(crate) enum Target {
    /// A directory, scanned where it lies.
    Directory(PathBuf),
    /// A single file, copied into a directory of its own before the scan.
    File(PathBuf),
    /// What no local path resolves to: a package name, a URL, or a repository,
    /// read as a prompt for the agent that will fetch it.
    Prompt(String),
}

impl Target {
    /// Classify what the operator named. Nothing is fetched here: a name no
    /// path resolves to is carried as written until the run tries to reach it.
    pub(crate) fn from_arg(arg: &str) -> Self {
        let path = Path::new(arg);
        match fs::metadata(path) {
            Ok(meta) if meta.is_dir() => Target::Directory(path.to_path_buf()),
            Ok(meta) if meta.is_file() => Target::File(path.to_path_buf()),
            _ => Target::Prompt(arg.to_string()),
        }
    }

    /// The directory the scan walks. A file is copied into `input_dir` first, so
    /// every phase behind this call sees a tree. `input_dir` is recreated here,
    /// so the caller must have finished wiping the folder that holds it.
    pub(crate) fn resolve(&self, input_dir: &Path) -> Result<PathBuf, String> {
        match self {
            Target::Directory(path) => fs::canonicalize(path)
                .map_err(|e| format!("cannot resolve directory '{}': {e}", path.display())),
            Target::File(path) => stage_file(path, input_dir),
            Target::Prompt(text) => Err(format!(
                "nothing to analyze at '{text}': malwi takes a directory or a single file"
            )),
        }
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Directory(path) | Target::File(path) => write!(f, "{}", path.display()),
            Target::Prompt(text) => write!(f, "{text}"),
        }
    }
}

/// Copy `file` into an emptied `input_dir` and return that directory.
fn stage_file(file: &Path, input_dir: &Path) -> Result<PathBuf, String> {
    let name = file
        .file_name()
        .ok_or_else(|| format!("cannot analyze '{}': it names no file", file.display()))?;
    let _ = fs::remove_dir_all(input_dir);
    fs::create_dir_all(input_dir)
        .map_err(|e| format!("cannot create {}: {e}", input_dir.display()))?;
    fs::copy(file, input_dir.join(name)).map_err(|e| {
        format!(
            "cannot copy '{}' into {}: {e}",
            file.display(),
            input_dir.display()
        )
    })?;
    fs::canonicalize(input_dir).map_err(|e| format!("cannot resolve {}: {e}", input_dir.display()))
}

/// Options of `malwi analyze <TARGET>`.
pub(crate) struct Args {
    pub(crate) target: Target,
    pub(crate) max_turns: Option<u32>,
    pub(crate) max_time: Option<Duration>,
    pub(crate) concurrency: usize,
    pub(crate) output_file: Option<PathBuf>,
    pub(crate) failure_threshold: Option<FailureThreshold>,
    pub(crate) instruction: Option<String>,
    pub(crate) models: Option<ModelTable>,
}

pub(crate) fn parse(args: &[String]) -> Result<Args, CliExit> {
    let mut target: Option<Target> = None;
    let mut max_turns: Option<u32> = None;
    let mut max_time: Option<Duration> = None;
    let mut concurrency: usize = 2;
    let mut output_file: Option<PathBuf> = None;
    let mut failure_threshold: Option<FailureThreshold> = None;
    let mut instruction: Option<String> = None;
    let mut models: Option<ModelTable> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--max-turns" => {
                i += 1;
                max_turns = Some(
                    args.get(i)
                        .and_then(|s| s.parse().ok())
                        .ok_or_else(|| rejected("--max-turns expects a positive number"))?,
                );
            }
            "--max-time" => {
                i += 1;
                max_time = Some(
                    args.get(i)
                        .and_then(|s| parse_duration(s))
                        .ok_or_else(|| rejected("--max-time expects e.g. 90, 30s, 5m, 1h"))?,
                );
            }
            "--concurrency" => {
                i += 1;
                concurrency = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| rejected("--concurrency expects a positive number"))?;
            }
            "--output" => {
                i += 1;
                output_file = Some(PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| rejected("--output expects a path"))?,
                ));
            }
            "--fail-malicious" => {
                if failure_threshold.is_none() {
                    failure_threshold = Some(FailureThreshold::Malicious);
                }
            }
            "--fail-exploitable" => {
                failure_threshold = Some(FailureThreshold::Exploitable);
            }
            "--instruction" => {
                i += 1;
                instruction = Some(
                    args.get(i)
                        .cloned()
                        .ok_or_else(|| rejected("--instruction expects text"))?,
                );
            }
            "--models" => {
                i += 1;
                let path = args
                    .get(i)
                    .map(Path::new)
                    .ok_or_else(|| rejected("--models expects a path"))?;
                models = Some(ModelTable::load(path).map_err(CliExit::ArgumentRejected)?);
            }
            "-h" | "--help" => return Err(CliExit::HelpRequested(help())),
            arg if arg.starts_with('-') => return Err(rejected(&format!("unknown flag: {arg}"))),
            _ => target = Some(Target::from_arg(&args[i])),
        }
        i += 1;
    }

    Ok(Args {
        target: target.ok_or_else(|| CliExit::ArgumentRejected(help()))?,
        max_turns,
        max_time,
        concurrency,
        output_file,
        failure_threshold,
        instruction,
        models,
    })
}

pub(crate) fn help() -> String {
    "malwi analyze. Perform a deep security evaluation of a given file or directory.

Usage: malwi analyze <TARGET> [OPTIONS]

Alias: a

Options:
      --concurrency <N>        Agent pool size per phase (default: 2)
      --max-turns <N>          Per-queue turn limit (default: unlimited)
      --max-time <DUR>         Time limit. Bare seconds or s/m/h suffix (default: unlimited)
      --output <FILE>          Write analysis JSON to FILE (default: .malwi/analysis.json)
      --fail-malicious         Stop and exit 2 on the first confirmed malicious finding
      --fail-exploitable       Stop and exit 2 on the first exploitable or malicious finding
      --instruction <TEXT>     Append a custom instruction to every agent's prompt
      --models <FILE>          One model per agent as JSON, keyed by task label,
                               pool name, or agent name. A value is a model name or
                               an object of model, reasoning, and context_window
                               (default: every agent runs the model the environment
                               names)
  -h, --help                   Show this help

Examples:
  malwi analyze ./src
  malwi a ./node_modules/left-pad"
        .to_string()
}

pub(crate) async fn run(args: Args) {
    let concurrency = args.concurrency.max(1);
    let roster = roster(concurrency);
    let models = resolve_models(args.models.as_ref(), &roster, default_model);
    let provider = Provider::from_env().unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    });

    verify_models(&provider, &models).await;

    // Start every run from a clean working folder, and before the target is
    // staged into it: no task state, knowledge, or results carried over from a
    // prior scan, and no copy of a prior scan's file left behind.
    let _ = fs::remove_dir_all(WORK_DIR);

    let scan_dir = args
        .target
        .resolve(Path::new(INPUT_DIR))
        .unwrap_or_else(|message| {
            eprintln!("{message}");
            std::process::exit(1);
        });

    let scan = ScanTree::collect(&scan_dir);
    if scan.files_by_ext.is_empty() {
        eprintln!(
            "no files with extensions found under {} ({} file(s) walked)",
            args.target, scan.files,
        );
        std::process::exit(1);
    }

    let files_walked = scan.files;

    // Seed the attack-pattern pages before indexing: `Knowledge::load` builds its
    // index from whatever it finds on disk, so the seed must be in place first.
    let project_dir = format!("{WORK_DIR}/project");
    if let Err(e) = crate::attacks::copy_seed_into(std::path::Path::new(&project_dir)) {
        eprintln!("cannot seed project knowledge: {e}");
        std::process::exit(1);
    }
    let project_knowledge = Knowledge::load(Path::new(&project_dir).join("knowledge"))
        .unwrap_or_else(|e| {
            eprintln!("cannot open project knowledge: {e}");
            std::process::exit(1);
        });

    // Run-scoped writable store, seeded with the same attack-pattern pages the
    // Tracer gets. The Seeker records each query it runs here, so a refilled task
    // reads the index and skips shapes already tried.
    let searches_dir = format!("{WORK_DIR}/searches");
    if let Err(e) = crate::attacks::copy_seed_into(std::path::Path::new(&searches_dir)) {
        eprintln!("cannot seed search knowledge: {e}");
        std::process::exit(1);
    }
    let seeker_knowledge = Knowledge::load(Path::new(&searches_dir).join("knowledge"))
        .unwrap_or_else(|e| {
            eprintln!("cannot open search knowledge: {e}");
            std::process::exit(1);
        });

    // Write the tree's files into both worker stores as a paginated map, before
    // any agent starts, so Tracers and Seekers read it instead of re-globbing.
    discovery::write_file_map(&project_knowledge, &scan.files_by_ext);
    discovery::write_file_map(&seeker_knowledge, &scan.files_by_ext);

    eprintln!("malwi analyze: {}\n", args.target);

    let werk = Werk::new();
    werk.set_dir(WORK_DIR);
    werk.set_policy(Policy {
        // The default of 10 is tight for a weaker model that frequently replies
        // with no tool call at all: a task can burn its whole retry budget on
        // that alone, failing before it ever reaches a real finding.
        max_schema_retries: Some(20),
        max_turns: args.max_turns,
        max_time: args.max_time,
        ..Policy::default()
    });
    werk.on_event(|queue, event| log_event(event, queue));

    // A policy stop (time/turns/tokens) is graceful: unlike a ctrl-c abort it
    // must still produce the report. Recorded here because by report time the
    // Werk has been cancelled and its finish reason no longer names the limit.
    let policy_stopped = Arc::new(AtomicBool::new(false));
    let policy_flag = Arc::clone(&policy_stopped);
    werk.on_event(move |queue, event| {
        if !is_run_wide_policy_stop(event) {
            return;
        }
        policy_flag.store(true, Ordering::Relaxed);
        cancel_for_policy_stop(queue);
    });

    // A selected failure threshold records the first matching verdict and calls
    // off the Seeker, Tracer, and Analyst pools; the Explorer and Reporter still
    // run so the report is whole.
    let failure_verdict_found = Arc::new(AtomicBool::new(false));
    if let Some(threshold) = args.failure_threshold {
        let trip = Arc::clone(&failure_verdict_found);
        werk.on_result(move |queue, task, result| {
            if !is_failure_verdict(queue, task, result, threshold) {
                return;
            }
            trip.store(true, Ordering::Relaxed);
            queue.cancel_tasks(failure_query());
        });
    }

    // Capture the messages of any task that lands a malicious or exploitable
    // verdict as a training example under trajectories/, on every run. Benign
    // dismissals are skipped.
    werk.on_result_async(|queue, task, result| async move {
        if !is_finding_verdict(&result) {
            return;
        }
        let Some(agent) = task.get_assignee() else {
            return;
        };
        let model = queue.get_model_for_agent(agent);
        let _ = Trajectory::from_task(agent, model.as_deref(), &task).save(WORK_DIR);
    });

    let additional_focus = additional_focus(args.instruction.as_deref());

    // Every pool shares one Werk; labels route each task to its agent.
    for i in 0..concurrency {
        werk.add_agent(
            Agent::new()
                .provider(provider.clone())
                .model(models[&agent_name("Analyst", i)].clone())
                .role(ANALYST_AGENT.trim())
                .templates(shared_templates(&additional_focus))
                .template("verdicts", ANALYST_VERDICTS.trim())
                .label(ANALYSIS_LABEL)
                .dir(scan_dir.to_path_buf())
                .knowledge(&project_knowledge)
                .tools(analyst_tools()),
        );
    }

    // Bounded discovery, refilled after downstream work drains.
    for i in 0..concurrency {
        werk.add_agent(
            // Every task returns a validated result; the result hook routes hits.
            Agent::new()
                .provider(provider.clone())
                .model(models[&agent_name("Seeker", i)].clone())
                .role(SEEKER_AGENT.trim())
                .templates(shared_templates(&additional_focus))
                .template("searches_per_task", SEARCHES_PER_TASK.to_string())
                .label(SEEKER_LABEL)
                .dir(scan_dir.to_path_buf())
                .knowledge(&seeker_knowledge)
                .tools(seeker_tools()),
        );
    }

    // Demand-driven reachability. Shares project knowledge to read the
    // Explorer's pages and record its own alongside.
    for i in 0..concurrency {
        werk.add_agent(
            // Every task ends in a handover; tracer.md is what enforces it.
            Agent::new()
                .provider(provider.clone())
                .model(models[&agent_name("Tracer", i)].clone())
                .role(TRACER_AGENT.trim())
                .templates(shared_templates(&additional_focus))
                .label(TRACER_LABEL)
                .handover(
                    Task::new(ANALYST_HANDOVER).label(ANALYSIS_LABEL).schema(
                        Schema::new(finding_schema_json())
                            .expect("Analyst finding schema is a valid document"),
                    ),
                )
                .dir(scan_dir.to_path_buf())
                .knowledge(&project_knowledge)
                .tools(tracer_tools()),
        );
    }

    // Bounded overview into project knowledge; no handoff.
    for i in 0..concurrency {
        werk.add_agent(
            Agent::new()
                .provider(provider.clone())
                .model(models[&agent_name("Explorer", i)].clone())
                .role(EXPLORER_AGENT.trim())
                .templates(shared_templates(&additional_focus))
                .label(EXPLORER_LABEL)
                .dir(scan_dir.to_path_buf())
                .knowledge(&project_knowledge)
                .tools(explorer_tools()),
        );
    }
    for _ in 0..concurrency {
        werk.add_task(Task::new(EXPLORATION_BODY).label(EXPLORER_LABEL));
    }

    // Seed the discovery pool so the Seeker searches from the start.
    for _ in 0..concurrency.min(SEEKER_PASSES) {
        werk.add_task(seeker_task(SEARCH_BODY));
    }

    // A dry Seeker result ends at the Seeker; a hit becomes one Tracer task.
    werk.on_result(|queue, done, result| {
        if done.get_label() != Some(SEEKER_LABEL)
            || result.get("outcome").and_then(Value::as_str) != Some("hit")
        {
            return;
        }
        queue.add_task(trace_task(result.clone()).parent(done.get_id()));
    });

    // A typed finding opens its focused follow-up before refill observes
    // whether downstream work is still pending.
    werk.on_result(|queue, done, result| {
        let Some(investigation) = investigation(queue, done, result) else {
            return;
        };
        // A pool called off never claims what it is handed.
        if is_pool_called_off(queue, ANALYSIS_LABEL) {
            return;
        }
        queue.add_task(investigation);
    });

    // The Seeker pool refills only after all work its prior passes opened has
    // drained. One lock makes the count-and-add sequence atomic across results.
    refill_seekers(&werk, SEARCH_BODY, concurrency);

    let aborted = install_ctrl_c_handler(Arc::clone(&werk));

    let scanner = Scanner::new(&scan_dir);

    // One run, kept live across both phases: Explorers, Seekers, Tracers, and
    // Analysts work concurrently while the Reporter waits idle for its task.
    werk.start();
    let per_tech = scanner.discover(&werk, &scan).await;
    let total_hits: usize = per_tech.iter().map(|(_, n)| n).sum();
    if total_hits == 0 {
        crate::run::scanner(format!("{files_walked} files → 0 hits"));
    } else {
        let techs: Vec<&str> = per_tech.iter().map(|(t, _)| *t).collect();
        crate::run::scanner(format!(
            "{files_walked} files → {total_hits} hits ({}) → reachability",
            techs.join(", "),
        ));
    }

    // Hooks can create downstream work, and Agentwerk keeps that work inside
    // this drainage boundary.
    werk.finish_all_tasks().await;
    // A hard second-press ctrl-c aborts; a policy stop (time/turns/tokens) and a
    // wind-down are graceful and fall through to write the report below.
    if aborted.load(Ordering::Relaxed) {
        eprintln!("\ncancelled.");
        std::process::exit(130);
    }

    let mut analysis = build_analysis(&werk, &scan_dir, files_walked);

    let partial_coverage =
        policy_stopped.load(Ordering::Relaxed) || is_pool_called_off(&werk, SEEKER_LABEL);

    // Report phase: the Explorer pool has finished, so its summaries are on disk,
    // and the findings are already in `analysis`.
    let has_findings = analysis["findings"]
        .as_array()
        .is_some_and(|a| !a.is_empty());
    let has_exploration = !project_knowledge.get_index().is_empty();
    if has_findings || has_exploration {
        let reporter_output = run_report_phase(
            provider.clone(),
            models[REPORTER_NAME].clone(),
            &project_knowledge,
            render_findings_table(&analysis, partial_coverage),
            &additional_focus,
            Path::new(WORK_DIR),
            &scan_dir,
        )
        .await;
        if let Some(reporter_output) = reporter_output {
            merge_reporter_output(&reporter_output, &mut analysis, partial_coverage);
        }
    }

    // The Reporter ran on its own Werk in the scan's directory, so both Werks
    // logged to one file and this fold is the whole run.
    let stats = RunStats::fold(&werk);
    analysis["input_tokens"] = json!(stats.input_tokens);
    analysis["output_tokens"] = json!(stats.output_tokens);
    analysis["stats"] = serde_json::to_value(&stats).expect("RunStats serializes");

    let analysis_file = args
        .output_file
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("{WORK_DIR}/analysis.json")));
    let json_str = serde_json::to_string_pretty(&analysis).expect("serializable");
    fs::write(&analysis_file, json_str).expect("write analysis.json");

    print_summary(&stats, &analysis, &analysis_file, &scan, &scan_dir);

    // Surface the verdict that stopped the run through the exit status for
    // callers that selected a failure threshold.
    if args.failure_threshold.is_some() && failure_verdict_found.load(Ordering::Relaxed) {
        std::process::exit(2);
    }
}

/// Every agent the run builds, with its label. The Reporter works alone, so it
/// carries no member number.
fn roster(concurrency: usize) -> Vec<(String, &'static str)> {
    let mut agents: Vec<(String, &'static str)> = POOLS
        .iter()
        .flat_map(|(pool, label)| (0..concurrency).map(move |i| (agent_name(pool, i), *label)))
        .collect();
    agents.push((REPORTER_NAME.to_string(), REPORTER_LABEL));
    agents
}

fn seeker_task(body: impl Into<String>) -> Task {
    Task::new(body.into()).label(SEEKER_LABEL).schema(
        Schema::new(seeker_result_schema_json()).expect("seeker result schema is a valid document"),
    )
}

/// Refill the bounded Seeker pool after its downstream work drains.
fn refill_seekers(werk: &Arc<Werk>, body: &str, concurrency: usize) {
    let refill = Arc::new(Mutex::new(()));
    let body = body.to_string();
    werk.on_result(move |queue, done, _| {
        if !matches!(
            done.get_label(),
            Some(SEEKER_LABEL | TRACER_LABEL | ANALYSIS_LABEL)
        ) || done.is_cancelled()
            || is_pool_called_off(queue, SEEKER_LABEL)
        {
            return;
        }

        let _refill = refill.lock().expect("seeker refill lock poisoned");
        if queue
            .find_task("label IN (tracing, security_analysis) AND pending = true")
            .is_some()
        {
            return;
        }

        let pending = queue.find_tasks("label = seeking AND pending = true").len();
        let created = queue.find_tasks("label = seeking").len();
        let open_slots = concurrency.saturating_sub(pending);
        let remaining = SEEKER_PASSES.saturating_sub(created);
        for _ in 0..open_slots.min(remaining) {
            queue.add_task(seeker_task(body.clone()));
        }
    });
}

pub(crate) fn trace_task(body: impl serde::Serialize) -> Task {
    let value = serde_json::to_value(body).expect("trace task body should serialize");
    let data = match value {
        Value::String(text) => text,
        value => serde_json::to_string_pretty(&value).expect("trace task body should render"),
    };
    let body = format!("<reported_code>\n{data}\n</reported_code>");
    Task::new(body).label(TRACER_LABEL).schema(
        Schema::new(trace_result_schema_json()).expect("trace result schema is a valid document"),
    )
}

/// Call off every pool a policy stop ends, sparing the investigations already
/// open: each is detail the run paid an Analyst for, and with the analysis label
/// off nothing new opens. Their IDs are read before the query is handed over,
/// since a cancel filter that read the task store would deadlock.
pub(crate) fn cancel_for_policy_stop(werk: &Arc<Werk>) {
    let spared: Vec<String> = werk
        .find_tasks(ANALYSIS_LABEL)
        .into_iter()
        .filter(|task| is_investigation(werk, task))
        .map(|task| task.get_id().to_string())
        .collect();
    werk.cancel_tasks(policy_stop_query(&spared));
}

/// Cancellation is answered per task, so it is asked of one the label owns.
fn is_pool_called_off(werk: &Werk, label: &str) -> bool {
    werk.find_task(format!("label = {label} AND cancelled = true"))
        .is_some()
}

/// Run the Reporter on its own `Werk`, so nothing that stopped the scan
/// (time limit, cancel) can stop the report. No max time: the schema-retry budget
/// bounds a Reporter that never finishes its task.
async fn run_report_phase(
    provider: Provider,
    model: Model,
    knowledge: &Arc<Knowledge>,
    findings_table: String,
    additional_focus: &str,
    dir: &Path,
    scan_dir: &Path,
) -> Option<Value> {
    let report_werk = Werk::new();
    report_werk.set_dir(dir);
    report_werk.set_policy(Policy {
        // Same allowance as the scan Werk: a weaker model can burn the default
        // budget on replies with no tool call.
        max_schema_retries: Some(20),
        ..Policy::default()
    });
    report_werk.on_event(|werk, event| log_event(event, werk));
    report_werk.add_agent(
        Agent::new()
            .provider(provider)
            .model(model)
            .role(REPORTER_AGENT.trim())
            .templates(shared_templates(additional_focus))
            .label(REPORTER_LABEL)
            .knowledge(knowledge)
            // Read-only access to the scanned tree so the Reporter can quote the
            // exact cited line as a code excerpt instead of inventing one.
            .dir(scan_dir.to_path_buf())
            .tools(reporter_tools()),
    );
    let report = report_werk.add_task(
        Task::new(findings_table)
            .label(REPORTER_LABEL)
            .schema(reporter_result_schema()),
    );
    report_werk.finish_task(report).await
}

/// Call off the Explorer and Seeker pools on the first ctrl-c, letting the
/// in-flight backlog drain into a report. A second press forces an exit in case
/// the drain itself wedges, and raises the returned flag so the report phase
/// never starts on the way out.
fn install_ctrl_c_handler(werk: Arc<Werk>) -> Arc<AtomicBool> {
    let aborted = Arc::new(AtomicBool::new(false));
    let raised = Arc::clone(&aborted);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }
        eprintln!(
            "\n[ctrl-c] winding down: no new work, finishing in-flight analysis then reporting. \
             Press again to force exit."
        );
        werk.cancel_tasks(wind_down_query());
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }
        eprintln!("\n[ctrl-c] hard exit on second press.");
        raised.store(true, Ordering::Relaxed);
        werk.cancel_all_tasks();
        std::process::exit(130);
    });
    aborted
}

/// Fold the Reporter's `{summary, details}` into the analysis. A missing field
/// leaves the `build_analysis` tally in place.
fn merge_reporter_output(result: &Value, analysis: &mut Value, partial_coverage: bool) {
    if let Some(summary) = result["summary"].as_str() {
        analysis["summary"] = json!(normalize_reporter_summary(
            summary,
            analysis["verdict"].as_str().unwrap_or("unknown"),
            partial_coverage,
        ));
    }
    if let Some(d) = result.get("details") {
        analysis["details"] = d.clone();
    }
}

#[cfg(test)]
mod tests {
    use crate::cli::{parse_line as parse, CliExit, Command};

    #[test]
    fn scan_takes_its_target_and_its_flags() {
        let Ok(Command::Analyze(args)) =
            parse("analyze ./src --concurrency 4 --max-time 5m --fail-malicious")
        else {
            panic!("analyze should parse");
        };
        assert!(matches!(args.target, Target::Directory(_)));
        assert_eq!(args.target.to_string(), "./src");
        assert_eq!(args.concurrency, 4);
        assert_eq!(args.max_time, Some(Duration::from_secs(300)));
        assert_eq!(args.failure_threshold, Some(FailureThreshold::Malicious));
    }

    #[test]
    fn failure_flags_select_the_least_severe_threshold_in_any_order() {
        for (line, expected) in [
            ("analyze ./src", None),
            (
                "analyze ./src --fail-malicious",
                Some(FailureThreshold::Malicious),
            ),
            (
                "analyze ./src --fail-exploitable",
                Some(FailureThreshold::Exploitable),
            ),
            (
                "analyze ./src --fail-malicious --fail-exploitable",
                Some(FailureThreshold::Exploitable),
            ),
            (
                "analyze ./src --fail-exploitable --fail-malicious",
                Some(FailureThreshold::Exploitable),
            ),
        ] {
            let Ok(Command::Analyze(args)) = parse(line) else {
                panic!("analyze should parse: {line}");
            };
            assert_eq!(args.failure_threshold, expected, "{line}");
        }
    }

    #[test]
    fn fail_fast_is_no_longer_an_analyze_flag() {
        let Err(CliExit::ArgumentRejected(message)) = parse("analyze ./src --fail-fast") else {
            panic!("--fail-fast should be rejected");
        };
        assert!(message.contains("unknown flag: --fail-fast"), "{message}");
    }

    #[test]
    fn a_directory_without_a_command_is_rejected() {
        let Err(CliExit::ArgumentRejected(message)) = parse("./src") else {
            panic!("a bare path names no command");
        };
        assert!(message.contains("unknown command: ./src"), "{message}");
    }

    #[test]
    fn scan_without_a_target_shows_its_help() {
        let Err(CliExit::ArgumentRejected(message)) = parse("analyze") else {
            panic!("analyze needs a target");
        };
        assert!(message.contains("malwi analyze <TARGET>"), "{message}");
    }

    #[test]
    fn a_file_target_is_kept_apart_from_a_directory_target() {
        let Ok(Command::Analyze(file)) = parse("analyze src/main.rs") else {
            panic!("a file is a target");
        };
        assert!(matches!(file.target, Target::File(_)));

        let Ok(Command::Analyze(dir)) = parse("analyze ./src") else {
            panic!("a directory is a target");
        };
        assert!(matches!(dir.target, Target::Directory(_)));
    }

    #[test]
    fn a_target_no_path_resolves_to_is_carried_as_a_prompt() {
        let Ok(Command::Analyze(args)) = parse("analyze left-pad") else {
            panic!("a package name is a target");
        };
        let Target::Prompt(text) = args.target else {
            panic!("no path resolves to left-pad");
        };
        assert_eq!(text, "left-pad");
    }

    fn input_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("malwi_target_{}_{name}", std::process::id()))
    }

    #[test]
    fn a_file_target_resolves_to_a_directory_holding_a_copy() {
        let input = input_dir("file");
        let staged = Target::File(PathBuf::from("src/main.rs"))
            .resolve(&input)
            .expect("a readable file stages");

        assert!(staged.is_dir(), "{}", staged.display());
        assert_eq!(
            fs::read(staged.join("main.rs")).expect("the copy is readable"),
            fs::read("src/main.rs").expect("the original is readable"),
        );
        let _ = fs::remove_dir_all(&input);
    }

    #[test]
    fn a_directory_target_resolves_to_itself() {
        let staged = Target::Directory(PathBuf::from("./src"))
            .resolve(&input_dir("dir"))
            .expect("an existing directory resolves");
        assert_eq!(staged, fs::canonicalize("./src").expect("./src exists"));
    }

    /// The seam for targets an agent will fetch: today the run stops here, and
    /// this test is what changes when it learns to materialize one.
    #[test]
    fn a_target_that_is_not_a_path_is_refused_by_name() {
        let error = Target::Prompt("left-pad".to_string())
            .resolve(&input_dir("prompt"))
            .expect_err("nothing local is named left-pad");
        assert!(error.contains("left-pad"), "{error}");
    }

    #[test]
    fn an_unknown_scan_flag_is_named() {
        let Err(CliExit::ArgumentRejected(message)) = parse("analyze ./src --deep") else {
            panic!("--deep is not a flag");
        };
        assert!(message.contains("--deep"), "{message}");
    }

    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::AtomicUsize;

    use agentwerk::providers::types::{
        ContentBlock, ModelResponse, ResponseStatus, StreamEvent, TokenUsage,
    };
    use agentwerk::providers::{ModelRequest, ProviderLike, ProviderResult};
    use agentwerk::tools::Tool;
    use agentwerk::Event;
    use agentwerk::Query;
    use tokio::sync::Semaphore;

    use super::*;

    /// The Tracer named `{output_contract}` while its builder passed none, and
    /// shipped the placeholder to the model as text.
    #[test]
    fn every_placeholder_an_analyze_role_names_is_one_the_run_substitutes() {
        let shared: Vec<&str> = shared_templates("").iter().map(|(key, _)| *key).collect();
        let per_role: [(&str, &str, &[&str]); 5] = [
            ("seeker", SEEKER_AGENT, &["searches_per_task"]),
            ("analyst", ANALYST_AGENT, &["verdicts"]),
            ("tracer", TRACER_AGENT, &[]),
            ("explorer", EXPLORER_AGENT, &[]),
            ("reporter", REPORTER_AGENT, &[]),
        ];
        for (name, role, extra) in per_role {
            let passed: Vec<&str> = shared
                .iter()
                .copied()
                .chain(extra.iter().copied())
                .collect();
            crate::cli::assert_placeholders_are_passed(name, role, &passed);
            crate::cli::assert_role_prompt_shape(name, role);
            crate::cli::assert_role_orientation(name, role);
            assert!(
                role.trim_end().ends_with("{additional_focus}"),
                "{name} must append operator guidance"
            );
        }
    }

    #[test]
    fn analyst_handover_labels_and_delimits_trace_evidence() {
        assert_eq!(
            ANALYST_HANDOVER,
            "<trace_evidence>\n{parent_result}\n</trace_evidence>"
        );
    }

    #[test]
    fn rendered_analyze_assignments_use_descriptive_xml_blocks() {
        assert!(EXPLORATION_BODY.starts_with("<overview_assignment>\n"));
        assert!(EXPLORATION_BODY.ends_with("\n</overview_assignment>"));
        assert!(SEARCH_BODY.starts_with("<search_assignment>\n"));
        assert!(SEARCH_BODY.ends_with("\n</search_assignment>"));

        let trace = trace_task(json!({"path": "src/lib.rs", "line": 7}));
        let body = trace.get_task().as_str().expect("trace body is text");
        assert!(body.starts_with("<reported_code>\n{"), "{body}");
        assert!(body.ends_with("\n</reported_code>"), "{body}");
    }

    /// A role naming a tool it was not given spends a turn on `ToolNotFound`,
    /// and one omitting a tool it has never reaches for it. Neither shows up in
    /// a build: a stale line survived a merge in `analyst.md` and told the
    /// Analyst about `manage_knowledge`, which agentwerk had already renamed.
    #[test]
    fn every_role_lists_the_tools_its_pool_is_given() {
        // `knowledge` comes with the agent's store and `finish` is registered by
        // default, so both are granted to every pool without being named.
        let granted = |tools: Vec<Tool>| {
            let mut names: Vec<String> = tools.iter().map(|t| t.get_name().to_string()).collect();
            names.extend(["knowledge".to_string(), "finish".to_string()]);
            names.sort();
            names
        };
        for (pool, role, tools) in [
            ("Analyst", ANALYST_AGENT, analyst_tools()),
            ("Seeker", SEEKER_AGENT, seeker_tools()),
            ("Tracer", TRACER_AGENT, tracer_tools()),
            ("Explorer", EXPLORER_AGENT, explorer_tools()),
            ("Reporter", REPORTER_AGENT, reporter_tools()),
        ] {
            let mut declared = crate::cli::declared_prompt_tools(role);
            declared.sort();
            assert_eq!(declared, granted(tools), "{pool}");
        }
    }

    /// A schema-bound finish in agentwerk 0.1.29 takes the result object's
    /// fields directly, so the shared contract must not teach the old envelope.
    #[test]
    fn the_output_contract_names_the_fields_finish_reads() {
        assert!(
            OUTPUT_CONTRACT.contains("top-level arguments")
                && !OUTPUT_CONTRACT.contains("under its `result` argument"),
            "the contract must describe v0.1.29's bound finish arguments: {OUTPUT_CONTRACT}"
        );
    }

    #[test]
    fn analyze_prompts_use_the_finding_vocabulary_at_each_handover() {
        assert!(ANALYST_AGENT.contains("`verdict`: exactly"));
        assert!(ANALYST_AGENT.contains("| Mode | `type` rule |"));
        assert!(ANALYST_AGENT.contains("Focused investigation"));
        assert!(!ANALYST_AGENT.contains("classification"));
        assert!(!ANALYST_AGENT.contains("`none`"));

        assert!(TRACER_AGENT.contains("Set `evidence`"));
        assert!(!TRACER_AGENT.contains("Set `finding`"));

        assert!(REPORTER_AGENT.contains("established focused facts"));
        assert!(!REPORTER_AGENT.contains("pattern_language"));
        assert!(!REPORTER_AGENT.contains("classification"));
        assert!(!REPORTER_AGENT.contains("{verdicts}"));
        assert!(!REPORTER_AGENT.contains("VERDICT PROTOCOL"));
    }

    #[test]
    fn malicious_verdicts_do_not_require_reachability() {
        assert!(ANALYST_VERDICTS
            .contains("Reachability changes\nexposure, not fully implemented deliberate harm"));
        assert!(ANALYST_AGENT.contains("Describe unreachable harm as limited exposure"));
        assert!(!ANALYST_VERDICTS.contains("All three criteria pass"));
        assert!(!ANALYST_AGENT.contains("fails\n  Realized. That is Benign"));
    }

    #[test]
    fn reporter_preserves_supplied_verdict_language_without_recommendations() {
        assert!(
            REPORTER_AGENT.contains("Start `summary` with `Required summary opening` exactly once")
        );
        assert!(REPORTER_AGENT.contains(
            "NEVER recommend installation, removal, mitigation, remediation, or another action"
        ));
        assert!(REPORTER_AGENT.contains("the limited exposure without weakening the verdict"));
        assert!(REPORTER_AGENT.contains("Analyst's final decision"));
    }

    /// AQL is checked when it runs, and a `cancel` inside a ctrl-c handler is
    /// the worst place to find a typo. `Query::new` answers with a `Result`.
    #[test]
    fn every_query_the_scan_builds_compiles() {
        for query in [
            policy_stop_query(&[]),
            policy_stop_query(&["t-3".to_string(), "t-9".to_string()]),
            failure_query(),
            wind_down_query(),
            "label IN (tracing, security_analysis) AND pending = true".to_string(),
            "label = seeking AND pending = true".to_string(),
            "label = seeking".to_string(),
            format!("label = {SEEKER_LABEL} AND cancelled = true"),
        ] {
            Query::<Task>::new(&query).unwrap_or_else(|e| panic!("{query}: {e}"));
        }
    }

    #[test]
    fn roster_holds_every_pool_member_and_the_reporter() {
        let roster = roster(2);
        let names: Vec<&str> = roster.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            [
                "Analyst 1",
                "Analyst 2",
                "Seeker 1",
                "Seeker 2",
                "Tracer 1",
                "Tracer 2",
                "Explorer 1",
                "Explorer 2",
                "Reporter",
            ]
        );
        assert_eq!(roster.last().unwrap().1, REPORTER_LABEL);
    }

    #[test]
    fn without_a_models_file_every_agent_runs_the_environment_model() {
        let roster = roster(2);
        let models = resolve_models(None, &roster, || Model::new("model-from-env"));
        assert_eq!(models.len(), roster.len());
        assert!(models.values().all(|m| m.get_name() == "model-from-env"));
    }

    /// What every mocked reply charges, so a fold over the run's events has a
    /// figure to land on.
    const MOCK_INPUT_TOKENS: u64 = 1200;
    const MOCK_OUTPUT_TOKENS: u64 = 340;

    /// Finishes whatever task it is given by echoing a fixed `result`.
    struct FinishMock(Value);

    impl ProviderLike for FinishMock {
        fn respond(
            &self,
            _request: ModelRequest,
            _on_event: Arc<dyn Fn(StreamEvent) + Send + Sync>,
        ) -> Pin<Box<dyn Future<Output = ProviderResult<ModelResponse>> + Send + '_>> {
            let result = self.0.clone();
            Box::pin(async move {
                Ok(ModelResponse {
                    content: vec![ContentBlock::ToolUse {
                        id: "call-1".into(),
                        name: "finish".into(),
                        input: result,
                    }],
                    status: ResponseStatus::ToolUse,
                    usage: TokenUsage {
                        input_tokens: MOCK_INPUT_TOKENS,
                        output_tokens: MOCK_OUTPUT_TOKENS,
                    },
                    model: "mock".into(),
                })
            })
        }
    }

    /// Announces that it was claimed, then waits for the test to release it.
    struct GatedFinishMock {
        started: Arc<Semaphore>,
        release: Arc<Semaphore>,
    }

    struct KnowledgeAwareFinishMock {
        result: Value,
        saw_overview: Arc<AtomicBool>,
    }

    impl ProviderLike for KnowledgeAwareFinishMock {
        fn respond(
            &self,
            request: ModelRequest,
            _on_event: Arc<dyn Fn(StreamEvent) + Send + Sync>,
        ) -> Pin<Box<dyn Future<Output = ProviderResult<ModelResponse>> + Send + '_>> {
            self.saw_overview.store(
                request.system_prompt.contains("project-overview"),
                Ordering::Relaxed,
            );
            let result = self.result.clone();
            Box::pin(async move {
                Ok(ModelResponse {
                    content: vec![ContentBlock::ToolUse {
                        id: "call-1".into(),
                        name: "finish".into(),
                        input: result,
                    }],
                    status: ResponseStatus::ToolUse,
                    usage: TokenUsage::default(),
                    model: "mock".into(),
                })
            })
        }
    }

    #[tokio::test]
    async fn analysts_and_reporters_receive_the_explorers_project_store() {
        use agentwerk::agents::knowledge::Page;

        let dir = std::env::temp_dir().join(format!("shared_project_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let knowledge = Knowledge::load(dir.join("knowledge")).expect("knowledge opens");
        knowledge
            .get_pages()
            .save(Page {
                slug: "project-overview".into(),
                kind: "Knowledge".into(),
                description: "The Explorer's overview of the project.".into(),
                content: "# Project overview\n\nA package manager plugin.".into(),
                tags: vec!["project".into()],
            })
            .expect("overview is writable");

        let analyst_saw = Arc::new(AtomicBool::new(false));
        let analyst_werk = Werk::new();
        analyst_werk.set_dir(dir.join("analyst"));
        analyst_werk.add_agent(
            Agent::new()
                .provider(Provider::new(KnowledgeAwareFinishMock {
                    result: json!({
                        "verdict": "benign", "path": "src/main.rs", "description": "ordinary",
                    }),
                    saw_overview: Arc::clone(&analyst_saw),
                }))
                .model(Model::new("mock"))
                .role("analyst")
                .label(ANALYSIS_LABEL)
                .knowledge(&knowledge),
        );
        let analysis =
            analyst_werk.add_task(Task::new("evidence").label(ANALYSIS_LABEL).schema(
                Schema::new(finding_schema_json()).expect("Analyst finding schema is valid"),
            ));
        analyst_werk.finish_task(analysis).await;

        let reporter_saw = Arc::new(AtomicBool::new(false));
        let summary =
            "A grounded project security summary for the package under review. ".repeat(4);
        let details =
            "Evidence, mechanism, and impact grounded in the reviewed source tree. ".repeat(12);
        run_report_phase(
            Provider::new(KnowledgeAwareFinishMock {
                result: json!({"summary": summary, "details": details}),
                saw_overview: Arc::clone(&reporter_saw),
            }),
            Model::new("mock"),
            &knowledge,
            "verdict: benign\nfindings: 0\ncoverage: full\n".into(),
            "",
            &dir,
            &dir,
        )
        .await;

        assert!(analyst_saw.load(Ordering::Relaxed));
        assert!(reporter_saw.load(Ordering::Relaxed));
        let _ = fs::remove_dir_all(&dir);
    }

    impl ProviderLike for GatedFinishMock {
        fn respond(
            &self,
            _request: ModelRequest,
            _on_event: Arc<dyn Fn(StreamEvent) + Send + Sync>,
        ) -> Pin<Box<dyn Future<Output = ProviderResult<ModelResponse>> + Send + '_>> {
            let started = Arc::clone(&self.started);
            let release = Arc::clone(&self.release);
            Box::pin(async move {
                started.add_permits(1);
                let permit = release.acquire().await.expect("release semaphore open");
                permit.forget();
                Ok(ModelResponse {
                    content: vec![ContentBlock::ToolUse {
                        id: "call-1".into(),
                        name: "finish".into(),
                        input: json!({"done": true}),
                    }],
                    status: ResponseStatus::ToolUse,
                    usage: TokenUsage::default(),
                    model: "mock".into(),
                })
            })
        }
    }

    #[tokio::test]
    async fn concurrent_seeker_refills_stay_bounded_by_passes_and_concurrency() {
        let dir = std::env::temp_dir().join(format!("seeker_refill_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let werk = Werk::new();
        werk.set_dir(&dir);
        let concurrency = 4;
        for _ in 0..concurrency {
            werk.add_agent(
                Agent::new()
                    .provider(Provider::new(FinishMock(json!({
                        "outcome": "nothing", "pattern": "unused-pattern",
                    }))))
                    .model(Model::new("mock"))
                    .role("seeker")
                    .label(SEEKER_LABEL),
            );
        }
        for _ in 0..concurrency.min(SEEKER_PASSES) {
            werk.add_task(seeker_task("search"));
        }
        refill_seekers(&werk, "search", concurrency);
        let max_pending = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&max_pending);
        werk.on_result(move |queue, _, _| {
            observed.fetch_max(
                queue.find_tasks("label = seeking AND pending = true").len(),
                Ordering::Relaxed,
            );
        });

        werk.finish_all_tasks().await;

        assert_eq!(werk.find_tasks("label = seeking").len(), SEEKER_PASSES);
        assert!(max_pending.load(Ordering::Relaxed) <= concurrency);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn seeker_refill_waits_for_traces_analyses_and_type_follow_ups() {
        let dir = std::env::temp_dir().join(format!("seeker_gate_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let werk = Werk::new();
        werk.set_dir(&dir);
        werk.add_agent(
            Agent::new()
                .provider(Provider::new(FinishMock(json!({
                    "outcome": "nothing", "pattern": "unused-pattern",
                }))))
                .model(Model::new("mock"))
                .role("seeker")
                .label(SEEKER_LABEL),
        );
        let started = Arc::new(Semaphore::new(0));
        let release = Arc::new(Semaphore::new(0));
        for label in [TRACER_LABEL, ANALYSIS_LABEL] {
            werk.add_agent(
                Agent::new()
                    .provider(Provider::new(GatedFinishMock {
                        started: Arc::clone(&started),
                        release: Arc::clone(&release),
                    }))
                    .model(Model::new("mock"))
                    .role(label)
                    .label(label),
            );
        }

        werk.add_task(seeker_task("search"));
        werk.add_task(Task::new("trace").label(TRACER_LABEL));
        let question = werk.add_task(Task::new("analysis").label(ANALYSIS_LABEL));
        werk.add_task(
            Task::new("type follow-up")
                .label(ANALYSIS_LABEL)
                .parent(question),
        );
        refill_seekers(&werk, "search", 1);
        let seeker_done = Arc::new(Semaphore::new(0));
        let observed = Arc::clone(&seeker_done);
        werk.on_result(move |_, done, _| {
            if done.get_label() == Some(SEEKER_LABEL) {
                observed.add_permits(1);
            }
        });

        let running = Arc::clone(&werk);
        let drain = tokio::spawn(async move { running.finish_all_tasks().await });
        let permit = started
            .acquire_many(2)
            .await
            .expect("trace and analysis were claimed");
        permit.forget();
        let permit = seeker_done.acquire().await.expect("seeker finished");
        permit.forget();

        assert_eq!(
            werk.find_tasks("label = seeking").len(),
            1,
            "downstream pending work keeps refill closed"
        );

        release.add_permits(3);
        drain.await.expect("drain task joined");
        assert_eq!(werk.find_tasks("label = seeking").len(), SEEKER_PASSES);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn cancellation_queries_do_not_retroactively_cancel_finished_tasks() {
        let dir = std::env::temp_dir().join(format!("pending_cancel_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let werk = Werk::new();
        werk.set_dir(&dir);
        werk.add_agent(
            Agent::new()
                .provider(Provider::new(FinishMock(json!({"done": true}))))
                .model(Model::new("mock"))
                .role("seeker")
                .label(SEEKER_LABEL),
        );
        let finished = werk.add_task(Task::new("done").label(SEEKER_LABEL));
        werk.finish_task(finished.clone()).await;
        let pending = werk.add_task(Task::new("pending").label(SEEKER_LABEL));

        werk.cancel_tasks(failure_query());

        assert!(!werk.get_task(&finished).unwrap().is_cancelled());
        assert!(werk.get_task(&pending).unwrap().is_cancelled());
        let _ = fs::remove_dir_all(&dir);
    }

    /// Answers an investigation task with the side-loading finding and every
    /// other task with the plain one.
    struct InvestigationMock;

    impl ProviderLike for InvestigationMock {
        fn respond(
            &self,
            request: ModelRequest,
            _on_event: Arc<dyn Fn(StreamEvent) + Send + Sync>,
        ) -> Pin<Box<dyn Future<Output = ProviderResult<ModelResponse>> + Send + '_>> {
            let asked: String = request
                .messages
                .iter()
                .map(|message| serde_json::to_string(message).unwrap_or_default())
                .collect();
            let finding_type =
                crate::types::find("side-loading").expect("side-loading is registered");
            let finding = json!({
                "verdict": "exploitable",
                "path": "scripts/install.js",
                "line": 12,
                "type": finding_type.name(),
                "description": "downloads and runs a setup script",
            });
            let mut result = finding.clone();
            // The messages are JSON, so their newlines are escaped: match one line.
            let heading = finding_type.task().lines().next().unwrap_or_default();
            if asked.contains(heading) {
                result["source"] = json!("https://cdn.example.test/setup.sh");
                result["control"] = json!("static");
                result["user_consent"] = json!(false);
                result["trigger"] = json!({
                    "phase": "installation",
                    "location": {"path": "package.json", "line": 4},
                    "execution_condition": "always, on every install",
                });
            }
            Box::pin(async move {
                Ok(ModelResponse {
                    content: vec![ContentBlock::ToolUse {
                        id: "call-1".into(),
                        name: "finish".into(),
                        input: result,
                    }],
                    status: ResponseStatus::ToolUse,
                    usage: TokenUsage::default(),
                    model: "mock".into(),
                })
            })
        }
    }

    /// Types a malicious payload first, then rules the named type out
    /// while retaining the malicious verdict for the behavior it did establish.
    struct ObfuscationMock;

    impl ProviderLike for ObfuscationMock {
        fn respond(
            &self,
            request: ModelRequest,
            _on_event: Arc<dyn Fn(StreamEvent) + Send + Sync>,
        ) -> Pin<Box<dyn Future<Output = ProviderResult<ModelResponse>> + Send + '_>> {
            let asked: String = request
                .messages
                .iter()
                .map(|message| serde_json::to_string(message).unwrap_or_default())
                .collect();
            let finding_type =
                crate::types::find("obfuscation").expect("obfuscation is registered");
            let result = if asked.contains(finding_type.task().lines().next().unwrap_or_default()) {
                json!({
                    "verdict": "malicious", "path": "loader.py", "line": 8,
                    "description": "executes downloaded source directly",
                })
            } else {
                json!({
                    "verdict": "malicious", "path": "loader.py", "line": 8,
                    "type": finding_type.name(), "description": "decodes a blob into exec",
                })
            };
            Box::pin(async move {
                Ok(ModelResponse {
                    content: vec![ContentBlock::ToolUse {
                        id: "call-1".into(),
                        name: "finish".into(),
                        input: result,
                    }],
                    status: ResponseStatus::ToolUse,
                    usage: TokenUsage::default(),
                    model: "mock".into(),
                })
            })
        }
    }

    #[tokio::test]
    async fn typed_malicious_finding_is_investigated_before_failure_stops() {
        let dir = std::env::temp_dir().join(format!("malicious_followup_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let werk = Werk::new();
        werk.set_dir(&dir);
        werk.add_agent(
            Agent::new()
                .provider(Provider::new(ObfuscationMock))
                .model(Model::new("mock"))
                .role("analyst")
                .label(ANALYSIS_LABEL),
        );
        let stopped = Arc::new(AtomicBool::new(false));
        let tripped = Arc::clone(&stopped);
        werk.on_result(move |queue, task, result| {
            if is_failure_verdict(queue, task, result, FailureThreshold::Malicious) {
                tripped.store(true, Ordering::Relaxed);
                queue.cancel_tasks(failure_query());
            }
        });
        werk.on_result(|queue, done, result| {
            if let Some(follow_up) = investigation(queue, done, result) {
                if !is_pool_called_off(queue, ANALYSIS_LABEL) {
                    queue.add_task(follow_up);
                }
            }
        });
        werk.add_task(
            Task::new("the evidence").label(ANALYSIS_LABEL).schema(
                Schema::new(finding_schema_json()).expect("Analyst finding schema is valid"),
            ),
        );

        werk.finish_all_tasks().await;

        let tasks = werk.find_tasks(format!("label = {ANALYSIS_LABEL}"));
        assert_eq!(tasks.len(), 2, "the follow-up opens no recursive follow-up");
        let follow_up = tasks
            .iter()
            .find(|task| is_investigation(&werk, task))
            .expect("one focused follow-up ran");
        assert!(
            !follow_up.is_cancelled(),
            "the threshold waited for its answer"
        );
        assert_eq!(
            follow_up.get_result().unwrap()["verdict"],
            json!("malicious")
        );
        assert!(stopped.load(Ordering::Relaxed));
        let _ = fs::remove_dir_all(&dir);
    }

    /// Opens telemetry from the plain finding, then answers its focused
    /// investigation with the outcome supplied by the test.
    struct TelemetryInvestigationMock(Value);

    impl ProviderLike for TelemetryInvestigationMock {
        fn respond(
            &self,
            request: ModelRequest,
            _on_event: Arc<dyn Fn(StreamEvent) + Send + Sync>,
        ) -> Pin<Box<dyn Future<Output = ProviderResult<ModelResponse>> + Send + '_>> {
            let asked: String = request
                .messages
                .iter()
                .map(|message| serde_json::to_string(message).unwrap_or_default())
                .collect();
            let finding_type = crate::types::find("telemetry").expect("telemetry is registered");
            let result = if asked.contains(finding_type.task().lines().next().unwrap_or_default()) {
                self.0.clone()
            } else {
                json!({
                    "verdict": "exploitable",
                    "path": "src/telemetry.py",
                    "line": 18,
                    "type": finding_type.name(),
                    "description": "initializes an external analytics transmission",
                })
            };
            Box::pin(async move {
                Ok(ModelResponse {
                    content: vec![ContentBlock::ToolUse {
                        id: "call-1".into(),
                        name: "finish".into(),
                        input: result,
                    }],
                    status: ResponseStatus::ToolUse,
                    usage: TokenUsage::default(),
                    model: "mock".into(),
                })
            })
        }
    }

    async fn investigated_telemetry(outcome: Value, suffix: &str) -> Value {
        let dir =
            std::env::temp_dir().join(format!("malwi_telemetry_{suffix}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let werk = Werk::new();
        werk.set_dir(&dir);
        werk.add_agent(
            Agent::new()
                .provider(Provider::new(TelemetryInvestigationMock(outcome)))
                .model(Model::new("mock"))
                .role("analyst")
                .label(ANALYSIS_LABEL),
        );
        werk.on_result(|queue, done, result| {
            if let Some(investigation) = investigation(queue, done, result) {
                queue.add_task(investigation);
            }
        });
        werk.add_task(
            Task::new("the evidence").label(ANALYSIS_LABEL).schema(
                Schema::new(finding_schema_json()).expect("Analyst finding schema is valid"),
            ),
        );
        werk.start();
        werk.finish_tasks(|_: &Task| true).await;

        let analysis = build_analysis(&werk, &dir, 1);
        let _ = std::fs::remove_dir_all(&dir);
        analysis
    }

    #[tokio::test]
    async fn telemetry_without_affirmative_consent_is_confirmed() {
        let analysis = investigated_telemetry(
            json!({
                "verdict": "exploitable",
                "path": "src/telemetry.py",
                "line": 18,
                "type": "telemetry",
                "description": "sends host and command data automatically at startup",
                "provider": "Segment",
                "destination": "https://api.segment.io/v1/track at src/telemetry.py:18",
                "data": ["hostname from platform.node() at src/telemetry.py:12"],
                "user_consent": false,
                "trigger": {
                    "phase": "startup",
                    "location": {"path": "src/telemetry.py", "line": 18},
                    "execution_condition": "whenever the module is imported",
                    "cadence": "once per process start",
                },
            }),
            "confirmed",
        )
        .await;

        assert_eq!(analysis["verdict"], json!("exploitable"));
        assert_eq!(analysis["findings"][0]["type"], json!("telemetry"));
        assert_eq!(analysis["findings"][0]["user_consent"], json!(false));
    }

    #[tokio::test]
    async fn affirmative_telemetry_opt_in_is_benign() {
        let analysis = investigated_telemetry(
            json!({
                "verdict": "benign",
                "path": "src/telemetry.py",
                "line": 18,
                "description": "the request runs only after the default-off --share-usage flag",
            }),
            "opt_in",
        )
        .await;

        assert_eq!(analysis["verdict"], json!("benign"));
        assert!(analysis["findings"][0].get("type").is_none());
    }

    #[tokio::test]
    async fn secret_exfiltration_takes_precedence_over_telemetry() {
        let analysis = investigated_telemetry(
            json!({
                "verdict": "malicious",
                "path": "src/telemetry.py",
                "line": 18,
                "description": "conceals and sends API_TOKEN to an external collector",
            }),
            "exfiltration",
        )
        .await;

        assert_eq!(analysis["verdict"], json!("malicious"));
        assert!(analysis["findings"][0].get("type").is_none());
    }

    /// The whole type flow without an external model: opened, claimed off the
    /// second label, validated, and folded into one finding rather than two.
    #[tokio::test]
    async fn an_exploitable_finding_reaches_the_report_as_one_investigated_finding() {
        let dir = std::env::temp_dir().join(format!("malwi_side_loading_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let werk = Werk::new();
        werk.set_dir(&dir);
        let finding_type = crate::types::find("side-loading").expect("side-loading is registered");
        werk.add_agent(
            Agent::new()
                .provider(Provider::new(InvestigationMock))
                .model(Model::new("mock"))
                .role("analyst")
                .label(ANALYSIS_LABEL),
        );
        werk.on_result(|queue, done, result| {
            if let Some(investigation) = investigation(queue, done, result) {
                queue.add_task(investigation);
            }
        });
        werk.add_task(
            Task::new("the evidence").label(ANALYSIS_LABEL).schema(
                Schema::new(finding_schema_json()).expect("Analyst finding schema is valid"),
            ),
        );
        werk.start();
        werk.finish_tasks(|_: &Task| true).await;

        let investigations: Vec<Task> = werk
            .find_tasks(|t: &Task| t.get_label() == Some(ANALYSIS_LABEL))
            .into_iter()
            .filter(|task| is_investigation(&werk, task))
            .collect();
        assert_eq!(
            investigations.len(),
            1,
            "one finding opens one investigation, and it opens none of its own"
        );
        let assignee = investigations[0].get_assignee().unwrap_or_default();
        assert!(
            assignee.starts_with(ANALYSIS_LABEL),
            "the Analyst pool claims the type's task, not {assignee}",
        );
        assert_eq!(
            investigation::investigated_type(&werk, &investigations[0])
                .map(|finding_type| finding_type.name()),
            Some(finding_type.name()),
            "the type is read off the finding that opened it",
        );

        let analysis = build_analysis(&werk, &dir, 1);
        let findings = analysis["findings"]
            .as_array()
            .expect("findings is an array");
        assert_eq!(
            findings.len(),
            1,
            "the investigation is not a second finding"
        );
        assert_eq!(findings[0]["type"], json!(finding_type.name()));
        // The parent finding names the same type, so only its fields prove the
        // investigation won dedup.
        assert!(findings[0]["source"].is_string(), "{:?}", findings[0]);
        assert_eq!(findings[0]["control"], json!("static"));
        assert_eq!(
            findings[0]["trigger"]["location"]["path"],
            json!("package.json")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // The report phase: a `reporter`-labelled schema task, drained on its own
    // Werk, and its `{summary, details}` folded into the analysis. Reproduces
    // the report phase of `main` without an external model.
    #[tokio::test]
    async fn reporter_output_is_claimed_by_label_and_merged() {
        let dir = std::env::temp_dir().join(format!("scanner_reporter_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        // Long enough to clear the schema length floors.
        let summary = format!(
            "{} {}",
            analysis::verdict_language("malicious"),
            "acme-widget hides a credential-stealing loader. ".repeat(5)
        );
        let details = "lib/telemetry.js decodes and executes a shell payload. ".repeat(25);
        let provider = Provider::new(FinishMock(json!({
            "summary": summary,
            "details": details,
        })));
        let knowledge = Knowledge::load(&dir).expect("knowledge opens");
        let reporter_output = run_report_phase(
            provider,
            Model::new("mock"),
            &knowledge,
            "verdict: malicious\nfindings: 1\n".to_string(),
            "",
            &dir,
            &dir,
        )
        .await
        .expect("the Reporter answers its task");

        let mut analysis = json!({
            "verdict": "malicious",
            "summary": "1 malicious finding across 1 of 3 files",
            "findings": [],
        });
        merge_reporter_output(&reporter_output, &mut analysis, false);

        assert_eq!(
            analysis["summary"],
            json!(summary.trim()),
            "reporter summary should replace the build_analysis tally",
        );
        assert_eq!(analysis["details"], json!(details));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // agentwerk keeps its counters internal, so every figure `analysis.json` and
    // the summary line carry is folded from the event log the Werk wrote. The
    // fold must find the finished task under the label that claimed it, and
    // what the request that finished it spent.
    #[tokio::test]
    async fn folded_stats_report_the_run_the_werk_logged() {
        let dir = std::env::temp_dir().join(format!("run_stats_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let summary = "acme-widget hides a credential-stealing loader. ".repeat(5);
        let details = "lib/telemetry.js decodes and executes a shell payload. ".repeat(25);
        let provider = Provider::new(FinishMock(json!({
            "summary": summary,
            "details": details,
        })));
        let knowledge = Knowledge::load(&dir).expect("knowledge opens");
        run_report_phase(
            provider,
            Model::new("mock"),
            &knowledge,
            "verdict: malicious\nfindings: 1\n".to_string(),
            "",
            &dir,
            &dir,
        )
        .await
        .expect("the Reporter answers its task");

        // A second Werk over the same directory is what the scan holds at
        // report time, and the fold answers for the log the first one wrote.
        let reader = Werk::new();
        reader.set_dir(&dir);
        let stats = RunStats::fold(&reader);

        assert_eq!(stats.count(Event::TASK_FINISHED), 1);
        // Both halves of a pipeline bar: the label's created tasks are its
        // denominator, and a bar with none is left off the summary entirely.
        assert_eq!(stats.label_count(REPORTER_LABEL, Event::TASK_CREATED), 1,);
        assert_eq!(stats.label_count(REPORTER_LABEL, Event::TASK_FINISHED), 1,);
        assert_eq!(stats.input_tokens, MOCK_INPUT_TOKENS);
        assert_eq!(stats.output_tokens, MOCK_OUTPUT_TOKENS);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
