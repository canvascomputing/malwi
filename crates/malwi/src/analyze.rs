//! The `analyze` command: finds IoC matches and routes each through reachability
//! analysis to an Analyst. Curated extensions scan synchronously against their
//! catalogues and hand their matches to a Tracer. In parallel, Seekers search
//! the tree continuously with regex `grep` queries; an interesting hit also
//! hands over to a Tracer. The Tracer establishes how the flagged code could be
//! reached and hands that analysis to an Analyst for the verdict. A pool of
//! Explorers captures the project's intent alongside, so analysis has that context.
//! Explorers, Seekers, Tracers, and Analysts share one `TicketQueue`; once the
//! pools drain, the Reporter phrases the verdict on its own uncapped queue, so
//! a `--max-time` stop never cuts the summary.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agentwerk::agents::Trajectory;
use agentwerk::providers::{provider_from_env, Model, Provider};
use agentwerk::tools::{FinishTool, GlobTool, GrepTool, ListDirectoryTool, ReadFileTool};
use agentwerk::{Agent, Knowledge, Ticket, TicketQueue};
use serde_json::{json, Value};

use crate::cli::{
    agent_name, default_model, parse_duration, rejected, resolve_models, verify_models, CliExit,
    ModelTable,
};
use crate::discovery::{
    ScanTree, Scanner, ANALYSIS_LABEL, EXPLORER_LABEL, SEEKER_LABEL, TRACER_LABEL,
};
use crate::report::{
    analyst_result_schema, build_analysis, is_run_wide_policy_stop, log_event, print_summary,
    render_findings_table, reporter_result_schema,
};

const SEEKER_AGENT: &str = include_str!("roles/seeker.md");
const ANALYST_AGENT: &str = include_str!("roles/analyst.md");
const ANALYST_VERDICTS: &str = include_str!("roles/verdicts.md");
const TRACER_AGENT: &str = include_str!("roles/tracer.md");
const EXPLORER_AGENT: &str = include_str!("roles/explorer.md");
const REPORTER_AGENT: &str = include_str!("roles/reporter.md");
const REPORTER_LABEL: &str = "reporter";
const REPORTER_NAME: &str = "Reporter";

/// Pool name and the label its tickets carry, shared by the built agents and
/// the `--models` roster so the two cannot disagree.
const POOLS: [(&str, &str); 4] = [
    ("Analyst", ANALYSIS_LABEL),
    ("Seeker", SEEKER_LABEL),
    ("Tracer", TRACER_LABEL),
    ("Explorer", EXPLORER_LABEL),
];

const REPORT_INPUT_LABELS: [&str; 4] = [ANALYSIS_LABEL, TRACER_LABEL, EXPLORER_LABEL, SEEKER_LABEL];

/// Shared `finish` calling convention, substituted into every agent
/// whose ticket carries a `Schema`. One source of truth instead of each
/// agent's `Output` section hand-writing its own wording, since a model
/// that leaves a field JSON-encoded as a string (rather than emitting it as
/// a native array or object) fails schema validation.
const OUTPUT_CONTRACT: &str = include_str!("roles/output_contract.md");

/// Distinct searches a Seeker aims for per ticket before the pool refills it.
/// Injected into the prompt so the target lives in one place.
const SEARCHES_PER_TICKET: u32 = 10;

/// The scanner's working folder: tickets, knowledge stores, and the analysis
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
    pub(crate) fail_fast: bool,
    pub(crate) instruction: Option<String>,
    pub(crate) models: Option<ModelTable>,
}

pub(crate) fn parse(args: &[String]) -> Result<Args, CliExit> {
    let mut target: Option<Target> = None;
    let mut max_turns: Option<u32> = None;
    let mut max_time: Option<Duration> = None;
    let mut concurrency: usize = 2;
    let mut output_file: Option<PathBuf> = None;
    let mut fail_fast: bool = false;
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
            "--fail-fast" => {
                fail_fast = true;
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
        fail_fast,
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
      --fail-fast              Stop on the first malicious finding
      --instruction <TEXT>     Append a custom instruction to every agent's prompt
      --models <FILE>          One model per agent as JSON, keyed by ticket label,
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
    let provider = provider_from_env().unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    });

    verify_models(provider.as_ref(), &models).await;

    // Start every run from a clean working folder, and before the target is
    // staged into it: no tickets, knowledge, or results carried over from a
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
    if scan.extensions.is_empty() {
        eprintln!(
            "no files with extensions found under {} ({} file(s) walked)",
            args.target, scan.files,
        );
        std::process::exit(1);
    }

    let files_walked = scan.files;

    let analyst_knowledge = Knowledge::load(WORK_DIR).unwrap_or_else(|e| {
        eprintln!("cannot open analyst knowledge: {e}");
        std::process::exit(1);
    });

    // Seed the attack-pattern pages before indexing: `Knowledge::load` builds its
    // index from whatever it finds on disk, so the seed must be in place first.
    let exploration_dir = format!("{WORK_DIR}/exploration");
    if let Err(e) = crate::attacks::copy_seed_into(std::path::Path::new(&exploration_dir)) {
        eprintln!("cannot seed exploration knowledge: {e}");
        std::process::exit(1);
    }
    let exploration_knowledge = Knowledge::load(&exploration_dir).unwrap_or_else(|e| {
        eprintln!("cannot open exploration knowledge: {e}");
        std::process::exit(1);
    });

    // Run-scoped writable store, seeded with the same attack-pattern pages the
    // Tracer gets. The Seeker records each query it runs here, so a refilled ticket
    // reads the index and skips shapes already tried.
    let searches_dir = format!("{WORK_DIR}/searches");
    if let Err(e) = crate::attacks::copy_seed_into(std::path::Path::new(&searches_dir)) {
        eprintln!("cannot seed search knowledge: {e}");
        std::process::exit(1);
    }
    let seeker_knowledge = Knowledge::load(&searches_dir).unwrap_or_else(|e| {
        eprintln!("cannot open search knowledge: {e}");
        std::process::exit(1);
    });

    // Write the tree's files into both worker stores as a paginated map, before
    // any agent starts, so Tracers and Seekers read it instead of re-globbing.
    crate::discovery::write_file_map(&exploration_knowledge, &scan.files_by_ext);
    crate::discovery::write_file_map(&seeker_knowledge, &scan.files_by_ext);

    eprintln!("malwi analyze: {}\n", args.target);

    let tickets = TicketQueue::new();
    tickets.dir(WORK_DIR);
    // The default of 10 is tight for a weaker model that frequently replies with
    // no tool call at all: a ticket can burn its whole retry budget on that alone,
    // failing via MaxSchemaRetries before it ever reaches a real finding.
    tickets.max_schema_retries(20);
    tickets.schema_for_label(ANALYSIS_LABEL, analyst_result_schema());
    if let Some(n) = args.max_turns {
        tickets.max_turns(n);
    }
    if let Some(d) = args.max_time {
        tickets.max_time(d);
    }
    let log_tickets = Arc::clone(&tickets);
    tickets.on_event(move |e| log_event(e, &log_tickets));

    // A policy trip alone never flips `is_cancelled()`, so `--max-time` would
    // otherwise just abandon tickets `InProgress` forever.
    tickets.cancel_on_event(is_run_wide_policy_stop);

    // A policy stop (time/turns/tokens) is a graceful end, not an abort: unlike a
    // ctrl-c cancel it must still produce the report. Record it so the abort check
    // can tell the two apart, since both flip `is_cancelled()`.
    let policy_stopped = Arc::new(AtomicBool::new(false));
    let policy_flag = Arc::clone(&policy_stopped);
    tickets.on_event(move |e| {
        if is_run_wide_policy_stop(e) {
            policy_flag.store(true, Ordering::Relaxed);
        }
    });

    // Fail-fast records the first malicious verdict and calls off the Seeker,
    // Tracer, and Analyst pools; the Explorer and Reporter still run so the
    // report is whole.
    let malicious_found = Arc::new(AtomicBool::new(false));
    if args.fail_fast {
        let trip = Arc::clone(&malicious_found);
        tickets.on_result(move |_, result| {
            if is_malicious_verdict(result) {
                trip.store(true, Ordering::Relaxed);
            }
        });
        for label in [SEEKER_LABEL, TRACER_LABEL, ANALYSIS_LABEL] {
            tickets.cancel_label_on_result(label, |_, result| is_malicious_verdict(result));
        }
    }

    // Capture the messages of any ticket that lands a malicious or exploitable
    // verdict as a training example under trajectories/, on every run (not just
    // fail-fast). Benign dismissals are skipped.
    let trajectory_queue = Arc::clone(&tickets);
    tickets.on_result(move |ticket, result| {
        if !is_finding_verdict(result) {
            return;
        }
        let Some(agent) = ticket.assignee.as_deref() else {
            return;
        };
        let model = trajectory_queue.model_for_agent(agent);
        let _ = Trajectory::from_ticket(agent, model.as_deref(), ticket).save(WORK_DIR);
    });

    let instruction_section = match args.instruction.as_deref() {
        None => String::new(),
        Some(text) => format!("Additional instructions:\n\n{text}"),
    };

    // The Explorer only sketches an overview, so each ticket is one tight pass:
    // one file-map page, at most three high-level reads, one short page, done.
    let explorer_time_budget = "an overview only: read at most 3 high-level files \
        (a README or the entry point), then write one short page"
        .to_string();

    // Every pool shares one queue; labels route each ticket to its agent.
    for i in 0..concurrency {
        let name = agent_name("Analyst", i);
        tickets.agent(
            Agent::new()
                .provider(Arc::clone(&provider))
                .model(models[&name].clone())
                .name(name)
                .role(ANALYST_AGENT.trim())
                .template("instruction", &instruction_section)
                .template("verdicts", ANALYST_VERDICTS.trim())
                .template("output_contract", OUTPUT_CONTRACT.trim())
                .label(ANALYSIS_LABEL)
                .dir(scan_dir.to_path_buf())
                .knowledge(&analyst_knowledge)
                .tool(ReadFileTool)
                .tool(ListDirectoryTool)
                .tool(GrepTool)
                .build(),
        );
    }

    // Continuous discovery, refilled after every ticket.
    for i in 0..concurrency {
        let name = agent_name("Seeker", i);
        tickets.agent(
            // Every ticket ends in a handover; seeker.md is what enforces it.
            Agent::new()
                .provider(Arc::clone(&provider))
                .model(models[&name].clone())
                .name(name)
                .role(SEEKER_AGENT.trim())
                .template("instruction", &instruction_section)
                .template("searches_per_ticket", SEARCHES_PER_TICKET.to_string())
                .label(SEEKER_LABEL)
                .dir(scan_dir.to_path_buf())
                .knowledge(&seeker_knowledge)
                .tool(GrepTool)
                .build(),
        );
    }

    // Demand-driven reachability. Shares exploration_knowledge to read the
    // Explorer's pages and record its own alongside.
    for i in 0..concurrency {
        let name = agent_name("Tracer", i);
        tickets.agent(
            // Every ticket ends in a handover; tracer.md is what enforces it.
            Agent::empty()
                .provider(Arc::clone(&provider))
                .model(models[&name].clone())
                .name(name)
                .role(TRACER_AGENT.trim())
                .template("instruction", &instruction_section)
                .label(TRACER_LABEL)
                .dir(scan_dir.to_path_buf())
                .knowledge(&exploration_knowledge)
                .tool(ReadFileTool)
                .tool(ListDirectoryTool)
                .tool(GlobTool)
                .tool(GrepTool)
                .tool(FinishTool)
                .build(),
        );
    }

    // Bounded overview into exploration_knowledge; no handoff.
    for i in 0..concurrency {
        let name = agent_name("Explorer", i);
        tickets.agent(
            Agent::new()
                .provider(Arc::clone(&provider))
                .model(models[&name].clone())
                .name(name)
                .role(EXPLORER_AGENT.trim())
                .template("instruction", &instruction_section)
                .template("explorer_time_budget", &explorer_time_budget)
                .label(EXPLORER_LABEL)
                .dir(scan_dir.to_path_buf())
                .knowledge(&exploration_knowledge)
                .tool(ReadFileTool)
                .tool(ListDirectoryTool)
                .tool(GlobTool)
                .build(),
        );
    }
    let exploration_body = "Open file-map-01 with manage_knowledge to see the layout, then read \
         at most three high-level files (a README or the main entry point) to sketch what the \
         project is and does, and write one short overview page. Overview only, not an exhaustive read.";
    for _ in 0..concurrency {
        tickets.ticket(Ticket::new(exploration_body).label(EXPLORER_LABEL));
    }

    // Seed the discovery pool so the Seeker searches from the start.
    let search_body = "Choose an untested pattern and search for it: a past-incident technique \
         whose file type appears in the file map (open its page for the marker and grep it), or a \
         common dangerous call for a language in the tree. Skip patterns already recorded in knowledge.";
    for _ in 0..concurrency {
        tickets.ticket(Ticket::new(search_body).label(SEEKER_LABEL));
    }

    // Only the Seeker refills: the Explorer's overview is bounded to its seed
    // tickets and the Tracer is demand-driven.
    {
        let weak = Arc::downgrade(&tickets);
        let search_body = search_body.to_string();
        tickets.create_ticket_on_result(move |done, _| {
            if !done.has_label(SEEKER_LABEL) {
                return None;
            }
            // A ticket carrying a cancelled label is never claimed.
            if weak.upgrade()?.is_label_cancelled(SEEKER_LABEL) {
                return None;
            }
            Some(Ticket::new(search_body.clone()).label(SEEKER_LABEL))
        });
    }

    install_ctrl_c_handler(Arc::clone(&tickets));

    let scanner = Scanner::new(&scan_dir);

    // One run, kept live across both phases: Explorers, Seekers, Tracers, and
    // Analysts work concurrently while the Reporter waits idle for its ticket.
    tickets.start();
    let per_tech = scanner.discover(&tickets, &scan).await;
    let total_hits: usize = per_tech.iter().map(|(_, n)| n).sum();
    if total_hits == 0 {
        crate::report::scanner(format!("{files_walked} files → 0 hits"));
    } else {
        let techs: Vec<&str> = per_tech.iter().map(|(t, _)| *t).collect();
        crate::report::scanner(format!(
            "{files_walked} files → {total_hits} hits ({}) → reachability",
            techs.join(", "),
        ));
    }

    // Wait for the findings, the project summary, and any Seeker ticket to finish.
    // The pools drain on their own; under --max-time the cap is the backstop.
    wait_for_report_inputs(&tickets).await;
    // A hard second-press ctrl-c aborts; a policy stop (time/turns/tokens) and a
    // wind-down are graceful and fall through to write the report below.
    if tickets.is_cancelled() && !policy_stopped.load(Ordering::Relaxed) {
        eprintln!("\ncancelled.");
        std::process::exit(130);
    }

    let mut analysis = build_analysis(&tickets, &scan_dir, files_walked);

    // Stop every pool, including any Seeker still searching, before the report
    // phase: the Reporter runs on its own queue, out of the cap's reach.
    tickets.cancel();
    tickets.finish().await;

    // Report phase: the Explorer pool has finished, so its summaries are on disk,
    // and the findings are already in `analysis`.
    let has_findings = analysis["findings"]
        .as_array()
        .is_some_and(|a| !a.is_empty());
    let has_exploration = !exploration_knowledge.index().is_empty();
    // Coverage is partial when the pools were called off early (time cap,
    // ctrl-c, fail-fast) rather than drained; the Reporter scopes an
    // all-clear accordingly.
    let partial_coverage =
        policy_stopped.load(Ordering::Relaxed) || tickets.is_label_cancelled(SEEKER_LABEL);
    let report_tickets = if has_findings || has_exploration {
        let report_tickets = run_report_phase(
            Arc::clone(&provider),
            models[REPORTER_NAME].clone(),
            &exploration_knowledge,
            render_findings_table(&analysis, partial_coverage),
            &instruction_section,
            Path::new(WORK_DIR),
            &scan_dir,
        )
        .await;
        merge_reporter_verdict(&report_tickets, &mut analysis);
        Some(report_tickets)
    } else {
        None
    };

    let stats = tickets.stats();
    let report_stats = report_tickets.as_ref().map(|r| r.stats());
    let report_input = report_stats.as_ref().map_or(0, |s| s.input_tokens());
    let report_output = report_stats.as_ref().map_or(0, |s| s.output_tokens());
    analysis["input_tokens"] = json!(stats.input_tokens() + report_input);
    analysis["output_tokens"] = json!(stats.output_tokens() + report_output);
    analysis["stats"] = serde_json::to_value(stats).expect("Stats serializes");

    let analysis_file = args
        .output_file
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("{WORK_DIR}/analysis.json")));
    let json_str = serde_json::to_string_pretty(&analysis).expect("serializable");
    fs::write(&analysis_file, json_str).expect("write analysis.json");

    print_summary(
        &tickets,
        report_tickets.as_deref(),
        &analysis,
        &analysis_file,
        &scan,
        &scan_dir,
    );

    // Surface a malicious verdict through the exit status for `--fail-fast` callers.
    if args.fail_fast && malicious_found.load(Ordering::Relaxed) {
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

/// Block until the Reporter's inputs are ready. Polls rather than calling
/// [`TicketQueue::finish`], which would wait on the entire queue. A called-off
/// pool's tickets stay pending forever, so they are skipped.
async fn wait_for_report_inputs(tickets: &TicketQueue) {
    loop {
        if tickets.is_cancelled() {
            return;
        }
        let pending = !tickets
            .find_tickets(|t| {
                t.is_pending()
                    && REPORT_INPUT_LABELS
                        .iter()
                        .any(|label| t.has_label(label) && !tickets.is_label_cancelled(label))
            })
            .is_empty();
        if !pending {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Run the Reporter on its own `TicketQueue`, so nothing that stopped the scan
/// (time limit, cancel) can stop the report. No max time: the schema-retry budget
/// bounds a Reporter that never finishes its ticket.
async fn run_report_phase(
    provider: Arc<dyn Provider>,
    model: Model,
    knowledge: &Arc<Knowledge>,
    findings_table: String,
    instruction: &str,
    dir: &Path,
    scan_dir: &Path,
) -> Arc<TicketQueue> {
    let report_tickets = TicketQueue::new();
    report_tickets.dir(dir);
    // Same allowance as the scan queue: a weaker model can burn the default
    // budget on replies with no tool call.
    report_tickets.max_schema_retries(20);
    let log_tickets = Arc::clone(&report_tickets);
    report_tickets.on_event(move |e| log_event(e, &log_tickets));
    report_tickets.agent(
        Agent::new()
            .name(REPORTER_NAME)
            .provider(provider)
            .model(model)
            .role(REPORTER_AGENT.trim())
            .template("instruction", instruction)
            .template("output_contract", OUTPUT_CONTRACT.trim())
            .template("verdicts", ANALYST_VERDICTS.trim())
            .label(REPORTER_LABEL)
            .knowledge(knowledge)
            // Read-only access to the scanned tree so the Reporter can quote the
            // exact cited line as a code excerpt instead of inventing one.
            .dir(scan_dir.to_path_buf())
            .tool(ReadFileTool)
            .build(),
    );
    report_tickets.ticket(
        Ticket::new(findings_table)
            .label(REPORTER_LABEL)
            .schema(reporter_result_schema()),
    );
    report_tickets.finish().await;
    report_tickets
}

/// Call off the Explorer and Seeker pools on the first ctrl-c, letting the
/// in-flight backlog drain into a report. A second press forces an exit in case
/// the drain itself wedges.
fn install_ctrl_c_handler(tickets: Arc<TicketQueue>) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }
        eprintln!(
            "\n[ctrl-c] winding down: no new work, finishing in-flight analysis then reporting. \
             Press again to force exit."
        );
        tickets.cancel_label(EXPLORER_LABEL);
        tickets.cancel_label(SEEKER_LABEL);
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }
        eprintln!("\n[ctrl-c] hard exit on second press.");
        tickets.cancel();
        std::process::exit(130);
    });
}

/// Read the Reporter's `{summary, details}` off its finished ticket and fold it
/// into the analysis. Missing fields leave the `build_analysis` tally in place.
fn merge_reporter_verdict(tickets: &TicketQueue, analysis: &mut Value) {
    let Some(result) = tickets.results_for_label(REPORTER_LABEL).pop() else {
        return;
    };
    if let Some(s) = result.get("summary") {
        analysis["summary"] = s.clone();
    }
    if let Some(d) = result.get("details") {
        analysis["details"] = d.clone();
    }
}

/// True when a schema-validated result object carries `status: "malicious"`.
fn is_malicious_verdict(result: &Value) -> bool {
    result.get("status").and_then(|v| v.as_str()) == Some("malicious")
}

/// True when a result carries a non-benign verdict (`malicious` or
/// `exploitable`): the analyst reached an actual finding, not a dismissal.
fn is_finding_verdict(result: &Value) -> bool {
    matches!(
        result.get("status").and_then(|v| v.as_str()),
        Some("malicious") | Some("exploitable")
    )
}

#[cfg(test)]
mod tests {
    use crate::cli::{parse_line as parse, CliExit, Command};

    #[test]
    fn scan_takes_its_target_and_its_flags() {
        let Ok(Command::Analyze(args)) =
            parse("analyze ./src --concurrency 4 --max-time 5m --fail-fast")
        else {
            panic!("analyze should parse");
        };
        assert!(matches!(args.target, Target::Directory(_)));
        assert_eq!(args.target.to_string(), "./src");
        assert_eq!(args.concurrency, 4);
        assert_eq!(args.max_time, Some(Duration::from_secs(300)));
        assert!(args.fail_fast);
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

    use agentwerk::providers::types::{
        ContentBlock, ModelResponse, ResponseStatus, StreamEvent, TokenUsage,
    };
    use agentwerk::providers::{ModelRequest, Provider, ProviderResult};

    use super::*;

    #[test]
    fn malicious_verdict_reads_status_from_validated_result() {
        assert!(is_malicious_verdict(
            &json!({"status": "malicious", "path": "a.py"})
        ));
        assert!(!is_malicious_verdict(&json!({"status": "benign"})));
        assert!(!is_malicious_verdict(&json!({"path": "a.py"})));
        assert!(!is_malicious_verdict(&json!("a plain summary")));
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
        let models = resolve_models(None, &roster, || Model::from_name("model-from-env"));
        assert_eq!(models.len(), roster.len());
        assert!(models.values().all(|m| m.name == "model-from-env"));
    }

    #[test]
    fn finding_verdict_matches_malicious_and_exploitable_but_not_benign() {
        assert!(is_finding_verdict(
            &json!({"status": "malicious", "path": "a.py"})
        ));
        assert!(is_finding_verdict(
            &json!({"status": "exploitable", "path": "a.py"})
        ));
        assert!(!is_finding_verdict(&json!({"status": "benign"})));
        assert!(!is_finding_verdict(&json!({"path": "a.py"})));
        assert!(!is_finding_verdict(&json!("a plain summary")));
    }

    /// Finishes whatever ticket it is given by echoing a fixed `result`.
    struct FinishMock(Value);

    impl Provider for FinishMock {
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
                        input: json!({ "result": result }),
                    }],
                    status: ResponseStatus::ToolUse,
                    usage: TokenUsage::default(),
                    model: "mock".into(),
                })
            })
        }
    }

    // The report phase: a `reporter`-labelled schema ticket, drained on its own
    // queue, and its `{summary, details}` folded into the analysis. Reproduces
    // the report phase of `main` without a live model.
    #[tokio::test]
    async fn reporter_verdict_is_claimed_by_label_and_merged() {
        let dir = std::env::temp_dir().join(format!("scanner_reporter_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        // Long enough to clear the schema length floors.
        let summary = "acme-widget hides a credential-stealing loader. ".repeat(5);
        let details = "lib/telemetry.js decodes and executes a shell payload. ".repeat(25);
        let provider: Arc<dyn Provider> = Arc::new(FinishMock(json!({
            "summary": summary,
            "details": details,
        })));
        let knowledge = Knowledge::load(&dir).expect("knowledge opens");
        let report_tickets = run_report_phase(
            provider,
            Model::from_name("mock"),
            &knowledge,
            "worst_status: malicious\nfindings: 1\n".to_string(),
            "",
            &dir,
            &dir,
        )
        .await;

        let mut analysis = json!({
            "status": "malicious",
            "summary": "1 malicious finding across 1 of 3 files",
            "findings": [],
        });
        merge_reporter_verdict(&report_tickets, &mut analysis);

        assert_eq!(
            analysis["summary"],
            json!(summary),
            "reporter summary should replace the build_analysis tally",
        );
        assert_eq!(analysis["details"], json!(details));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
