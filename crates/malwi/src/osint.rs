//! The `osint` command: an open-source intelligence pass over malwi's own blind
//! spots. A Curator audits the attack-pattern corpus and names the techniques it
//! cannot recognize, a Scout pool hunts public sources for each gap, an Editor
//! pool drafts a page from the sources, and a Verifier pool checks each draft
//! back against its own citations. Only an accepted page is installed, so a run
//! that finds nothing trustworthy leaves the corpus exactly as it was.

mod web_search;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agentwerk::providers::provider_from_env;
use agentwerk::providers::{Model, Provider};
use agentwerk::tools::FetchUrlTool;
use agentwerk::{Agent, Knowledge, Ticket, TicketQueue};
use serde_json::{json, Value};

use crate::attacks;
use crate::cli::{
    agent_name, default_model, parse_duration, rejected, resolve_models, verify_models, CliExit,
    ModelTable,
};
use crate::report::{headline, is_run_wide_policy_stop, log_event, truncate};
use web_search::{brave_key_from_env, gap_schema, verdict_schema, web_search_tool, PAGE_FORMAT};

const CURATOR_AGENT: &str = include_str!("roles/curator.md");
const SCOUT_AGENT: &str = include_str!("roles/scout.md");
const EDITOR_AGENT: &str = include_str!("roles/editor.md");
const VERIFIER_AGENT: &str = include_str!("roles/verifier.md");
const OUTPUT_CONTRACT: &str = include_str!("roles/output_contract.md");

const CURATION_LABEL: &str = "curation";
const SCOUTING_LABEL: &str = "scouting";
const EDITING_LABEL: &str = "editing";
const VERIFICATION_LABEL: &str = "verification";
const CURATOR_NAME: &str = "Curator";

/// Pool name and the label its tickets carry, shared by the built agents and
/// the `--models` roster so the two cannot disagree. The Curator is absent: it
/// works alone on its own queue and is appended to the roster by name.
const POOLS: [(&str, &str); 3] = [
    ("Scout", SCOUTING_LABEL),
    ("Editor", EDITING_LABEL),
    ("Verifier", VERIFICATION_LABEL),
];

/// The command's working folder: tickets, the knowledge store the chain drafts
/// into, and the osint output all live here. Wiped at the start of every run so
/// no half-finished draft from a prior run is mistaken for new work.
const WORK_DIR: &str = ".malwi/osint";

/// Where a page lands when there is no source tree to extend. Deliberately
/// outside [`WORK_DIR`]: an accepted page is the run's only lasting output, and
/// the wipe above would otherwise delete what the previous run installed.
const FALLBACK_PAGES_DIR: &str = ".malwi/attacks";

/// Gaps one run researches. The Curator is asked for this many and the list is
/// truncated to it, so a run costs a predictable number of Scout chains.
const MAX_GAPS: usize = 5;

/// Where the run's JSON lands. Inside [`WORK_DIR`], so a rerun replaces it.
const OSINT_FILE: &str = ".malwi/osint/osint.json";

/// Options of `malwi osint [FOCUS]`.
pub(crate) struct Args {
    /// What to steer the hunt towards. Without it the run audits the whole
    /// knowledge base and picks its own gaps.
    pub(crate) steer: Option<String>,
    pub(crate) max_time: Option<Duration>,
    pub(crate) concurrency: usize,
    pub(crate) knowledge_dir: Option<PathBuf>,
    pub(crate) models: Option<ModelTable>,
}

/// Every word outside a flag is part of the focus, so quoting it is optional.
/// No focus at all is legal: the run then audits the whole knowledge base.
pub(crate) fn parse(args: &[String]) -> Result<Args, CliExit> {
    let mut words: Vec<&str> = Vec::new();
    let mut max_time: Option<Duration> = None;
    let mut concurrency: usize = 2;
    let mut knowledge_dir: Option<PathBuf> = None;
    let mut models: Option<ModelTable> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
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
            "--knowledge" => {
                i += 1;
                knowledge_dir = Some(PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| rejected("--knowledge expects a path"))?,
                ));
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
            word => words.push(word),
        }
        i += 1;
    }

    Ok(Args {
        steer: (!words.is_empty()).then(|| words.join(" ")),
        max_time,
        concurrency,
        knowledge_dir,
        models,
    })
}

pub(crate) fn help() -> String {
    "malwi osint. Performs deep research about supply-chain attacks for updating
the knowledge base of research agents.

Usage: malwi osint [FOCUS] [OPTIONS]

Alias: o

Options:
      --concurrency <N>        Agent pool size per phase (default: 2)
      --max-time <DUR>         Time limit. Bare seconds or s/m/h suffix (default: unlimited)
      --knowledge <DIR>        Install new pages here (default: the source tree
                               when run from a checkout, else .malwi/attacks)
      --models <FILE>          One model per agent as JSON, keyed by ticket label,
                               pool name, or agent name. A value is a model name or
                               an object of model, reasoning, and context_window
                               (default: every agent runs the model the environment
                               names)
  -h, --help                   Show this help

Environment:
  BRAVE_API_KEY   Required. Web search runs through the Brave Search API.

Examples:
  malwi osint
  malwi o npm registry attacks 2026 --max-time 20m"
        .to_string()
}

pub(crate) async fn run(args: Args) {
    let concurrency = args.concurrency.max(1);
    let roster = roster(concurrency);
    let models = resolve_models(args.models.as_ref(), &roster, default_model);

    // The web is the whole point of this command, so a missing key stops the
    // run before any model call rather than after every Scout ticket has failed.
    let brave_key = brave_key_from_env().unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    });

    let provider = provider_from_env().unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    });

    verify_models(provider.as_ref(), &models).await;

    let _ = fs::remove_dir_all(WORK_DIR);

    // Seed the corpus before indexing: `Knowledge::load` builds its index from
    // whatever it finds on disk, and the Curator audits that index.
    let work_dir = Path::new(WORK_DIR);
    if let Err(e) = attacks::copy_seed_into(work_dir) {
        eprintln!("cannot seed osint knowledge: {e}");
        std::process::exit(1);
    }
    let knowledge = Knowledge::load(work_dir).unwrap_or_else(|e| {
        eprintln!("cannot open osint knowledge: {e}");
        std::process::exit(1);
    });

    let install_dir = args
        .knowledge_dir
        .clone()
        .unwrap_or_else(|| attacks::install_dir(Path::new(FALLBACK_PAGES_DIR)));

    let steer_section = match args.steer.as_deref() {
        None => String::new(),
        Some(text) => format!("Additional instructions:\n\n{text}"),
    };

    eprintln!(
        "malwi osint: up to {MAX_GAPS} gap(s), pages install into {}\n",
        install_dir.display(),
    );

    let (gaps, audit_stats) = run_curation_phase(
        Arc::clone(&provider),
        models[CURATOR_NAME].clone(),
        &knowledge,
        &brave_key,
        &steer_section,
        &args,
    )
    .await;
    if gaps.is_empty() {
        eprintln!("\nno gap named: the corpus covers what the audit could find.");
        std::process::exit(0);
    }

    let tickets = TicketQueue::new();
    tickets.dir(WORK_DIR);
    // The default of 10 is tight for a weaker model that frequently replies with
    // no tool call at all: a ticket can burn its whole retry budget on that alone.
    tickets.max_schema_retries(20);
    tickets.schema_for_label(VERIFICATION_LABEL, verdict_schema());
    if let Some(d) = args.max_time {
        tickets.max_time(d);
    }
    let log_tickets = Arc::clone(&tickets);
    tickets.on_event(move |e| log_event(e, &log_tickets));

    // A policy trip alone never flips `is_cancelled()`, so `--max-time` would
    // otherwise just abandon tickets `InProgress` forever.
    tickets.cancel_on_event(is_run_wide_policy_stop);
    let policy_stopped = Arc::new(AtomicBool::new(false));
    let policy_flag = Arc::clone(&policy_stopped);
    tickets.on_event(move |e| {
        if is_run_wide_policy_stop(e) {
            policy_flag.store(true, Ordering::Relaxed);
        }
    });

    build_pools(
        &tickets,
        &provider,
        &models,
        &knowledge,
        &brave_key,
        &steer_section,
        concurrency,
    );

    for gap in &gaps {
        tickets.ticket(Ticket::new(scouting_body(gap)).label(SCOUTING_LABEL));
    }

    install_ctrl_c_handler(Arc::clone(&tickets));

    headline("OSINT");
    tickets.finish().await;

    // A hard second-press ctrl-c already exited; a first press or a policy stop
    // is graceful and falls through, so whatever was verified still installs.
    let pages = install_verified_pages(&tickets, &knowledge, &install_dir);

    // The audit ran on its own queue, so its spend is added back here: a total
    // that counted only the pools would report a fraction of what the run cost.
    let stats = tickets.stats();
    let audit_input = audit_stats["input_tokens"].as_u64().unwrap_or(0);
    let audit_output = audit_stats["output_tokens"].as_u64().unwrap_or(0);
    let osint = json!({
        "steer": args.steer,
        "install_dir": install_dir.display().to_string(),
        "partial": policy_stopped.load(Ordering::Relaxed) || tickets.is_cancelled(),
        "gaps": gaps,
        "pages": pages,
        "input_tokens": stats.input_tokens() + audit_input,
        "output_tokens": stats.output_tokens() + audit_output,
        "stats": serde_json::to_value(stats).expect("Stats serializes"),
        "audit_stats": audit_stats,
    });

    let osint_file = Path::new(OSINT_FILE);
    let json_str = serde_json::to_string_pretty(&osint).expect("serializable");
    if let Err(e) = fs::write(osint_file, json_str) {
        eprintln!("cannot write {}: {e}", osint_file.display());
        std::process::exit(1);
    }

    print_summary(&osint, osint_file, &install_dir);
}

/// Every agent the run builds, with its label. The Curator works alone, so it
/// carries no member number.
fn roster(concurrency: usize) -> Vec<(String, &'static str)> {
    let mut agents: Vec<(String, &'static str)> = POOLS
        .iter()
        .flat_map(|(pool, label)| (0..concurrency).map(move |i| (agent_name(pool, i), *label)))
        .collect();
    agents.push((CURATOR_NAME.to_string(), CURATION_LABEL));
    agents
}

/// Run the Curator alone on its own queue and read the gap list off its ticket.
/// Separate from the osint queue because the whole chain is shaped by this one
/// result: there is nothing for the pools to claim until it lands.
async fn run_curation_phase(
    provider: Arc<dyn Provider>,
    model: Model,
    knowledge: &Arc<Knowledge>,
    brave_key: &str,
    steer: &str,
    args: &Args,
) -> (Vec<Value>, Value) {
    let curation_tickets = TicketQueue::new();
    curation_tickets.dir(WORK_DIR);
    curation_tickets.max_schema_retries(20);
    // The audit spends the same budget the chain does: an uncapped Curator can
    // search past `--max-time` and leave nothing for the pools it feeds.
    if let Some(d) = args.max_time {
        curation_tickets.max_time(d);
    }
    curation_tickets.cancel_on_event(is_run_wide_policy_stop);
    let log_tickets = Arc::clone(&curation_tickets);
    curation_tickets.on_event(move |e| log_event(e, &log_tickets));
    curation_tickets.agent(
        Agent::new()
            .name(CURATOR_NAME)
            .provider(provider)
            .model(model)
            .role(CURATOR_AGENT.trim())
            .template("instruction", steer)
            .template("max_gaps", MAX_GAPS.to_string())
            .template("output_contract", OUTPUT_CONTRACT.trim())
            .label(CURATION_LABEL)
            .knowledge(knowledge)
            .tool(web_search_tool(brave_key.to_string()))
            .build(),
    );
    curation_tickets.ticket(
        Ticket::new(curation_body(args.steer.as_deref()))
            .label(CURATION_LABEL)
            .schema(gap_schema()),
    );

    headline("AUDIT");
    curation_tickets.finish().await;

    // The queue dies with this function, and `Stats` borrows from it, so the
    // audit's spend is handed back serialized: it is the caller's only chance
    // to count what the audit cost.
    let stats = serde_json::to_value(curation_tickets.stats()).expect("Stats serializes");
    let Some(result) = curation_tickets.results_for_label(CURATION_LABEL).pop() else {
        return (Vec::new(), stats);
    };
    let gaps = result["gaps"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .take(MAX_GAPS)
        .collect();
    (gaps, stats)
}

/// Register the Scout, Editor, and Verifier pools. Each hands over to the next
/// by label, so the chain is wired by the roles rather than by a driver step.
fn build_pools(
    tickets: &TicketQueue,
    provider: &Arc<dyn Provider>,
    models: &std::collections::BTreeMap<String, Model>,
    knowledge: &Arc<Knowledge>,
    brave_key: &str,
    steer: &str,
    concurrency: usize,
) {
    for i in 0..concurrency {
        let name = agent_name("Scout", i);
        tickets.agent(
            Agent::new()
                .provider(Arc::clone(provider))
                .model(models[&name].clone())
                .name(name)
                .role(SCOUT_AGENT.trim())
                .template("instruction", steer)
                .label(SCOUTING_LABEL)
                .knowledge(knowledge)
                .tool(web_search_tool(brave_key.to_string()))
                .tool(FetchUrlTool)
                .build(),
        );
    }

    for i in 0..concurrency {
        let name = agent_name("Editor", i);
        tickets.agent(
            Agent::new()
                .provider(Arc::clone(provider))
                .model(models[&name].clone())
                .name(name)
                .role(EDITOR_AGENT.trim())
                .template("instruction", steer)
                .template("page_format", PAGE_FORMAT.trim())
                .label(EDITING_LABEL)
                .knowledge(knowledge)
                .tool(FetchUrlTool)
                .build(),
        );
    }

    for i in 0..concurrency {
        let name = agent_name("Verifier", i);
        tickets.agent(
            Agent::new()
                .provider(Arc::clone(provider))
                .model(models[&name].clone())
                .name(name)
                .role(VERIFIER_AGENT.trim())
                .template("instruction", steer)
                .template("page_format", PAGE_FORMAT.trim())
                .template("output_contract", OUTPUT_CONTRACT.trim())
                .label(VERIFICATION_LABEL)
                .knowledge(knowledge)
                .tool(FetchUrlTool)
                .build(),
        );
    }
}

/// The ticket body the Curator claims. A steer becomes the assignment rather
/// than a footnote in the role, because the role argues hard for spreading gaps
/// across ecosystems and an operator who named a subject has already made that
/// call. The ticket is the instruction the model acts on; the role is context.
fn curation_body(steer: Option<&str>) -> String {
    const SWEEP: &str = "List your knowledge to see what the corpus already covers, read the \
         pages closest to what you intend to name, then search for campaigns and techniques none \
         of them describe. Name the gaps worth researching, each with the search that would \
         confirm it.";
    match steer {
        None => SWEEP.to_string(),
        Some(subject) => format!(
            "Audit the corpus against this subject, and nothing else:\n\n\
             {subject}\n\n\
             Search for that subject by name first, before any other query. Read what the index \
             already says about it, then name the techniques it leaves uncovered. The guideline \
             about spreading gaps across ecosystems does not apply to this ticket: the subject \
             above replaces it, and a gap outside the subject is off-ticket however good it \
             looks. If the corpus already covers the subject, name the narrower techniques still \
             missing inside it rather than ranging outside.",
        ),
    }
}

/// The ticket body a Scout claims: one gap, in the Curator's own words.
fn scouting_body(gap: &Value) -> String {
    format!(
        "## Gap\n\n{}\n\n## Why it matters\n\n{}\n\n## Suggested search\n\n{}",
        gap["topic"].as_str().unwrap_or(""),
        gap["why"].as_str().unwrap_or(""),
        gap["query"].as_str().unwrap_or(""),
    )
}

/// Move every accepted draft out of the run's store and into the install
/// directory. A rejected page and a page whose slug the binary already ships
/// are both recorded and left where they are.
fn install_verified_pages(
    tickets: &TicketQueue,
    knowledge: &Knowledge,
    install_dir: &Path,
) -> Vec<Value> {
    tickets
        .results_for_label(VERIFICATION_LABEL)
        .into_iter()
        .map(|verdict| {
            let slug = verdict["slug"].as_str().unwrap_or("").trim().to_string();
            let accepted = verdict["verdict"].as_str() == Some("accepted");
            let tags = tags_of(&verdict);
            let outcome = install_one(&slug, accepted, &tags, knowledge, install_dir);
            json!({
                "slug": slug,
                "verdict": verdict["verdict"],
                "reason": verdict["reason"].as_str().unwrap_or(""),
                "tags": tags,
                "installed": outcome.is_ok(),
                "outcome": outcome.unwrap_or_else(|message| message),
            })
        })
        .collect()
}

/// The technique tags the Verifier assigned, which the Editor's save had no
/// field to carry.
fn tags_of(verdict: &Value) -> Vec<String> {
    verdict["tags"]
        .as_array()
        .map(|tags| {
            tags.iter()
                .filter_map(|t| t.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// `Ok` carries where the page landed, `Err` why it did not. The draft is read
/// back through the store rather than off disk, so the description the Editor
/// gave the page survives into the corpus front matter.
fn install_one(
    slug: &str,
    accepted: bool,
    tags: &[String],
    knowledge: &Knowledge,
    install_dir: &Path,
) -> Result<String, String> {
    if !accepted {
        return Err("rejected by the Verifier".to_string());
    }
    if slug.is_empty() {
        return Err("the verdict named no page".to_string());
    }
    // Overwriting a shipped page would let one run silently rewrite what the
    // scanner already knows, so a slug the binary carries is never installed.
    if attacks::is_seeded(slug) {
        return Err(format!("{slug} is already part of the corpus"));
    }
    let Ok(mut page) = knowledge.pages().load(slug) else {
        return Err(format!("no draft named {slug} was saved"));
    };
    page.tags = tags.to_vec();
    match attacks::install(&page, install_dir) {
        Ok(page_file) => Ok(page_file.display().to_string()),
        Err(e) => Err(format!("cannot write into {}: {e}", install_dir.display())),
    }
}

/// Call off the Scout pool on the first ctrl-c, letting drafts already in flight
/// drain through verification. A second press forces an exit in case the drain
/// itself wedges.
fn install_ctrl_c_handler(tickets: Arc<TicketQueue>) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }
        eprintln!(
            "\n[ctrl-c] winding down: no new sources, finishing the drafts in flight. \
             Press again to force exit."
        );
        tickets.cancel_label(SCOUTING_LABEL);
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }
        eprintln!("\n[ctrl-c] hard exit on second press.");
        tickets.cancel();
        std::process::exit(130);
    });
}

fn print_summary(osint: &Value, osint_file: &Path, install_dir: &Path) {
    let pages = osint["pages"].as_array().cloned().unwrap_or_default();
    let installed = pages
        .iter()
        .filter(|p| p["installed"] == json!(true))
        .count();
    let gaps = osint["gaps"].as_array().map_or(0, |g| g.len());

    headline("OSINT SUMMARY");
    eprintln!("gaps researched: {gaps}");
    eprintln!("pages installed: {installed} of {} drafted", pages.len());
    for page in &pages {
        let slug = page["slug"].as_str().unwrap_or("");
        let mark = if page["installed"] == json!(true) {
            "+"
        } else {
            "-"
        };
        eprintln!(
            "  {mark} {slug}: {}",
            truncate(page["outcome"].as_str().unwrap_or(""), 90),
        );
    }
    if installed > 0 {
        eprintln!("\ninstalled into {}", install_dir.display());
        eprintln!("rebuild to embed the new pages: make");
    }
    eprintln!("osint: {}", osint_file.display());
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use agentwerk::agents::knowledge::Page;

    use super::*;
    use crate::cli::{parse_line as parse, Command};

    #[test]
    fn osint_joins_its_words_into_one_steer() {
        let Ok(Command::Osint(args)) = parse("osint npm registry attacks --max-time 5m") else {
            panic!("osint should parse");
        };
        assert_eq!(args.steer.as_deref(), Some("npm registry attacks"));
        assert_eq!(args.max_time, Some(Duration::from_secs(300)));
    }

    /// Guards the autonomous audit: a bare `osint` is a run, not a usage error.
    #[test]
    fn osint_without_words_steers_nowhere() {
        let Ok(Command::Osint(args)) = parse("osint") else {
            panic!("osint should parse without a focus");
        };
        assert_eq!(args.steer, None);
        assert_eq!(args.concurrency, 2);
    }

    /// Guards the trimmed surface: these three are scan's alone, and osint must
    /// name them rather than swallow one as a word of the focus.
    #[test]
    fn a_flag_osint_no_longer_carries_is_named() {
        for line in [
            "osint --max-gaps 3",
            "osint --max-turns 4",
            "osint --output o.json",
        ] {
            let Err(CliExit::ArgumentRejected(message)) = parse(line) else {
                panic!("{line} names no osint flag");
            };
            assert!(message.contains("unknown flag"), "{message}");
        }
    }

    #[test]
    fn an_unknown_osint_flag_is_named() {
        let Err(CliExit::ArgumentRejected(message)) = parse("osint --deep") else {
            panic!("--deep is not a flag");
        };
        assert!(message.contains("--deep"), "{message}");
    }

    /// The tags a Verifier assigns alongside its verdict.
    fn tags() -> Vec<String> {
        vec!["auto-executing-install-hook".to_string()]
    }

    fn gap(topic: &str) -> Value {
        json!({"topic": topic, "why": "no page describes it", "query": "a search"})
    }

    #[test]
    fn roster_holds_every_pool_member_and_the_curator() {
        let roster = roster(2);
        let names: Vec<&str> = roster.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            [
                "Scout 1",
                "Scout 2",
                "Editor 1",
                "Editor 2",
                "Verifier 1",
                "Verifier 2",
                "Curator",
            ]
        );
        assert_eq!(roster.last().unwrap().1, CURATION_LABEL);
    }

    /// Guards `--models` for osint: a pool key covers its members, and the
    /// Curator is reachable by name.
    #[test]
    fn a_models_file_covers_the_osint_roster_by_pool_and_by_name() {
        let table = crate::cli::ModelTable::parse(
            r#"{"Scout": "gpt-5", "editing": "gpt-4o", "Verifier": "gpt-4o", "Curator": "gpt-5"}"#,
        )
        .expect("the table parses");

        let models = table
            .resolve_for(&roster(2))
            .expect("the roster is covered");

        assert_eq!(models["Scout 2"].name, "gpt-5");
        assert_eq!(models["Editor 1"].name, "gpt-4o");
        assert_eq!(models["Curator"].name, "gpt-5");
    }

    /// Guards the steer: an operator who names a subject gets an audit of that
    /// subject, not a sweep with the subject mentioned somewhere in the role.
    #[test]
    fn a_steer_becomes_the_curation_ticket_rather_than_a_footnote() {
        let steered = curation_body(Some("the ChainDrop npm campaign"));

        assert!(steered.contains("the ChainDrop npm campaign"), "{steered}");
        assert!(
            steered.contains("does not apply to this ticket"),
            "the ticket must call off the spread rule it competes with: {steered}",
        );
        assert!(!curation_body(None).contains("nothing else"));
    }

    #[test]
    fn a_scouting_body_carries_the_gap_the_curator_named() {
        let body = scouting_body(&gap("source-build-only payloads"));

        assert!(body.contains("source-build-only payloads"), "{body}");
        assert!(body.contains("a search"), "{body}");
    }

    /// A run store holding one drafted page, plus the directory it installs into.
    fn staged(name: &str, slug: &str) -> (Arc<Knowledge>, PathBuf) {
        let root = std::env::temp_dir().join(format!("{name}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let knowledge = Knowledge::load(root.join("store")).expect("knowledge opens");
        knowledge
            .pages()
            .save(Page {
                slug: slug.to_string(),
                kind: "Knowledge".to_string(),
                description: "A campaign that hid a payload in a lockfile.".to_string(),
                content: "# A campaign\n\n## Carrier\nan npm lockfile".to_string(),
                tags: Vec::new(),
            })
            .expect("draft is writable");
        (knowledge, root.join("installed"))
    }

    /// The Editor's save carries no tags, so the corpus gets them only if the
    /// Verifier's verdict reaches the installed frontmatter.
    #[test]
    fn an_accepted_page_lands_carrying_the_tags_the_verifier_assigned() {
        let (knowledge, installed) = staged("research_accept", "a-new-campaign");

        let outcome = install_one("a-new-campaign", true, &tags(), &knowledge, &installed);

        let page = fs::read_to_string(installed.join("a-new-campaign.md")).expect("page installed");
        assert!(outcome.is_ok(), "{outcome:?}");
        assert!(page.contains("## Carrier"), "{page}");
        assert!(
            page.contains("tags: [auto-executing-install-hook]"),
            "{page}"
        );
    }

    #[test]
    fn a_rejected_page_stays_out_and_names_the_verifier() {
        let (knowledge, installed) = staged("research_reject", "a-new-campaign");

        let outcome = install_one("a-new-campaign", false, &tags(), &knowledge, &installed);

        assert!(!installed.join("a-new-campaign.md").exists());
        assert_eq!(outcome, Err("rejected by the Verifier".to_string()));
    }

    /// Guards the corpus: a run may add pages, never rewrite a shipped one.
    #[test]
    fn a_slug_the_binary_already_ships_is_never_overwritten() {
        let (knowledge, installed) = staged("research_seeded", "xz-utils-liblzma-backdoor");

        let outcome = install_one(
            "xz-utils-liblzma-backdoor",
            true,
            &tags(),
            &knowledge,
            &installed,
        );

        assert!(!installed.join("xz-utils-liblzma-backdoor.md").exists());
        assert!(
            outcome.unwrap_err().contains("already part of the corpus"),
            "a seeded slug should be refused"
        );
    }

    #[test]
    fn a_verdict_naming_a_page_nobody_drafted_reports_the_missing_draft() {
        let (knowledge, installed) = staged("research_missing", "a-new-campaign");

        let outcome = install_one(
            "a-page-never-written",
            true,
            &tags(),
            &knowledge,
            &installed,
        );

        assert!(
            outcome.unwrap_err().contains("no draft named"),
            "a verdict without a draft should say so"
        );
    }
}
