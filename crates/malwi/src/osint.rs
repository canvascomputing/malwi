//! The `osint` command: an open-source intelligence pass over malwi's own blind
//! spots. A Curator audits the attack-pattern corpus and names the techniques it
//! cannot recognize, a Scout pool hunts public sources for each gap, an Editor
//! pool drafts a page from the sources, and a Verifier pool checks each draft
//! back against its own citations. Only an accepted page is installed, so a run
//! that finds nothing trustworthy leaves the corpus exactly as it was.

mod web_search;

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agentwerk::providers::{Model, Provider};
use agentwerk::tools::FetchTool;
use agentwerk::{Agent, FinishReason, Knowledge, Policy, Schema, Task, Werk};
use serde_json::{json, Value};

use crate::attacks;
use crate::cli::{
    additional_focus, agent_name, default_model, parse_duration, rejected, resolve_models,
    verify_models, CliExit, ModelTable,
};
use crate::run::{headline, log_event, truncate, RunStats};
use web_search::{
    brave_key_from_env, dossier_schema_json, editor_result_schema_json, gap_schema,
    verification_schema_json, web_search_tool, PAGE_FORMAT,
};

const CURATOR_AGENT: &str = include_str!("osint/agents/curator.md");
const SCOUT_AGENT: &str = include_str!("osint/agents/scout.md");
const EDITOR_AGENT: &str = include_str!("osint/agents/editor.md");
const VERIFIER_AGENT: &str = include_str!("osint/agents/verifier.md");
const OUTPUT_CONTRACT: &str = include_str!("output_contract.md");
const EDITOR_HANDOVER: &str = "<cited_dossier>\n{parent_result}\n</cited_dossier>";
const VERIFIER_HANDOVER: &str = "<draft_result>\n{parent_result}\n</draft_result>";

/// Templates every agent is given, whatever its own role names: a role whose
/// builder forgot one ships the `{placeholder}` to the model as literal text.
fn shared_templates(additional_focus: &str) -> [(&'static str, &str); 2] {
    [
        ("additional_focus", additional_focus),
        ("output_contract", OUTPUT_CONTRACT.trim()),
    ]
}

pub(crate) const CURATION_LABEL: &str = "curation";
pub(crate) const SCOUTING_LABEL: &str = "scouting";
pub(crate) const EDITING_LABEL: &str = "editing";
pub(crate) const VERIFICATION_LABEL: &str = "verification";
const CURATOR_NAME: &str = "Curator";

/// Pool name and the label its tasks carry, shared by the built agents and
/// the `--models` roster so the two cannot disagree. The Curator works alone
/// on the same Werk and is appended to the roster by name.
const POOLS: [(&str, &str); 3] = [
    ("Scout", SCOUTING_LABEL),
    ("Editor", EDITING_LABEL),
    ("Verifier", VERIFICATION_LABEL),
];

/// The command's working folder: task state, the knowledge store the chain drafts
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
      --models <FILE>          One model per agent as JSON, keyed by task label,
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
    // run before any model call rather than after every Scout task has failed.
    let brave_key = brave_key_from_env().unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    });

    let provider = Provider::from_env().unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    });

    verify_models(&provider, &models).await;

    let _ = fs::remove_dir_all(WORK_DIR);

    // Seed the corpus before indexing: `Knowledge::load` builds its index from
    // whatever it finds on disk, and the Curator audits that index.
    let work_dir = Path::new(WORK_DIR);
    if let Err(e) = attacks::copy_seed_into(work_dir) {
        eprintln!("cannot seed osint knowledge: {e}");
        std::process::exit(1);
    }
    let knowledge = Knowledge::load(work_dir.join("knowledge")).unwrap_or_else(|e| {
        eprintln!("cannot open osint knowledge: {e}");
        std::process::exit(1);
    });

    let install_dir = args
        .knowledge_dir
        .clone()
        .unwrap_or_else(|| attacks::install_dir(Path::new(FALLBACK_PAGES_DIR)));

    let additional_focus = additional_focus(args.steer.as_deref());

    eprintln!(
        "malwi osint: up to {MAX_GAPS} gap(s), pages install into {}\n",
        install_dir.display(),
    );

    let werk = Werk::new();
    werk.set_dir(WORK_DIR);
    werk.set_policy(Policy {
        // The default of 10 is tight for a weaker model that frequently replies
        // with no tool call at all: a task can burn its whole retry budget on
        // that alone.
        max_schema_retries: Some(20),
        max_time: args.max_time,
        ..Policy::default()
    });
    werk.on_event(|queue, event| log_event(event, queue));

    werk.add_agent(
        Agent::new()
            .provider(provider.clone())
            .model(models[CURATOR_NAME].clone())
            .role(CURATOR_AGENT.trim())
            .templates(shared_templates(&additional_focus))
            .template("max_gaps", MAX_GAPS.to_string())
            .label(CURATION_LABEL)
            .knowledge(&knowledge)
            .tool(web_search_tool(brave_key.clone())),
    );

    build_pools(
        &werk,
        &provider,
        &models,
        &knowledge,
        &brave_key,
        &additional_focus,
        concurrency,
    );

    route_curation(&werk);
    route_scouting(&werk);
    werk.add_task(
        Task::new(curation_body(args.steer.as_deref()))
            .label(CURATION_LABEL)
            .schema(gap_schema()),
    );

    install_ctrl_c_handler(Arc::clone(&werk));

    headline("AUDIT + OSINT");
    werk.finish_all_tasks().await;

    let gaps = curation_gaps(&werk);
    if gaps.is_empty() {
        eprintln!("\nno gap named: the corpus covers what the audit could find.");
        return;
    }

    // A hard second-press ctrl-c already exited; a first press or a policy stop
    // is graceful and falls through, so whatever was verified still installs.
    let pages = install_verified_pages(&werk, &knowledge, &install_dir);

    let stats = RunStats::fold(&werk);
    let osint = json!({
        "steer": args.steer,
        "install_dir": install_dir.display().to_string(),
        // A drained Werk is the only whole run: a cap or a ctrl-c leaves gaps.
        "partial": werk.get_finish_reason() != Some(FinishReason::Drained),
        "gaps": gaps,
        "pages": pages,
        "input_tokens": stats.input_tokens,
        "output_tokens": stats.output_tokens,
        "stats": serde_json::to_value(&stats).expect("RunStats serializes"),
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

/// Fan one Curator result out into Scout tasks.
fn route_curation(werk: &Werk) {
    werk.on_result(|queue, done, result| {
        if done.get_label() != Some(CURATION_LABEL) {
            return;
        }
        for gap in result["gaps"]
            .as_array()
            .into_iter()
            .flatten()
            .take(MAX_GAPS)
        {
            queue.add_task(Task::new(scouting_body(gap)).label(SCOUTING_LABEL).schema(
                Schema::new(dossier_schema_json()).expect("dossier schema is a valid document"),
            ));
        }
    });
}

/// Forward only dossiers with two distinct signal sources. Agentwerk's schema
/// subset has no `uniqueItems`, so this private boundary performs that one
/// cross-item check and removes harmless duplicates before the Editor sees it.
fn route_scouting(werk: &Werk) {
    werk.on_result(|queue, done, result| {
        if done.get_label() != Some(SCOUTING_LABEL) {
            return;
        }
        let Some(dossier) = normalize_dossier_sources(result) else {
            return;
        };
        queue.add_task(editor_task(&dossier).parent(done.get_id()));
    });
}

fn normalize_dossier_sources(dossier: &Value) -> Option<Value> {
    let sources = dossier["signal"]["sources"].as_array()?;
    let mut seen = HashSet::new();
    let unique: Vec<Value> = sources
        .iter()
        .filter_map(Value::as_str)
        .filter(|source| seen.insert((*source).to_string()))
        .map(|source| Value::String(source.to_string()))
        .collect();
    if unique.len() < 2 {
        return None;
    }
    let mut normalized = dossier.clone();
    normalized["signal"]["sources"] = Value::Array(unique);
    Some(normalized)
}

fn editor_task(dossier: &Value) -> Task {
    let dossier = serde_json::to_string_pretty(dossier).expect("a dossier serializes as JSON");
    let body = EDITOR_HANDOVER.replace("{parent_result}", &dossier);
    Task::new(body).label(EDITING_LABEL).schema(
        Schema::new(editor_result_schema_json()).expect("editor result schema is a valid document"),
    )
}

/// Read the Curator's bounded gap list after the complete workflow drains.
fn curation_gaps(werk: &Werk) -> Vec<Value> {
    werk.find_result(CURATION_LABEL)
        .and_then(|result| result["gaps"].as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .take(MAX_GAPS)
        .collect()
}

/// Register the Scout, Editor, and Verifier pools.
fn build_pools(
    werk: &Werk,
    provider: &Provider,
    models: &std::collections::BTreeMap<String, Model>,
    knowledge: &Arc<Knowledge>,
    brave_key: &str,
    additional_focus: &str,
    concurrency: usize,
) {
    for i in 0..concurrency {
        werk.add_agent(
            Agent::new()
                .provider(provider.clone())
                .model(models[&agent_name("Scout", i)].clone())
                .role(SCOUT_AGENT.trim())
                .templates(shared_templates(additional_focus))
                .label(SCOUTING_LABEL)
                .knowledge(knowledge)
                .tool(web_search_tool(brave_key.to_string()))
                .tool(FetchTool::new()),
        );
    }

    for i in 0..concurrency {
        werk.add_agent(
            Agent::new()
                .provider(provider.clone())
                .model(models[&agent_name("Editor", i)].clone())
                .role(EDITOR_AGENT.trim())
                .templates(shared_templates(additional_focus))
                .template("page_format", PAGE_FORMAT.trim())
                .label(EDITING_LABEL)
                .handover(
                    Task::new(VERIFIER_HANDOVER)
                        .label(VERIFICATION_LABEL)
                        .schema(
                            Schema::new(verification_schema_json())
                                .expect("verifier result schema is a valid document"),
                        ),
                )
                .knowledge(knowledge)
                .tool(FetchTool::new()),
        );
    }

    for i in 0..concurrency {
        werk.add_agent(
            Agent::new()
                .provider(provider.clone())
                .model(models[&agent_name("Verifier", i)].clone())
                .role(VERIFIER_AGENT.trim())
                .templates(shared_templates(additional_focus))
                .template("page_format", PAGE_FORMAT.trim())
                .label(VERIFICATION_LABEL)
                .knowledge(knowledge)
                .tool(FetchTool::new()),
        );
    }
}

/// The task body the Curator claims. A steer becomes the assignment rather
/// than a footnote in the role, because the role argues hard for spreading gaps
/// across ecosystems and an operator who named a subject has already made that
/// call. The task is the instruction the model acts on; the role is context.
fn curation_body(steer: Option<&str>) -> String {
    const SWEEP: &str = concat!(
        "<audit_assignment>\n",
        "- Compare existing attack-pattern pages with documented supply-chain incidents.\n",
        "- Return only missing mechanisms worth researching.\n",
        "- Give one confirming search for each mechanism.\n",
        "</audit_assignment>"
    );
    match steer {
        None => SWEEP.to_string(),
        Some(subject) => format!(
            concat!(
                "<audit_subject>\n{subject}\n</audit_subject>\n",
                "<audit_assignment>\n",
                "- Research only the supplied subject.\n",
                "- Search for it by name first.\n",
                "- Compare public sources with existing pages.\n",
                "- Return only missing techniques within that subject.\n",
                "- Narrow the technique when broad coverage already exists.\n",
                "</audit_assignment>"
            ),
            subject = subject,
        ),
    }
}

/// The task body a Scout claims: one gap, in the Curator's own words.
fn scouting_body(gap: &Value) -> String {
    format!(
        "<gap>\nTopic: {}\nMissing from existing pages: {}\nSuggested search: {}\n</gap>",
        gap["topic"].as_str().unwrap_or(""),
        gap["why"].as_str().unwrap_or(""),
        gap["query"].as_str().unwrap_or(""),
    )
}

/// The verification results the install reads.
fn verified_pages_query() -> String {
    format!("{VERIFICATION_LABEL} AND status = Finished")
}

fn wind_down_query() -> String {
    format!("pending = true AND label IN ({CURATION_LABEL}, {SCOUTING_LABEL})")
}

/// Move every accepted draft out of the run's store and into the install
/// directory. A rejected page and a page whose slug the binary already ships
/// are both recorded and left where they are.
fn install_verified_pages(werk: &Werk, knowledge: &Knowledge, install_dir: &Path) -> Vec<Value> {
    werk.find_tasks(verified_pages_query())
        .into_iter()
        .filter_map(|task| Some((drafted_slug(werk, &task), task.get_result()?.clone())))
        .map(|(slug, result)| {
            let accepted = result["status"].as_str() == Some("accepted");
            let tags = tags_of(&result);
            let outcome = install_one(&slug, accepted, &tags, knowledge, install_dir);
            json!({
                "slug": slug,
                "status": result["status"],
                "reason": result["reason"].as_str().unwrap_or(""),
                "tags": tags,
                "installed": outcome.is_ok(),
                "outcome": outcome.unwrap_or_else(|message| message),
            })
        })
        .collect()
}

/// The slug the Editor saved its draft under, read off the task the
/// verification came from. The Editor is the only agent that knows it, so
/// taking it from the Verifier's copy would trust a retyping.
fn drafted_slug(werk: &Werk, verification: &Task) -> String {
    let drafted = verification
        .get_parent()
        .and_then(|id| werk.get_task(id))
        .and_then(|editor| editor.get_result().cloned());
    slug_of(drafted.as_ref())
}

/// The slug an Editor result names, empty when it named none.
fn slug_of(result: Option<&Value>) -> String {
    result
        .and_then(|result| result["slug"].as_str())
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// The technique tags the Verifier assigned, which the Editor's save had no
/// field to carry.
fn tags_of(result: &Value) -> Vec<String> {
    result["tags"]
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
        return Err("the verification named no page".to_string());
    }
    // Overwriting a shipped page would let one run silently rewrite what the
    // scanner already knows, so a slug the binary carries is never installed.
    if attacks::is_seeded(slug) {
        return Err(format!("{slug} is already part of the corpus"));
    }
    let Ok(mut page) = knowledge.get_pages().get_page(slug) else {
        return Err(format!("no draft named {slug} was saved"));
    };
    page.tags = tags.to_vec();
    match attacks::install(&page, install_dir) {
        Ok(page_file) => Ok(page_file.display().to_string()),
        Err(e) => Err(format!("cannot write into {}: {e}", install_dir.display())),
    }
}

/// Call off pending Curator and Scout work on the first ctrl-c, letting drafts
/// already in flight drain through verification. A second press forces an exit.
fn install_ctrl_c_handler(werk: Arc<Werk>) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }
        eprintln!(
            "\n[ctrl-c] winding down: no new sources, finishing the drafts in flight. \
             Press again to force exit."
        );
        werk.cancel_tasks(wind_down_query());
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }
        eprintln!("\n[ctrl-c] hard exit on second press.");
        werk.cancel_all_tasks();
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
    use std::future::Future;
    use std::path::PathBuf;
    use std::pin::Pin;

    use agentwerk::agents::knowledge::Page;
    use agentwerk::providers::types::{
        ContentBlock, ModelResponse, ResponseStatus, StreamEvent, TokenUsage,
    };
    use agentwerk::providers::{ModelRequest, ProviderLike, ProviderResult};

    use super::*;
    use crate::cli::{parse_line as parse, Command};
    use agentwerk::schemas::Schema;
    use agentwerk::Query;

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
                    usage: TokenUsage::default(),
                    model: "mock".into(),
                })
            })
        }
    }

    struct SlowFinishMock;

    impl ProviderLike for SlowFinishMock {
        fn respond(
            &self,
            _request: ModelRequest,
            _on_event: Arc<dyn Fn(StreamEvent) + Send + Sync>,
        ) -> Pin<Box<dyn Future<Output = ProviderResult<ModelResponse>> + Send + '_>> {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok(ModelResponse {
                    content: vec![ContentBlock::ToolUse {
                        id: "call-1".into(),
                        name: "finish".into(),
                        input: json!({"gaps": []}),
                    }],
                    status: ResponseStatus::ToolUse,
                    usage: TokenUsage::default(),
                    model: "mock".into(),
                })
            })
        }
    }

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

    /// The tags a Verifier assigns alongside its status.
    fn tags() -> Vec<String> {
        vec!["auto-executing-install-hook".to_string()]
    }

    fn gap(topic: &str) -> Value {
        json!({"topic": topic, "why": "no page describes it", "query": "a search"})
    }

    fn dossier(sources: Value) -> Value {
        let cited = |text: &str| json!({"text": text, "source": "https://example.test/a"});
        json!({
            "incident": cited("an incident"),
            "carrier": cited("an extension"),
            "technique": cited("a hidden project hook"),
            "effect": cited("command execution"),
            "signal": {
                "shape": "an activation hook importing a bundled loader",
                "sources": sources,
                "literals": [],
            },
            "unconfirmed": "nothing",
        })
    }

    /// The scan queue's guard, over these roles. The Curator's `{date}` is
    /// agentwerk's own, which is why nothing here passes one.
    #[test]
    fn every_placeholder_an_osint_role_names_is_one_the_run_substitutes() {
        let shared: Vec<&str> = shared_templates("").iter().map(|(key, _)| *key).collect();
        let per_role: [(&str, &str, &[&str]); 4] = [
            ("curator", CURATOR_AGENT, &["max_gaps"]),
            ("scout", SCOUT_AGENT, &[]),
            ("editor", EDITOR_AGENT, &["page_format"]),
            ("verifier", VERIFIER_AGENT, &["page_format"]),
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
    fn every_osint_role_lists_its_available_tools() {
        for (name, role, expected) in [
            (
                "curator",
                CURATOR_AGENT,
                &["brave_search", "finish", "knowledge"][..],
            ),
            (
                "scout",
                SCOUT_AGENT,
                &["brave_search", "fetch", "finish", "knowledge"][..],
            ),
            (
                "editor",
                EDITOR_AGENT,
                &["fetch", "finish", "knowledge"][..],
            ),
            (
                "verifier",
                VERIFIER_AGENT,
                &["fetch", "finish", "knowledge"][..],
            ),
        ] {
            let mut declared = crate::cli::declared_prompt_tools(role);
            declared.sort();
            assert_eq!(declared, expected, "{name}");
        }
    }

    #[test]
    fn verifier_prompt_returns_an_operational_status() {
        assert!(VERIFIER_AGENT.contains("`status`: exactly `accepted` or `rejected`"));
        assert!(!VERIFIER_AGENT.contains("`verdict`:"));
    }

    #[test]
    fn osint_handovers_label_and_delimit_parent_results() {
        assert_eq!(
            EDITOR_HANDOVER,
            "<cited_dossier>\n{parent_result}\n</cited_dossier>"
        );
        assert_eq!(
            VERIFIER_HANDOVER,
            "<draft_result>\n{parent_result}\n</draft_result>"
        );
    }

    #[test]
    fn scout_sources_are_deduplicated_before_editor_handoff() {
        let normalized = normalize_dossier_sources(&dossier(json!([
            "https://example.test/a",
            "https://example.org/b",
            "https://example.test/a",
        ])))
        .expect("two distinct sources remain");
        assert_eq!(
            normalized["signal"]["sources"],
            json!(["https://example.test/a", "https://example.org/b"])
        );
        assert!(normalize_dossier_sources(&dossier(json!([
            "https://example.test/a",
            "https://example.test/a",
        ])))
        .is_none());
    }

    #[test]
    fn editor_receives_one_delimited_normalized_record() {
        let normalized = normalize_dossier_sources(&dossier(json!([
            "https://example.test/a",
            "https://example.org/b",
            "https://example.test/a",
        ])))
        .expect("two distinct sources remain");
        let task = editor_task(&normalized);
        let body = task.get_task().as_str().expect("editor body is text");

        assert!(body.starts_with("<cited_dossier>\n{"), "{body}");
        assert!(body.ends_with("\n</cited_dossier>"), "{body}");
        assert!(
            body.contains(
                "\"sources\": [\n      \"https://example.test/a\",\n      \"https://example.org/b\"\n    ]"
            ),
            "{body}"
        );
    }

    #[tokio::test]
    async fn scout_result_with_one_distinct_source_opens_no_editor_task() {
        let dir = std::env::temp_dir().join(format!("osint_sources_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let werk = Werk::new();
        werk.set_dir(&dir);
        werk.add_agent(
            Agent::new()
                .provider(Provider::new(FinishMock(dossier(json!([
                    "https://example.test/a",
                    "https://example.test/a",
                ])))))
                .model(Model::new("mock"))
                .role("scout")
                .label(SCOUTING_LABEL),
        );
        route_scouting(&werk);
        werk.add_task(
            Task::new("research")
                .label(SCOUTING_LABEL)
                .schema(Schema::new(dossier_schema_json()).expect("dossier schema compiles")),
        );

        werk.finish_all_tasks().await;

        assert!(werk
            .find_tasks(format!("label = {EDITING_LABEL}"))
            .is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn editor_examples_cover_present_and_absent_incident_literals() {
        let examples: Vec<&str> = EDITOR_AGENT.split("<example>").skip(1).collect();
        assert!(examples[0].contains("\\nIncident literals:\\n"));
        assert!(!examples[1].contains("\\nIncident literals:\\n"));
    }

    /// AQL is checked when it runs, and one of these cancels from a ctrl-c
    /// handler. `Query::new` answers with a `Result` instead of panicking.
    #[test]
    fn every_query_the_osint_run_builds_compiles() {
        for query in [verified_pages_query(), wind_down_query()] {
            Query::<Task>::new(&query).unwrap_or_else(|e| panic!("{query}: {e}"));
        }
    }

    #[test]
    fn first_ctrl_c_cancels_only_pending_curation_and_scouting() {
        let dir = std::env::temp_dir().join(format!("osint_cancel_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let werk = Werk::new();
        werk.set_dir(&dir);
        let ids = [
            (
                CURATION_LABEL,
                werk.add_task(Task::new("c").label(CURATION_LABEL)),
            ),
            (
                SCOUTING_LABEL,
                werk.add_task(Task::new("s").label(SCOUTING_LABEL)),
            ),
            (
                EDITING_LABEL,
                werk.add_task(Task::new("e").label(EDITING_LABEL)),
            ),
            (
                VERIFICATION_LABEL,
                werk.add_task(Task::new("v").label(VERIFICATION_LABEL)),
            ),
        ];

        werk.cancel_tasks(wind_down_query());

        for (label, id) in ids {
            let cancelled = werk.get_task(&id).is_some_and(|task| task.is_cancelled());
            assert_eq!(
                cancelled,
                matches!(label, CURATION_LABEL | SCOUTING_LABEL),
                "{label}"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn curator_result_fans_out_and_finish_all_waits_for_every_handover() {
        let dir = std::env::temp_dir().join(format!("osint_chain_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let werk = Werk::new();
        werk.set_dir(&dir);

        let gaps = json!({"gaps": [
            {
                "topic": "source-build-only payloads",
                "why": "the existing pages cover published archives but not payloads assembled only during source builds",
                "query": "source build supply chain payload campaign",
            },
            {
                "topic": "malicious editor extensions",
                "why": "the existing pages cover package registries but not extension marketplaces that execute project hooks",
                "query": "malicious editor extension supply chain campaign",
            },
        ]});
        let dossier = dossier(json!(["https://example.test/a", "https://example.org/b"]));

        werk.add_agent(
            Agent::new()
                .provider(Provider::new(FinishMock(gaps)))
                .model(Model::new("mock"))
                .role("curator")
                .label(CURATION_LABEL),
        );
        werk.add_agent(
            Agent::new()
                .provider(Provider::new(FinishMock(dossier)))
                .model(Model::new("mock"))
                .role("scout")
                .label(SCOUTING_LABEL),
        );
        werk.add_agent(
            Agent::new()
                .provider(Provider::new(FinishMock(json!({"slug": "new-campaign"}))))
                .model(Model::new("mock"))
                .role("editor")
                .label(EDITING_LABEL)
                .handover(
                    Task::new("{parent_result}")
                        .label(VERIFICATION_LABEL)
                        .schema(
                            Schema::new(verification_schema_json())
                                .expect("verifier schema compiles"),
                        ),
                ),
        );
        werk.add_agent(
            Agent::new()
                .provider(Provider::new(FinishMock(json!({
                    "status": "accepted",
                    "reason": "two independent sources establish the mechanism and its stable matching signal",
                    "tags": ["auto-executing-install-hook"],
                }))))
                .model(Model::new("mock"))
                .role("verifier")
                .label(VERIFICATION_LABEL),
        );
        route_curation(&werk);
        route_scouting(&werk);
        werk.add_task(
            Task::new("audit")
                .label(CURATION_LABEL)
                .schema(gap_schema()),
        );

        werk.finish_all_tasks().await;

        assert_eq!(curation_gaps(&werk).len(), 2);
        for label in [SCOUTING_LABEL, EDITING_LABEL, VERIFICATION_LABEL] {
            assert_eq!(
                werk.find_tasks(format!("label = {label}")).len(),
                2,
                "{label}"
            );
            assert_eq!(
                werk.find_tasks(format!("label = {label} AND status = Finished"))
                    .len(),
                2,
                "{label} drained"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn empty_curation_opens_no_scout_work() {
        let dir = std::env::temp_dir().join(format!("osint_empty_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let werk = Werk::new();
        werk.set_dir(&dir);
        werk.add_agent(
            Agent::new()
                .provider(Provider::new(FinishMock(json!({"gaps": []}))))
                .model(Model::new("mock"))
                .role("curator")
                .label(CURATION_LABEL),
        );
        route_curation(&werk);
        werk.add_task(
            Task::new("audit")
                .label(CURATION_LABEL)
                .schema(gap_schema()),
        );

        werk.finish_all_tasks().await;

        assert!(curation_gaps(&werk).is_empty());
        assert!(werk
            .find_tasks(format!("label = {SCOUTING_LABEL}"))
            .is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn one_policy_budget_covers_curation_and_prevents_late_fan_out() {
        let dir = std::env::temp_dir().join(format!("osint_policy_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let werk = Werk::new();
        werk.set_dir(&dir);
        werk.set_policy(Policy {
            max_time: Some(Duration::from_millis(10)),
            ..Policy::default()
        });
        werk.add_agent(
            Agent::new()
                .provider(Provider::new(SlowFinishMock))
                .model(Model::new("mock"))
                .role("curator")
                .label(CURATION_LABEL),
        );
        route_curation(&werk);
        werk.add_task(
            Task::new("audit")
                .label(CURATION_LABEL)
                .schema(gap_schema()),
        );

        werk.finish_all_tasks().await;

        assert!(matches!(
            werk.get_finish_reason(),
            Some(FinishReason::PolicyViolated(_))
        ));
        assert!(werk
            .find_tasks(format!("label = {SCOUTING_LABEL}"))
            .is_empty());
        let _ = fs::remove_dir_all(&dir);
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

        assert_eq!(models["Scout 2"].get_name(), "gpt-5");
        assert_eq!(models["Editor 1"].get_name(), "gpt-4o");
        assert_eq!(models["Curator"].get_name(), "gpt-5");
    }

    /// Guards the steer: an operator who names a subject gets an audit of that
    /// subject, not a sweep with the subject mentioned somewhere in the role.
    #[test]
    fn a_steer_becomes_the_curation_task_rather_than_a_footnote() {
        let steered = curation_body(Some("the ChainDrop npm campaign"));

        assert!(
            steered.starts_with("<audit_subject>\nthe ChainDrop npm campaign\n</audit_subject>\n"),
            "{steered}"
        );
        assert!(
            steered.contains("Return only missing techniques within that subject"),
            "the assignment must stay inside the supplied subject: {steered}",
        );
        assert!(steered.ends_with("</audit_assignment>"), "{steered}");
        assert!(!curation_body(None).contains("<audit_subject>"));
        assert!(curation_body(None).starts_with("<audit_assignment>\n"));
        assert!(curation_body(None).ends_with("\n</audit_assignment>"));
    }

    #[test]
    fn a_scouting_body_carries_the_gap_the_curator_named() {
        let body = scouting_body(&gap("source-build-only payloads"));

        assert!(body.starts_with("<gap>\n"), "{body}");
        assert!(body.contains("source-build-only payloads"), "{body}");
        assert!(body.contains("a search"), "{body}");
        assert!(body.ends_with("\n</gap>"), "{body}");
    }

    /// A run store holding one drafted page, plus the directory it installs into.
    fn staged(name: &str, slug: &str) -> (Arc<Knowledge>, PathBuf) {
        let root = std::env::temp_dir().join(format!("{name}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let knowledge = Knowledge::load(root.join("store")).expect("knowledge opens");
        knowledge
            .get_pages()
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

    /// The slug is the Editor's, read off the task the verification came
    /// from. Taking it from the Verifier's result would trust a retyping of a
    /// key `install_one` looks the page up by.
    #[test]
    fn the_slug_installed_is_the_one_the_editor_saved() {
        assert_eq!(
            slug_of(Some(&json!({"slug": "a-new-campaign"}))),
            "a-new-campaign"
        );
        assert_eq!(slug_of(Some(&json!({"slug": "  spaced  "}))), "spaced");
        // No editor task, or an editor that named nothing: install_one then
        // reports the missing draft rather than installing something arbitrary.
        assert_eq!(slug_of(None), "");
        assert_eq!(slug_of(Some(&json!({"status": "accepted"}))), "");
    }

    #[test]
    fn an_editor_result_without_a_slug_is_rejected() {
        let schema = Schema::new(editor_result_schema_json()).expect("a valid document");
        assert!(schema.validate(json!({"slug": "a-new-campaign"})).is_ok());
        assert!(schema.validate(json!({})).is_err());
        // The old shape: the slug buried in prose.
        assert!(schema
            .validate(json!(
                "slug: a-new-campaign\n\nSources:\n- https://example.test"
            ))
            .is_err());
        // A slug that is not kebab-case names no page the Editor could have saved.
        assert!(schema.validate(json!({"slug": "A New Campaign"})).is_err());
    }

    /// The Editor's save carries no tags, so the corpus gets them only if the
    /// Verifier's result reaches the installed frontmatter.
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
    fn a_verification_naming_a_page_nobody_drafted_reports_the_missing_draft() {
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
            "a verification without a draft should say so"
        );
    }
}
