//! Which command the operator asked for, and the roster of models it resolves
//! to, probed for reachability before it runs. Each verb parses its own
//! arguments and writes its own help; this file routes to them.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use agentwerk::providers::{
    Message, Model, ModelRequest, Provider, ProviderResult, ReasoningEffort,
};
use serde_json::Value;

use crate::{analyze, download, osint};

/// What the operator asked malwi to do.
pub(crate) enum Command {
    Analyze(analyze::Args),
    Osint(osint::Args),
    Download(download::Args),
}

/// Why parsing produced no command to run.
#[derive(Debug)]
pub(crate) enum CliExit {
    /// The operator asked for help; the payload is the help text.
    HelpRequested(String),
    /// The arguments name no runnable command. The payload is one line, or a
    /// whole help text when the operator gave nothing to correct.
    ArgumentRejected(String),
}

impl Command {
    pub(crate) fn parse() -> Self {
        let args: Vec<String> = std::env::args().skip(1).collect();
        match parse_args(&args) {
            Ok(command) => command,
            Err(CliExit::HelpRequested(help)) => {
                eprintln!("{help}");
                std::process::exit(0);
            }
            Err(CliExit::ArgumentRejected(message)) => {
                eprintln!("{message}");
                std::process::exit(1);
            }
        }
    }
}

/// The one-letter shortcut for each command. A fixed table rather than prefix
/// matching, so `a` keeps meaning `analyze` once a second `a` verb exists.
const SHORTCUTS: [(&str, &str); 3] = [("a", "analyze"), ("o", "osint"), ("d", "download")];

/// The command an argument names, with a shortcut expanded. Anything else is
/// returned as written, so a rejection echoes what the operator typed.
fn command_word(arg: &str) -> &str {
    SHORTCUTS
        .iter()
        .find(|(short, _)| *short == arg)
        .map_or(arg, |(_, word)| *word)
}

fn parse_args(args: &[String]) -> Result<Command, CliExit> {
    match args.first().map(String::as_str).map(command_word) {
        None => Err(CliExit::ArgumentRejected(top_help())),
        Some("-h" | "--help") => Err(CliExit::HelpRequested(top_help())),
        Some("analyze") => analyze::parse(&args[1..]).map(Command::Analyze),
        Some("osint") => osint::parse(&args[1..]).map(Command::Osint),
        Some("download") => download::parse(&args[1..]).map(Command::Download),
        Some(other) => Err(CliExit::ArgumentRejected(format!(
            "unknown command: {other}\n\n{}",
            top_help()
        ))),
    }
}

/// One command line, parsed the way the binary parses it. Each verb keeps its
/// argument tests beside its own parser, and they all reach the dispatch here.
#[cfg(test)]
pub(crate) fn parse_line(line: &str) -> Result<Command, CliExit> {
    let args: Vec<String> = line.split_whitespace().map(String::from).collect();
    parse_args(&args)
}

fn top_help() -> String {
    "malwi. An agentic malware scanner for source trees and software packages.

Usage: malwi <COMMAND> [OPTIONS]

Commands:
  analyze, a   Perform a deep security evaluation of a file or a directory
  osint, o     Find gaps in the attack-pattern knowledge and fill them from public sources
  download, d  Fetch a package's published artefacts without running its package manager

Options:
  -h, --help   Show this help

Run `malwi <COMMAND> --help` for a command's own options."
        .to_string()
}

/// One agent of a pool: `Analyst 2` is the second Analyst.
pub(crate) fn agent_name(pool: &str, index: usize) -> String {
    format!("{pool} {}", index + 1)
}

/// What every agent runs without `--models`: the model the environment names,
/// resolved the same way the provider itself is.
pub(crate) fn default_model() -> Model {
    Model::from_env().unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    })
}

/// One model per agent name. A `--models` file covers the whole roster or the
/// run stops here.
pub(crate) fn resolve_models(
    table: Option<&ModelTable>,
    roster: &[(String, &str)],
    default: impl FnOnce() -> Model,
) -> BTreeMap<String, Model> {
    let Some(table) = table else {
        let default = default();
        return roster
            .iter()
            .map(|(name, _)| (name.clone(), default.clone()))
            .collect();
    };
    table.resolve_for(roster).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    })
}

/// Output-token budget for one reachability probe. Generous because a reasoning
/// model spends a tight one inside its thinking block and never answers, and the
/// truncated reply or 500 that follows says nothing about the configuration.
const PROBE_TOKENS: u32 = 512;

/// Probes one model gets before its failure is believed.
const PROBE_ATTEMPTS: u32 = 3;

/// Delay after the first failed probe, multiplied by the attempt number.
const PROBE_BACKOFF: Duration = Duration::from_millis(500);

/// Confirm every distinct model in the roster answers, and stop the run with
/// one message if any does not.
///
/// Probing before any work means a wrong key, model, or endpoint fails here
/// with a clear message instead of failing every ticket downstream.
pub(crate) async fn verify_models(provider: &Provider, models: &BTreeMap<String, Model>) {
    let mut probed = BTreeSet::new();
    for model in models.values() {
        if !probed.insert(model.name.as_str()) {
            continue;
        }
        if let Err(error) = probe(provider, &model.name).await {
            eprintln!(
                "cannot reach model '{}': {error}\n\
                 check the API key and endpoint for the configured provider, \
                 and the model names in --models.",
                model.name,
            );
            std::process::exit(1);
        }
    }
}

/// Ask one model to answer once, retrying while the failure is transient.
///
/// A 5xx or a dropped connection says nothing about whether the key, model,
/// and endpoint are right, so believing the first one turns a hiccup upstream
/// into a run that never starts. A classified failure is returned on the spot:
/// a wrong key or an unknown model fails the same way on every attempt.
async fn probe(provider: &Provider, model: &str) -> ProviderResult<()> {
    let mut attempt = 1;
    loop {
        let request = ModelRequest {
            model: model.to_string(),
            system_prompt: String::new(),
            messages: vec![Message::user("ping")],
            tools: Vec::new(),
            max_request_tokens: Some(PROBE_TOKENS),
            tool_choice: None,
            reasoning_effort: ReasoningEffort::Off,
        };
        let error = match provider.respond(request, Arc::new(|_| {})).await {
            Ok(_) => return Ok(()),
            Err(error) => error,
        };
        if !error.is_retryable() || attempt == PROBE_ATTEMPTS {
            return Err(error);
        }
        tokio::time::sleep(PROBE_BACKOFF * attempt).await;
        attempt += 1;
    }
}

/// The `--models` file, keyed by ticket label, pool, or single agent.
#[derive(Debug)]
pub(crate) struct ModelTable(BTreeMap<String, Model>);

impl ModelTable {
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path)
            .map_err(|e| format!("--models: cannot read {}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{e} (in {})", path.display()))
    }

    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let entries: BTreeMap<String, Value> =
            serde_json::from_str(text).map_err(|e| format!("--models: cannot parse JSON: {e}"))?;
        entries
            .iter()
            .map(|(key, value)| model_from(key, value).map(|model| (key.clone(), model)))
            .collect::<Result<_, _>>()
            .map(Self)
    }

    /// One model per `(name, label)` agent. First match wins: name, pool, label.
    ///
    /// An uncovered agent and a key naming no agent are both errors, since the
    /// file is the only model source and a typo has nothing to fall back to.
    pub(crate) fn resolve_for(
        &self,
        roster: &[(String, &str)],
    ) -> Result<BTreeMap<String, Model>, String> {
        let mut resolved = BTreeMap::new();
        let mut matched = BTreeSet::new();
        let mut uncovered = Vec::new();
        for (name, label) in roster {
            let keys = [name.as_str(), pool_of(name), label];
            matched.extend(keys.into_iter().filter(|key| self.0.contains_key(*key)));
            match keys.into_iter().find(|key| self.0.contains_key(*key)) {
                Some(key) => {
                    resolved.insert(name.clone(), self.0[key].clone());
                }
                None => uncovered.push(format!("{name} ({label})")),
            }
        }

        let unmatched: Vec<&str> = self
            .0
            .keys()
            .map(String::as_str)
            .filter(|key| !matched.contains(key))
            .collect();
        let mut problems = Vec::new();
        if !uncovered.is_empty() {
            problems.push(format!("--models: no model for {}", uncovered.join(", ")));
        }
        if !unmatched.is_empty() {
            problems.push(format!(
                "--models: no agent matches {}\nvalid keys: {}, or one agent such as \"{}\"",
                unmatched.join(", "),
                valid_keys(roster).join(", "),
                roster[0].0,
            ));
        }
        if problems.is_empty() {
            Ok(resolved)
        } else {
            Err(problems.join("\n"))
        }
    }
}

fn model_from(key: &str, value: &Value) -> Result<Model, String> {
    if let Some(name) = value.as_str() {
        return Ok(Model::from_name(name));
    }
    let Some(fields) = value.as_object() else {
        return Err(format!(
            "--models: {key} expects a model name or an object with a \"model\" field"
        ));
    };
    if let Some(unknown) = fields
        .keys()
        .find(|k| !matches!(k.as_str(), "model" | "reasoning" | "context_window"))
    {
        return Err(format!(
            "--models: {key} has unknown field \"{unknown}\"; accepted: model, reasoning, context_window"
        ));
    }
    let name = fields
        .get("model")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("--models: {key} needs a \"model\" field naming the model"))?;
    let mut model = Model::from_name(name);
    if let Some(value) = fields.get("reasoning") {
        model = model.reasoning_effort(reasoning_from(key, value)?);
    }
    if let Some(value) = fields.get("context_window") {
        let size = value.as_u64().filter(|n| *n > 0).ok_or_else(|| {
            format!("--models: {key} expects \"context_window\" as a positive number of tokens")
        })?;
        model = model.context_window(size);
    }
    Ok(model)
}

fn reasoning_from(key: &str, value: &Value) -> Result<ReasoningEffort, String> {
    match value.as_str() {
        Some("off") => Ok(ReasoningEffort::Off),
        Some("low") => Ok(ReasoningEffort::Low),
        Some("medium") => Ok(ReasoningEffort::Medium),
        Some("high") => Ok(ReasoningEffort::High),
        _ => Err(format!(
            "--models: {key} expects \"reasoning\" as off, low, medium, or high"
        )),
    }
}

/// `Analyst 2` belongs to pool `Analyst`.
fn pool_of(name: &str) -> &str {
    match name.rsplit_once(' ') {
        Some((pool, number)) if number.chars().all(|c| c.is_ascii_digit()) => pool,
        _ => name,
    }
}

fn valid_keys<'a>(roster: &'a [(String, &'a str)]) -> Vec<&'a str> {
    let mut keys: Vec<&str> = Vec::new();
    for (name, label) in roster {
        for key in [*label, pool_of(name)] {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
    }
    keys
}

/// Parse `30`, `30s`, `5m`, or `1h` into a `Duration`. Bare numbers are seconds.
pub(crate) fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num, mult): (&str, u64) = match s.as_bytes().last().copied() {
        Some(b's') => (&s[..s.len() - 1], 1),
        Some(b'm') => (&s[..s.len() - 1], 60),
        Some(b'h') => (&s[..s.len() - 1], 3600),
        Some(b'0'..=b'9') => (s, 1),
        _ => return None,
    };
    num.parse::<u64>()
        .ok()
        .map(|n| Duration::from_secs(n * mult))
}

pub(crate) fn rejected(message: &str) -> CliExit {
    CliExit::ArgumentRejected(message.to_string())
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    use agentwerk::providers::{
        ModelResponse, ProviderError, ProviderLike, ResponseStatus, StreamEvent, TokenUsage,
    };

    use super::*;

    use super::parse_line as parse;

    /// Fails the first `failures` probes with `error`, then answers.
    struct ProbedProvider {
        failures: u32,
        error: fn() -> ProviderError,
        attempts: AtomicU32,
        budgets: Mutex<Vec<Option<u32>>>,
    }

    impl ProbedProvider {
        /// Behind an `Arc` so the test keeps the counters `Provider` hides.
        fn new(failures: u32, error: fn() -> ProviderError) -> Arc<Self> {
            Arc::new(Self {
                failures,
                error,
                attempts: AtomicU32::new(0),
                budgets: Mutex::new(Vec::new()),
            })
        }

        fn attempts(&self) -> u32 {
            self.attempts.load(Ordering::SeqCst)
        }
    }

    impl ProviderLike for ProbedProvider {
        fn respond(
            &self,
            request: ModelRequest,
            _on_event: Arc<dyn Fn(StreamEvent) + Send + Sync>,
        ) -> Pin<Box<dyn Future<Output = ProviderResult<ModelResponse>> + Send + '_>> {
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
            self.budgets
                .lock()
                .expect("probe budgets should lock")
                .push(request.max_request_tokens);
            Box::pin(async move {
                if attempt < self.failures {
                    return Err((self.error)());
                }
                Ok(ModelResponse {
                    content: Vec::new(),
                    status: ResponseStatus::EndTurn,
                    usage: TokenUsage::default(),
                    model: "probe".into(),
                })
            })
        }
    }

    fn transient() -> ProviderError {
        ProviderError::StatusUnclassified {
            status: 500,
            message: "Response finished before thinking was completed".into(),
            retryable: true,
            retry_delay: None,
        }
    }

    fn classified() -> ProviderError {
        ProviderError::AuthenticationFailed {
            message: "invalid api key".into(),
        }
    }

    /// Guards the invariant that a transient upstream failure never decides
    /// whether the operator's configuration is usable.
    #[tokio::test(start_paused = true)]
    async fn a_transient_probe_failure_is_retried_until_the_model_answers() {
        let probed = ProbedProvider::new(2, transient);
        assert!(probe(&Provider::new(Arc::clone(&probed)), "any-model")
            .await
            .is_ok());
        assert_eq!(probed.attempts(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_transient_probe_failure_gives_up_after_the_attempt_budget() {
        let probed = ProbedProvider::new(u32::MAX, transient);
        assert!(probe(&Provider::new(Arc::clone(&probed)), "any-model")
            .await
            .is_err());
        assert_eq!(probed.attempts(), PROBE_ATTEMPTS);
    }

    /// A wrong key fails the same way on every attempt, so retrying it only
    /// delays the message the operator needs.
    #[tokio::test(start_paused = true)]
    async fn a_classified_probe_failure_is_not_retried() {
        let probed = ProbedProvider::new(u32::MAX, classified);
        assert!(probe(&Provider::new(Arc::clone(&probed)), "any-model")
            .await
            .is_err());
        assert_eq!(probed.attempts(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn the_probe_leaves_room_for_a_thinking_model_to_answer() {
        let probed = ProbedProvider::new(0, transient);
        probe(&Provider::new(Arc::clone(&probed)), "any-model")
            .await
            .expect("probe answers");
        let budgets = probed.budgets.lock().expect("probe budgets should lock");
        let [Some(budget)] = budgets.as_slice() else {
            panic!("one probe carries one output budget");
        };
        assert!(
            *budget >= 512,
            "a reasoning model spends its whole allowance inside the thinking \
             block, so {budget} tokens never reaches an answer",
        );
    }

    #[test]
    fn a_one_letter_shortcut_names_the_same_command() {
        assert!(matches!(parse("a ./src"), Ok(Command::Analyze(_))));
        assert!(matches!(parse("o"), Ok(Command::Osint(_))));
        assert!(matches!(parse("d requests"), Ok(Command::Download(_))));
    }

    /// Guards the fixed shortcut table against being loosened into prefix
    /// matching, which would make `s` ambiguous once a second `s` verb exists.
    #[test]
    fn a_longer_prefix_is_not_a_shortcut() {
        for line in ["sc ./src", "os"] {
            let Err(CliExit::ArgumentRejected(message)) = parse(line) else {
                panic!("{line} names no command");
            };
            assert!(message.contains("unknown command"), "{message}");
        }
    }

    #[test]
    fn research_is_no_longer_a_command() {
        let Err(CliExit::ArgumentRejected(message)) = parse("research") else {
            panic!("research was replaced by osint");
        };
        assert!(message.contains("unknown command: research"), "{message}");
    }

    /// Guards the strict-subcommand rule: a path is not an implicit scan.
    #[test]
    fn help_is_not_an_error() {
        for line in [
            "--help",
            "analyze --help",
            "osint --help",
            "download --help",
        ] {
            assert!(
                matches!(parse(line), Err(CliExit::HelpRequested(_))),
                "{line}"
            );
        }
    }

    #[test]
    fn parses_supported_formats() {
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration("2h"), Some(Duration::from_secs(7200)));
        assert_eq!(parse_duration("  45s  "), Some(Duration::from_secs(45)));
    }

    #[test]
    fn rejects_invalid_input() {
        assert!(parse_duration("").is_none());
        assert!(parse_duration("   ").is_none());
        assert!(parse_duration("5d").is_none());
        assert!(parse_duration("90min").is_none());
        assert!(parse_duration("abc").is_none());
    }

    fn roster() -> Vec<(String, &'static str)> {
        vec![
            ("Analyst 1".to_string(), "security_analysis"),
            ("Analyst 2".to_string(), "security_analysis"),
            ("Reporter".to_string(), "reporter"),
        ]
    }

    fn resolve(json: &str) -> Result<BTreeMap<String, Model>, String> {
        ModelTable::parse(json)?.resolve_for(&roster())
    }

    #[test]
    fn a_bare_string_entry_is_the_model_name() {
        let models = resolve(r#"{"Analyst": "gpt-5", "reporter": "gpt-4o"}"#).unwrap();
        assert_eq!(models["Analyst 1"].name, "gpt-5");
        assert_eq!(models["Reporter"].name, "gpt-4o");
    }

    #[test]
    fn an_object_entry_carries_reasoning_and_context_window() {
        let models = resolve(
            r#"{
                "Analyst": {"model": "gpt-5", "reasoning": "high"},
                "reporter": {"model": "my-local-model", "context_window": 65536}
            }"#,
        )
        .unwrap();
        assert_eq!(
            models["Analyst 1"].get_reasoning_effort(),
            ReasoningEffort::High
        );
        assert_eq!(models["Reporter"].get_context_window(), Some(65_536));
    }

    #[test]
    fn an_agent_name_wins_over_its_pool_and_a_pool_over_its_label() {
        let models = resolve(
            r#"{
                "Analyst 2": "gpt-4o",
                "Analyst": "gpt-5",
                "security_analysis": "mistral-medium-2508",
                "reporter": "gpt-5"
            }"#,
        )
        .unwrap();
        assert_eq!(models["Analyst 2"].name, "gpt-4o");
        assert_eq!(models["Analyst 1"].name, "gpt-5");
    }

    #[test]
    fn a_key_every_agent_of_it_overrides_is_still_accepted() {
        let models =
            resolve(r#"{"Analyst": "gpt-5", "security_analysis": "gpt-4o", "reporter": "gpt-5"}"#);
        assert!(models.is_ok(), "{:?}", models.unwrap_err());
    }

    #[test]
    fn an_agent_no_key_covers_is_named_with_its_label() {
        let error = resolve(r#"{"security_analysis": "gpt-5"}"#).unwrap_err();
        assert!(error.contains("Reporter (reporter)"), "{error}");
    }

    #[test]
    fn a_key_matching_no_agent_is_listed_with_the_valid_ones() {
        let error = resolve(r#"{"security_analysis": "gpt-5", "reporting": "gpt-5"}"#).unwrap_err();
        assert!(error.contains("reporting"), "{error}");
        assert!(error.contains("Analyst"), "{error}");
    }

    #[test]
    fn an_unknown_reasoning_word_names_the_accepted_ones() {
        let error = ModelTable::parse(r#"{"Analyst": {"model": "gpt-5", "reasoning": "max"}}"#)
            .unwrap_err();
        assert!(error.contains("off, low, medium, or high"), "{error}");
    }

    #[test]
    fn an_unknown_field_is_named() {
        let error =
            ModelTable::parse(r#"{"Analyst": {"model": "gpt-5", "effort": "high"}}"#).unwrap_err();
        assert!(error.contains("effort"), "{error}");
    }

    #[test]
    fn an_entry_without_a_model_field_is_rejected() {
        let error = ModelTable::parse(r#"{"Analyst": {"reasoning": "high"}}"#).unwrap_err();
        assert!(error.contains("model"), "{error}");
    }
}
