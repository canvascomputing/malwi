//! CLI argument parsing and help text, and the roster of models the parsed
//! arguments resolve to, probed for reachability before a command runs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agentwerk::providers::{
    model_from_env, Message, Model, ModelRequest, Provider, ProviderResult, ReasoningEffort,
};
use serde_json::Value;

/// What the operator asked malwi to do.
pub(crate) enum Command {
    Scan(ScanArgs),
    Osint(OsintArgs),
}

/// What the operator named as the thing to scan.
pub(crate) enum ScanTarget {
    /// A directory, scanned where it lies.
    Directory(PathBuf),
    /// A single file, copied into a directory of its own before the scan.
    File(PathBuf),
    /// What no local path resolves to: a package name, a URL, or a repository,
    /// read as a prompt for the agent that will fetch it.
    Prompt(String),
}

impl ScanTarget {
    /// Classify what the operator named. Nothing is fetched here: a name no
    /// path resolves to is carried as written until the run tries to reach it.
    pub(crate) fn from_arg(arg: &str) -> Self {
        let path = Path::new(arg);
        match fs::metadata(path) {
            Ok(meta) if meta.is_dir() => ScanTarget::Directory(path.to_path_buf()),
            Ok(meta) if meta.is_file() => ScanTarget::File(path.to_path_buf()),
            _ => ScanTarget::Prompt(arg.to_string()),
        }
    }

    /// The directory the scan walks. A file is copied into `input_dir` first, so
    /// every phase behind this call sees a tree. `input_dir` is recreated here,
    /// so the caller must have finished wiping the folder that holds it.
    pub(crate) fn resolve(&self, input_dir: &Path) -> Result<PathBuf, String> {
        match self {
            ScanTarget::Directory(path) => fs::canonicalize(path)
                .map_err(|e| format!("cannot resolve directory '{}': {e}", path.display())),
            ScanTarget::File(path) => stage_file(path, input_dir),
            ScanTarget::Prompt(text) => Err(format!(
                "nothing to scan at '{text}': malwi scans a directory or a single file"
            )),
        }
    }
}

impl std::fmt::Display for ScanTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanTarget::Directory(path) | ScanTarget::File(path) => write!(f, "{}", path.display()),
            ScanTarget::Prompt(text) => write!(f, "{text}"),
        }
    }
}

/// Copy `file` into an emptied `input_dir` and return that directory.
fn stage_file(file: &Path, input_dir: &Path) -> Result<PathBuf, String> {
    let name = file
        .file_name()
        .ok_or_else(|| format!("cannot scan '{}': it names no file", file.display()))?;
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

/// Options of `malwi scan <TARGET>`.
pub(crate) struct ScanArgs {
    pub(crate) target: ScanTarget,
    pub(crate) max_turns: Option<u32>,
    pub(crate) max_time: Option<Duration>,
    pub(crate) concurrency: usize,
    pub(crate) output_file: Option<PathBuf>,
    pub(crate) fail_fast: bool,
    pub(crate) instruction: Option<String>,
    pub(crate) models: Option<ModelTable>,
}

/// Options of `malwi osint [FOCUS]`.
pub(crate) struct OsintArgs {
    /// What to steer the hunt towards. Without it the run audits the whole
    /// knowledge base and picks its own gaps.
    pub(crate) steer: Option<String>,
    pub(crate) max_time: Option<Duration>,
    pub(crate) concurrency: usize,
    pub(crate) knowledge_dir: Option<PathBuf>,
    pub(crate) models: Option<ModelTable>,
}

/// Why parsing produced no command to run.
#[derive(Debug)]
enum CliExit {
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
/// matching, so `s` keeps meaning `scan` once a second `s` verb exists.
const SHORTCUTS: [(&str, &str); 2] = [("s", "scan"), ("o", "osint")];

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
        Some("scan") => parse_scan(&args[1..]).map(Command::Scan),
        Some("osint") => parse_osint(&args[1..]).map(Command::Osint),
        Some(other) => Err(CliExit::ArgumentRejected(format!(
            "unknown command: {other}\n\n{}",
            top_help()
        ))),
    }
}

fn parse_scan(args: &[String]) -> Result<ScanArgs, CliExit> {
    let mut target: Option<ScanTarget> = None;
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
            "-h" | "--help" => return Err(CliExit::HelpRequested(scan_help())),
            arg if arg.starts_with('-') => return Err(rejected(&format!("unknown flag: {arg}"))),
            _ => target = Some(ScanTarget::from_arg(&args[i])),
        }
        i += 1;
    }

    Ok(ScanArgs {
        target: target.ok_or_else(|| CliExit::ArgumentRejected(scan_help()))?,
        max_turns,
        max_time,
        concurrency,
        output_file,
        fail_fast,
        instruction,
        models,
    })
}

/// Every word outside a flag is part of the focus, so quoting it is optional.
/// No focus at all is legal: the run then audits the whole knowledge base.
fn parse_osint(args: &[String]) -> Result<OsintArgs, CliExit> {
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
            "-h" | "--help" => return Err(CliExit::HelpRequested(osint_help())),
            arg if arg.starts_with('-') => return Err(rejected(&format!("unknown flag: {arg}"))),
            word => words.push(word),
        }
        i += 1;
    }

    Ok(OsintArgs {
        steer: (!words.is_empty()).then(|| words.join(" ")),
        max_time,
        concurrency,
        knowledge_dir,
        models,
    })
}

fn top_help() -> String {
    "malwi. An agentic malware scanner for source trees and software packages.

Usage: malwi <COMMAND> [OPTIONS]

Commands:
  scan, s    Scan a file or a directory and write a JSON verdict
  osint, o   Find gaps in the attack-pattern knowledge and fill them from public sources

Options:
  -h, --help   Show this help

Run `malwi <COMMAND> --help` for a command's own options."
        .to_string()
}

fn scan_help() -> String {
    "malwi scan. Identifies the project's purpose, scans for threat indicators
(from a curated catalogue or via a Seeker searching the tree for threats),
and dispatches suspect matches to an Analyst pool for deeper investigation.

Usage: malwi scan <TARGET> [OPTIONS]

Alias: s

A TARGET is a directory, scanned where it lies, or a single file, copied into
the working folder and scanned there.

Options:
      --concurrency <N>        Agent pool size per phase (default: 2)
      --max-turns <N>          Per-queue turn limit (default: unlimited)
      --max-time <DUR>         Time limit. Bare seconds or s/m/h suffix (default: unlimited)
      --output <FILE>          Write analysis JSON to FILE (default: .malwi/analysis.json)
      --fail-fast              Cancel the scan on the first malicious finding
      --instruction <TEXT>     Append a custom instruction to every agent's prompt
      --models <FILE>          One model per agent as JSON, keyed by ticket label,
                               pool name, or agent name. A value is a model name or
                               an object of model, reasoning, and context_window
                               (default: every agent runs the model the environment
                               names)
  -h, --help                   Show this help

Examples:
  malwi scan ./src
  malwi s ./node_modules/left-pad"
        .to_string()
}

fn osint_help() -> String {
    "malwi osint. Audits the attack-pattern knowledge for incidents it does not
cover, hunts each gap through web search and page fetches, drafts a page per
incident, and installs the ones that survive verification. A source checkout
takes the new pages directly, so the next build ships them.

Usage: malwi osint [FOCUS] [OPTIONS]

Alias: o

A FOCUS steers the hunt towards one area. Without one the run picks its own gaps.

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

/// One agent of a pool: `Analyst 2` is the second Analyst.
pub(crate) fn agent_name(pool: &str, index: usize) -> String {
    format!("{pool} {}", index + 1)
}

/// What every agent runs without `--models`: the model the environment names,
/// resolved the same way the provider itself is.
pub(crate) fn default_model() -> Model {
    let name = model_from_env().unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    });
    Model::from_name(&name)
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

/// Output-token budget for one reachability probe. agentwerk's own `verify`
/// allows 16, which a reasoning model spends inside its thinking block before
/// emitting anything: the gateway then answers with a truncated reply or with
/// a 500, neither of which says the configuration is wrong.
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
pub(crate) async fn verify_models(provider: &dyn Provider, models: &BTreeMap<String, Model>) {
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
async fn probe(provider: &dyn Provider, model: &str) -> ProviderResult<()> {
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
    fn load(path: &Path) -> Result<Self, String> {
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
fn parse_duration(s: &str) -> Option<Duration> {
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

fn rejected(message: &str) -> CliExit {
    CliExit::ArgumentRejected(message.to_string())
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    use agentwerk::providers::{
        ModelResponse, ProviderError, ResponseStatus, StreamEvent, TokenUsage,
    };

    use super::*;

    fn parse(line: &str) -> Result<Command, CliExit> {
        let args: Vec<String> = line.split_whitespace().map(String::from).collect();
        parse_args(&args)
    }

    /// Fails the first `failures` probes with `error`, then answers.
    struct ProbedProvider {
        failures: u32,
        error: fn() -> ProviderError,
        attempts: AtomicU32,
        budgets: Mutex<Vec<Option<u32>>>,
    }

    impl ProbedProvider {
        fn new(failures: u32, error: fn() -> ProviderError) -> Self {
            Self {
                failures,
                error,
                attempts: AtomicU32::new(0),
                budgets: Mutex::new(Vec::new()),
            }
        }

        fn attempts(&self) -> u32 {
            self.attempts.load(Ordering::SeqCst)
        }
    }

    impl Provider for ProbedProvider {
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
        let provider = ProbedProvider::new(2, transient);
        assert!(probe(&provider, "any-model").await.is_ok());
        assert_eq!(provider.attempts(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_transient_probe_failure_gives_up_after_the_attempt_budget() {
        let provider = ProbedProvider::new(u32::MAX, transient);
        assert!(probe(&provider, "any-model").await.is_err());
        assert_eq!(provider.attempts(), PROBE_ATTEMPTS);
    }

    /// A wrong key fails the same way on every attempt, so retrying it only
    /// delays the message the operator needs.
    #[tokio::test(start_paused = true)]
    async fn a_classified_probe_failure_is_not_retried() {
        let provider = ProbedProvider::new(u32::MAX, classified);
        assert!(probe(&provider, "any-model").await.is_err());
        assert_eq!(provider.attempts(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn the_probe_leaves_room_for_a_thinking_model_to_answer() {
        let provider = ProbedProvider::new(0, transient);
        probe(&provider, "any-model").await.expect("probe answers");
        let budgets = provider.budgets.lock().expect("probe budgets should lock");
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
    fn scan_takes_its_target_and_its_flags() {
        let Ok(Command::Scan(args)) = parse("scan ./src --concurrency 4 --max-time 5m --fail-fast")
        else {
            panic!("scan should parse");
        };
        assert!(matches!(args.target, ScanTarget::Directory(_)));
        assert_eq!(args.target.to_string(), "./src");
        assert_eq!(args.concurrency, 4);
        assert_eq!(args.max_time, Some(Duration::from_secs(300)));
        assert!(args.fail_fast);
    }

    #[test]
    fn a_one_letter_shortcut_names_the_same_command() {
        assert!(matches!(parse("s ./src"), Ok(Command::Scan(_))));
        assert!(matches!(parse("o"), Ok(Command::Osint(_))));
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
    fn a_directory_without_a_command_is_rejected() {
        let Err(CliExit::ArgumentRejected(message)) = parse("./src") else {
            panic!("a bare path names no command");
        };
        assert!(message.contains("unknown command: ./src"), "{message}");
    }

    #[test]
    fn scan_without_a_target_shows_its_help() {
        let Err(CliExit::ArgumentRejected(message)) = parse("scan") else {
            panic!("scan needs a target");
        };
        assert!(message.contains("malwi scan <TARGET>"), "{message}");
    }

    #[test]
    fn a_file_target_is_kept_apart_from_a_directory_target() {
        let Ok(Command::Scan(file)) = parse("scan src/main.rs") else {
            panic!("a file is a target");
        };
        assert!(matches!(file.target, ScanTarget::File(_)));

        let Ok(Command::Scan(dir)) = parse("scan ./src") else {
            panic!("a directory is a target");
        };
        assert!(matches!(dir.target, ScanTarget::Directory(_)));
    }

    #[test]
    fn a_target_no_path_resolves_to_is_carried_as_a_prompt() {
        let Ok(Command::Scan(args)) = parse("scan left-pad") else {
            panic!("a package name is a target");
        };
        let ScanTarget::Prompt(text) = args.target else {
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
        let staged = ScanTarget::File(PathBuf::from("src/main.rs"))
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
        let staged = ScanTarget::Directory(PathBuf::from("./src"))
            .resolve(&input_dir("dir"))
            .expect("an existing directory resolves");
        assert_eq!(staged, fs::canonicalize("./src").expect("./src exists"));
    }

    /// The seam for targets an agent will fetch: today the run stops here, and
    /// this test is what changes when it learns to materialize one.
    #[test]
    fn a_target_that_is_not_a_path_is_refused_by_name() {
        let error = ScanTarget::Prompt("left-pad".to_string())
            .resolve(&input_dir("prompt"))
            .expect_err("nothing local is named left-pad");
        assert!(error.contains("left-pad"), "{error}");
    }

    #[test]
    fn an_unknown_scan_flag_is_named() {
        let Err(CliExit::ArgumentRejected(message)) = parse("scan ./src --deep") else {
            panic!("--deep is not a flag");
        };
        assert!(message.contains("--deep"), "{message}");
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

    #[test]
    fn help_is_not_an_error() {
        for line in ["--help", "scan --help", "osint --help"] {
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
