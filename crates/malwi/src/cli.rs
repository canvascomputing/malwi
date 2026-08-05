//! CLI argument parsing and help text.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use agentwerk::providers::{Model, ReasoningEffort};
use serde_json::Value;

/// What the operator asked malwi to do.
pub(crate) enum Command {
    Scan(ScanArgs),
    Research(ResearchArgs),
}

/// Options of `malwi scan <DIR>`.
pub(crate) struct ScanArgs {
    pub(crate) dir: PathBuf,
    pub(crate) max_turns: Option<u32>,
    pub(crate) max_time: Option<Duration>,
    pub(crate) concurrency: usize,
    pub(crate) output_file: Option<PathBuf>,
    pub(crate) fail_fast: bool,
    pub(crate) instruction: Option<String>,
    pub(crate) models: Option<ModelTable>,
}

/// Options of `malwi research <QUESTION>`.
pub(crate) struct ResearchArgs {
    pub(crate) question: String,
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

fn parse_args(args: &[String]) -> Result<Command, CliExit> {
    match args.first().map(String::as_str) {
        None => Err(CliExit::ArgumentRejected(top_help())),
        Some("-h" | "--help") => Err(CliExit::HelpRequested(top_help())),
        Some("scan") => parse_scan(&args[1..]).map(Command::Scan),
        Some("research") => parse_research(&args[1..]).map(Command::Research),
        Some(other) => Err(CliExit::ArgumentRejected(format!(
            "unknown command: {other}\n\n{}",
            top_help()
        ))),
    }
}

fn parse_scan(args: &[String]) -> Result<ScanArgs, CliExit> {
    let mut dir: Option<PathBuf> = None;
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
            _ => dir = Some(PathBuf::from(&args[i])),
        }
        i += 1;
    }

    Ok(ScanArgs {
        dir: dir.ok_or_else(|| CliExit::ArgumentRejected(scan_help()))?,
        max_turns,
        max_time,
        concurrency,
        output_file,
        fail_fast,
        instruction,
        models,
    })
}

/// Every remaining word is the question, so quoting it is optional.
fn parse_research(args: &[String]) -> Result<ResearchArgs, CliExit> {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        return Err(CliExit::HelpRequested(research_help()));
    }
    if let Some(flag) = args.iter().find(|arg| arg.starts_with('-')) {
        return Err(rejected(&format!("unknown flag: {flag}")));
    }
    if args.is_empty() {
        return Err(CliExit::ArgumentRejected(research_help()));
    }
    Ok(ResearchArgs {
        question: args.join(" "),
    })
}

fn top_help() -> String {
    "malwi. An agentic malware scanner for source trees and software packages.

Usage: malwi <COMMAND> [OPTIONS]

Commands:
  scan       Scan a directory and write a JSON verdict
  research   Answer a security question (not yet implemented)

Options:
  -h, --help   Show this help

Run `malwi <COMMAND> --help` for a command's own options."
        .to_string()
}

fn scan_help() -> String {
    "malwi scan. Identifies the project's purpose, scans for threat indicators
(from a curated catalogue or via a Seeker searching the tree for threats),
and dispatches suspect matches to an Analyst pool for deeper investigation.

Usage: malwi scan <DIR> [OPTIONS]

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

Example:
  malwi scan ./src"
        .to_string()
}

fn research_help() -> String {
    "malwi research. Answers a security question from public sources. Not yet implemented.

Usage: malwi research <QUESTION>

Options:
  -h, --help   Show this help

Example:
  malwi research \"how did the shai-hulud npm worm spread\""
        .to_string()
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

    fn parse(text: &str) -> Result<Self, String> {
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
    use super::*;

    fn parse(line: &str) -> Result<Command, CliExit> {
        let args: Vec<String> = line.split_whitespace().map(String::from).collect();
        parse_args(&args)
    }

    #[test]
    fn scan_takes_the_directory_and_its_flags() {
        let Ok(Command::Scan(args)) = parse("scan ./src --concurrency 4 --max-time 5m --fail-fast")
        else {
            panic!("scan should parse");
        };
        assert_eq!(args.dir, PathBuf::from("./src"));
        assert_eq!(args.concurrency, 4);
        assert_eq!(args.max_time, Some(Duration::from_secs(300)));
        assert!(args.fail_fast);
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
    fn scan_without_a_directory_shows_its_help() {
        let Err(CliExit::ArgumentRejected(message)) = parse("scan") else {
            panic!("scan needs a directory");
        };
        assert!(message.contains("malwi scan <DIR>"), "{message}");
    }

    #[test]
    fn an_unknown_scan_flag_is_named() {
        let Err(CliExit::ArgumentRejected(message)) = parse("scan ./src --deep") else {
            panic!("--deep is not a flag");
        };
        assert!(message.contains("--deep"), "{message}");
    }

    #[test]
    fn research_joins_its_words_into_one_question() {
        let Ok(Command::Research(args)) = parse("research how did shai-hulud spread") else {
            panic!("research should parse");
        };
        assert_eq!(args.question, "how did shai-hulud spread");
    }

    #[test]
    fn help_is_not_an_error() {
        for line in ["--help", "scan --help", "research --help"] {
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
