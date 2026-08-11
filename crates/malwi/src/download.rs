//! The `download` command: one prompt in, one package tree out. No package
//! manager is invoked anywhere, so nothing the package ships runs on the way
//! in: an install is exactly the code malwi is about to look at.

mod archive;
mod ecosystem;

use std::fs;
use std::path::{Path, PathBuf};

use agentwerk::providers::Provider;
use agentwerk::{Agent, Ticket, TicketQueue};
use serde_json::{json, Value};

use crate::cli::{default_model, rejected, resolve_models, verify_models, CliExit, ModelTable};
use ecosystem::Package;

const CATEGORIZER_AGENT: &str = include_str!("roles/categorizer.md");
const OUTPUT_CONTRACT: &str = include_str!("roles/output_contract.md");

pub(crate) const CATEGORIZATION_LABEL: &str = "categorization";
const CATEGORIZER_NAME: &str = "Categorizer";

/// Everything a run writes lives under here, tickets included: the command owns
/// one folder and leaves nothing elsewhere.
const DOWNLOADS_DIR: &str = "downloads";

const TICKETS_DIR: &str = "downloads/.tickets";

const MANIFEST_FILE: &str = "download.json";

/// Appended to an artefact's own name, so a release's sdist and its wheels
/// cannot unpack over each other.
const EXTRACTED_SUFFIX: &str = ".extracted";

/// Options of `malwi download <PROMPT>`.
pub(crate) struct Args {
    pub(crate) prompt: String,
    pub(crate) models: Option<ModelTable>,
}

/// Every word outside a flag is part of the prompt, so quoting it is optional.
/// Unlike an osint focus, an empty prompt is nothing to act on: there is no
/// default package to download.
pub(crate) fn parse(args: &[String]) -> Result<Args, CliExit> {
    let mut words: Vec<&str> = Vec::new();
    let mut models: Option<ModelTable> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
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

    if words.is_empty() {
        return Err(CliExit::ArgumentRejected(help()));
    }
    Ok(Args {
        prompt: words.join(" "),
        models,
    })
}

pub(crate) fn help() -> String {
    let registries = ecosystem::names().join(", ");
    format!(
        "malwi download. Downloads a package for inspection.

Usage: malwi download <PROMPT> [OPTIONS]

Alias: d

A PROMPT names a package: a registry and a name, a name and a version, or a page
URL. A URL is downloaded directly.

Registries: {registries}

Files land in downloads/<ECOSYSTEM>/<NAME>/<VERSION>/, with a download.json
listing what was fetched.

Options:
      --models <FILE>          One model per agent as JSON, keyed by ticket label,
                               pool name, or agent name. A value is a model name or
                               an object of model, reasoning, and context_window
                               (default: every agent runs the model the environment
                               names)
  -h, --help                   Show this help

Examples:
  malwi download pypi requests
  malwi d py stanza 1.14.0
  malwi download https://www.npmjs.com/package/left-pad"
    )
}

pub(crate) async fn run(args: Args) {
    // A registry URL names its package outright, so this path needs no model
    // and no API key.
    let wanted = match ecosystem::verify(&args.prompt) {
        Some(package) => package,
        None => categorize(&args).await,
    };

    let root = Path::new(DOWNLOADS_DIR);
    let (package, artefacts) = wanted
        .ecosystem
        .download(&wanted, root)
        .await
        .unwrap_or_else(|error| {
            eprintln!("{error}");
            std::process::exit(1);
        });

    let dir = package.dir(root);
    let unpacked: Vec<Value> = artefacts
        .iter()
        .map(|artefact| unpack(artefact, &dir))
        .collect();

    let manifest = json!({
        "prompt": args.prompt,
        "ecosystem": package.ecosystem.name(),
        "id": package.id,
        "name": package.name,
        "name_normalized": package.name_normalized(),
        "purl": package.purl(),
        "version": package.version(),
        "dir": dir.display().to_string(),
        "artefacts": unpacked,
    });

    let manifest_file = dir.join(MANIFEST_FILE);
    let json_str = serde_json::to_string_pretty(&manifest).expect("serializable");
    if let Err(e) = fs::write(&manifest_file, json_str) {
        eprintln!("cannot write {}: {e}", manifest_file.display());
        std::process::exit(1);
    }

    print_summary(&manifest, &dir);
}

/// Unpack one artefact beside itself and report what it held. A failure leaves
/// the artefact where it is: a scan can still read a file nothing could open.
fn unpack(artefact: &ecosystem::Artefact, dir: &Path) -> Value {
    let file = dir.join(&artefact.file_name);
    let dest = PathBuf::from(format!("{}{EXTRACTED_SUFFIX}", file.display()));
    let mut entry = serde_json::Map::new();
    entry.insert("file".into(), json!(file.display().to_string()));
    entry.insert("url".into(), json!(artefact.url));
    entry.insert("bytes".into(), json!(artefact.bytes));
    match archive::extract(&file, &dest) {
        Ok(None) => {}
        Ok(Some(unpacked)) => {
            entry.insert("extracted".into(), json!(dest.display().to_string()));
            entry.insert("files".into(), json!(unpacked.files));
            entry.insert("skipped".into(), json!(unpacked.skipped));
        }
        Err(error) => {
            eprintln!("cannot unpack {}: {error}", file.display());
            entry.insert("error".into(), json!(error));
        }
    }
    Value::Object(entry)
}

async fn categorize(args: &Args) -> Package {
    let roster = vec![(CATEGORIZER_NAME.to_string(), CATEGORIZATION_LABEL)];
    let models = resolve_models(args.models.as_ref(), &roster, default_model);

    let provider = Provider::from_env().unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    });
    verify_models(&provider, &models).await;

    let _ = fs::remove_dir_all(TICKETS_DIR);

    let tickets = TicketQueue::new();
    tickets.dir(TICKETS_DIR);
    tickets.max_schema_retries(20);
    tickets.agent(
        Agent::new()
            .provider(provider)
            .model(models[CATEGORIZER_NAME].clone())
            .role(CATEGORIZER_AGENT.trim())
            .template("ecosystems", ecosystem::names().join(", "))
            .template("output_contract", OUTPUT_CONTRACT.trim())
            .label(CATEGORIZATION_LABEL)
            .build(),
    );
    tickets.ticket(
        Ticket::new(categorization_body(&args.prompt))
            .label(CATEGORIZATION_LABEL)
            .schema(ecosystem::package_schema()),
    );

    // No event log: one ticket answering one question is not a pipeline to
    // watch, and its whole result is the line printed once it lands.
    let Some(result) = tickets.finish_all().await.pop() else {
        eprintln!("the Categorizer named no package for '{}'", args.prompt);
        std::process::exit(1);
    };
    package_from(&result, &args.prompt)
}

/// The ticket body the Categorizer claims: the operator's words, unedited.
fn categorization_body(prompt: &str) -> String {
    format!("Name the package this asks for:\n\n{prompt}")
}

/// Read the Categorizer's answer into the package to ask for, or stop the run.
fn package_from(result: &Value, prompt: &str) -> Package {
    let named = result["ecosystem"].as_str().unwrap_or_default();
    let Some(ecosystem) = ecosystem::find(named) else {
        eprintln!(
            "cannot tell which registry '{prompt}' names\nmalwi downloads from {}",
            ecosystem::names().join(", ")
        );
        std::process::exit(1);
    };

    let id = result["id"].as_str().unwrap_or_default().trim();
    if id.is_empty() {
        eprintln!("the Categorizer named {named} but no package in it");
        std::process::exit(1);
    }
    let name = result["name"].as_str().unwrap_or_default().trim();

    Package::wanted(
        ecosystem,
        id.to_string(),
        (!name.is_empty()).then(|| name.to_string()),
        version_from(result),
    )
}

/// The pinned version, if the prompt carried one. An empty string and `latest`
/// are both how a model says "none named": the registry picks.
fn version_from(result: &Value) -> Option<String> {
    let version = result["version"].as_str().unwrap_or_default().trim();
    let pinned = !version.is_empty() && !version.eq_ignore_ascii_case("latest");
    pinned.then(|| version.to_string())
}

fn print_summary(manifest: &Value, dir: &Path) {
    eprintln!(
        "{} {} from {}",
        manifest["name"].as_str().unwrap_or(""),
        manifest["version"].as_str().unwrap_or(""),
        manifest["ecosystem"].as_str().unwrap_or(""),
    );
    eprintln!("- {}", artefact_line(manifest));
    eprintln!("- {}/", dir.display());
}

/// What landed, one entry per artefact kind: a release publishing twenty wheels
/// is one entry rather than twenty, and the full list is in the manifest.
fn artefact_line(manifest: &Value) -> String {
    let mut kinds: Vec<Kind> = Vec::new();
    for artefact in manifest["artefacts"].as_array().into_iter().flatten() {
        let file = Path::new(artefact["file"].as_str().unwrap_or(""));
        let name = file.file_name().unwrap_or_default().to_string_lossy();
        let named = kind(&name).to_string();
        if !kinds.iter().any(|k| k.name == named) {
            kinds.push(Kind {
                name: named.clone(),
                ..Default::default()
            });
        }
        let entry = kinds
            .iter_mut()
            .find(|k| k.name == named)
            .expect("the kind was just pushed");
        entry.artefacts += 1;
        entry.bytes += artefact["bytes"].as_u64().unwrap_or(0);
        entry.skipped += artefact["skipped"].as_u64().unwrap_or(0);
        if let Some(files) = artefact["files"].as_u64() {
            entry.files = Some(entry.files.unwrap_or(0) + files);
        }
    }
    kinds
        .iter()
        .map(Kind::render)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The artefacts of one kind in a release, summed. `files` is absent when
/// nothing of the kind was an archive malwi opens.
#[derive(Default)]
struct Kind {
    name: String,
    artefacts: usize,
    bytes: u64,
    files: Option<u64>,
    skipped: u64,
}

impl Kind {
    fn render(&self) -> String {
        let count = match self.artefacts {
            1 => String::new(),
            n => format!(" ×{n}"),
        };
        let mut held = size(self.bytes);
        if let Some(files) = self.files {
            let unit = match files {
                1 => "file",
                _ => "files",
            };
            held.push_str(&format!("  {files} {unit}"));
        }
        if self.skipped > 0 {
            held.push_str(&format!(", {} refused", self.skipped));
        }
        format!("{}{count} ({held})", self.name)
    }
}

/// The kind a file name names. Matched against the suffixes registries publish,
/// because a version number carries dots of its own and splitting on those
/// names nothing.
fn kind(file_name: &str) -> &str {
    const KINDS: [&str; 8] = [
        ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".whl", ".zip", ".crate", ".egg",
    ];
    let lower = file_name.to_lowercase();
    KINDS
        .into_iter()
        .find(|suffix| lower.ends_with(suffix))
        .map_or(file_name, |suffix| &suffix[1..])
}

fn size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    match bytes as f64 {
        b if b >= MIB => format!("{:.1} MiB", b / MIB),
        b if b >= KIB => format!("{:.1} KiB", b / KIB),
        _ => format!("{bytes} B"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{parse_line as parse, Command};

    #[test]
    fn download_joins_its_words_into_one_prompt() {
        let Ok(Command::Download(args)) = parse("download py stanza 1.14.0") else {
            panic!("download should parse");
        };
        assert_eq!(args.prompt, "py stanza 1.14.0");
    }

    /// Guards the one difference from a focus: there is no package to fall back
    /// on, so a prompt-less download is a usage error rather than a run.
    #[test]
    fn download_without_words_names_nothing_to_fetch() {
        let Err(CliExit::ArgumentRejected(message)) = parse("download") else {
            panic!("download needs a prompt");
        };
        assert!(message.contains("malwi download"), "{message}");
    }

    #[test]
    fn an_unknown_download_flag_is_named() {
        let Err(CliExit::ArgumentRejected(message)) = parse("download requests --extract") else {
            panic!("--extract is not a flag");
        };
        assert!(message.contains("--extract"), "{message}");
    }

    #[test]
    fn a_size_reads_at_the_scale_it_lands_in() {
        assert_eq!(size(512), "512 B");
        assert_eq!(size(1536), "1.5 KiB");
        assert_eq!(size(1_956_577), "1.9 MiB");
    }

    #[test]
    fn artefacts_of_one_kind_collapse_into_one_entry() {
        let manifest = json!({"artefacts": [
            {"file": "d/numpy-2.0-cp39.whl", "bytes": 1024, "files": 10, "skipped": 0},
            {"file": "d/numpy-2.0-cp310.whl", "bytes": 1024, "files": 10, "skipped": 0},
            {"file": "d/numpy-2.0.tar.gz", "bytes": 2048, "files": 20, "skipped": 1},
        ]});

        assert_eq!(
            artefact_line(&manifest),
            "whl ×2 (2.0 KiB  20 files), tar.gz (2.0 KiB  20 files, 1 refused)"
        );
    }

    /// An artefact malwi opens nothing of keeps its own name: `bin` or `exe`
    /// says less about what landed than the file it came from.
    #[test]
    fn an_artefact_of_no_known_kind_keeps_its_name() {
        let manifest = json!({"artefacts": [{"file": "d/model.bin", "bytes": 12}]});

        assert_eq!(artefact_line(&manifest), "model.bin (12 B)");
    }

    #[test]
    fn a_version_the_model_left_empty_means_the_latest_release() {
        assert!(version_from(&json!({"version": ""})).is_none());
        assert!(version_from(&json!({"version": "  "})).is_none());
        assert!(version_from(&json!({"version": "latest"})).is_none());
        assert_eq!(
            version_from(&json!({"version": "1.14.0"})).as_deref(),
            Some("1.14.0")
        );
    }
}
