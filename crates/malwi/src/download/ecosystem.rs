//! The machinery the `download` command drives. A registry serves its metadata
//! as JSON and its artefacts as static files, so nothing here needs a package
//! manager and no install hook ever runs.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use agentwerk::schemas::Schema;
use serde_json::{json, Value};

mod cargo;
mod npm;
mod pypi;

/// Sent with every registry request. crates.io answers a request without one
/// with a 403, and the other two rate-limit an anonymous client harder.
const USER_AGENT: &str = concat!(
    "malwi/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/canvascomputing/malwi)"
);

/// Ceiling on one request. A registry that hangs would otherwise hold the whole
/// command open with no output.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Ceiling on one artefact. Far above any real package, and low enough that a
/// registry serving an endless body fails instead of filling the disk.
const MAX_ARTEFACT_BYTES: u64 = 512 * 1024 * 1024;

/// The bytes malwi keeps literal in a path.
const POSIX_SAFE: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-._~";

/// A registry malwi pulls from directly, without its package manager.
///
/// Everything an implementation writes is registry-specific: the URL shapes it
/// answers to, and how to read its metadata. The fetching, the path building,
/// and the writing all happen once, below.
pub(crate) trait Ecosystem: Sync {
    /// The registry's name, and the first segment of every purl it produces.
    fn name(&self) -> &'static str;

    /// The package a registry page URL names, or `None` for any other URL.
    fn verify(&self, url: &str) -> Option<(String, Option<String>)>;

    /// Where the registry describes one package. A version is passed for the
    /// registries that answer per release rather than per package.
    fn metadata_url(&self, id: &str, version: Option<&str>) -> String;

    /// The media type that document is asked for as; only npm needs another.
    fn accept(&self) -> &'static str {
        "application/json"
    }

    /// The package and the files that document describes.
    fn resolve(&'static self, id: &str, body: &Value, version: Option<&str>) -> Resolved;
}

/// What a registry's metadata resolves to, before a byte is fetched.
type Resolved = Result<(Package, Vec<Artefact>), String>;

/// The registries malwi can reach. A prompt naming none of them stops the run.
pub(crate) static ECOSYSTEMS: [&dyn Ecosystem; 3] = [&pypi::PyPi, &npm::Npm, &cargo::Cargo];

/// One package, from what a prompt asked for through to what a registry served.
///
/// `id` is what the registry is queried with, an opaque identifier in registries
/// beyond these three, which is why it is not `name`. `name` is the registry's
/// own once one has answered: the path derives from it, so it must not depend on
/// how a prompt spelled it. `version` is absent until a registry names one,
/// which is why nothing upstream of `download` can build a path.
pub(crate) struct Package {
    pub(crate) ecosystem: &'static dyn Ecosystem,
    pub(crate) id: String,
    pub(crate) name: String,
    version: Option<String>,
}

/// One file the registry publishes. `bytes` is zero until `download` has
/// written it.
pub(crate) struct Artefact {
    pub(crate) file_name: String,
    pub(crate) url: String,
    pub(crate) bytes: u64,
}

impl Package {
    /// What a prompt asked for, before any registry has answered. A `name` of
    /// `None` is a package nobody spelled out: the id stands in until a registry
    /// prints its own.
    pub(crate) fn wanted(
        ecosystem: &'static dyn Ecosystem,
        id: String,
        name: Option<String>,
        version: Option<String>,
    ) -> Self {
        Package {
            ecosystem,
            name: name.unwrap_or_else(|| id.clone()),
            id,
            version,
        }
    }

    /// The version the registry served. Only a package `download` handed back
    /// carries one, and only those are ever asked for a path.
    pub(crate) fn version(&self) -> &str {
        self.version
            .as_deref()
            .expect("a path is built only from a package a registry resolved")
    }

    /// The name made path-safe. Derived here rather than taken from any answer,
    /// so nothing a model or a registry says can shape a path.
    pub(crate) fn name_normalized(&self) -> String {
        posix_encode(&self.name)
    }

    /// The package's own path: `<ecosystem>/<name_normalized>/<version>`.
    pub(crate) fn purl(&self) -> String {
        format!(
            "{}/{}/{}",
            self.ecosystem.name(),
            self.name_normalized(),
            self.version()
        )
    }

    /// Where the artefacts of this release live under `root`.
    pub(crate) fn dir(&self, root: &Path) -> PathBuf {
        root.join(self.ecosystem.name())
            .join(self.name_normalized())
            .join(self.version())
    }
}

/// A string made safe to carry through a path and a shell, and injective: the
/// safe set holds no `%`, so an encoded group is never read back as literals.
///
/// Uppercase is encoded rather than folded. Folding would map two distinct
/// registry names onto one directory, which on a case-insensitive filesystem is
/// the collision the encoding exists to prevent.
pub(crate) fn posix_encode(text: &str) -> String {
    text.bytes()
        .map(|b| match POSIX_SAFE.contains(&b) {
            true => (b as char).to_string(),
            false => format!("%{b:02X}"),
        })
        .collect()
}

/// The package a registry page URL names outright. Matched before any model
/// call, so a pasted URL costs nothing to resolve.
pub(crate) fn verify(prompt: &str) -> Option<Package> {
    let prompt = prompt.trim();
    ECOSYSTEMS.iter().find_map(|ecosystem| {
        let (id, version) = ecosystem.verify(prompt)?;
        Some(Package::wanted(*ecosystem, id, None, version))
    })
}

/// The ecosystem of that name, or `None` for a registry malwi cannot reach.
pub(crate) fn find(name: &str) -> Option<&'static dyn Ecosystem> {
    ECOSYSTEMS.iter().copied().find(|e| e.name() == name)
}

/// Every registry's name, for the help text, the Categorizer's prompt, and the
/// schema it answers under.
pub(crate) fn names() -> Vec<&'static str> {
    ECOSYSTEMS.iter().map(|e| e.name()).collect()
}

impl dyn Ecosystem {
    /// Download every artefact published for one release into `root/<purl>`.
    /// The version is resolved from registry metadata first, so the directory
    /// names the release that was actually served.
    pub(crate) async fn download(
        &'static self,
        wanted: &Package,
        root: &Path,
    ) -> Result<(Package, Vec<Artefact>), String> {
        let version = wanted.version.as_deref();
        let body = fetch_json(&self.metadata_url(&wanted.id, version), self.accept()).await?;
        let (mut package, mut artefacts) = self.resolve(&wanted.id, &body, version)?;

        // The registry's own version becomes a directory name, so it is checked
        // before anything asks the package for a path.
        let version = package
            .version
            .take()
            .ok_or_else(|| format!("{} named no version of {}", self.name(), package.id))?;
        package.version = Some(path_segment(&version, "version")?);

        if artefacts.is_empty() {
            return Err(format!(
                "{} {} publishes no artefact for version {}",
                self.name(),
                package.id,
                package.version()
            ));
        }

        let dir = package.dir(root);
        fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;

        let client = client()?;
        for artefact in &mut artefacts {
            let file_name = path_segment(&artefact.file_name, "artefact name")?;
            let file = dir.join(&file_name);
            artefact.bytes = fetch_file(&client, &artefact.url, &file).await?;
        }
        Ok((package, artefacts))
    }
}

/// Result schema for the Categorizer ticket. `unknown` is a legal answer: a
/// prompt naming a registry malwi cannot reach must fail by name rather than be
/// forced into one of the three.
pub(crate) fn package_schema() -> Schema {
    let mut ecosystems = names();
    ecosystems.push("unknown");
    Schema::new(json!({
        "type": "object",
        "properties": {
            "ecosystem": {"type": "string", "enum": ecosystems},
            "id": {"type": "string", "maxLength": 214},
            "name": {"type": "string", "maxLength": 214},
            "version": {"type": "string", "maxLength": 64},
        },
        "required": ["ecosystem", "id", "name", "version"],
    }))
    .expect("package schema is a valid document")
}

/// A path segment taken from a registry, refused when it could leave the
/// download folder. Only the package name is encoded; a version and a file name
/// stay literal, so what landed on disk is what the registry published.
fn path_segment(value: &str, what: &str) -> Result<String, String> {
    let value = value.trim();
    let usable = !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains('/')
        && !value.contains('\\')
        && !value.contains('\0');
    match usable {
        true => Ok(value.to_string()),
        false => Err(format!("{what} '{value}' is not a usable path segment")),
    }
}

/// A client carrying the header and the deadline every registry request needs.
fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| format!("cannot build an HTTP client: {e}"))
}

async fn fetch_json(url: &str, accept: &str) -> Result<Value, String> {
    let response = client()?
        .get(url)
        .header("Accept", accept)
        .send()
        .await
        .map_err(|e| format!("cannot reach {url}: {e}"))?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(format!("no such package: {url} answered 404"));
    }
    if !status.is_success() {
        return Err(format!("{url} answered {status}"));
    }
    response
        .json::<Value>()
        .await
        .map_err(|e| format!("{url} answered unreadable JSON: {e}"))
}

/// One artefact onto disk, written through a temporary name so an interrupted
/// download never leaves a truncated file looking complete.
///
/// Read chunk by chunk rather than into memory: a host answering chunked with
/// an endless body carries no length to check, and buffering it would grow the
/// process until it is killed instead of failing at the ceiling.
async fn fetch_file(client: &reqwest::Client, url: &str, file: &Path) -> Result<u64, String> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("cannot reach {url}: {e}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("{url} answered {status}"));
    }

    let partial = PathBuf::from(format!("{}.part", file.display()));
    let mut out = fs::File::create(&partial)
        .map_err(|e| format!("cannot write {}: {e}", partial.display()))?;
    let mut bytes: u64 = 0;
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|e| format!("cannot read {url}: {e}"))?;
        let Some(chunk) = chunk else { break };
        bytes += chunk.len() as u64;
        if bytes > MAX_ARTEFACT_BYTES {
            let _ = fs::remove_file(&partial);
            return Err(format!(
                "{url} sends more than the {MAX_ARTEFACT_BYTES} byte limit"
            ));
        }
        out.write_all(&chunk)
            .map_err(|e| format!("cannot write {}: {e}", partial.display()))?;
    }
    drop(out);

    fs::rename(&partial, file).map_err(|e| format!("cannot write {}: {e}", file.display()))?;
    Ok(bytes)
}

/// The path segments a registry page URL carries after `prefix`, or `None` when
/// the URL names another host or another kind of page. Written by hand rather
/// than parsed: three fixed shapes do not earn a URL dependency.
fn page_segments(url: &str, hosts: &[&str], prefix: &str) -> Option<Vec<String>> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let rest = rest.split(['?', '#']).next()?;
    let (host, path) = rest.split_once('/')?;
    let host = host.strip_prefix("www.").unwrap_or(host);
    if !hosts.contains(&host) {
        return None;
    }
    let mut segments = path.split('/').filter(|s| !s.is_empty());
    if segments.next()? != prefix {
        return None;
    }
    let segments: Vec<String> = segments.map(String::from).collect();
    (!segments.is_empty()).then_some(segments)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISPLAY_NAME: &str = "Requests";

    fn registry(name: &str) -> &'static dyn Ecosystem {
        find(name).expect("a registry malwi reaches")
    }

    fn package(name: &str, version: &str) -> Package {
        Package::wanted(
            registry("pypi"),
            name.to_lowercase(),
            Some(name.to_string()),
            Some(version.to_string()),
        )
    }

    #[test]
    fn an_uppercase_name_is_encoded_rather_than_folded() {
        assert_eq!(posix_encode(DISPLAY_NAME), "%52equests");
    }

    #[test]
    fn a_scoped_npm_name_encodes_its_marker_and_separator() {
        assert_eq!(posix_encode("@types/node"), "%40types%2Fnode");
    }

    #[test]
    fn the_safe_set_passes_through_untouched() {
        assert_eq!(posix_encode("left-pad_1.0~x"), "left-pad_1.0~x");
    }

    #[test]
    fn a_multi_byte_character_encodes_one_group_per_byte() {
        assert_eq!(posix_encode("naïve"), "na%C3%AFve");
    }

    /// Injectivity is what keeps two registry names off one directory: the safe
    /// set holds no `%`, so an encoded group cannot be spelled literally.
    #[test]
    fn a_literal_percent_group_does_not_collide_with_an_encoded_one() {
        assert_ne!(posix_encode("a b"), posix_encode("a%20b"));
    }

    #[test]
    fn a_purl_is_the_ecosystem_the_encoded_name_and_the_version() {
        assert_eq!(
            package(DISPLAY_NAME, "2.31.0").purl(),
            "pypi/%52equests/2.31.0"
        );
    }

    #[test]
    fn a_purl_is_the_path_under_the_download_root() {
        let dir = package(DISPLAY_NAME, "2.31.0").dir(Path::new("downloads"));
        assert_eq!(dir, Path::new("downloads/pypi/%52equests/2.31.0"));
    }

    #[test]
    fn a_version_that_would_leave_the_download_folder_is_refused() {
        assert!(path_segment("../../etc", "version").is_err());
        assert!(path_segment("..", "version").is_err());
        assert!(path_segment("", "version").is_err());
        assert!(path_segment("2.31.0", "version").is_ok());
    }

    #[test]
    fn a_url_on_a_foreign_host_is_left_to_the_model() {
        assert!(verify("https://example.test/project/requests").is_none());
        assert!(verify("https://pypi.org/help/").is_none());
        assert!(verify("requests").is_none());
    }

    #[test]
    fn the_schema_rejects_an_ecosystem_malwi_cannot_reach() {
        let schema = package_schema();
        assert!(schema
            .validate(json!({
                "ecosystem": "rubygems",
                "id": "rails",
                "name": "rails",
                "version": "",
            }))
            .is_err());
        assert!(schema
            .validate(json!({
                "ecosystem": "pypi",
                "id": "requests",
                "name": "Requests",
                "version": "2.31.0",
            }))
            .is_ok());
    }
}
