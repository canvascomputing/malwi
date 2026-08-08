//! crates.io. One `.crate` tarball per version, served behind a redirect to the
//! CDN that the client follows on its own.

use serde_json::Value;

use super::{page_segments, Artefact, Ecosystem, Package, Resolved};

pub(super) struct Cargo;

impl Ecosystem for Cargo {
    fn name(&self) -> &'static str {
        "cargo"
    }

    /// `https://crates.io/crates/<id>[/<version>]`.
    fn verify(&self, url: &str) -> Option<(String, Option<String>)> {
        let segments = page_segments(url, &["crates.io"], "crates")?;
        Some((segments[0].clone(), segments.get(1).cloned()))
    }

    /// One document covers every version, so the version is picked from it
    /// rather than asked for.
    fn metadata_url(&self, id: &str, _version: Option<&str>) -> String {
        format!("https://crates.io/api/v1/crates/{id}")
    }

    fn resolve(&'static self, id: &str, body: &Value, version: Option<&str>) -> Resolved {
        let name = body["crate"]["name"].as_str().unwrap_or(id);
        // A crate whose newest release is a pre-release has no stable version,
        // and an operator who named no version still expects what crates.io shows.
        let version = match version {
            Some(version) => version.to_string(),
            None => body["crate"]["max_stable_version"]
                .as_str()
                .or_else(|| body["crate"]["newest_version"].as_str())
                .ok_or("crates.io named no version for this crate")?
                .to_string(),
        };
        let published = body["versions"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|v| v["num"].as_str() == Some(version.as_str()));
        let Some(published) = published else {
            return Err(format!(
                "crates.io publishes no version {version} of {name}"
            ));
        };
        let url = match published["dl_path"].as_str() {
            Some(path) => format!("https://crates.io{path}"),
            None => format!("https://crates.io/api/v1/crates/{name}/{version}/download"),
        };
        let package = Package::wanted(
            self,
            id.to_string(),
            Some(name.to_string()),
            Some(version.clone()),
        );
        let artefacts = vec![Artefact {
            file_name: format!("{name}-{version}.crate"),
            url,
            bytes: 0,
        }];
        Ok((package, artefacts))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::{find, verify as verify_prompt};
    use super::*;

    fn cargo() -> &'static dyn Ecosystem {
        find("cargo").expect("cargo is a registry malwi reaches")
    }

    #[test]
    fn an_unpinned_crate_resolves_to_the_newest_stable_version() {
        let body = json!({
            "crate": {"name": "serde", "max_stable_version": "1.0.0", "newest_version": "2.0.0-rc.1"},
            "versions": [
                {"num": "2.0.0-rc.1", "dl_path": "/api/v1/crates/serde/2.0.0-rc.1/download"},
                {"num": "1.0.0", "dl_path": "/api/v1/crates/serde/1.0.0/download"},
            ],
        });

        let (package, artefacts) = cargo()
            .resolve("serde", &body, None)
            .expect("a crate document parses");

        assert_eq!(package.version(), "1.0.0");
        assert_eq!(artefacts[0].file_name, "serde-1.0.0.crate");
        assert_eq!(
            artefacts[0].url,
            "https://crates.io/api/v1/crates/serde/1.0.0/download"
        );
    }

    #[test]
    fn an_unpinned_page_names_no_version() {
        let package = verify_prompt("https://crates.io/crates/serde").expect("a crates.io page");

        assert_eq!(package.ecosystem.name(), "cargo");
        assert_eq!(package.id, "serde");
    }
}
