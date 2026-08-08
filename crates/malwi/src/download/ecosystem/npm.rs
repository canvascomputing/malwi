//! npm. One tarball per version, listed in a packument covering every version
//! the package ever had.

use serde_json::Value;

use super::{page_segments, Artefact, Ecosystem, Package, Resolved};

pub(super) struct Npm;

impl Ecosystem for Npm {
    fn name(&self) -> &'static str {
        "npm"
    }

    /// `https://www.npmjs.com/package/<id>[/v/<version>]`, where `<id>` is two
    /// segments for a scoped package.
    fn verify(&self, url: &str) -> Option<(String, Option<String>)> {
        let segments = page_segments(url, &["npmjs.com"], "package")?;
        let (id, rest) = match segments[0].starts_with('@') {
            true => (
                format!("{}/{}", segments[0], segments.get(1)?),
                &segments[2..],
            ),
            false => (segments[0].clone(), &segments[1..]),
        };
        let version = match rest {
            [tag, version] if tag == "v" => Some(version.clone()),
            _ => None,
        };
        Some((id, version))
    }

    /// One packument covers every version, so the version is picked from it
    /// rather than asked for.
    fn metadata_url(&self, id: &str, _version: Option<&str>) -> String {
        format!("https://registry.npmjs.org/{}", id.replace('/', "%2f"))
    }

    /// The abbreviated packument: the full one carries every README the package
    /// ever shipped, which for a long-lived package is megabytes nothing reads.
    fn accept(&self) -> &'static str {
        "application/vnd.npm.install-v1+json"
    }

    fn resolve(&'static self, id: &str, body: &Value, version: Option<&str>) -> Resolved {
        let version = match version {
            Some(version) => version.to_string(),
            None => body["dist-tags"]["latest"]
                .as_str()
                .ok_or("npm named no latest version for this package")?
                .to_string(),
        };
        let release = &body["versions"][&version];
        if release.is_null() {
            return Err(format!(
                "npm publishes no version {version} of this package"
            ));
        }
        let url = release["dist"]["tarball"]
            .as_str()
            .ok_or_else(|| format!("npm serves no tarball for version {version}"))?;
        let package = Package::wanted(
            self,
            id.to_string(),
            body["name"].as_str().map(String::from),
            Some(version),
        );
        let artefacts = vec![Artefact {
            file_name: url.rsplit('/').next().unwrap_or_default().to_string(),
            url: url.to_string(),
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

    fn npm() -> &'static dyn Ecosystem {
        find("npm").expect("npm is a registry malwi reaches")
    }

    fn packument() -> Value {
        json!({
            "name": "left-pad",
            "dist-tags": {"latest": "1.3.0"},
            "versions": {
                "1.2.0": {"dist": {"tarball": "https://registry.test/left-pad-1.2.0.tgz"}},
                "1.3.0": {"dist": {"tarball": "https://registry.test/left-pad-1.3.0.tgz"}},
            },
        })
    }

    #[test]
    fn an_unpinned_package_resolves_to_the_latest_tag() {
        let (package, artefacts) = npm()
            .resolve("left-pad", &packument(), None)
            .expect("a packument parses");

        assert_eq!(package.version(), "1.3.0");
        assert_eq!(artefacts[0].file_name, "left-pad-1.3.0.tgz");
    }

    #[test]
    fn a_version_nobody_published_is_refused() {
        assert!(npm()
            .resolve("left-pad", &packument(), Some("9.9.9"))
            .is_err());
    }

    #[test]
    fn a_scoped_page_keeps_its_scope_in_the_id() {
        let package =
            verify_prompt("https://www.npmjs.com/package/@types/node/v/20.1.0").expect("npm");

        assert_eq!(package.ecosystem.name(), "npm");
        assert_eq!(package.id, "@types/node");
        assert_eq!(package.version(), "20.1.0");
    }
}
