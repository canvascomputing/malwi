//! PyPI. A release is served as one JSON document listing every file published
//! under it, so the sdist and each wheel come back from a single request.

use serde_json::Value;

use super::{page_segments, Artefact, Ecosystem, Package, Resolved};

pub(super) struct PyPi;

impl Ecosystem for PyPi {
    fn name(&self) -> &'static str {
        "pypi"
    }

    /// `https://pypi.org/project/<id>[/<version>]`.
    fn verify(&self, url: &str) -> Option<(String, Option<String>)> {
        let segments = page_segments(url, &["pypi.org"], "project")?;
        Some((segments[0].clone(), segments.get(1).cloned()))
    }

    /// The latest release and a pinned one answer under the same document
    /// shape, so one document serves both.
    fn metadata_url(&self, id: &str, version: Option<&str>) -> String {
        match version {
            None => format!("https://pypi.org/pypi/{id}/json"),
            Some(version) => format!("https://pypi.org/pypi/{id}/{version}/json"),
        }
    }

    /// `urls` is the release's whole file set: the sdist and every wheel, which
    /// a scan needs to see, since a payload can sit in only one of them.
    fn resolve(&'static self, id: &str, body: &Value, _version: Option<&str>) -> Resolved {
        let version = body["info"]["version"]
            .as_str()
            .ok_or("pypi named no version for this release")?;
        let artefacts = body["urls"]
            .as_array()
            .map(|urls| {
                urls.iter()
                    .filter_map(|u| {
                        Some(Artefact {
                            file_name: u["filename"].as_str()?.to_string(),
                            url: u["url"].as_str()?.to_string(),
                            bytes: 0,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let package = Package::wanted(
            self,
            id.to_string(),
            body["info"]["name"].as_str().map(String::from),
            Some(version.to_string()),
        );
        Ok((package, artefacts))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::{find, verify as verify_prompt};
    use super::*;

    fn pypi() -> &'static dyn Ecosystem {
        find("pypi").expect("pypi is a registry malwi reaches")
    }

    #[test]
    fn a_release_carries_the_sdist_and_every_wheel() {
        let body = json!({
            "info": {"name": "Requests", "version": "2.31.0"},
            "urls": [
                {"filename": "requests-2.31.0.tar.gz", "url": "https://files.test/a.tar.gz"},
                {"filename": "requests-2.31.0-py3-none-any.whl", "url": "https://files.test/b.whl"},
            ],
        });

        let (package, artefacts) = pypi()
            .resolve("requests", &body, None)
            .expect("a release document parses");

        assert_eq!(package.version(), "2.31.0");
        assert_eq!(package.name, "Requests");
        assert_eq!(
            artefacts
                .iter()
                .map(|a| a.file_name.as_str())
                .collect::<Vec<_>>(),
            ["requests-2.31.0.tar.gz", "requests-2.31.0-py3-none-any.whl"]
        );
    }

    #[test]
    fn a_project_page_names_its_package_without_a_model() {
        let package =
            verify_prompt("https://pypi.org/project/requests/2.31.0/").expect("a pypi page");

        assert_eq!(package.ecosystem.name(), "pypi");
        assert_eq!(package.id, "requests");
        assert_eq!(package.version(), "2.31.0");
    }

    #[test]
    fn a_page_that_is_not_a_project_is_left_to_the_model() {
        assert!(PyPi.verify("https://pypi.org/help/").is_none());
        assert!(PyPi
            .verify("https://example.test/project/requests")
            .is_none());
    }
}
