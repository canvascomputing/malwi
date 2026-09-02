//! The machinery the `osint` command drives: the web-search tool the agents hunt
//! with, the page format they write to, and the schemas each phase of the chain
//! is held to.

use agentwerk::schemas::Schema;
use agentwerk::tools::Tool;
use agentwerk::Event;
use serde_json::{json, Value};

/// Brave's web-search endpoint. The key travels in `X-Subscription-Token`.
const BRAVE_ENDPOINT: &str = "https://api.search.brave.com/res/v1/web/search";

/// The most results Brave returns for one query.
const MAX_RESULTS: u64 = 20;

/// Model-facing instructions for choosing and calling `brave_search`.
const BRAVE_SEARCH_DESCRIPTION: &str = include_str!("web_search.md");

/// The body of an attack-pattern page, bound into the Editor and the Verifier so
/// the format lives in one place rather than in two prompts that can drift. The
/// front matter is absent on purpose: the knowledge store writes its own, and
/// [`crate::attacks::install`] rewrites it into the corpus form, so a
/// model that hand-wrote one would leave the installed page with two.
pub(crate) const PAGE_FORMAT: &str = include_str!("agents/page_format.md");

/// The Brave API key, without which no osint agent can search. Trimmed: the key
/// travels in a header, and a stray newline makes the request unbuildable, so
/// every search would fail with a transport error rather than this one.
pub(crate) fn brave_key_from_env() -> Result<String, String> {
    match std::env::var("BRAVE_API_KEY") {
        Ok(key) if !key.trim().is_empty() => Ok(key.trim().to_string()),
        _ => Err(
            "BRAVE_API_KEY is not set: osint reaches the web through the Brave \
                  Search API. Create a key at https://brave.com/search/api and export it."
                .to_string(),
        ),
    }
}

/// Web search for the osint agents. One tool instance per agent, so each pool
/// member searches under its own key clone.
pub(crate) fn web_search_tool(api_key: String) -> Tool {
    Tool::new("brave_search")
        .description(BRAVE_SEARCH_DESCRIPTION.trim())
        .schema(json!({
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "The exact web search query to run."},
                "count": {"type": "integer", "description": "The number of results to return, from 1 through 20. Defaults to 5."},
            },
            "required": ["query"],
        }))
        .concurrent(true)
        .handler(move |input: Value| {
            let api_key = api_key.clone();
            async move { search(&api_key, &input).await }
        })
}

/// A reachable-but-unhelpful endpoint is the model's problem to route around,
/// so every failure comes back as a tool error rather than killing the task.
async fn search(api_key: &str, input: &Value) -> Event {
    let query = input["query"].as_str().unwrap_or("").trim();
    if query.is_empty() {
        return Event::tool_call_failed("query must not be empty");
    }
    let count = input["count"]
        .as_u64()
        .unwrap_or(5)
        .clamp(1, MAX_RESULTS)
        .to_string();

    let response = reqwest::Client::new()
        .get(BRAVE_ENDPOINT)
        .query(&[("q", query), ("count", &count)])
        .header("X-Subscription-Token", api_key)
        .header("Accept", "application/json")
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        Err(e) => return Event::tool_call_failed(format!("brave search failed: {e}")),
    };
    let status = response.status();
    if !status.is_success() {
        return Event::tool_call_failed(format!(
            "brave search returned {status}: check BRAVE_API_KEY and the plan's rate limit"
        ));
    }
    match response.json::<Value>().await {
        Ok(body) => Event::tool_call_finished(render_results(&body)),
        Err(e) => Event::tool_call_failed(format!("brave search returned unreadable JSON: {e}")),
    }
}

/// Render a Brave response as the markdown the model reads. Split from the
/// request so the rendering is testable without a network call.
pub(crate) fn render_results(body: &Value) -> String {
    let Some(results) = body["web"]["results"].as_array() else {
        return "No results found.".to_string();
    };
    if results.is_empty() {
        return "No results found.".to_string();
    }
    results
        .iter()
        .map(|r| {
            format!(
                "## {}\n{}\n{}\n",
                r["title"].as_str().unwrap_or(""),
                r["url"].as_str().unwrap_or(""),
                r["description"].as_str().unwrap_or(""),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Result schema for the Curator task: the gaps the corpus has, each with the
/// search that would confirm it. Attaching it makes `finish` reject a prose
/// answer, which the host cannot fan out into tasks.
pub(crate) fn gap_schema() -> Schema {
    Schema::new(json!({
        "type": "object",
        "properties": {
            "gaps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "topic": {"type": "string", "minLength": 8, "maxLength": 120, "description": "The missing campaign or reusable technique."},
                        "why": {"type": "string", "minLength": 40, "maxLength": 1200, "description": "What the corpus covers and the specific coverage it lacks."},
                        "query": {"type": "string", "minLength": 3, "maxLength": 200, "description": "A focused first search for evidence about the gap."},
                    },
                    "required": ["topic", "why", "query"],
                },
            },
        },
        "required": ["gaps"],
    }))
    .expect("gap schema is a valid document")
}

/// One cited section of a Scout's dossier. The claim and its citation travel as
/// one object, so neither can arrive attached to a neighbour or to nothing.
fn cited_section(claim: &str) -> Value {
    json!({
        "type": "object",
        "properties": {
            "text": {"type": "string", "minLength": 1, "description": claim},
            "source": {
                "type": "string",
                "pattern": "^https?://",
                "description": "A fetched HTTP(S) page that directly supports the text.",
            },
        },
        "required": ["text", "source"],
    })
}

/// Result schema for a Scout task: the cited dossier the Editor writes a page
/// from. Nothing outside these fields survives, and without them a source-less
/// section is caught by the Verifier two tasks later rather than by a retry.
pub(crate) fn dossier_schema_json() -> Value {
    json!({
        "type": "object",
        "properties": {
            "incident": cited_section("The incident or campaign name and when it happened."),
            "carrier": cited_section("The software, package, archive, extension, or update that carried the payload."),
            "technique": cited_section("How the payload was concealed, activated, and executed."),
            "effect": cited_section("What the payload did after activation."),
            "signal": {
                "type": "object",
                "properties": {
                    "shape": {
                        "type": "string",
                        "minLength": 1,
                        "description": "A reusable code or structural pattern that can identify the technique beyond this incident.",
                    },
                    "sources": {
                        "type": "array",
                        "minItems": 2,
                        "items": {"type": "string", "pattern": "^https?://"},
                        "description": "At least two unique fetched HTTP(S) pages that support the reusable shape.",
                    },
                    "literals": {
                        "type": "array",
                        "description": "Incident-specific strings worth recording. Use an empty array when sources establish none.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "value": {"type": "string", "minLength": 1, "description": "The exact incident-specific string."},
                                "source": {"type": "string", "pattern": "^https?://", "description": "A fetched page containing or directly supporting this literal."},
                            },
                            "required": ["value", "source"],
                        },
                    },
                },
                "required": ["shape", "sources", "literals"],
            },
            "unconfirmed": {
                "type": "string",
                "minLength": 1,
                "description": "What the fetched sources do not establish, or \"nothing\".",
            },
        },
        "required": ["incident", "carrier", "technique", "effect", "signal", "unconfirmed"],
    })
}

/// Result schema for an Editor task: the slug of the draft it saved. The
/// slug is a lookup key, not prose: `install_one` loads the page by it, so it
/// travels as a field rather than through a Verifier retyping it.
pub(crate) fn editor_result_schema_json() -> Value {
    json!({
        "type": "object",
        "properties": {
            "slug": {
                "type": "string",
                "minLength": 3,
                "maxLength": 80,
                "pattern": "^[a-z0-9]+(-[a-z0-9]+)*$",
                "description": "The slug you saved the page under, exactly as you saved it.",
            },
        },
        "required": ["slug"],
    })
}

/// Result schema for a Verifier task, as a plain JSON document bound to the
/// verification label: whether the drafted page may be installed, and why. A
/// page is installed only on `accepted`, so a result without a status is retried
/// rather than read as approval. Which page it judged comes off the Editor's
/// task, never a slug the Verifier retyped.
///
/// `tags` rides on the result because `knowledge` has no field for
/// them, so the Editor cannot set them when it saves the draft. The Verifier
/// has read both the page and the index by the time it answers, which is what
/// it takes to pick a tag the corpus already uses.
pub(crate) fn verification_schema_json() -> Value {
    json!({
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["accepted", "rejected"], "description": "Accept only when every factual section and reusable signal is supported by fetched sources."},
            "reason": {"type": "string", "minLength": 40, "maxLength": 900, "description": "The decisive evidence for acceptance or the exact unsupported or inaccurate claim."},
            "tags": {
                "type": "array",
                "minItems": 1,
                "maxItems": 2,
                "items": {"type": "string", "pattern": "^[a-z0-9]+(-[a-z0-9]+)*$"},
                "description": "One equivalent existing technique tag, or one precise new technique tag when no equivalent exists.",
            },
        },
        "required": ["status", "reason", "tags"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_schema_uses_status_for_its_operational_decision() {
        let schema = Schema::new(verification_schema_json()).expect("a valid document");
        let reason = "The fetched advisory supports the draft's claim about its execution path.";

        assert!(schema
            .validate(json!({
                "status": "accepted",
                "reason": reason,
                "tags": ["auto-executing-install-hook"],
            }))
            .is_ok());
        assert!(schema
            .validate(json!({
                "verdict": "accepted",
                "reason": reason,
                "tags": ["auto-executing-install-hook"],
            }))
            .is_err());
    }

    #[test]
    fn brave_search_description_uses_the_tool_prompt_shape() {
        let description = web_search_tool("key".to_string())
            .get_description()
            .to_string();
        for marker in ["Usage:", "# Instructions", "Example usage:", "<example>"] {
            assert!(
                description.contains(marker),
                "missing {marker}: {description}"
            );
        }
    }

    #[test]
    fn brave_results_render_title_url_and_description() {
        let body = json!({"web": {"results": [
            {"title": "Shai-Hulud 2.0", "url": "https://example.test/a", "description": "npm worm"},
            {"title": "Advisory", "url": "https://example.test/b", "description": "vendor post"},
        ]}});

        let rendered = render_results(&body);

        assert!(rendered.contains("## Shai-Hulud 2.0"), "{rendered}");
        assert!(rendered.contains("https://example.test/b"), "{rendered}");
        assert!(rendered.contains("npm worm"), "{rendered}");
    }

    #[test]
    fn a_response_without_web_results_reports_none() {
        assert_eq!(render_results(&json!({})), "No results found.");
        assert_eq!(
            render_results(&json!({"web": {"results": []}})),
            "No results found."
        );
    }

    /// The dossier a Scout hands the Editor, whole.
    fn dossier() -> Value {
        json!({
            "incident": {
                "text": "ChainDrop, November 2026",
                "source": "https://example.test/advisory",
            },
            "carrier": {
                "text": "a patch release of a build plugin",
                "source": "https://example.test/advisory",
            },
            "technique": {
                "text": "the build hook selected a payload by platform, then executed it",
                "source": "https://example.test/post-mortem",
            },
            "effect": {
                "text": "CI credentials were posted to a webhook",
                "source": "https://example.test/post-mortem",
            },
            "signal": {
                "shape": "a build hook fetching source and piping it into a shell",
                "sources": [
                    "https://example.test/advisory",
                    "https://example.test/post-mortem",
                ],
                "literals": [{
                    "value": "curl -fsSL",
                    "source": "https://example.test/advisory",
                }],
            },
            "unconfirmed": "how the maintainer's account was taken over",
        })
    }

    #[test]
    fn a_dossier_carries_every_section_with_the_page_it_was_read_from() {
        let schema = Schema::new(dossier_schema_json()).expect("a valid document");
        assert!(schema.validate(dossier()).is_ok());
        // The old shape: one markdown document with the citations inline.
        assert!(schema
            .validate(json!(
                "## Incident\nChainDrop — Source: https://example.test/advisory"
            ))
            .is_err());
        for missing in [
            "incident",
            "carrier",
            "technique",
            "effect",
            "signal",
            "unconfirmed",
        ] {
            let mut incomplete = dossier();
            incomplete
                .as_object_mut()
                .expect("an object")
                .remove(missing);
            assert!(schema.validate(incomplete).is_err(), "{missing}");
        }

        let mut old_signal = dossier();
        old_signal["signal"] = json!({
            "text": "curl -fsSL",
            "sources": ["https://example.test/advisory", "https://example.test/post-mortem"],
        });
        assert!(schema.validate(old_signal).is_err());
    }

    #[test]
    fn a_section_without_the_page_behind_it_is_rejected() {
        let schema = Schema::new(dossier_schema_json()).expect("a valid document");
        let mut uncited = dossier();
        uncited["technique"] = json!({"text": "the build hook executed a payload"});
        assert!(schema.validate(uncited).is_err());

        let mut unfetched = dossier();
        unfetched["technique"]["source"] = json!("the vendor's write-up");
        assert!(schema.validate(unfetched).is_err());
    }

    /// The signal becomes the search malwi runs against real code, so one blog's
    /// invention would send every future scan hunting a string that does not exist.
    #[test]
    fn a_signal_resting_on_one_source_is_rejected() {
        let schema = Schema::new(dossier_schema_json()).expect("a valid document");
        let mut single = dossier();
        single["signal"]["sources"] = json!(["https://example.test/advisory"]);
        assert!(schema.validate(single).is_err());
    }

    #[test]
    fn signal_literals_may_be_empty_but_every_literal_needs_a_source() {
        let schema = Schema::new(dossier_schema_json()).expect("a valid document");
        let mut empty = dossier();
        empty["signal"]["literals"] = json!([]);
        assert!(schema.validate(empty).is_ok());

        let mut uncited = dossier();
        uncited["signal"]["literals"] = json!([{"value": "curl -fsSL"}]);
        assert!(schema.validate(uncited).is_err());
    }

    #[test]
    fn a_gap_list_of_prose_is_rejected_by_the_schema() {
        assert!(gap_schema().validate(json!("three gaps, roughly")).is_err());
        assert!(gap_schema()
            .validate(json!({"gaps": [{
                "topic": "PyPI compiled-extension droppers",
                "why": "No page covers a payload that only assembles during a source build.",
                "query": "PyPI malicious sdist setup.py build payload 2026",
            }]}))
            .is_ok());
    }

    #[test]
    fn an_audit_may_report_that_it_found_no_gap() {
        assert!(gap_schema().validate(json!({"gaps": []})).is_ok());
    }
}
