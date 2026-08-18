//! The machinery the `osint` command drives: the web-search tool the agents hunt
//! with, the page format they write to, and the schemas each phase of the chain
//! is held to.

use agentwerk::schemas::Schema;
use agentwerk::tools::{Tool, ToolResult};
use serde_json::{json, Value};

/// Brave's web-search endpoint. The key travels in `X-Subscription-Token`.
const BRAVE_ENDPOINT: &str = "https://api.search.brave.com/res/v1/web/search";

/// The most results Brave returns for one query.
const MAX_RESULTS: u64 = 20;

/// The body of an attack-pattern page, bound into the Editor and the Verifier so
/// the format lives in one place rather than in two prompts that can drift. The
/// front matter is absent on purpose: the knowledge store writes its own, and
/// [`crate::attacks::install`] rewrites it into the corpus form, so a
/// model that hand-wrote one would leave the installed page with two.
pub(crate) const PAGE_FORMAT: &str = include_str!("../roles/page_format.md");

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
        .description("Search the web. Returns titles, URLs, and descriptions.")
        .schema(json!({
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "count": {"type": "integer", "description": "Results count (1-20, default: 5)"},
            },
            "required": ["query"],
        }))
        .concurrent(true)
        .handler(move |input: Value, _ctx| {
            let api_key = api_key.clone();
            async move { search(&api_key, &input).await }
        })
        .build()
}

/// A reachable-but-unhelpful endpoint is the model's problem to route around,
/// so every failure comes back as a tool error rather than killing the ticket.
async fn search(api_key: &str, input: &Value) -> ToolResult {
    let query = input["query"].as_str().unwrap_or("").trim();
    if query.is_empty() {
        return ToolResult::error("query must not be empty");
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
        Err(e) => return ToolResult::error(format!("brave search failed: {e}")),
    };
    let status = response.status();
    if !status.is_success() {
        return ToolResult::error(format!(
            "brave search returned {status}: check BRAVE_API_KEY and the plan's rate limit"
        ));
    }
    match response.json::<Value>().await {
        Ok(body) => ToolResult::success(render_results(&body)),
        Err(e) => ToolResult::error(format!("brave search returned unreadable JSON: {e}")),
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

/// Result schema for the Curator ticket: the gaps the corpus has, each with the
/// search that would confirm it. Attaching it makes `finish` reject a prose
/// answer, which the host cannot fan out into tickets.
pub(crate) fn gap_schema() -> Schema {
    Schema::new(json!({
        "type": "object",
        "properties": {
            "gaps": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "properties": {
                        "topic": {"type": "string", "minLength": 8, "maxLength": 120},
                        "why": {"type": "string", "minLength": 40, "maxLength": 1200},
                        "query": {"type": "string", "minLength": 3, "maxLength": 200},
                    },
                    "required": ["topic", "why", "query"],
                },
            },
        },
        "required": ["gaps"],
    }))
    .expect("gap schema is a valid document")
}

/// Result shape for a Verifier ticket, as a plain JSON document bound to the
/// verification label: which drafted page was judged, whether it may be
/// installed, and why. A page is installed only on `accepted`, so a shapeless
/// verdict must be retried rather than read as approval.
///
/// `tags` rides on the verdict because `knowledge` has no field for
/// them, so the Editor cannot set them when it saves the draft. The Verifier
/// has read both the page and the index by the time it answers, which is what
/// it takes to pick a tag the corpus already uses.
pub(crate) fn verdict_schema_json() -> Value {
    json!({
        "type": "object",
        "properties": {
            "slug": {"type": "string", "minLength": 3, "maxLength": 80},
            "verdict": {"type": "string", "enum": ["accepted", "rejected"]},
            "reason": {"type": "string", "minLength": 40, "maxLength": 900},
            "tags": {
                "type": "array",
                "minItems": 1,
                "maxItems": 2,
                "items": {"type": "string", "pattern": "^[a-z0-9]+(-[a-z0-9]+)*$"},
            },
        },
        "required": ["slug", "verdict", "reason", "tags"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
