Searches the public web through Brave Search and returns matching pages.

Returns titles, URLs, and result descriptions as numbered Markdown entries. Search results are
leads rather than evidence. Use `fetch` on a returned URL before citing a claim.

Usage:
- `query`: the exact search query to run
- `count`: 1-20 results. Defaults to 5
- Run independent queries concurrently when each can stand alone

# Instructions
- Name the subject, mechanism, ecosystem, and year in `query`, because broad searches return
  unrelated incidents
- Use `count` only when the default five results cannot expose enough independent sources
- IMPORTANT: Treat descriptions as leads and fetch the source page before citing a claim
- NEVER send an empty `query`, because the tool rejects it without reaching Brave Search

Example usage:

<example>
user: "Find primary reporting about source-build payloads in PyPI packages during 2026."
assistant: <thinking>The request needs current public sources about a specific mechanism.</thinking>
brave_search({
  "query": "PyPI source build payload supply chain attack 2026 primary source",
  "count": 5
})
assistant: Found five leads to inspect with `fetch`.
</example>
