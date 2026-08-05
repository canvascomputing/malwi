<p align="center">
  <img src="https://raw.githubusercontent.com/canvascomputing/malwi/main/logo.png" width="200" />
</p>

<h1 align="center">malwi</h1>

<p align="center">
  <strong>An agentic malware scanner for source trees and software packages.</strong>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#usage">Usage</a> •
  <a href="#output">Output</a> •
  <a href="#development">Development</a>
</p>

<p align="center">malwi greps a directory for known indicators of compromise, searches it for new ones, works out how the flagged code is reached, and returns one verdict per finding.</p>

<p align="center"><em>malwi is short for "malware investigator": one binary that produces one JSON verdict.</em></p>

---

## Installation

```bash
cargo install malwi
```

## Quick Start

```bash
export ANTHROPIC_API_KEY=...
malwi ./suspicious-package
```

The binary streams the agents' work to stderr and writes a structured analysis to `.malwi/analysis.json` (override with `--output`).

```text
malwi scan: /Users/me/suspicious-package

[Scanner] 142 files → 17 hits (JavaScript, Python) → reachability
[Explorer 1] exploring project...
[Seeker 1] grep discord\.com/api/webhooks/
[Tracer 1] → handover to security_analysis: reached from the postinstall hook
[Analyst 1] → malicious lib/telemetry.js: decodes and runs a shell payload on import

=== Summary ===

1 malicious, 3 benign findings across 2 of 142 files

  👹 MALICIOUS · 2 min 14 sec

  ── pipeline ─────────────────────────────
  exploring  ██████████  2/2 · 12 req
  seeking    ████████░░  8/10 · 41 req
  tracing    ██████████  17/17 · 63 req
  analysis   ██████████  17/17 · 88 req
  ── run ──────────────────────────────────
  44/46 tickets · 0 failed · 204 req · 511 tools · 162k↑ 44k↓

  report → .malwi/analysis.json
```

> Configure an LLM provider first (see [Environment](#environment)).

## Usage

```text
malwi <DIR> [OPTIONS]
```

### How a scan works

Five kinds of agent share the work. Four of them run at once; the fifth writes the report once the rest are done.

- **Scanner**: not an agent. Greps every recognized file against the curated catalogue for its language and clusters nearby matches into one piece of evidence.
- **Explorer**: reads a README or an entry point and writes a short overview, so a verdict is judged against what the project claims to be.
- **Seeker**: keeps searching the tree for indicators the catalogue does not carry, one pattern at a time, and hands over any hit worth pursuing.
- **Tracer**: takes one piece of evidence and establishes how that code is reached, from an entry point through its callers.
- **Analyst**: reads the real code behind the trace and returns the verdict, one of `malicious`, `exploitable`, or `benign`.
- **Reporter**: turns the findings into the report's plain-language summary. It runs after the scan, so a time limit never cuts the summary short.

Catalogues ship for JavaScript and TypeScript, Python, Rust, C and C++, Go, and Haskell. Any other file type is covered by the Seeker.

### Flags

| Flag | Description |
|------|-------------|
| `--concurrency <N>` | Agents per pool (default: 2). |
| `--max-turns <N>` | Cap the turns the scan may take. |
| `--max-time <DUR>` | Cap the scan duration. Bare seconds or an `s`/`m`/`h` suffix. |
| `--output <FILE>` | Write the analysis JSON to FILE (default: `.malwi/analysis.json`). |
| `--fail-fast` | Stop the scan at the first malicious finding and still report. |
| `--instruction <TEXT>` | Append your own instruction to every agent's prompt. |
| `--models <FILE>` | Give each agent its own model: see [Models](#models). |
| `-h`, `--help` | Show this help. |

### Examples

```bash
malwi ./src                                     # default scan
malwi ./package --concurrency 4                 # four agents per pool
malwi ./package --max-time 5m                   # cap at 5 minutes
malwi ./package --fail-fast                     # stop at the first malicious finding
malwi ./package --output /tmp/scan.json         # custom report location
malwi ./package --models models.json            # one model per agent
```

### Models

Without `--models`, every agent runs the model the environment names (see [Environment](#environment)). A `--models` file assigns models per agent, keyed by agent name (`Analyst 2`), by pool (`Analyst`), or by ticket label (`security_analysis`). The most specific key wins.

```json
{
  "Analyst": { "model": "claude-sonnet-4-20250514", "reasoning": "high" },
  "Seeker": "claude-haiku-4-5-20251001",
  "Tracer": "claude-haiku-4-5-20251001",
  "Explorer": "claude-haiku-4-5-20251001",
  "Reporter": "claude-sonnet-4-20250514"
}
```

A value is either a model name or an object of `model`, `reasoning` (`off`, `low`, `medium`, `high`), and `context_window`. The file has to cover every agent: an uncovered agent and a key that names no agent are both errors.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed: the verdict is in the report. |
| `1` | Bad arguments, an unreadable directory, or an unreachable model. |
| `2` | A malicious finding under `--fail-fast`. |
| `130` | Cancelled with a second ctrl-c. |

A first ctrl-c winds the scan down: no new work starts, the analysis in flight finishes, and the report is still written.

## Output

### Terminal

Each agent's steps stream to stderr as they happen, prefixed with the agent's name. The run closes with a summary: the verdict, the elapsed time, per-pool progress, and where the report was written.

### Report file

The JSON report (default `.malwi/analysis.json`) carries:

| Field | Description |
|-------|-------------|
| `status` | The worst verdict found: `malicious`, `exploitable`, or `benign`. |
| `summary` | What the scan found, in plain language. |
| `details` | The technical account behind the summary. |
| `findings` | One entry per verdict. |
| `input_tokens` | Tokens sent across the whole run. |
| `output_tokens` | Tokens received across the whole run. |
| `stats` | Per-label timings, ticket counts, tool calls, and request counters. |

Each finding carries:

| Field | Description |
|-------|-------------|
| `status` | The verdict: `malicious`, `exploitable`, or `benign`. |
| `path` | Path to the file, relative to the scanned directory. |
| `line` | Line the verdict is about. |
| `column` | Column the verdict is about. |
| `description` | Why the analyst reached this verdict. |

A `benign` finding is kept on purpose: it records that a flagged line was examined and cleared.

## Workspace directory

`malwi` writes one directory (`.malwi/` under the current working directory) per run. It is wiped at the start of every scan.

| Entry | Contents |
|-------|----------|
| `analysis.json` | The final JSON report. |
| `results.jsonl` | One line per finished ticket. |
| `tickets.jsonl` | One line per ticket transition. |
| `tickets/` | Full ticket state at each transition. |
| `exploration/` | What the Explorer learned and the Tracer recorded. |
| `searches/` | Which searches the Seeker already ran. |
| `trajectories/` | The full exchange behind every non-benign verdict. |
| `stats.json` | Token, request, and timing counters. |

The directory is `.gitignore`d by default.

# Development

## Workspace

- `crates/malwi/`: the binary.
- `crates/malwi/src/roles/`: agent role prompts.
- `crates/malwi/src/threats/`: per-language indicator catalogues.
- `crates/malwi/src/knowledge/`: past-incident pages seeded into the agents' knowledge.
- `crates/malwi/tests/fixtures/`: sample trees to scan.

## Building and testing

```bash
make                # build (warnings are errors)
make test           # unit tests
make fmt            # format code
make clean          # remove build artifacts
make update         # update dependencies
make hooks          # install Claude Code hooks
```

## Running the scanner locally

```bash
make run dir=./src                                  # default settings
make run dir=./src args="--concurrency 4"           # four agents per pool
make run dir=./src args="--max-time 5m --fail-fast"
```

A synthetic package that reaches a `malicious` verdict lives in `crates/malwi/tests/fixtures/python-malware`.

## Publishing

```bash
make bump                  # bump patch version, run tests, commit, tag
make bump part=minor       # bump minor version
make bump part=major       # bump major version
```

GitHub Actions handles the crates.io publish via trusted publishing once the new tag is pushed (`git push --tags`).

## Documentation

```bash
make doc                   # cargo doc --no-deps -p malwi (strict rustdoc)
```

## Environment

`malwi` reads the same provider environment variables as [agentwerk](https://crates.io/crates/agentwerk). The provider is picked from whichever API key is set; the model comes from the same place unless `--models` overrides it.

**General**

| Variable | Description |
|----------|-------------|
| `MODEL` | Model override that wins whatever the provider is. |
| `MODEL_CONTEXT_WINDOW` | Context window override, in tokens. |

**Anthropic**

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | API key (required). |
| `ANTHROPIC_BASE_URL` | API URL (default: `https://api.anthropic.com`). |
| `ANTHROPIC_MODEL` | Model (default: `claude-sonnet-4-20250514`). |

**Mistral**

| Variable | Description |
|----------|-------------|
| `MISTRAL_API_KEY` | API key (required). |
| `MISTRAL_BASE_URL` | API URL (default: `https://api.mistral.ai`). |
| `MISTRAL_MODEL` | Model (default: `mistral-medium-2508`). |

**OpenAI**

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | API key (required). |
| `OPENAI_BASE_URL` | API URL (default: `https://api.openai.com`). |
| `OPENAI_MODEL` | Model (default: `gpt-4o`). |

**LiteLLM proxy**

| Variable | Description |
|----------|-------------|
| `LITELLM_BASE_URL` | Proxy URL (default: `http://localhost:4000`). |
| `LITELLM_API_KEY` | Auth key (required to select the proxy). |
| `LITELLM_MODEL` | Model (default: `claude-sonnet-4-20250514`). |
| `LITELLM_PROVIDER` | Pick the provider explicitly: `anthropic`, `mistral`, `openai`, or `litellm`. |
