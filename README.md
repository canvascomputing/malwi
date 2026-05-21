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

<p align="center">malwi walks a directory, grep-matches known indicators of compromise per language, and dispatches LLM-driven security analysts at each suspect line. Unrecognized file types are first triaged by a per-extension threat researcher.</p>

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

The binary prints a terminal summary to stderr and writes a structured analysis to `.malwi/analysis.json` (override with `--output`).

```text
malware scan: /Users/me/suspicious-package
  142 files, 5 file types (3 recognized, 2 unrecognized)
  2 parallel workers

  17 suspect matches from known extensions, analyzing...

verdict:    suspicious
findings:   4
duration:   42s
report:     .malwi/analysis.json
```

> Configure an LLM provider first (see [Environment](#environment)).

## Usage

```text
malwi <DIR> [OPTIONS]
```

`malwi` walks `<DIR>`, splits its file extensions into a curated set (greps statically) and an unknown set (a threat researcher generates patterns), and dispatches matches to a security analyst pool.

| Flag | Description |
|------|-------------|
| `--concurrency <N>` | Worker pool size per phase (default: 2). |
| `--max-steps <N>` | Per-system step cap (default: unlimited). |
| `--max-time <DUR>` | Time cap. Bare seconds or `s`/`m`/`h` suffix (default: unlimited). |
| `--output <PATH>` | Write the analysis JSON to PATH (default: `.malwi/analysis.json`). |
| `--no-briefing` | Drop the IoC briefing from analyst tickets; ticket body becomes just source and line. |
| `-h`, `--help` | Show this help. |

### Examples

```bash
malwi ./src                                     # default scan
malwi ./package --concurrency 4                 # 4 analysts in parallel
malwi ./package --max-time 5m                   # cap at 5 minutes
malwi ./package --output /tmp/scan.json         # custom report location
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed; verdict is in the report. |
| `1` | Misconfigured arguments or unreadable scan directory. |
| `130` | Operator cancelled with ctrl-c. |

## Output

### Terminal summary

`malwi` writes a one-screen summary to stderr at the end of the run: scan directory, files walked, file types, worker count, suspect matches, verdict, finding count, duration, and the path to the JSON report.

### Report file

The JSON report (default `.malwi/analysis.json`) carries:

| Field | Description |
|-------|-------------|
| `status` | One of `benign`, `suspicious`, `malicious`. |
| `summary` | One-line human-readable verdict. |
| `findings` | Array of finding objects. |
| `input_tokens` | Total input tokens consumed across all providers. |
| `output_tokens` | Total output tokens produced across all providers. |
| `stats` | Per-label timings, ticket counts, and request counters. |

Each finding object carries:

| Field | Description |
|-------|-------------|
| `path` | Repository-relative path to the file. |
| `line` | Line number of the IoC match. |
| `severity` | One of `low`, `medium`, `high`. |
| `verdict` | One of `benign`, `suspicious`, `malicious`. |
| `summary` | One-line description of the finding. |
| `evidence` | Verbatim line that triggered the match. |
| `context` | Analyst's reasoning. |

### Events

Every lifecycle transition is an [agentwerk](https://crates.io/crates/agentwerk) `Event`. `malwi`'s default renderer prints a concise line per event to stderr.

| | Kind | Description |
|-|------|-------------|
| **Ticket** | `TicketStarted` | An agent claimed a ticket. |
| | `TicketDone` | A ticket finished successfully. |
| | `TicketFailed` | A ticket failed. |
| **Provider** | `RequestStarted` | A provider request started. |
| | `RequestFinished` | A provider request finished and reported its token usage. |
| | `RequestFailed` | A provider request failed and stopped the ticket. |
| **Tool** | `ToolCallStarted` | A tool invocation started. |
| | `ToolCallFinished` | A tool invocation finished. |
| | `ToolCallFailed` | A tool invocation failed but the ticket continues. |
| **Run** | `PolicyViolated` | A policy limit was breached and execution stopped. |

## Workspace directory

`malwi` writes one directory (`.malwi/` under the current working directory) per run:

| File | Contents |
|------|----------|
| `analysis.json` | The final JSON report. |
| `results.jsonl` | One NDJSON line per finished ticket. |
| `tickets.jsonl` | One JSON line per ticket lifecycle transition. |
| `tickets/<key>/ticket.<ts>.json` | Full ticket state at each transition. |
| `pages/`, `index.md` | The analyst's knowledge store. |
| `stats.json` | Run-wide token, request, and timing counters. |

The directory is `.gitignore`d by default; the knowledge store is cleared at the start of every run.

# Development

## Workspace

- `crates/malwi/`: the binary.
- `roles/`: agent role prompts loaded via `include_str!`.
- `threats/`: per-language IoC catalogues.

## Building and testing

```bash
make                # build (warnings are errors)
make test           # unit tests bundled by tests/unit (workspace --lib)
make fmt            # format code
make clean          # remove build artifacts
make update         # update dependencies
make hooks          # install Claude Code hooks
```

## Running the scanner locally

```bash
make run dir=./src                                  # default settings
make run dir=./src args="--concurrency 4"           # 4 analysts
make run dir=./src args="--max-time 5m --no-briefing"
```

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

`malwi` reads the same provider environment variables as [agentwerk](https://crates.io/crates/agentwerk).

**General**

| Variable | Description |
|----------|-------------|
| `MODEL` | Generic model override for `model_from_env()`. |

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
| `LITELLM_API_KEY` | Auth key (required to select via `from_env()`). |
| `LITELLM_MODEL` | Model (default: `claude-sonnet-4-20250514`). |
| `LITELLM_PROVIDER` | LLM provider (`anthropic`, `mistral`, `openai`, `litellm`): explicit selection that overrides API-key auto-detection. |
