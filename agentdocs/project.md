# Project

malwi is a CLI that scans a directory for indicators of compromise, works out how the flagged code is reached, and returns one verdict per finding. The six sections below list the design principles the rest of the binary is measured against.

## Single-purpose tool

**malwi does one job: scan a directory, return a JSON verdict.**

- One binary, one verb per capability: `malwi analyze <TARGET>` is the scanner, `malwi osint [FOCUS]` the researcher.
- Input is a path on disk; output is a JSON report at `.malwi/analysis.json` or at `--output`.
- The tool exits cleanly on cancel, time-up, and policy trip; partial results survive.
- No daemon, no plugin system, no shell integration.

## Static first, LLM second

**A cheap deterministic pass runs before the model is asked anything.**

- Curated catalogues per language carry the static indicators, ranked strongest first.
- Files with known extensions are grouped by catalogue; one worker reads each file once and only matches become tasks.
- A Seeker pool covers what the catalogues miss in at most 20 passes.
- The model is invoked on suspect lines and their callers, never on whole trees.

## Reachability decides

**A grep hit is evidence, not a verdict.**

- The Tracer establishes how the flagged code is reached before an Analyst judges it.
- The Analyst reads the real code, names the actor and the boundary, and returns `malicious`, `exploitable`, or `benign`.
- A `benign` finding is kept: it records that a flagged line was examined and cleared.
- The Explorer's overview of the project is available to every judgement, so intent is weighed alongside the code.

## Agentic by construction

**Every model call is one task on an [agentwerk](https://crates.io/crates/agentwerk) `Werk`.**

- Five roles, each a markdown file: Explorer, Seeker, Tracer, Analyst, Reporter.
- Tasks carry labels for routing; agents never call each other directly.
- Explorer, Tracer, Analyst, and Reporter share project state through `Knowledge` pages; the Seeker keeps an isolated search ledger.
- The whole scan is one cooperative loop with shared cancellation.

## Provider-agnostic

**Any agentwerk-supported provider runs the scan.**

- Anthropic, OpenAI, Mistral, and LiteLLM are selected from environment variables.
- Switching providers changes only the environment; the binary does not change.
- `Provider::from_env()` and `Model::from_env()` (in `agentwerk::providers`) drive the default choice.
- `--models` overrides the default per agent, per pool, or per label.

## Correctness over convenience

**Zero warnings, typed errors, no silent fallbacks.**

- The build MUST pass with `RUSTFLAGS="-D warnings"`: any warning fails it.
- A finding without a verdict, a path, or a description is rejected by its schema and retried.
- IMPORTANT: no blanket `From<io::Error>` or `From<serde_json::Error>`. Every conversion is an explicit mapping into a typed variant.
- Misconfigured arguments, an unreachable model, and an unreadable directory each fail fast with a one-line message.
