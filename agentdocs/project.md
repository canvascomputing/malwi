# Project

malwi is a CLI that scans a directory for indicators of compromise and dispatches LLM-driven security analysts at the matches. The six sections below list the design principles the rest of the binary is measured against.

## Single-purpose tool

**malwi does one job: scan a directory, return a JSON verdict.**

- One binary, one entry point: `malwi <DIR>`.
- Input is a path on disk; output is a JSON report on stdout or at `--output`.
- The tool exits cleanly on cancel, time-up, and policy trip; partial results survive.
- No daemon, no plugin system, no shell integration.

## Static first, LLM second

**A cheap deterministic pass runs before the model is asked anything.**

- Curated catalogues per language carry the static IoC patterns.
- Files with a known extension grep synchronously; only matches become tickets.
- Files with an unknown extension go through a Threat Researcher agent that produces the patterns.
- The model is invoked only on suspect lines, not on whole trees.

## Agentic by construction

**Every model call is one ticket on one [agentwerk](https://crates.io/crates/agentwerk) `TicketSystem`.**

- A `Security Analyst` pool reads suspect lines and decides verdict, severity, and context.
- A `Threat Researcher` agent generates IoC queries for unrecognized extensions.
- Tickets carry labels for routing; agents never call each other directly.
- The whole run is one cooperative loop with shared cancellation.

## Provider-agnostic

**Any agentwerk-supported provider runs the scan.**

- Anthropic, OpenAI, Mistral, and LiteLLM are selected from environment variables.
- Switching providers changes only the environment; the binary does not change.
- All providers share one retry policy through agentwerk.
- `from_env()` and `model_from_env()` (in `agentwerk::providers`) drive the choice.

## Observe, do not prescribe

**The CLI emits structured events. The terminal output is one renderer over them.**

- Every lifecycle transition is an agentwerk `Event`.
- The stderr stream is the default renderer; the JSON file is the audit trail.
- Operators can pipe stderr into another tool without touching the report.
- No built-in TUI, no progress bars, no third-party logger.

## Correctness over convenience

**Zero warnings, typed errors, no silent fallbacks.**

- The build MUST pass with `RUSTFLAGS="-D warnings"`: any warning fails it.
- A finding without a verdict, severity, or location is rejected and retried.
- IMPORTANT: no blanket `From<io::Error>` or `From<serde_json::Error>`. Every conversion is an explicit mapping into a typed variant.
- Misconfigured CLI args fail fast with a one-line message.
