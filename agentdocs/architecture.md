# Architecture

The invariants that shape how code fits together. Layout says where code lives; this file says why the seams are where they are.

## Two phases, one ticket system

**A scan runs in two phases: discovery, then analysis. Both share one agentwerk `TicketSystem`.**

- Discovery walks the scan directory, partitions files by extension, and runs the static grep pass on known extensions.
- Analysis consumes the suspect lines discovery produced and the analyst pool decides each verdict.
- A single `TicketSystem` carries the queue, the registered agents, the policies, and the interrupt signal across both phases.
- The analyst pool is registered BEFORE discovery starts so tickets drain live the moment the first match returns.

## Known vs unknown extensions

**File extensions split into two routing paths at startup.**

- Known extensions resolve to a curated catalogue and grep synchronously on a blocking task.
- Unknown extensions route to a per-extension `Threat Researcher` agent that produces the IoC patterns itself.
- Each researcher hands its match bundle to an analyst via `WriteHandoverTool`; no host-side drainer is needed.
- A file without an extension is dropped; an extension with no hits and no researcher is silently ignored.

## Per-extension Threat Researcher

**One Threat Researcher agent per unknown extension, because `template_variable` binds per agent, not per ticket.**

- The agent's `name` doubles as a label; the seed ticket is pinned by labelling it with that name.
- The agent's role text contains a `{extension}` placeholder filled in at agent-build time.
- A generic pool cannot carry different `{extension}` bindings on different tickets, so the per-extension agent is the right unit.
- The agent terminates with `WriteHandoverTool`, atomically finishing its own ticket and spawning an analyst ticket.

## Security Analyst pool

**A fixed-size pool of identical analyst agents shares one label.**

- Pool size is `--concurrency` (default 2); each worker is built by the same closure with a different name suffix.
- Every analyst carries the same `ANALYSIS_LABEL`; tickets routed to that label are claimed by whichever worker is free.
- The pool shares a `Knowledge` store rooted in the workspace directory; the store is cleared at the top of every run.
- Each analyst writes its result with `WriteResultTool` (terminal) or escalates with `WriteHandoverTool` (rare).

## Cooperative cancellation

**Three signals fold into one cancel: ctrl-c, `--max-time`, and the framework's own interrupt signal.**

- `operator_cancel` is set by a tokio task watching `tokio::signal::ctrl_c`; a second press hard-exits.
- `time_up` is set by a tokio task sleeping for the configured deadline.
- A relay task watches both atomics and calls `TicketSystem::cancel()` when either trips.
- The driver inspects the two atomics after `finish().await` to set the exit code (`130` for cancel, `0` for time-up with partial summary).

## Workspace directory

**One `.malwi/` directory holds knowledge, results, and ticket logs for the run.**

- The directory is created under the current working directory at startup.
- `TicketSystem::dir(...)` points the system at it; `Knowledge::open(...)` opens the analyst store inside it.
- Knowledge is cleared at the top of each run; results and ticket logs are append-only.
- The directory is `.gitignore`d by default; operators commit it deliberately or never.

## Report assembly

**The JSON report is built from finished tickets after the loop drains.**

- `report::build_analysis` reads `tickets.tickets()` and turns each `Done` analyst result into one finding.
- `report::build_stats_json` lifts token, request, and timing counters off `Stats`.
- The combined report is written to `.malwi/analysis.json` (or `--output PATH`) and summarized to stderr.
- A zero-finding run still emits a JSON document with `status: "benign"` so downstream tooling has a stable shape.

## One observer, one error path

**`Event` reports state. `ProviderError`, `ToolError`, and the binary's CLI errors report failed contracts.**

- State transitions exist only as agentwerk `Event` payloads streamed by the event handler.
- An observable failure fires both the typed error and a matching `Event` (`RequestFailed`, `ToolCallFailed`, `PolicyViolated`).
- A model-fixable failure (wrong arguments, schema mismatch) goes back to the model as a `ToolResult::Error`; it still fires `ToolCallFailed` but does not stop the run.
- The CLI's own errors print one line to stderr and exit non-zero; they do not pretend to be events.
