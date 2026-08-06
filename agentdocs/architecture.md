# Architecture

The invariants that shape how code fits together. Layout says where code lives; this file says why the seams are where they are.

## Two queues, one scan

**Every agent but the Reporter shares one `TicketQueue`. The Reporter gets its own.**

- Explorer, Seeker, Tracer, and Analyst pools all run on the scan queue, so a hit found late still drains through the same path.
- `--max-turns` and `--max-time` bound only the scan queue.
- `run_report_phase` builds a second, uncapped queue, so a time limit or a cancel never cuts the summary.
- The Reporter's counters are folded into the totals with `with_report`, so the tally still covers the whole run.

## Evidence before verdict

**A verdict is never reached from a grep hit alone: reachability comes first.**

- Discovery and the Seeker both produce evidence, and both enqueue it on `TRACER_LABEL`.
- The Tracer establishes how the flagged code is reached and hands its trace to `ANALYSIS_LABEL`.
- The Analyst reads the real code behind the trace and returns the verdict object.
- The handover is atomic: `FinishTool` closes the Tracer's ticket and opens the Analyst's in one call.

## Static first, agents alongside

**Discovery greps synchronously; the pools are already running when it starts.**

- `tickets.start()` runs before `Scanner::discover`, so the first cluster is claimed while the sweep is still walking.
- Each catalogue splits into pattern, substring, and file passes, one `spawn_blocking` task each.
- A file's hits within `CLUSTER_RADIUS` lines become one ticket, so an analyst sees a whole payload rather than one line of it.
- Clusters are enqueued by lowest `rank` first, so the strongest evidence reaches the Analyst first.

## Osint fills the corpus it audits

**`osint` is the scanner pointed at its own blind spots, and it feeds the same pages the scan reads.**

- A Curator runs alone on its own queue: nothing for the pools to claim exists until its gap list lands, so the fan-out is a driver step rather than a hook.
- Scout, Editor, and Verifier pools share one queue, chained by `finish` handovers on `editing` and `verification`.
- The gap list and every verdict carry a `Schema`, so a prose answer the driver cannot fan out is retried at `finish` time.
- `--max-time` bounds the audit queue and the osint queue alike: an uncapped Curator would spend the budget its own pools need.
- The gap count is fixed at `MAX_GAPS` rather than exposed: a run costs a predictable number of Scout chains.

## Verification gates installation

**A page reaches the corpus only after an agent has checked it back against its own citations.**

- The Editor writes drafts into the run's `Knowledge` store; only `osint.rs` writes into the source tree.
- The Verifier fetches a cited source before any verdict, and a page it rejects stays where it is.
- A slug the binary already ships is refused: a run may add pages, never rewrite what the scanner already believes.
- The installed front matter is rewritten from the store's page rather than carried over, so `type: AttackPattern` is the command's guarantee and not the model's.

## Knowledge is the shared surface

**Agents never call each other: they read and write pages in shared stores.**

- `exploration/` carries the Explorer's overview and the Tracer's notes; both pools open the same store.
- `searches/` carries what the Seeker already tried, so a refilled ticket does not repeat a search.
- Both stores are seeded from `attacks::copy_seed_into` before `Knowledge::load` indexes them.
- The file map is written into both stores up front, so no agent has to glob the tree.

## Only the Seeker refills

**Discovery is bounded; search is not.**

- `create_ticket_on_result` enqueues a new Seeker ticket whenever one finishes, unless the label is cancelled.
- The Explorer is bounded to `--concurrency` seed tickets: an overview, not an exhaustive read.
- The Tracer and the Analyst are demand-driven and never seed themselves.
- The refill checks `is_label_cancelled` first, since a ticket on a cancelled label would never be claimed.

## Three ways to stop

**A wind-down, a policy stop, and an abort are distinct, and only the abort skips the report.**

- A first ctrl-c cancels the Explorer and Seeker labels; the backlog drains and the report is written.
- A policy stop (time, turns, tokens) calls `TicketQueue::cancel` through `cancel_on_event`, and is recorded in `policy_stopped` so the driver can tell it from an abort.
- A second ctrl-c exits `130` on the spot.
- `--fail-fast` cancels the Seeker, Tracer, and Analyst labels on the first malicious result, then exits `2` after reporting.

## Report assembly

**`build_analysis` reads finished analyst tickets; the Reporter phrases them.**

- One finding per `(path, line, column)`; a repeat upgrades the entry only if its verdict is more severe.
- A result missing a valid `status` counts as `unparsed` and is named in the summary rather than dropped silently.
- `render_findings_table` passes the findings to the Reporter, flagged `partial` when the pools were called off early.
- `merge_reporter_verdict` folds the Reporter's `{summary, details}` over the tally; a missing field leaves the tally in place.

## Schemas hold the contract

**A result the report cannot use is rejected at `finish` time, not at report time.**

- `schema_for_label(ANALYSIS_LABEL, ...)` makes every analyst ticket validate its verdict object.
- The Reporter's ticket carries `reporter_result_schema` with length floors, so a skimped summary is retried.
- `max_schema_retries(20)` raises the default, because a weaker model burns retries on replies with no tool call at all.
- `OUTPUT_CONTRACT` is bound into every schema-carrying role, so the calling convention is stated once.

## One observer, one error path

**`Event` reports state. Typed errors report failed contracts.**

- State transitions exist only as agentwerk `Event` payloads, rendered by `log_event`.
- A model-fixable failure goes back to the model as a tool error; it fires `ToolCallFailed` but does not stop the run.
- Every non-benign verdict is saved as a `Trajectory` under `trajectories/`, on every run.
- The CLI's own errors print one line to stderr and exit non-zero; they do not pretend to be events.
