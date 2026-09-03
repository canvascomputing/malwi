# Architecture

The invariants that shape how code fits together. Layout says where code lives; this file says why the seams are where they are.

## Two Werks, one scan

**Every agent but the Reporter shares one `Werk`. The Reporter gets its own.**

- Explorer, Seeker, Tracer, and Analyst pools all run on the scan Werk, so a hit found late still drains through the same path.
- `--max-turns` and `--max-time` bound only the scan Werk.
- `run_report_phase` builds a second, uncapped Werk, so a time limit or a cancel never cuts the summary.
- Both Werks write the same event log, so the folded tally still covers the whole run.

## Evidence before verdict

**A verdict is never reached from a grep hit alone: reachability comes first.**

- Discovery and the Seeker both produce evidence, and both put it on `TRACER_LABEL` carrying the same `path`, `line`, `column` triple: discovery renders a task body, while the host routes the Seeker's schema-checked hit.
- The Tracer establishes how the flagged code is reached and hands its trace to `ANALYSIS_LABEL`.
- For an initial verdict, the Analyst treats the Tracer's cited trace as established evidence and returns a finding without reopening files or re-deriving callers; a focused type investigation may inspect only the extra facts its protocol requires.
- The handover is atomic: `FinishTool` closes the Tracer's task and opens the Analyst's in one call.
- A malicious or exploitable finding with a registered type owned by its verdict opens one investigation. It carries the analysis label, so an Analyst claims it, and the type's schema on the task itself. A type costs a task, not a role and not a model.
- What marks a task an investigation is its parent: a plain analysis task is handed over by a Tracer, an investigation by an Analyst. `is_investigation` is the one place that asks, and `investigated_type` reads the type from the finding that opened it. An investigation that rules the type out omits `type`.
- A finding without `type` opens nothing, which bounds how many investigations a run pays for.
- Telemetry is one exploitable type across providers. Its investigation must establish an external destination, concrete transmitted data, activation and cadence, and the absence of affirmative default-off consent; SDK or instrumentation evidence alone remains a lead.

## Static first, agents alongside

**`ScanTree` inventories once; catalogue workers read each applicable file once.**

- `ScanTree` retains every path, including extensionless files; extensions are the keys of its grouped path map.
- Active extensions are grouped by catalogue. Each catalogue compiles once and gets one `spawn_blocking` worker.
- A worker reads each applicable file once, combines code-pattern and substring hits, then clusters them. Filename indicators match the retained path inventory rather than walking again.
- A file's hits within `CLUSTER_RADIUS` lines become one task, so an analyst sees a whole payload rather than one line of it.
- Clusters are enqueued by lowest `rank` first, so the strongest evidence reaches the Analyst first.

## Osint fills the corpus it audits

**`osint` is the scanner pointed at its own blind spots, and it feeds the same pages the scan reads.**

- Curator, Scout, Editor, and Verifier share one Werk and policy. A Curator result hook creates one Scout task per gap; Scout-to-Editor-to-Verifier remains a configured handover chain.
- Every step of the chain carries a `Schema`: a prose gap list the driver cannot fan out, and a dossier whose claim carries no source or whose signal rests on one, are both retried at `finish` time rather than reaching the agent that would have to work around them.
- `--max-time` bounds the complete audit-to-verification workflow once.
- The gap count is fixed at `MAX_GAPS` rather than exposed: a run costs a predictable number of Scout chains.

## Verification gates installation

**A page reaches the corpus only after an agent has checked it back against its own citations.**

- The Editor writes drafts into the run's `Knowledge` store; only `osint.rs` writes into the source tree.
- The Verifier fetches a cited source before returning a status, and a page it rejects stays where it is.
- A slug the binary already ships is refused: a run may add pages, never rewrite what the scanner already believes.
- The installed front matter is rewritten from the store's page rather than carried over, so `type: AttackPattern` is the command's guarantee and not the model's.

## Knowledge is the shared surface

**Agents never call each other: they read and write pages in shared stores.**

- `project/` carries the Explorer's overview and the Tracer's and Analyst's notes; Explorer, Tracer, Analyst, and Reporter open the same store.
- `searches/` carries what the Seeker already tried, so a refilled task does not repeat a search.
- Both stores are seeded from `attacks::copy_seed_into` before `Knowledge::load` indexes them.
- The file map is written into both stores up front, so no agent has to glob the tree.

## Seeker refill is finite and downstream-aware

**Discovery and search are both bounded.**

- At most `SEEKER_PASSES` (20) tasks are created, with at most `--concurrency` pending at once.
- One mutex protects the AQL count-and-refill sequence. Refill waits while a Tracer, Analyst, or type follow-up is pending, and listens to those results so it reopens when they drain.
- The Explorer is bounded to `--concurrency` seed tasks: an overview, not an exhaustive read.
- The Tracer and the Analyst are demand-driven and never seed themselves.

## Three ways to stop

**A wind-down, a policy stop, and an abort are distinct, and only the abort skips the report.**

- A first ctrl-c cancels pending Explorer and Seeker tasks; the backlog drains and the report is written. OSINT similarly cancels pending Curator and Scout work while existing Editor and Verifier tasks drain.
- A policy stop (time, turns, tokens) ends the run inside the Werk, and is recorded in `policy_stopped`: by report time the Werk has been cancelled and its own finish reason no longer names the limit.
- It cancels `POLICY_STOP_LABELS` while sparing the investigations already open by ID: each is detail the run already paid an Analyst for, and with the analysis label off nothing new opens. The IDs are read in the handler, because a cancel filter that touched the task store would deadlock the claim path.
- A second ctrl-c exits `130` on the spot.
- `--fail-malicious` cancels pending Seeker, Tracer, and Analyst tasks on the first confirmed malicious finding; `--fail-exploitable` does the same for any exploitable or malicious finding. Both exit `2` after reporting, and the analysis label covers investigations too.
- Every exploitable verdict reaches the exploitable threshold immediately, whether or not its finding names a registered type. An untyped malicious finding also reaches either threshold immediately; a typed malicious finding first opens its focused follow-up and stops only if that answer remains malicious.

## Report assembly

**`build_analysis` reads finished analyst and investigation tasks; the Reporter phrases them.**

- Parent identity resolves follow-ups first: an investigation replaces the exact finding task that opened it, including a downgrade to benign. Unrelated results then deduplicate by `(path, line)` and verdict severity, so a separate malicious finding at the same location still wins.
- The key holds no `column`: an investigation restates its parent finding, and one Analyst naming a column where another left it null would split one finding into two.
- A type reaches the report only when all its fields are present. A policy stop can leave `type` on the opening finding without establishing those fields.
- A result missing a valid `verdict` counts as `unparsed` and is named in the summary rather than dropped silently. A task still `Todo` is skipped: a backlog no Analyst claimed is work the run never reached, not a result it could not parse.
- `render_findings_table` passes the findings to the Reporter, flagged `partial` when the pools were called off early.
- `merge_reporter_output` folds the Reporter's `{summary, details}` over the tally; a missing field leaves the tally in place.

## Schemas hold the contract

**A result the report cannot use is rejected at `finish` time, not at report time.**

- Every result-bearing task carries its own `Schema`. Plain analysis tasks use the finding schema, while investigations carry their type-specific schema.
- The Reporter's task carries `reporter_result_schema` with length floors, so a skimped summary is retried.
- Every Werk is bounded by one `Policy`, and `max_schema_retries: Some(20)` raises the default, because a weaker model burns retries on replies with no tool call at all.
- `OUTPUT_CONTRACT` and the operator's `--instruction` are passed to every agent through one `shared_templates`, whatever its role names: a role referencing a template its own builder forgot ships the placeholder to the model as literal text, and nothing at run time says so.
- A schema is serialized into the `finish` tool it validates, so a field's `description` is how the model learns it: the finding's type enum, its description, and every type's fields are assembled from `TYPES`.
- A type's schema is the base finding plus its own fields, required only once `type` names it. Omitting `type` records that the investigation ruled it out.
- Each stage boundary validates its result. Seeker tasks validate hits before the host creates Tracer tasks; configured Tracer and OSINT handovers attach the receiving task's schema. A field the next stage has to re-derive out of prose is one it can invent, and an invention validates.
- For object schemas, the finish call exposes the schema's fields as top-level arguments. Wrapping them in `result` is rejected; `the_output_contract_names_the_fields_finish_reads` pins the role text to that API.
- A code location is always `path`, `line`, `column`, the triple grep reports: flat when an object has one location, nested under a name when it has more than one.

## One observer, one error path

**`Event` reports state. Typed errors report failed contracts.**

- State transitions exist only as agentwerk `Event` payloads, rendered by `log_event`.
- A model-fixable failure goes back to the model as a tool error; it fires `tool_call_failed` but does not stop the run.
- Every non-benign finding is saved as a `Trajectory` under `trajectories/` by an awaited async result hook, on every run.
- The CLI's own errors print one line to stderr and exit non-zero; they do not pretend to be events.
