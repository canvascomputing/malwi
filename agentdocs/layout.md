# Layout

Where code lives and the rules that govern placement.

## Workspace

**One workspace, one binary crate.**

- `crates/malwi/` is the binary.
- Cargo workspace at the repo root is the only build entry point.
- `crates/malwi/build.rs` generates the attack-page table from `src/attacks/`; nothing else runs at build time.
- A second crate is added only when a piece of code earns reuse outside `malwi`.

## Top-level files

**Each top-level source file is one concern the operator observes directly.**

- `main.rs` parses the command and hands it the rest of the arguments; it holds nothing else.
- `cli.rs` defines the command dispatch, each command's argument parser, the `--models` table, and the help texts.
- `cli.rs` also probes the resolved roster: every command verifies its models through `verify_models` before doing any work.
- `discovery.rs` walks the tree, compiles the catalogues, runs the grep passes, and enqueues the tickets they produce.
- `report.rs` turns finished tickets into the analysis JSON, renders the event stream, and prints the summary.
- `osint.rs` holds the web-search tool, the page format, and the schemas the research chain is held to.
- `attacks.rs` seeds the past-incident pages into a `Knowledge` store and installs researched ones.

## Commands

**Every command is one verb on the binary and one file named for that verb.**

- `scan.rs` is `malwi scan <DIR>`: it builds both `TicketQueue`s and every agent, drives the scan, and writes the report.
- `research.rs` is `malwi research [TOPIC]`: it fills the gaps in the attack corpus from public sources.
- A command file exposes one `run` taking that command's parsed arguments, so `main.rs` stays a dispatch table.
- A bare path is not a command: `malwi ./src` is rejected, never an implicit scan.
- IMPORTANT: `scan.rs` is the command, `discovery.rs` the machinery it drives; new scanning mechanics belong in `discovery.rs`.
- IMPORTANT: `research.rs` is the command, `osint.rs` the machinery it drives; new intelligence-gathering mechanics belong in `osint.rs`.

## The `roles/` directory

**Each agent role is one markdown file loaded via `include_str!`.**

- `explorer.md`, `seeker.md`, `tracer.md`, `analyst.md`, `reporter.md` are the scan roles.
- `curator.md`, `scout.md`, `editor.md`, `verifier.md` are the research roles.
- `verdicts.md`, `output_contract.md`, and `page_format.md` are not roles: they are shared fragments bound into whichever roles need them.
- New roles earn their own file; never inline a multi-paragraph role string in Rust.
- `{template}` placeholders in the file are bound at agent-build time through `Agent::template`.

## The `threats/` directory

**One JSON file per language: the curated indicator catalogue.**

- `python.json`, `javascript.json`, `rust.json`, `go.json`, `cpp.json`, `haskell.json` are catalogues.
- An entry carries `category`, `query`, `type` (`pattern`, `substring`, or `file`), `reason`, and `rank`.
- `rank` MUST equal the entry's position in the file: the tests enforce it, and discovery enqueues low ranks first.
- Catalogues are loaded via `include_str!` and dispatched by file extension in `known_extension_to_catalogue`.

## The `attacks/` directory

**One page per real supply-chain incident, beside the `attacks.rs` that seeds them.**

- Every page carries OKF frontmatter (`type: AttackPattern`, `description`, `tags`) and the five sections `## Carrier`, `## Technique`, `## Payload/effect`, `## Detectable signal`, `## Sources`.
- `## Detectable signal` states the generalizable shape first and this incident's literals second: a page of literals alone catches a replay and nothing else.
- The three tests in `attacks.rs` enforce that shape, so a hand-written page and a researched one stay readable to the same agent.
- `build.rs` generates the `PAGES` table from the directory, so adding a page is dropping in a file.
- Pages are embedded at compile time, so an installed binary carries its own seed.
- `malwi research` writes here directly, which is why the table is generated rather than hand-kept.
- The index is rebuilt from the pages by `Knowledge::load`; never check one in.

## Tests

**Tests live next to the code they cover.**

- Inline `#[cfg(test)] mod tests` for unit coverage of `discovery.rs`, `report.rs`, `cli.rs`, `scan.rs`, `research.rs`, `osint.rs`, `attacks.rs`.
- `cli.rs` parses a `&[String]` into a command, so argument handling is tested without spawning the binary.
- Sample trees to scan live under `crates/malwi/tests/fixtures/`.
- `tests/fixtures/python-malware/` is synthetic, and exists so a scan deterministically reaches a `malicious` verdict.

## Specs

**`specs/` holds design notes for non-trivial changes.**

- One markdown file per change, dated `YYYY-MM-DD-<slug>.md`.
- Specs survive after the change ships; they document why a decision was made.
- A spec is required only when the change touches the agent topology or the report shape.
