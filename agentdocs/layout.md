# Layout

Where code lives and the rules that govern placement.

## Workspace

**One workspace, one binary crate.**

- `crates/malwi/` is the binary.
- Cargo workspace at the repo root is the only build entry point.
- A second crate is added only when a piece of code earns reuse outside `malwi`.

## Top-level files

**Each top-level source file is one concern the operator observes directly.**

- `main.rs` parses the command and hands it the rest of the arguments; it holds nothing else.
- `cli.rs` defines the command dispatch, each command's argument parser, the `--models` table, and the help texts.
- `discovery.rs` walks the tree, compiles the catalogues, runs the grep passes, and enqueues the tickets they produce.
- `report.rs` turns finished tickets into the analysis JSON, renders the event stream, and prints the summary.
- `attack_patterns.rs` seeds the past-incident pages into a `Knowledge` store.

## Commands

**Every command is one verb on the binary and one file named for that verb.**

- `scan.rs` is `malwi scan <DIR>`: it builds both `TicketQueue`s and every agent, drives the scan, and writes the report.
- `research.rs` is `malwi research <QUESTION>`: it answers a security question from public sources.
- A command file exposes one `run` taking that command's parsed arguments, so `main.rs` stays a dispatch table.
- A bare path is not a command: `malwi ./src` is rejected, never an implicit scan.
- IMPORTANT: `scan.rs` is the command, `discovery.rs` the machinery it drives; new scanning mechanics belong in `discovery.rs`.

## The `roles/` directory

**Each agent role is one markdown file loaded via `include_str!`.**

- `explorer.md`, `seeker.md`, `tracer.md`, `analyst.md`, `reporter.md` are the five roles.
- `verdicts.md` is not a role: it is the shared verdict rubric bound into the Analyst and the Reporter.
- New roles earn their own file; never inline a multi-paragraph role string in Rust.
- `{template}` placeholders in the file are bound at agent-build time through `Agent::template`.

## The `threats/` directory

**One JSON file per language: the curated indicator catalogue.**

- `python.json`, `javascript.json`, `rust.json`, `go.json`, `cpp.json`, `haskell.json` are catalogues.
- An entry carries `category`, `query`, `type` (`pattern`, `substring`, or `file`), `reason`, and `rank`.
- `rank` MUST equal the entry's position in the file: the tests enforce it, and discovery enqueues low ranks first.
- Catalogues are loaded via `include_str!` and dispatched by file extension in `known_extension_to_catalogue`.

## The `knowledge/` directory

**`knowledge/attack_patterns/` holds one page per real supply-chain incident.**

- Each page names the carrier, the technique, and the marker a search would find.
- Pages are embedded at compile time in `attack_patterns.rs`, so an installed binary carries its own seed.
- Adding a page means adding its `(slug, include_str!)` pair to `PAGES` and widening the array.
- The index is rebuilt from the pages by `Knowledge::load`; never check one in.

## Tests

**Tests live next to the code they cover.**

- Inline `#[cfg(test)] mod tests` for unit coverage of `discovery.rs`, `report.rs`, `cli.rs`, `scan.rs`, `attack_patterns.rs`.
- `cli.rs` parses a `&[String]` into a command, so argument handling is tested without spawning the binary.
- Sample trees to scan live under `crates/malwi/tests/fixtures/`.
- `tests/fixtures/python-malware/` is synthetic, and exists so a scan deterministically reaches a `malicious` verdict.

## Specs

**`specs/` holds design notes for non-trivial changes.**

- One markdown file per change, dated `YYYY-MM-DD-<slug>.md`.
- Specs survive after the change ships; they document why a decision was made.
- A spec is required only when the change touches the agent topology or the report shape.
