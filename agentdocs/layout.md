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
- `cli.rs` routes: it holds the `Command` enum, the shortcut table, the top-level help, and `CliExit`. It assembles, and nothing more.
- `cli.rs` also owns what every command shares: the `--models` table, `parse_duration`, and the roster probe.
- IMPORTANT: no command's arguments, parser, or help text live in `cli.rs`. Each verb defines its own `Args`, `parse`, and `help`, and `parse_args` calls them.
- Every command verifies its models through `verify_models` before doing any work.
- `discovery.rs` walks the tree, compiles the catalogues, runs the grep passes, and enqueues the tickets they produce.
- `report.rs` turns finished tickets into the analysis JSON, renders the event stream, and prints the summary.
- `report.rs` also holds `POOL_NAMES`, the one table mapping every command's ticket labels to the pool names the operator reads: agentwerk names an agent `<label>-<n>`.
- `attacks.rs` seeds the past-incident pages into a `Knowledge` store and installs researched ones.

## Commands

**Every command is one verb on the binary and one file named for that verb.**

- `analyze.rs` is `malwi analyze <TARGET>`: it builds both `TicketQueue`s and every agent, drives the run, and writes the report.
- `osint.rs` is `malwi osint [FOCUS]`: it fills the gaps in the attack corpus from public sources.
- `download.rs` is `malwi download <PROMPT>`: it fetches a package's published artefacts from its registry.
- Each verb has one fixed single-letter shortcut (`a`, `o`, `d`), expanded by one table in `cli.rs`; a longer prefix is not a shortcut.
- A TARGET is classified before the walk, and `analyze::Target::resolve` hands every phase behind it a directory: a file is copied into the working folder first.
- A command file exposes `Args`, `parse`, `help`, and one `run`, so `main.rs` stays a dispatch table and `cli.rs` stays a router.
- A bare path is not a command: `malwi ./src` is rejected, never an implicit run.
- IMPORTANT: `analyze.rs` is the command, `discovery.rs` the machinery it drives; new scanning mechanics belong in `discovery.rs`.
- IMPORTANT: `osint.rs` is the command, `osint/web_search.rs` the machinery it drives; new intelligence-gathering mechanics belong in `osint/web_search.rs`.
- IMPORTANT: `download.rs` is the command, `download/` the machinery it drives; a new registry belongs in its own file under `download/ecosystem/`.

## The `osint/` directory

**The machinery the `osint` verb drives lives beside the file that is the verb.**

- `web_search.rs` holds the web-search tool, the page format, and the schemas each phase of the chain is held to.
- Its modules stay private to `osint.rs`, so nothing outside the command reaches the machinery.
- `include_str!` inside `osint/` reaches the shared prompts one level up, as `../roles/…`.
- A second subcommand-free helper earns a file here; the verb file stays the command.

## The `download/` directory

**The machinery the `download` verb drives lives beside the file that is the verb.**

- `ecosystem.rs` holds the `Ecosystem` trait every registry implements, the `Package` a prompt resolves to, the `posix_encode` that makes a name a path, the HTTP helpers, and the schema the Categorizer is held to.
- `ecosystem/pypi.rs`, `ecosystem/npm.rs`, and `ecosystem/cargo.rs` are one registry each: a unit struct and its `impl Ecosystem`, holding nothing but that registry's URL shapes, endpoints, and metadata parsing.
- IMPORTANT: the trait is synchronous. A registry says where its metadata is and how to read it; the fetching, the path building, and the writing happen once in `ecosystem.rs`, so every registry stays testable without a network.
- `archive.rs` unpacks one artefact, filtering every entry: a path leaving the destination, a symlink, or an expansion past the ceiling is skipped rather than written.
- Artefacts land in `downloads/<ecosystem>/<name_normalized>/<version>/`, and the command writes nothing outside `downloads/`.
- IMPORTANT: a registry is reached through its static URLs only; no command here shells out to a package manager, because an install is the code being investigated.
- Adding a registry is one file beside these three and one entry in `ECOSYSTEMS`.

## The `roles/` directory

**Each agent role is one markdown file loaded via `include_str!`.**

- `explorer.md`, `seeker.md`, `tracer.md`, `analyst.md`, `reporter.md` are the analyze roles.
- `curator.md`, `scout.md`, `editor.md`, `verifier.md` are the osint roles.
- `categorizer.md` is the download role: it names the package a prompt means.
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
- `malwi osint` writes here directly, which is why the table is generated rather than hand-kept.
- The index is rebuilt from the pages by `Knowledge::load`; never check one in.

## Tests

**Tests live next to the code they cover.**

- Inline `#[cfg(test)] mod tests` for unit coverage of `discovery.rs`, `report.rs`, `cli.rs`, `analyze.rs`, `osint.rs`, `osint/web_search.rs`, `download.rs`, `download/ecosystem.rs`, each `download/ecosystem/*.rs`, `download/archive.rs`, `attacks.rs`.
- `cli::parse_line` turns one command line into a `Command`, so each verb tests its own arguments without spawning the binary.
- Sample trees to scan live under `crates/malwi/tests/fixtures/`.
- `tests/fixtures/python-malware/` is synthetic, and exists so a scan deterministically reaches a `malicious` verdict.

## Specs

**`specs/` holds design notes for non-trivial changes.**

- One markdown file per change, dated `YYYY-MM-DD-<slug>.md`.
- Specs survive after the change ships; they document why a decision was made.
- A spec is required only when the change touches the agent topology or the report shape.
