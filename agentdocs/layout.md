# Layout

Where code lives and the rules that govern placement.

## Workspace

**One workspace, one binary crate.**

- `crates/malwi/` is the binary.
- Cargo workspace at the repo root is the only build entry point.
- A second crate is added only when a piece of code earns reuse outside `malwi`.

## Top-level files

**Each top-level source file is one concern the operator observes directly.**

- `main.rs` parses CLI args, builds the `TicketSystem`, drives the scan, and writes the report.
- `scan.rs` walks the directory, partitions files by extension, and runs the static grep pass.
- `report.rs` turns finished tickets into the JSON analysis and prints the terminal summary.
- `cli.rs` defines the argument parser and the help text.

## The `roles/` directory

**Each agent role is one markdown file loaded via `include_str!`.**

- `security-analyst.md` is the analyst pool's role prompt.
- `threat-researcher.md` is the per-extension researcher's role prompt.
- New roles earn their own file; never inline a multi-paragraph role string in Rust.
- `{template}` placeholders in the file are bound at agent-build time through `template_variable`.

## The `threats/` directory

**One file per language: the curated IoC catalogue.**

- `python.md`, `javascript.md`, `rust.md`, `go.md`, `cpp.md`, `haskell.md` are catalogues.
- Each file lists patterns the static grep pass searches for, with one-line context per pattern.
- Catalogues are loaded via `include_str!` and dispatched by file extension.
- A language without a catalogue routes through the Threat Researcher.

## Tests

**Tests live next to the code they cover.**

- Inline `#[cfg(test)] mod tests` for unit coverage of `scan.rs`, `report.rs`, `cli.rs`.
- Integration tests against a real provider live under `crates/malwi/tests/`, bundled by `tests/integration.rs`.
- Fixtures (sample suspect files) live under `crates/malwi/tests/fixtures/`.

## Specs

**`specs/` holds design notes for non-trivial changes.**

- One markdown file per change, dated `YYYY-MM-DD-<slug>.md`.
- Specs survive after the change ships; they document why a decision was made.
- A spec is required only when the change touches the agent topology or the report shape.
