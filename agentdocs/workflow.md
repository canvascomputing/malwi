# Workflow

Commands used to build, test, release, and run the scanner.

## Build

**Every build MUST run with `-D warnings`.**

- `make` compiles the binary.
- `make fmt` formats the code.
- `make clean` removes build artefacts.
- Any warning fails the build.

## Test

**Test layout and writing rules live in [testing.md](testing.md).**

- `make test` runs `cargo test --workspace --bins` (the binary's inline `#[cfg(test)] mod tests`).

## Release

**`make bump` runs the full release step in one command.**

- `make bump` runs tests, bumps the patch version, commits, and tags.
- `make bump part=minor` bumps the minor version.
- `make bump part=major` bumps the major version.
- Push the new tag with `git push --tags`.

## Hooks

**`make hooks` installs Claude Code hooks into `.claude/settings.local.json`.**

- Source files live in `hooks/` (tracked). `make hooks` copies them into `.claude/hooks/` (ignored) and merges the config.
- `check-conventions.sh` injects `agentdocs/style.md` and `agentdocs/architecture.md` as context after each Rust file edit.

## Running an analysis

**`make run` invokes `malwi analyze` against a directory or a single file.**

- `make run dir=./src` analyzes `./src` with default settings.
- `make run dir=./pkg/index.js` analyzes one file, copied into the working folder first.
- `make run dir=./src args="--concurrency 4 --max-time 5m"` passes flags through.
- `make run dir=crates/malwi/tests/fixtures/python-malware args="--fail-fast"` analyzes the synthetic sample.
- Configure an LLM provider first: see [Environment](../DEVELOPMENT.md#environment).
- The full CLI reference lives in `malwi --help` and in the README.

## Downloading a package

**`make download` fetches a package's artefacts without running its package manager.**

- `make download prompt="py stanza 1.14.0"` resolves the prompt through the Categorizer, then downloads.
- `make download prompt=https://pypi.org/project/minisbd/0.9.5/` resolves from the URL alone, so it needs no provider credentials.
- Artefacts and their `.extracted/` trees land in `downloads/<ecosystem>/<name>/<version>/`, beside a `download.json`.
- A prompt naming a registry beyond pypi, npm, and cargo stops the run with one line and exit 1.
- Point `make run dir=…` at an extracted tree to analyze what was fetched.

## Running an osint pass

**`make osint` fills the gaps in the attack corpus from public sources.**

- `make osint` audits the corpus and picks its own gaps.
- `make osint focus="npm registry attacks" args="--max-time 20m"` scopes the hunt and bounds it.
- `BRAVE_API_KEY` MUST be set alongside the provider credentials; `.env` carries both, and every `make` target sources it.
- Accepted pages land in `crates/malwi/src/attacks/`, so review the diff and rebuild before committing.
