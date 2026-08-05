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

## Running a scan

**`make run` invokes the scanner against a directory.**

- `make run dir=./src` scans `./src` with default settings.
- `make run dir=./src args="--concurrency 4 --max-time 5m"` passes flags through.
- `make run dir=crates/malwi/tests/fixtures/python-malware args="--fail-fast"` scans the synthetic sample.
- Configure an LLM provider first: see [Environment](../README.md#environment) in the README.
- The full CLI reference lives in `malwi --help` and in the README.
