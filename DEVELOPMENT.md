# Development

## Workspace

- `crates/malwi/`: the binary. The Cargo workspace at the repo root is the only build entry point.

## Building and testing

```bash
make                # build (warnings are errors)
make test           # offline unit tests, then the model-backed integration suite
make test-unit      # deterministic offline tests only
make test-integration # sequential model-backed integration tests only
make fmt            # format code
make doc            # cargo doc --no-deps -p malwi (strict rustdoc)
make clean          # remove build artifacts
make update         # update dependencies
make hooks          # install Claude Code hooks
```

## Running

> Configure an LLM provider first (see [Environment](#environment)). `.env` at the repo root is sourced by every target below.

```bash
make run dir=./src                                            # analyze a directory
make run dir=./pkg/index.js                                   # analyze one file
make run dir=./src args="--concurrency 4 --max-time 5m"       # pass flags through
make osint                                                    # audit the attack corpus and fill its gaps
make osint focus="npm registry attacks" args="--max-time 20m" # scope the hunt
make download prompt="py stanza 1.14.0"                       # fetch a package's artefacts
```

The default test command includes six integration scans covering positive and benign cases for
obfuscation, side-loading, and telemetry. It requires the provider and model variables below, uses
network access and model quota, and may cost money. Integration fixtures are scanned as source
text and must never be executed.

A manual scan against the original synthetic sample remains available:

```bash
make run dir=crates/malwi/tests/fixtures/python-malware args="--fail-malicious --concurrency 1"
```

`--fail-malicious` exits `2` on the first confirmed malicious finding. `--fail-exploitable` does
the same for any exploitable or malicious finding. `make run` treats that signal as success.
The report lands in `.malwi/analysis.json`.

`malwi osint` writes accepted pages into `crates/malwi/src/attacks/`, so review the diff and rebuild before committing.

## Publishing

```bash
make bump                  # run tests, bump patch version, commit, tag
make bump part=minor       # bump minor version
make bump part=major       # bump major version
```

Push the new tag with `git push --tags`.

## Environment

| Variable | Description |
|----------|-------------|
| `LITELLM_PROVIDER` | Choose `anthropic`, `mistral`, `openai`, or `litellm` outright, ahead of the keys below. |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `MISTRAL_API_KEY`, `LITELLM_API_KEY` | Authenticate against that vendor. The first one set picks the provider. |
| `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, `MISTRAL_BASE_URL`, `LITELLM_BASE_URL` | Point that vendor at a different endpoint. |
| `MODEL` | Model every agent runs. Falls back to `ANTHROPIC_MODEL`, `OPENAI_MODEL`, `MISTRAL_MODEL`, or `LITELLM_MODEL` for the detected provider. |
| `MODEL_CONTEXT_WINDOW` | Context window size in tokens, over the registry's value for the name. |
| `BRAVE_API_KEY` | Required by `malwi osint`. Web search runs through the Brave Search API. |
| `SSL_CERT_FILE`, `SSL_CERT_DIR` | Trust these CA certificates instead of the built-in root store. |

`--models` overrides the model per agent, per pool, or per label; see `malwi analyze --help`.
