# CLAUDE.md - Project Guide for malwi

## What This Is

malwi is a **security tracing tool** for dynamic analysis. It injects an agent library (via `DYLD_INSERT_LIBRARIES` / `LD_PRELOAD`) into a target process, hooks function calls across four runtimes, and streams trace events back to a CLI over TCP.

**Four runtimes — always consider all four when writing tests, features, or auditing coverage:**

| Runtime | Hook mechanism | CLI flag | HookType | Example `event.function` |
|---------|---------------|----------|----------|--------------------------|
| **Native** | frida-gum Interceptor | `-s` | `Native` | `connect`, `malloc`, `open` |
| **Python** | sys.setprofile + PEP 578 audit hook | `--py` | `Python` | `urllib.request.urlopen`, `open` |
| **Node.js** | V8 bytecode tracer + codegen gate + N-API addon | `--js` | `Nodejs` | `fs.readFileSync`, `eval` |
| **Bash** | eval_builtin / source_builtin / execute_command_internal hooks | `-c` | `Bash` | `eval`, `curl`, `cat` |

Cross-runtime: **exec monitoring** (`--cm`) hooks fork/exec/spawn to trace child commands (`HookType::Exec`), and **envvar monitoring** tracks environment variable access (`HookType::EnvVar`).

## How It Works

```
CLI (cli/)                          Agent (injected into target process)
──────────                          ────────────────────────────────────
1. Starts TCP server                2. Agent loads via DYLD/LD_PRELOAD
3. Sends HookConfig (filters)  ──►  4. Installs hooks per runtime
                                    5. Hooks fire → build TraceEvent
6. Receives TraceEvents        ◄──  5. Send over TCP (binary wire)
7. Policy evaluation + display
```

The agent library is embedded in the CLI binary at compile time (`include_bytes!`). At runtime, the CLI extracts it to a temp file and sets the preload env var before spawning the target.

## Rules

- **Build/test with `make`, never raw `cargo`**: `make build`, `make test`
- **Never add crate dependencies without explicit user approval** (~48 production deps, keep minimal)
- **Update this file** when adding, renaming, moving, or removing files/modules
- **Update CLI help text** (`cli/src/main.rs` const strings) when changing runtime versions, policies, or subcommands
- **When tests fail after your changes, assume your changes caused it.** Do not dismiss failures as pre-existing or flaky. Investigate the failure, read the test, and trace it back to your diff before considering other causes.

## Workspace Crates

| Crate | Path | What it does |
|-------|------|-------------|
| `malwi` | `cli/` | CLI binary: spawns processes, receives events, policy engine, display |
| `malwi-intercept` | `intercept/` | Agent runtime: hooks for all 4 runtimes + exec monitoring. Re-exports malwi-protocol |
| `malwi-protocol` | `protocol/` | Shared types: `TraceEvent`, `HookType`, binary codec, glob matching |
| `malwi-agent` | `agent/` | Thin cdylib: constructor statics + `pub use malwi_intercept::*` |

## Key Directories

```
cli/src/
├── main.rs                 # Entry point, arg parsing, output formatting (text + JSON NDJSON)
├── spawn.rs                # Process spawning with agent injection
├── policy/                 # Policy engine + evaluation
│   ├── engine.rs           # PolicyEngine: compile YAML → match events → allow/deny/warn
│   ├── active.rs           # ActivePolicy: evaluate TraceEvents against compiled rules
│   ├── analysis.rs         # 7-engine command triage (safe/build/text/package/fileop/threat)
│   ├── detect.rs           # Auto-detect policy from command (npm install → npm-install policy)
│   └── templates/          # Policy presets + shared pattern groups
│       ├── mod.rs          # rules! macro, group macros, preset functions, YAML serializer
│       ├── taxonomy.rs     # Command taxonomy: Category enum, flat-file parser, singleton
│       ├── commands_*.yaml # Per-category command lists (shared + OS-specific via #[cfg])
│       └── *.yaml          # Pattern groups (credential_files, networking_symbols, etc.)

intercept/src/
├── agent/                  # Agent lifecycle (init → configure → ready → tracing)
├── native/                 # Native symbol hooks (frida-gum), review-mode hide enforcement
├── python/                 # Python tracing (sys.setprofile, audit hooks, CPython FFI)
├── nodejs/                 # Node.js tracing (V8 bytecode, codegen gate, N-API addon)
│   └── addon/              # Addon loading: --require preload, embed/extract per Node version
├── bash/                   # Bash tracing (eval_builtin, source_builtin, shell_execve hooks)
├── exec/                   # Child process monitoring (posix_spawn/fork/exec hooks)
└── tracing/                # Shared utilities: filters, event builder, timestamps, fork-safe mutex

protocol/src/
├── event.rs                # TraceEvent, EventType, Argument, NetworkInfo, RuntimeStack
├── protocol.rs             # HookType, FilterSpec, HookConfig
└── wire.rs                 # Length-prefixed binary codec
```

Each runtime module (`python/`, `nodejs/`, `bash/`) follows a standard pattern: `mod.rs` (facade), `detect.rs` (is_loaded, version), `hooks.rs` (callbacks), `format.rs` (arg formatting + NetworkInfo), `filters.rs` (filter management).

## Policy System

Policies are YAML files with sections: `network`, `commands`, `files`, `envvars`, `functions`. Each section has `allow`/`deny`/`warn`/`hide` lists with glob patterns. The CLI auto-detects policies per command (e.g., `npm install` → `npm-install` policy) or uses `~/.config/malwi/policies/default.yaml`.

**Hide enforcement** uses the review-mode mechanism: hide specs in the policy generate native hooks (getenv for envvar hide, stat/lstat/access for file hide). The agent sends review requests to the CLI, which evaluates the target against the policy and returns `ReviewDecision::Hide`. The agent then returns fake values (NULL for getenv, -1/ENOENT for stat/access).

**Envvar allow patterns** are encoded in `HookConfig` with a `!` prefix (e.g., `HookConfig { EnvVar, "!HF_HUB_*" }`). The agent strips the prefix and registers allow patterns for agent-side filtering.

**ConfigureResponse** contains only `hooks: Vec<HookConfig>` and `review_mode: bool` — all patterns are encoded in the hooks themselves or handled via review mode.

**Policy presets** are defined in `cli/src/policy/templates/mod.rs` using a `rules!` macro. Pattern groups are flat YAML lists (`credential_files.yaml`, `networking_symbols.yaml`, etc.) parsed via `parse_yaml_list()` into `OnceLock<Vec<String>>` statics, accessed via `macro_rules!` macros (e.g., `credential_files!()`).

**Command taxonomy** (`taxonomy.rs`) classifies commands into categories (Safe, Build, Text, Package, FileOperation, Threat) from per-category YAML files. OS-specific files (`commands_threat_macos.yaml`, `commands_safe_linux.yaml`) are included via `#[cfg(target_os)]`.

## Releasing

```bash
# Bump patch version (0.0.29 → 0.0.30), sync all files, and tag
bash scripts/bump-version.sh

# Set explicit version
bash scripts/bump-version.sh 0.1.0
```

## Building and Testing

```bash
make build                  # Build (includes cargo fmt)
make test                   # Run all tests (~1000+ across unit + integration)
make addon-install && make build  # Full build with Node.js addon
```

Integration tests live in `cli/tests/integration/` with per-runtime files (`python_tests.rs`, `nodejs_tests.rs`, `bash_tests.rs`, `native_tests.rs`). Tests use multi-version macros:

```rust
skip_if_no_python!(python => { /* runs against ALL discovered Python versions */ });
skip_if_no_node!(node => { /* runs against ALL discovered Node.js versions */ });
skip_if_no_bash!(bash => { /* runs against ALL discovered Bash versions */ });
```

For tests that only need **one** binary (policy, cross-runtime, etc.), use `_primary` macros:

```rust
skip_if_no_node_primary!(node => { /* first available Node.js only */ });
skip_if_no_python_primary!(python => { /* first available Python only */ });
skip_if_no_bash_primary!(bash => { /* first available Bash only */ });
```

Test binaries auto-discovered from `binaries/` at project root (or `MALWI_TEST_BINARIES` env var).

### Test Utilities (`common/mod.rs`)

**`cmd()` builder** — run malwi with a terminal-style command string:
```rust
let output = cmd(&format!("x --py urllib.request.urlopen -- {} -c {}", python.display(), sq(script)))
    .timeout(secs(10)).run();
```
- `cmd(command)` — parse command string, returns `Cmd` builder
- `.timeout(dur)` / `.stdin(input)` / `.noninteractive()` / `.env(k, v)` / `.dir(path)` — chain options
- `.run()` — execute, returns `TracerOutput`
- `sq(s)` — shell-quote a string for safe interpolation into `cmd()` format strings
- `secs(n)` — shorthand for `Duration::from_secs(n)`

**`TracerOutput`** — wrapper around `std::process::Output`:
- `output.stdout()` — decoded + ANSI-stripped
- `output.stdout_raw()` — decoded, no stripping (for JSON)
- `output.stderr()` — decoded
- `output.success()` — bool
- `output.json_events()` — parse NDJSON lines into `Vec<serde_json::Value>`
- `output.has_traced(func)` — true if any `[malwi]` line traces `func` (not denied/warning)
- `output.has_denied(func)` — true if any `[malwi] denied:` line contains `func`
- `output.has_warning(func)` — true if any `[malwi] warning:` line contains `func`
- `output.assert_success(context)` / `output.assert_stdout_contains(pattern, context)`

**Free functions** (for raw string checks):
- `has_traced_line(stdout, func)` / `has_denied_line(stdout, func)` / `has_warning_line(stdout, func)`
- `write_temp_policy(yaml)` / `write_temp_policy_with_prefix(prefix, yaml)` — unique temp files
- `parse_json_events(stdout)` — NDJSON parsing

### Preferred Test Style

```rust
#[test]
fn test_python_urllib_shows_url_argument() {
    setup();
    skip_if_no_python_primary!(python => {
        let output = cmd(&format!("x --py urllib.request.urlopen -- {} -c {}",
            python.display(), sq(SCRIPT))).run();
        assert!(output.has_traced("urllib.request.urlopen"), "stdout: {}", output.stdout());
    });
}
```

- Use `cmd(&format!(...)).run()` — command reads like a terminal invocation
- Use `output.has_traced()` / `has_denied()` / `has_warning()` for precise event checks
- Use `skip_if_no_*_primary!` for single-binary tests, `skip_if_no_*!` for multi-version
- Use `output.json_events()` for `-f json` assertions
- Use `write_temp_policy()` from common — never define it per-file

## Naming and Organization

### Runtime Modules (`intercept/src/<runtime>/`)

Each runtime module follows a standard file layout:

| File | Purpose |
|------|---------|
| `mod.rs` | Public facade — re-exports, no logic |
| `detect.rs` | `is_loaded()`, `detected_version()` |
| `hooks.rs` | Hook callback functions |
| `format.rs` | Argument formatting + `NetworkInfo` extraction |
| `filters.rs` | `add_filter`, `check_filter`, `has_filters` |
| `ffi.rs` | FFI type definitions (if needed) |

### YAML Data Files (`cli/src/policy/templates/`)

Two kinds of YAML files, both flat `- item` lists with a two-line header:

```yaml
# Category name.
# What the items in this list represent.
- item1
- item2
```

**Command taxonomy files** — named `commands_<category>.yaml`, with OS variants `commands_<category>_<os>.yaml`:
`commands_safe.yaml`, `commands_safe_macos.yaml`, `commands_safe_linux.yaml`, `commands_threat.yaml`, etc.

**Pattern group files** — descriptive snake_case: `credential_files.yaml`, `networking_symbols.yaml`, `network_functions_python.yaml`, `sensitive_envvars.yaml`, etc. Each gets a `macro_rules!` accessor (e.g., `credential_files!()`) backed by a `static OnceLock<Vec<String>>`.

### Test Files and Naming

Integration tests: `cli/tests/integration/<runtime>_tests.rs` — one file per runtime.

Test function pattern: `test_<runtime>_<scenario>_<expected_outcome>`
- Name after **behavior**, not internals
- Policy tests include policy name: `test_air_gap_blocks_curl`
- Use JSON output (`-f json`) + `output.json_events()` for structured assertions in new tests

### TraceEvent Function Names

No runtime prefix — runtime is identified by `HookType`:

| Runtime | Format | Example |
|---------|--------|---------|
| Python | `module.qualname` | `urllib.request.urlopen` |
| Node.js | `module.function` | `fs.readFileSync` |
| Native | bare C symbol | `connect`, `malloc` |
| Bash/Exec | command basename | `curl`, `eval` |
| EnvVar | variable name | `PATH`, `SECRET_KEY` |

### Other Conventions

- **FFI**: All C/Rust structs use `#[repr(C)]` with exact field order matching
- **Node.js injection**: Parent prepares `--require` wrapper before spawn. `NODE_OPTIONS` is set for child-process propagation but is not the primary injection path
- **CLI modules**: Descriptive snake_case (`agent_server.rs`, `embedded_agent.rs`, `shell_format.rs`)
- **Policy modules**: Grouped by concern — engine (`engine.rs`, `compiler.rs`, `compiled.rs`), evaluation (`active.rs`, `network.rs`, `files.rs`, `commands.rs`), templates (`templates/mod.rs`, `taxonomy.rs`)

## Key Type

```rust
// protocol/src/event.rs — the central data structure
TraceEvent {
    hook_type: HookType,            // Native, Python, Nodejs, Exec, EnvVar, Bash
    event_type: EventType,          // Enter or Leave
    function: String,               // "fs.readFileSync", "urllib.request.urlopen", "curl"
    arguments: Vec<Argument>,       // display string + raw_value per arg
    network_info: Option<NetworkInfo>,    // Structured host/port/url/protocol
    runtime_stack: Option<RuntimeStack>,  // Python/JS stack frames
    native_stack: Vec<usize>,       // Raw addresses (resolved CLI-side)
    source_file: Option<String>,    // Caller source file
    source_line: Option<u32>,       // Caller source line
}
```

## Review Mode Decisions

```rust
// protocol/src/protocol.rs
enum ReviewDecision {
    Allow,    // Proceed normally
    Block,    // Denied — return -1/EACCES
    Warn,     // Allowed but flagged
    Suppress, // Auto-allowed, nothing to show
    Hide,     // Make target non-existent (NULL/ENOENT)
}
```

## AgentServer

`AgentServer::new()` takes three parameters:
- `agent_config: ConfigureResponse` — hooks + review_mode, cloned to each agent on configure
- `event_tx` — channel for agent events to main loop
- `tracking: AgentTracking` — shared `active_count` + `reconnected_pids`

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `MALWI_URL` | TCP server URL for agent↔CLI communication |
| `MALWI_TEST_BINARIES` | Path to multi-version test binaries |
| `RUST_LOG=debug` | Enable debug logging |
