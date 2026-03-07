# CLAUDE.md - Project Guide for malwi

## Overview

malwi is a function tracing tool for dynamic analysis of executables. It supports:
- **Native functions** via malwi-intercept Interceptor
- **Python functions** via sys.setprofile hooks
- **Node.js functions** via hybrid tracing (V8 bytecode + codegen gate + N-API addon wrapping)
- **Executed commands** via fork/exec/spawn monitoring

The tool injects an agent library into target processes to intercept function calls and report them back to a CLI over HTTP.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       CLI — malwi (cli/)                        │
│  - Spawns processes with tracing                                │
│  - Receives trace events via HTTP                               │
│  - Policy engine + evaluation                                   │
│  - Depends on malwi-intercept (default-features = false)        │
└─────────────────────────────────────────────────────────────────┘
                              │ HTTP (localhost)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│             Agent cdylib — malwi-agent (agent/)                 │
│  - Thin wrapper: constructor statics + pub use malwi_intercept  │
│  - Injected via DYLD_INSERT_LIBRARIES / LD_PRELOAD              │
└─────────────────────────────────────────────────────────────────┘
                              │ links
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              Library — malwi-intercept (intercept/)             │
│  - Native interception engine (frida-gum)                       │
│  - Agent runtime (python/nodejs/bash/exec hooks)                │
│  - Re-exports malwi-protocol types                              │
│  - Sends TraceEvents to CLI via HTTP                            │
└─────────────────────────────────────────────────────────────────┘
                              │ depends on
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              Library — malwi-protocol (protocol/)               │
│  - Wire protocol types (TraceEvent, messages, codec)            │
│  - Glob pattern matching, platform utilities                    │
└─────────────────────────────────────────────────────────────────┘
```

## Workspace Crates

| Crate | Path | Purpose | Published |
|-------|------|---------|-----------|
| `malwi` | cli/ | CLI binary + policy engine | Yes |
| `malwi-intercept` | intercept/ | Interception, agent runtime (re-exports malwi-protocol) | Yes |
| `malwi-protocol` | protocol/ | Wire protocol types, codec, glob matching, platform utils | No |
| `malwi-agent` | agent/ | Thin cdylib wrapper (constructor statics + re-exports) | No |

`malwi-protocol` contains shared wire types (TraceEvent, AgentMessage, CliMessage, binary codec) and utilities (glob matching, platform detection). `malwi-intercept` depends on it and re-exports all its types, so existing `malwi_intercept::TraceEvent` imports continue to work. The `malwi-agent` crate is just a cdylib entry point that re-exports `malwi_intercept::*` and defines `__mod_init_func`/`.init_array` constructors.

Policy YAML templates live in `cli/src/policy/presets/` and are embedded at compile time via `include_str!`.

## Platform Support

| Platform | CLI | Agent | Node.js Tracing | Python Tracing |
|----------|-----|-------|-----------------|----------------|
| macOS arm64 | ✅ | ✅ | ✅ | ✅ |
| macOS x86_64 | ✅ | ✅ | ⚠️ (needs addon build) | ✅ |
| Linux x86_64 | ✅ | ✅ | ⚠️ (needs addon build) | ✅ |
| Linux arm64 | ✅ | ✅ | ⚠️ (needs addon build) | ✅ |
| Windows | ✅ | ⚠️ (no injection) | ❌ | ❌ |

## Building

**Always use `make` for building and testing, never raw `cargo` commands.**

```bash
# Full build (recommended - includes Node.js addon)
make addon-install && make build

# Build just Rust components (no Node.js tracing on most platforms)
make build

# Build Node.js addon only
make addon

# Install addon to prebuilt directory
make addon-install

# Format all Rust code (also runs automatically as part of `make build`)
make format

# Clean everything
make clean
```

## Releasing

```bash
# Bump patch version (0.0.24 → 0.0.25), sync all files, and tag
make bump

# Set explicit version
VERSION=0.1.0 make bump
```

## Testing

```bash
# Run all tests (recommended)
make test

# Multi-version testing (tests against all Node.js/Python versions in the binaries path)
MALWI_TEST_BINARIES=/path/to/binaries make test

# Manual test: Native symbol tracing
./malwi x -s malloc -- ./tests/simple_target

# Manual test: Node.js fs tracing
./malwi x --js 'fs.*' -- node -e "require('fs').readFileSync('/etc/passwd')"

# Manual test: Python open tracing
./malwi x --py open -- python3 -c "open('/etc/passwd').read()"

# Manual test: Exec command tracing
./malwi x --cm '*' -- python3 -c "import subprocess; subprocess.run(['curl', '--version'])"

# Trace only specific commands
./malwi x --cm curl -- node -e "require('child_process').spawnSync('curl', ['--version'])"
```

### Multi-Version Test Binaries

When `binaries/` exists at the project root, tests automatically use it. `MALWI_TEST_BINARIES` env var still works as an override.

Expected directory structure:
```
binaries/
├── arm64/mac/node/node-v23.11.1          # Direct executables
├── arm64/mac/python/python3.12/bin/python3
├── arm64/mac/bash/bash-5.2               # Direct executables
├── x64/linux/node/node-v.../bin/node     # Or direct executables
└── x64/linux/python/python3.../bin/python3
```

## CLI Module Structure

```
cli/src/
├── main.rs             # CLI entry point, arg parsing
├── lib.rs              # Library root
├── spawn.rs            # Process spawning orchestration
├── native_spawn.rs     # posix_spawn/fork+exec implementation
├── agent_server.rs     # HTTP server receiving agent events
├── monitor.rs          # Trace event processing and display
├── symbol_resolver.rs  # CLI-side symbol resolution (object crate)
├── shell_format.rs     # Shell output formatting
│
└── policy/             # Policy subsystem (includes absorbed policy engine)
    ├── mod.rs          # Module root + re-exports
    │
    │  # Policy engine (absorbed from former malwi-policy crate)
    ├── engine.rs       # PolicyEngine, HookSpecKind, PolicyDecision
    ├── compiler.rs     # Policy compilation (YAML → CompiledPolicy)
    ├── compiled.rs     # CompiledPolicy, CompiledRule, SectionKey, EnforcementMode
    ├── parser.rs       # YAML policy parsing
    ├── pattern.rs      # Glob pattern compilation
    ├── validate.rs     # Policy validation
    ├── yaml.rs         # Lightweight YAML parser
    ├── error.rs        # Policy error types
    │
    │  # Policy evaluation (CLI-specific)
    ├── active.rs       # ActivePolicy struct, evaluate_trace dispatch, hook derivation
    ├── network.rs      # Network policy evaluation (URL, domain, endpoint, protocol)
    ├── files.rs        # File access policy evaluation
    ├── commands.rs     # Command analysis integration
    ├── analysis.rs     # 7-engine command triage
    ├── taxonomy.rs     # Command taxonomy singleton
    ├── detect.rs       # Auto-detection of command-specific policies
    ├── templates.rs    # Embedded YAML strings, DEFAULT_SECURITY_YAML
    ├── config.rs       # Policy file management (~/.config/malwi/)
    │
    └── presets/        # YAML policy templates (embedded via include_str!)
        ├── default.yaml    # Observe-mode policy (warn/log, no blocking)
        ├── npm-install.yaml
        ├── pip-install.yaml
        ├── comfyui.yaml
        ├── openclaw.yaml
        ├── bash-install.yaml
        ├── air-gap.yaml    # Total network isolation
        ├── base.yaml       # Shared base sections reference
        └── taxonomy.yaml   # Command taxonomy data
```

## Protocol Module Structure

Wire protocol types live in `protocol/src/` (the `malwi-protocol` crate). `malwi-intercept` re-exports all types from this crate, so existing `malwi_intercept::TraceEvent` imports continue to work.

```
protocol/src/
├── lib.rs              # Crate root, module declarations, re-exports
├── event.rs            # TraceEvent, EventType, Argument, NativeFrame
├── exec.rs             # Command unwrapping utilities
├── glob.rs             # Glob pattern matching
├── message.rs          # AgentMessage, CliMessage
├── platform.rs         # Platform detection, agent_lib_name()
├── protocol.rs         # HookType, FilterSpec
└── wire.rs             # Length-prefixed wire encoding
```

## Intercept Module Structure

All agent runtime code lives in `intercept/src/` alongside the interception engine.

```
intercept/src/
├── lib.rs              # Crate root, module declarations, re-exports from malwi-protocol
│
├── interceptor/        # Native function interception engine
│   ├── mod.rs          # Interceptor struct
│   ├── listener.rs     # CallListener trait
│   └── invocation.rs   # InvocationContext
├── module.rs           # Module enumeration
├── backtrace.rs        # Native backtrace capture
├── types.rs            # Shared types (InvocationContext)
├── gum.rs              # Frida-gum FFI wrapper
├── ffi.rs              # FFI bindings
│
├── agent.rs            # Agent struct, malwi_agent_init(), global state
├── http_client.rs      # CLI communication
│
├── native/             # Infrastructure (HookManager, find_export, capture_backtrace)
│
├── tracing/            # SHARED utilities (all runtimes)
│   ├── mod.rs
│   ├── thread.rs       # thread_id() - single implementation
│   ├── time.rs         # elapsed_ns(), TRACE_START
│   ├── filter.rs       # FilterManager struct, pattern matching
│   └── event.rs        # EventBuilder for TraceEvent creation
│
├── python/             # Python tracing (sys.setprofile, audit hooks)
│   ├── mod.rs          # Public API facade + re-exports
│   ├── detect.rs       # is_loaded(), detected_version()
│   ├── filters.rs      # FilterManager wrapper
│   ├── profile.rs      # Profile hook registration and callback
│   ├── audit.rs        # Audit hook (PEP 578)
│   ├── ffi.rs          # CPython FFI types
│   ├── format.rs       # Argument formatting
│   ├── stack.rs        # Python stack capture
│   └── version.rs      # Version struct, parsing, Py_GetVersion()
│
├── nodejs/             # Node.js tracing (addon, bytecode hooks, filters)
│   ├── mod.rs          # Public API facade + re-exports
│   ├── detect.rs       # is_loaded(), detected_version()
│   ├── bytecode.rs     # V8 bytecode tracing (Runtime_TraceEnter/Exit)
│   ├── codegen.rs      # Synchronous eval/function-constructor gate
│   ├── filters.rs      # Filter management, initialization
│   ├── ffi.rs          # FFI types
│   ├── script.rs       # JS execution
│   ├── stack.rs        # JavaScript stack trace parsing
│   ├── symbols.rs      # V8 symbol names
│   └── addon/          # N-API addon management
│
├── bash/               # Bash tracing (shell hooks, builtins)
│   ├── mod.rs          # Public API facade + re-exports
│   ├── detect.rs       # is_loaded(), detected_version(), setup_bash_hooks()
│   ├── hooks.rs        # Hook callbacks (shell_execve, execute_command_internal, etc.)
│   └── structs.rs      # Bash internal struct layouts
│
├── exec/               # Child process monitoring (spawn/fork/exec)
│   ├── mod.rs
│   ├── spawn.rs        # posix_spawn/exec hooks, SpawnMonitor
│   ├── fork.rs         # fork() hooks, ForkMonitor
│   ├── filter.rs       # Exec command filter (ex: prefix)
│   └── envvar.rs       # Environment variable deny patterns
│
└── syscall/            # Direct syscall detection (scan+patch)
```

The `agent/` crate is a thin cdylib wrapper:

```
agent/src/
└── lib.rs              # Constructor statics + `pub use malwi_intercept::*;`
```

### Runtime Module Convention

Each language runtime module (`python/`, `nodejs/`, `bash/`, future runtimes) follows a standard convention for file naming and public API. The `native/` module is **infrastructure** consumed by all runtimes and does not follow this convention.

**Standard files:**

| File | Purpose | Required? |
|------|---------|-----------|
| `mod.rs` | Public API facade — re-exports, no logic | Required |
| `detect.rs` | `is_loaded()`, `detected_version()` | Required |
| `hooks.rs` | Hook callback functions | Required |
| `filters.rs` | FilterManager wrapper: `add_filter`, `check_filter`, `has_filters` | If applicable |
| `ffi.rs` | FFI type definitions | If applicable |

**Standard public API (re-exported from `mod.rs`):**

```rust
// Required for all language runtimes
pub fn is_loaded() -> bool;
pub fn detected_version() -> Option<...>;  // Version type varies per runtime

// Filter management (if the runtime has its own filter set)
pub fn add_filter(pattern: &str, capture_stack: bool);
pub fn check_filter(name: &str) -> (bool, bool);
pub fn has_filters() -> bool;

// EnvVar monitoring (if supported)
pub fn enable_envvar_monitoring();
pub fn is_envvar_monitoring_enabled() -> bool;
```

## Key Types

```rust
// intercept/src/protocol/event.rs
TraceEvent {
    timestamp_ns: u64,
    thread_id: u64,
    event_type: EventType,  // Enter or Leave
    function: String,       // e.g., "js:fs.readFileSync" or "py:open"
    module: String,
    arguments: Vec<Argument>,
    native_stack: Vec<NativeFrame>,
    runtime_stack: Option<RuntimeStack>,
}
```

## Dependency Policy

**Never add new crate dependencies without explicit user approval.** This project prioritizes a minimal dependency footprint to reduce supply-chain attack surface. Before proposing a new dependency:
1. Explain why the functionality can't be achieved with `std` or existing deps
2. State the crate name, its transitive dependency count, and maintenance status
3. Wait for approval before modifying any `Cargo.toml`

Current production deps (excluding internal crates): ~48 crates. Keep it minimal.

## Conventions

### Function Name Prefixes
- `js:` - JavaScript/Node.js functions (e.g., `js:fs.readFileSync`)
- `py:` - Python functions (e.g., `py:open`)
- `ex:` - Executed commands/child processes (e.g., `ex:curl`, `ex:*`)
- No prefix - Native functions

### Filter Patterns
Glob patterns are used for function matching:
- `fs.*` - All functions in fs module
- `*.readFile` - readFile in any module
- `http.request` - Exact match

### CLI Help Text (cli/src/main.rs)
The `--help` output for `malwi`, `malwi x`, `malwi m`, and `malwi p` is defined via `const` strings (`BANNER`, `HELP_OVERVIEW`, `X_AFTER_HELP`, `M_AFTER_HELP`, `P_AFTER_HELP`) and clap attributes in `cli/src/main.rs`. These texts include compatibility versions, policy names, usage examples, and policy section references. **When any of the following change, update the CLI help text to match:**
- Supported runtime versions (Python, Node.js, Bash)
- Supported platforms (macOS, Linux architectures)
- Available policy presets (added/removed/renamed in `cli/src/policy/presets/`)
- Policy section names or semantics
- Auto-detection rules in `cli/src/policy/detect.rs`
- Subcommand or argument additions/removals

### FFI Alignment
C/Rust FFI structs must use `#[repr(C)]` and match field order exactly.

### Deferred Initialization
Node.js addon may not be ready at agent load time. Use deferred init pattern:
1. Build wrapper and set preload options in parent process before spawn
2. Inject wrapper via Node argv (`--require=...`) for direct Node launches
3. Also set `NODE_OPTIONS` for compatibility and child-process propagation
4. Complete addon-specific FFI init when Node.js runtime is ready

### Node Injection Timing (Important)
- **Deterministic path:** parent prepares wrapper + injects `--require` before spawning Node
- `NODE_OPTIONS` is still set, but should be treated as compatibility/propagation, not sole timing guarantee
- In-process fallback that sets `NODE_OPTIONS` is too late for the current process (only affects descendants)
- SIP/restricted binaries on macOS can strip preload env vars; resolve shebangs and avoid restricted launchers

### Test Naming
All test functions use snake_case and follow this structure:

```
test_<subject>_<scenario>_<expected_outcome>
```

- **Subject**: What's being tested — the module, function, or feature (e.g., `python_tracing`, `format_read`, `policy_block`)
- **Scenario**: The specific input or condition (e.g., `glob_pattern`, `null_addr`, `with_t_flag`)
- **Expected outcome**: What should happen (e.g., `is_benign`, `returns_network_info`, `blocked`, `allowed`)

Guidelines:
- Name tests after **behavior**, not implementation details (no internal engine numbers, stage names, etc.)
- Include the expected outcome when the test verifies a specific result (e.g., `_is_suspicious`, `_returns_none`, `_blocked`)
- For pure formatting tests, describe what's displayed: `test_format_read_displays_fd_buf_count`
- For NetworkInfo extraction tests, use `_returns_network_info` suffix
- Integration tests include the runtime prefix: `test_python_*`, `test_nodejs_*`, `test_bash_*`, `test_native_*`
- Policy tests include the policy name: `test_pip_install_*`, `test_air_gap_*`, `test_default_security_*`

## Node Addon (node-addon/)

C++ N-API addon that wraps JavaScript functions:
- `binding.cc` - Main addon code
- `prebuilt/` - Pre-compiled .node files per Node version

Build with: `cd node-addon && npm run build`

## Common Issues

### "Invalid UTF-8" from Node.js tracing
Usually means FFI was called before addon was initialized. Check deferred init logic.

### Vector reallocation in C++
When building argument arrays, use `reserve()` before `push_back()` to prevent c_str() pointer invalidation.

### Addon not loading
Primary path is wrapper preload (`--require`) prepared before spawn.
`Script::Run` direct loading exists only as a legacy fallback (`MALWI_DIRECT_LOAD=1`).

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `MALWI_URL` | HTTP server URL for agent-CLI communication |
| `MALWI_TEST_BINARIES` | Override path to test binaries (auto-detected from `binaries/` if present) |
| `RUST_LOG=debug` | Enable debug logging |
