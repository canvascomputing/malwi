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
│                           CLI (cli/)                            │
│  - Spawns processes with tracing                                │
│  - Receives trace events via HTTP                                │
│  - Handles review mode prompts                                  │
└─────────────────────────────────────────────────────────────────┘
                              │ HTTP (localhost)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Agent (agent/)                           │
│  - Injected via DYLD_INSERT_LIBRARIES / LD_PRELOAD              │
│  - Manages hooks for native/Python/Node.js                      │
│  - Sends TraceEvents to CLI                                     │
└─────────────────────────────────────────────────────────────────┘
```

## Workspace Crates

| Crate | Path | Purpose |
|-------|------|---------|
| `malwi` | cli/ | CLI binary (includes process spawning) |
| `malwi-agent` | agent/ | Injected agent library (cdylib) |
| `malwi-protocol` | protocol/ | Wire protocol types (TraceEvent, messages) |
| `malwi-intercept` | intercept/ | Native function interception (code patching, module enumeration) |
| `malwi-policy` | policy/ | Policy engine (YAML parsing, compilation, evaluation) |

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
└── policy/             # Policy subsystem
    ├── mod.rs          # Module root + re-exports
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

## Agent Module Structure

```
agent/src/
├── lib.rs              # Agent entry point, global state
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
// protocol/src/event.rs
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
