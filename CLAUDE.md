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

Policy YAML templates live in `cli/src/policies/` and are embedded at compile time via `include_str!`.

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

# Format all Rust code
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
├── config.rs           # Policy file management (~/.config/malwi/)
├── auto_policy.rs      # Auto-detection of command-specific policies
├── default_policy.rs   # Default observe-mode policy constant
├── policy_bridge.rs    # Policy evaluation bridge (function/network/file/envvar)
├── shell_format.rs     # Shell output formatting
│
└── policies/           # YAML policy templates (embedded via include_str!)
    ├── default.yaml    # Observe-mode policy (warn/log, no blocking)
    ├── npm-install.yaml
    ├── pip-install.yaml
    ├── comfyui.yaml
    ├── openclaw.yaml
    ├── bash-install.yaml
    ├── air-gap.yaml    # Total network isolation
    └── base.yaml       # Shared base sections reference
```

## Agent Module Structure

```
agent/src/
├── lib.rs              # Agent entry point, global state
├── hooks.rs            # Native hook management (malwi-intercept)
├── http_client.rs       # CLI communication
├── native.rs           # Native code utilities (symbol resolution)
├── cpython.rs          # Python tracing via sys.setprofile
├── exec_filter.rs      # Exec command filtering (ex: prefix)
├── glob.rs             # Glob pattern matching
├── stack.rs            # Native stack capture
│
├── tracing/            # SHARED utilities (Python + Node.js)
│   ├── mod.rs
│   ├── thread.rs       # thread_id() - single implementation
│   ├── time.rs         # elapsed_ns(), TRACE_START
│   ├── filter.rs       # Filter struct, pattern matching
│   └── event.rs        # EventBuilder for TraceEvent creation
│
└── nodejs/             # Node.js tracing (addon, bytecode hooks, filters)
    ├── mod.rs          # Public API facade
    ├── bytecode.rs     # V8 bytecode tracing (Runtime_TraceEnter/Exit)
    ├── codegen.rs      # Synchronous eval/function-constructor gate
    ├── filters.rs      # Filter management, initialization
    ├── ffi.rs          # FFI types
    ├── script.rs       # JS execution
    ├── stack.rs        # JavaScript stack trace parsing
    ├── symbols.rs      # V8 symbol names
    └── addon/          # N-API addon management
        ├── mod.rs
        ├── callback.rs # Rust callback from C++ addon
        ├── embed.rs    # Addon binary extraction
        ├── ffi.rs      # Addon FFI functions
        └── loader.rs   # Addon loading strategies
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
