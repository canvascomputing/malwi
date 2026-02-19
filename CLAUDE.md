# CLAUDE.md - Project Guide for malwi

## Overview

malwi is a function tracing tool for dynamic analysis of executables. It supports:
- **Native functions** via malwi-intercept Interceptor
- **Python functions** via sys.setprofile hooks
- **Node.js functions** via N-API addon wrapping
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

# Clean everything
make clean
```

## Releasing

```bash
# Bump patch version (0.0.24 → 0.0.25), sync all files, and tag
bash scripts/bump-version.sh

# Set explicit version
bash scripts/bump-version.sh 0.1.0
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
1. Set up NODE_OPTIONS with --require
2. Store addon path in static
3. Complete initialization when Node.js is ready

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
Node.js addon is injected via Script::Run hook when Node.js starts executing JavaScript.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `MALWI_URL` | HTTP server URL for agent-CLI communication |
| `MALWI_TEST_BINARIES` | Override path to test binaries (auto-detected from `binaries/` if present) |
| `RUST_LOG=debug` | Enable debug logging |
