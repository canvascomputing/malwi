# Development Guide

## Prerequisites

### Required Tools
- **Rust** (stable, 1.70+) - `rustup install stable`
- **Node.js** (v18+) - for building the V8 introspection addon
- **Python** (3.9+) - for running Python tracing tests
- **Make** - build orchestration

### macOS-Specific
- **Xcode Command Line Tools** - `xcode-select --install`
- For Node 25+ addon: **LLVM 17+** (Apple clang lacks required C++20 support)

### Linux-Specific
- **GCC 10+** or **Clang 14+** with C++20 support
- **libelf-dev** / **elfutils-libelf-devel** (for symbol resolution)

## Build Process

### Quick Start
```bash
make addon-install  # Build Node.js addon for current Node version
make build          # Build CLI and agent
make test           # Run tests
```

### Full Multi-Version Build
```bash
# Set path to test binaries (Node/Python versions)
export MALWI_TEST_BINARIES=/path/to/binaries

# Build addons for all Node versions
make addon-all

# Build and test
make build
make test
```

### Build Components

| Component | Command | Output |
|-----------|---------|--------|
| CLI | `cargo build --release` | `target/release/malwi` |
| Agent | `cargo build --release -p malwi-agent` | `target/release/libmalwi_agent.{dylib,so}` |
| Node Addon | `make addon` | `node-addon/build/Release/v8_introspect.node` |
| Test Fixtures | `make fixtures` | `tests/*.exe` |

## Node.js Addon Build

The V8 introspection addon must be built for each Node.js major version due to V8 ABI changes.

### Standard Build (Node 18-24)
```bash
cd node-addon
npm install
npx node-gyp rebuild --target=22.0.0
```

### Node 25+ Build (Requires LLVM 17+)
Node 25+ uses V8 headers with C++20 designated initializers in template arguments, which Apple clang doesn't support. Building requires LLVM 17+ (any version with full C++20 support).

**Using the Makefile (recommended):**
```bash
# Build Node 25 addon
LLVM_PATH=/path/to/llvm NODE_TARGET=25.4.0 make addon-node25

# Build all versions including Node 25+
LLVM_PATH=/path/to/llvm MALWI_TEST_BINARIES=/path/to/binaries make addon-all
```

**How it works:**

The Makefile uses a wrapper approach: LLVM's clang++ compiles (for C++20 support), but Apple's clang++ links (to avoid libLTO ABI issues). Static libc++ from LLVM is linked to provide the C++ runtime.

**Manual build (if needed):**
```bash
# 1. Create wrapper script
cat > /tmp/cxx_wrapper.sh << 'EOF'
#!/bin/bash
LLVM_CXX="/path/to/llvm/bin/clang++"
APPLE_CXX="/usr/bin/clang++"
is_link=false; has_c=false; has_o_file=false
for arg in "$@"; do
  case "$arg" in -bundle|-shared|-dynamiclib) is_link=true;; -c) has_c=true;; *.o) has_o_file=true;; esac
done
[ "$has_o_file" = true ] && [ "$has_c" = false ] && is_link=true
if [ "$is_link" = true ]; then
  exec "$APPLE_CXX" "$@" /path/to/llvm/lib/libc++.a /path/to/llvm/lib/libc++abi.a
else
  exec "$LLVM_CXX" "$@"
fi
EOF
chmod +x /tmp/cxx_wrapper.sh

# 2. Build with wrapper
cd node-addon
CC=/path/to/llvm/bin/clang \
CXX=/tmp/cxx_wrapper.sh \
CXXFLAGS="-std=c++20 -nostdlibinc \
  -isystem /path/to/llvm/include/c++/v1 \
  -isystem $(/path/to/llvm/bin/clang -print-resource-dir)/include \
  -isystem $(xcrun --show-sdk-path)/usr/include" \
LDFLAGS="-nostdlib++" \
npx node-gyp rebuild --target=25.4.0
```

**Known Issues:**
- Using LLVM's clang++ for both compile AND link causes libLTO.dylib to load LLVM's libc++ at runtime, which conflicts with Apple's ld ("Abort trap: 6" / `___cxa_demangle` not found). The wrapper approach avoids this.
- Header order matters: libc++ headers must come before clang built-in headers, which must come before system C headers.

## Testing

### Single Version (PATH)
```bash
cargo test --release
```

### Multi-Version
```bash
MALWI_TEST_BINARIES=/path/to/binaries cargo test --release
```

### Expected Directory Structure for MALWI_TEST_BINARIES
```
binaries/
├── arm64/
│   └── mac/
│       ├── node/
│       │   ├── node-v20.11.0
│       │   ├── node-v22.11.0
│       │   ├── node-v23.11.1
│       │   ├── node-v24.13.0
│       │   └── node-v25.4.0
│       └── python/
│           ├── python3.9/bin/python3.9
│           ├── python3.10/bin/python3.10
│           ├── python3.11/bin/python3.11
│           ├── python3.12/bin/python3.12
│           └── python3.13/bin/python3.13
└── x64/
    └── linux/...
```

## Architecture Overview

```
CLI (malwi)          ─────HTTP───►  Agent (libmalwi_agent)
  ├─ Spawns process                    ├─ Injected via DYLD/LD_PRELOAD
  ├─ Receives TraceEvents              ├─ Hooks native functions (malwi-intercept)
  └─ Handles review mode               ├─ Hooks Python (sys.setprofile)
                                       └─ Hooks Node.js (V8 bytecode + addon)
```

## Performance Testing

### Micro-benchmarks (Criterion)

Four benchmark suites measure the hot paths in the tracing pipeline:

| Suite | Crate | Command | What it measures |
|-------|-------|---------|-----------------|
| `serialization` | common | `cargo bench --bench serialization` | Glob matching, JSON serialize/deserialize, batch encoding |
| `symbol_resolver` | cli | `cargo bench --bench symbol_resolver` | Module lookup (10/50/200 modules), stack frame resolution |
| `filter` | agent | `cargo bench --bench filter` | Filter checking (1-20 patterns), FilterManager lock overhead, concurrent access |
| `throughput` | cli | `cargo bench --bench throughput` | Single event roundtrip, burst 100 events, batch 64 events via `/events` endpoint |

```bash
# Run all benchmarks
cargo bench

# Run a specific suite
cargo bench --bench serialization

# Run a specific benchmark by name
cargo bench --bench filter -- check_filter_miss
```

Criterion saves HTML reports to `target/criterion/`. Open `target/criterion/report/index.html` to view results with charts and statistical analysis.

### End-to-end performance test

A regular integration test measures wall-clock tracing overhead against the `multithread` fixture:

```bash
cargo test --release --test integration perf_ -- --nocapture
```

This prints:
- Baseline (uninstrumented) runtime
- Traced runtime
- Overhead percentage
- Events captured and events/sec throughput

### Comparing before/after

To measure the impact of an optimization:

```bash
# 1. Baseline on current main
git stash  # if you have changes
cargo bench --save-baseline before

# 2. Apply changes
git stash pop
cargo bench --save-baseline after

# 3. Compare
cargo bench -- --baseline before
```

## Debugging

```bash
# Enable agent debug logging
RUST_LOG=debug ./target/release/malwi x --js '*' -- node -e "console.log(1)"

# Trace agent initialization
RUST_LOG=malwi_agent=trace ./target/release/malwi x ...
```
