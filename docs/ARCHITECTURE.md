# Architecture

## Overview

```
malwi x -- python3 app.py

┌─────────────────────────────────┐         ┌─────────────────────────────────┐
│            CLI                  │  HTTP   │         Agent (injected)        │
│                                 │◄────────│                                 │
│  HTTP server (tiny_http)        │         │  Constructor fires before       │
│    ↓ events via sync_channel    │         │  main() runs                    │
│  Main event loop                │         │                                 │
│    - policy evaluation          │         │  Hook callbacks                 │
│    - symbol resolution          │         │    ↓ events via sync_channel    │
│    - output formatting          │         │  Flush thread → POST /events    │
└─────────────────────────────────┘         └─────────────────────────────────┘
```

The CLI spawns the target process with the agent library preloaded (`DYLD_INSERT_LIBRARIES` on macOS, `LD_PRELOAD` on Linux). The agent intercepts function calls and sends trace events to the CLI over HTTP on localhost. The CLI evaluates each event against the security policy and outputs results.

## Startup sequence

```
CLI                                          Agent
 │                                            │
 ├─ Start HTTP server on random port          │
 ├─ Spawn process with agent preloaded ──────►│
 │                                            ├─ Constructor fires (before main)
 │                                            ├─ Init malwi-intercept
 │                                            ├─ Detect runtimes (Python/Node.js/Bash)
 │  ◄── POST /configure ──────────────────────├─ Request hook configuration
 ├─ Send hook configs ───────────────────────►│
 │                                            ├─ Install all hooks
 │                                            ├─ Enumerate loaded modules
 │  ◄── POST /ready ──────────────────────────├─ Report installed hooks + module map
 ├─ Store module map for symbol resolution    │
 │                                            ├─ main() runs
 │  ◄── POST /events ─────────────────────────├─ Hook callbacks fire, events stream
 │      ...                                   │      ...
 │                                            ├─ atexit: drain flush thread
 │  ◄── POST /shutdown ───────────────────────├─ Signal exit
 ├─ Process remaining events                  │
 ├─ Exit                                      │
```

The agent blocks on `/configure` before `main()` starts. This guarantees all hooks are installed before any user code runs.

## HTTP protocol

All communication is JSON over HTTP/1.1 on localhost. The agent uses `ureq` with connection pooling. The CLI uses `tiny_http`.

### Agent → CLI

| Endpoint | Purpose | Payload |
|----------|---------|---------|
| `POST /configure` | Request hook configs | `{ pid, nodejs_version }` |
| `POST /ready` | Report hooks installed | `{ pid, hooks_installed, modules }` |
| `POST /events` | Send trace events (batched) | `Vec<TraceEvent>` |
| `POST /child` | Report child process spawn | `{ parent_pid, child_pid, path, argv }` |
| `POST /review` | Block for user decision | `{ event: TraceEvent }` → `{ decision }` |
| `POST /shutdown` | Signal process exit | `{ pid }` |
| `GET /command` | Poll for shutdown signal | → `{ command: "shutdown" | null }` |

### Event format

```
TraceEvent {
    hook_type:     Native | Python | Nodejs | Exec
    event_type:    Enter | Leave
    function:      "py:requests.get" | "js:fs.readFileSync" | "curl" | "malloc"
    module:        source module or binary path
    arguments:     [{ index, raw_value, display, type_hint }]
    timestamp_ns:  monotonic nanoseconds since trace start
    thread_id:     OS thread ID
    native_stack:  [{ address, module, offset }]   — resolved CLI-side
    network_info:  { url, host, port, protocol }   — optional, for HTTP calls
}
```

### Batching

The agent groups events in a channel and flushes every 50ms or 64 events, whichever comes first. This reduces HTTP overhead from dozens of individual POSTs to 1-3 batched requests per flush window.

## Hook mechanisms

### Native (malwi-intercept Interceptor)

Attaches enter/exit listeners to exported symbols. A thread-local reentrancy guard prevents infinite recursion when hooked functions (e.g. `malloc`) are called from within the hook callback itself.

### Python (sys.setprofile)

Registers a C-level profile callback via the CPython API. The callback fires on every function enter/exit. Filter patterns select which functions to trace. Dedicated argument formatters extract structured data (URL, method, host) from HTTP library calls.

### Node.js (V8 bytecode + N-API addon)

Two mechanisms work together:

1. **N-API addon** — extracted from the agent binary, loaded via `NODE_OPTIONS=--require` before user code. Installs a require hook that wraps matching JavaScript functions at module load time. Calls back to the Rust agent via FFI.

2. **V8 bytecode hooks** — intercepts `Runtime_TraceEnter/Exit` for early code that runs before the addon loads (e.g. `--eval`).

### Bash (shell internals)

Hooks into Bash's internal functions via malwi-intercept:

- `shell_execve` — external commands
- `execute_command_internal` — all commands including builtins
- `eval_builtin`, `source_builtin` — eval and source

Uses `find_shell_builtin` to distinguish builtins from external commands and avoid double-tracing.

### Exec monitoring (fork/exec/spawn)

Hooks `fork`, `execve`, and `posix_spawn` to detect child process creation. The CLI converts child process reports into trace events and applies command policy rules.

## Policy evaluation

Policy evaluation happens **CLI-side only**. The agent is a passive hook handler — it captures and sends events without interpreting them.

The CLI evaluates each event in three passes:

1. **Function rules** — match against `python`, `node`, `functions`, `commands` sections
2. **HTTP URL rules** — match against `http`, `python.http`, `node.http` URL patterns
3. **Network rules** — match against `networking.domains`, `networking.protocols`, `networking.endpoints`

The strictest result wins: Block > Review > Warn > Display > Suppress.

## Symbol resolution

Native stack frames arrive as raw addresses. The agent sends module maps (base address + path) in the `/ready` request. The CLI resolves addresses to symbol names by reading the on-disk binaries using the `object` crate. This avoids deadlocks that would occur if symbol resolution happened inside the agent while intercept hooks are active.

## Synchronization

Two bounded `sync_channel`s provide backpressure:

1. **Agent-side**: hook callbacks → flush thread. Prevents memory growth if the flush thread can't keep up with HTTP sends.
2. **CLI-side**: HTTP server threads → main event loop. If the main thread is slow (e.g. stdout pipe full), HTTP handlers block on channel send, which naturally throttles the agent's HTTP responses.

The shutdown sequence is deterministic: the agent's atexit handler drains the flush thread and sets a `FLUSH_COMPLETE` flag before sending `/shutdown`. The CLI decrements `active_agents` only when processing the `Disconnected` event in the main loop, guaranteeing all preceding events in the FIFO channel have been handled.

## Crates

| Crate | Path | Role |
|-------|------|------|
| `malwi` | cli/ | CLI binary — server, event loop, policy, output, process spawning |
| `malwi-agent` | agent/ | Injected cdylib — hooks, event capture, HTTP client |
| `malwi-protocol` | protocol/ | Shared types — TraceEvent, protocol messages |
| `malwi-policy` | policy/ | Policy engine — YAML parsing, compilation, evaluation |
| `malwi-intercept` | intercept/ | Native function interception — code patching, module enumeration |
