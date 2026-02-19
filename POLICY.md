# Policy Reference

Policies are YAML files that control what `malwi` allows, denies, warns about, or prompts for review.

## Minimal example

```yaml
version: 1
commands:
  deny: [curl, wget, ssh, "*sudo*"]
network:
  allow: ["api.example.com/**"]
  deny: ["*/**"]
files:
  deny: ["~/.ssh/**", "*.pem"]
envvars:
  deny: ["*SECRET*", "AWS_*"]
```

## Full example

```yaml
version: 1

# Runtime function rules — intercept calls inside Node.js/Python
nodejs:
  allow: [dns.lookup, net.connect, fetch, "http.request", "https.request"]
  deny: [eval, vm.runInContext, "child_process.exec"]

python:
  deny: [os.system, os.popen, ctypes.CDLL]
  warn: [subprocess.run, subprocess.Popen.__init__]

# Command execution — controls what child processes can be spawned
commands:
  allow: [node, git, npm]
  deny: [curl, wget, ssh, nc, "*sudo*", "python*", perl]
  review: [sudo]            # prompt user before allowing

# Network — URL patterns, domain patterns, protocol restrictions
network:
  allow:
    - "registry.npmjs.org/**"
    - "api.example.com/**"
    - "127.0.0.1:*/**"
  deny:
    - "169.254.169.254/**"   # block cloud metadata (SSRF)
    - "metadata.google.internal/**"
  warn: ["*.onion", "*.i2p"] # flag anonymity networks
  protocols: [https, http, wss, ws]

# File access — protect credentials and sensitive paths
files:
  deny: ["~/.ssh/**", "~/.aws/**", "*.pem", "*.key", "*id_rsa*"]

# Environment variables — prevent secret exfiltration
envvars:
  deny: ["*SECRET*", "*PASSWORD*", "AWS_*", "GITHUB_*", DYLD_INSERT_LIBRARIES]
  warn: ["*TOKEN*", "*API_KEY*", "OPENAI_*"]

# Native C/system symbols
symbols:
  deny: [getpass, crypt]

# Direct syscall detection
syscalls:
  deny: ["*"]
```

## Sections

| Section | Controls |
|---------|----------|
| `python` | Python function calls (`os.system`, `eval`, `subprocess.run`, ...) |
| `nodejs` | Node.js function calls (`child_process.exec`, `fs.readFileSync`, ...) |
| `symbols` | Native C/system symbols (`getpass`, `crypt`, `connect`, ...) |
| `commands` | Child process execution (`curl`, `wget`, `ssh`, ...) |
| `network` | Network access by URL, domain, endpoint, or protocol |
| `files` | File reads and writes by path pattern |
| `envvars` | Environment variable access by name pattern |
| `syscalls` | Direct syscall instructions (inline `SVC`/`SYSCALL`) |

## Mode keys

Each section uses mode keys to assign an enforcement action to its rules:

| Key | Effect |
|-----|--------|
| `allow` | Explicitly permit |
| `deny` | Block the operation |
| `review` | Prompt user before allowing |
| `warn` | Log a warning, allow |
| `log` | Log silently, allow |
| `noop` | Suppress from output |

The strictest matching rule wins: `deny` > `review` > `warn` > `log` > `noop` > `allow`.

## Pattern syntax

Rules use glob patterns:

| Pattern | Matches |
|---------|---------|
| `fs.*` | All functions in `fs` module |
| `*.readFile` | `readFile` in any module |
| `http.request` | Exact match |
| `~/.ssh/**` | Any file under `~/.ssh/` |
| `*SECRET*` | Any string containing `SECRET` |
| `regex:^eval$` | Regex pattern (prefix with `regex:`) |

## Network section

The `network` section auto-classifies patterns:

| Pattern type | Detected when | Examples |
|-------------|---------------|---------|
| URL | Contains `/` | `registry.npmjs.org/**`, `169.254.169.254/**` |
| Endpoint | Contains `:` (no `/`) | `*:22`, `127.0.0.1:*` |
| Domain | Otherwise | `*.onion`, `metadata.google.internal` |

The `protocols` field restricts allowed protocols: `tcp`, `udp`, `http`, `https`, `ws`, `wss`.

```yaml
network:
  allow: ["registry.npmjs.org/**"]    # URL pattern
  deny: ["*:22"]                      # endpoint pattern (SSH port)
  warn: ["*.onion"]                   # domain pattern
  protocols: [https, http]            # only allow these protocols
```

## Constrained rules

Rules in `files` and `envvars` sections can have operation constraints:

```yaml
files:
  allow:
    - "/app/data/*.json": [read, write]
    - "/tmp/**": [read]
  deny:
    - "~/.ssh/**"

envvars:
  allow:
    - HOME: [read]
  deny:
    - "*SECRET*"
```

Valid operations: `read`, `write`, `edit`, `delete`, `create`, `execute`.

## Policy management

```bash
$ malwi p                    # list all policy files
$ malwi p reset              # rewrite all from built-in templates
$ malwi p npm-install        # write a single policy
$ malwi x -p my-policy.yaml -- node app.js  # use a custom policy
```

Policies are cached at `~/.config/malwi/policies/`. Edit them to customise.

## Auto-policies

When `malwi` detects a known command, it automatically applies a tailored policy:

| Command | Policy |
|---------|--------|
| `npm install`, `npm add`, `npm ci` | `npm-install` |
| `pip install`, `pip3 install` | `pip-install` |
| `comfyui`, `python main.py` (ComfyUI) | `comfyui` |
| `openclaw` | `openclaw` |

The policy file is written to `~/.config/malwi/policies/` on first use.
