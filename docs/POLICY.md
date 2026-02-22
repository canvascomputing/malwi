# Policy Reference

Policies are YAML files that control what `malwi` allows, denies, warns about,
or prompts for review during tracing.

---

## Full example

```yaml
version: 1

# ── Runtime function rules ───────────────────────────────────────────
# Intercept calls inside Node.js and Python runtimes.

nodejs:
  allow: [dns.lookup, net.connect, fetch, "http.request", "https.request"]
  deny:  [eval, vm.runInContext, "child_process.exec"]

python:
  deny: [os.system, os.popen, ctypes.CDLL]
  warn: [subprocess.run, subprocess.Popen.__init__]

# ── Command execution ────────────────────────────────────────────────
# Controls which child processes can be spawned.

commands:
  allow:  [node, git, npm]
  deny:   [curl, wget, ssh, nc, "*sudo*", "python*", perl]
  review: [sudo]                     # prompt before allowing

# ── Network ──────────────────────────────────────────────────────────
# URL patterns, domain patterns, endpoint patterns, protocol allowlist.

network:
  allow:
    - "registry.npmjs.org/**"
    - "api.example.com/**"
    - "127.0.0.1:*/**"
  deny:
    - "169.254.169.254/**"           # block cloud metadata (SSRF)
    - "metadata.google.internal/**"
  warn: ["*.onion", "*.i2p"]         # flag anonymity networks
  protocols: [https, http, wss, ws]

# ── File access ──────────────────────────────────────────────────────
# Protect credentials and sensitive paths.

files:
  deny: ["~/.ssh/**", "~/.aws/**", "*.pem", "*.key", "*id_rsa*"]

# ── Environment variables ────────────────────────────────────────────
# Prevent secret exfiltration via env var reads.

envvars:
  deny: ["*SECRET*", "*PASSWORD*", "AWS_*", "GITHUB_*", DYLD_INSERT_LIBRARIES]
  warn: ["*TOKEN*", "*API_KEY*", "OPENAI_*"]

# ── Native C/system symbols ──────────────────────────────────────────

symbols:
  deny: [getpass, crypt]
```

---

## Sections

| Section    | Controls                                                           |
|------------|--------------------------------------------------------------------|
| `python`   | Python function calls (`os.system`, `eval`, `subprocess.run`, ...) |
| `nodejs`   | Node.js function calls (`child_process.exec`, `fs.readFileSync`)   |
| `symbols`  | Native C/system symbols (`getpass`, `crypt`, `connect`, ...)       |
| `commands` | Child process execution (`curl`, `wget`, `ssh`, ...)               |
| `network`  | Network access by URL, domain, endpoint, or protocol               |
| `files`    | File reads and writes by path pattern                              |
| `envvars`  | Environment variable access by name pattern                        |
| `syscalls` | Direct syscall instructions (inline `SVC`/`SYSCALL`)               |

---

## Mode keys

Each section uses mode keys to assign an enforcement action to its rules:

| Key      | Effect                     |
|----------|----------------------------|
| `allow`  | Explicitly permit          |
| `deny`   | Block the operation        |
| `review` | Prompt user before allowing|
| `warn`   | Log a warning, allow       |
| `log`    | Log silently, allow        |
| `noop`   | Suppress from output       |

**Precedence:** The most specific matching pattern wins. On equal specificity,
the strictest mode wins: `deny` > `review` > `warn` > `log` > `noop` > `allow`.

---

## Pattern syntax

Rules use glob patterns by default. Prefix with `regex:` for regular expressions.

| Pattern         | Matches                               |
|-----------------|---------------------------------------|
| `fs.*`          | All functions in the `fs` module      |
| `*.readFile`    | `readFile` in any module              |
| `http.request`  | Exact match                           |
| `~/.ssh/**`     | Any file under `~/.ssh/`              |
| `*SECRET*`      | Any string containing `SECRET`        |
| `regex:^eval$`  | Regex pattern (prefix with `regex:`)  |

- `*` matches any characters **except** `/`
- `**` matches any characters **including** `/`
- `?` matches a single character

---

## Network section

The `network` section auto-classifies patterns based on their shape:

| Pattern type | Detected when          | Examples                                        |
|--------------|------------------------|-------------------------------------------------|
| URL          | Contains `/`           | `registry.npmjs.org/**`, `169.254.169.254/**`   |
| Endpoint     | Contains `:` (no `/`)  | `*:22`, `127.0.0.1:*`                           |
| Domain       | Otherwise              | `*.onion`, `metadata.google.internal`            |

The `protocols` field restricts allowed protocols: `tcp`, `udp`, `http`, `https`, `ws`, `wss`.

```yaml
network:
  allow: ["registry.npmjs.org/**"]     # URL pattern
  deny:  ["*:22"]                      # endpoint pattern (SSH port)
  warn:  ["*.onion"]                   # domain pattern
  protocols: [https, http]             # only these protocols allowed
```

---

## Constrained rules

Function rules can include argument constraints — the rule only matches
when at least one argument matches the constraint pattern:

```yaml
nodejs:
  deny:
    - eval: ["*"]                      # deny eval with any argument
  allow:
    - "http.request": ["https://api.example.com/*"]
```

---

## Policy includes

Policies can inherit from shared base policies using `includes`:

```yaml
version: 1
includes: [base]

python:
  deny:
    - eval
```

The included policy's sections are merged into the child. If the child defines
the same section, child rules take priority — duplicate patterns from the base
are skipped.

---

## Policy management

```bash
malwi p                             # list all policy files
malwi p reset                       # rewrite all from built-in templates
malwi p npm-install                 # write a single policy
malwi x -p my-policy.yaml -- node app.js   # use a custom policy
```

Policies are cached at `~/.config/malwi/policies/`. Edit them to customise.

---

## Auto-detection

When `malwi` detects a known command, it automatically applies a tailored policy:

| Command                              | Policy          |
|--------------------------------------|-----------------|
| `npm install`, `npm add`, `npm ci`   | `npm-install`   |
| `pip install`, `pip3 install`        | `pip-install`   |
| `comfyui`, `python main.py` (ComfyUI)| `comfyui`      |
| `openclaw`                           | `openclaw`      |

The policy file is written to `~/.config/malwi/policies/` on first use.
