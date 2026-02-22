## 👹 `malwi` - Detect Evil Code

<div align="center">
  <img src="logo.png" alt="malwi logo" width="200">
  <h3>Stop Supply-Chain Attacks in Node.js, Python, Bash</h3>
  <p><a href="#openclaw"><img src="images/openclaw.png" alt="OpenClaw" height="16"></a> <a href="#openclaw">OpenClaw</a> &ensp;·&ensp; <a href="#comfyui"><img src="images/comfyui.png" alt="ComfyUI" height="16"></a> <a href="#comfyui">ComfyUI</a> &ensp;·&ensp; <a href="#npm-install"><img src="images/npm.png" alt="npm" height="16"></a> <a href="#npm-install">npm-install</a> &ensp;·&ensp; <a href="#pip-install"><img src="images/pypi.png" alt="PyPI" height="16"></a> <a href="#pip-install">pip-install</a> &ensp;·&ensp; <a href="#bash-execution"><img src="images/bash.png" alt="Bash" height="16"></a> <a href="#bash-execution">bash-execution</a></p>
</div>

<div align="center">

*Advanced cyberattacks threaten critical infrastructure, digital sovereignty, and the freedom of societies. Campaigns like the Shai-Hulud npm attacks (2025) demonstrated how simple it is to misuse the trust in open-source software.* `malwi` blocks unauthorized network calls and file access in Python, Node.js and Bash at runtime, using curated supply-chain security policies or custom ones.

**Compatibility**: `Python 3.10-3.14` · `Node.js 21-25` · `Bash 4.4-5.3` · `macOS arm64, arm64e` ([⚠️ SIP](#macos-system-integrity-protection-sip)) and `Linux arm64, x86_64`

</div>

## Installation

```
pip install --user malwi
```

## Demo

A policy controls what `malwi` allows, denies, warns about, or logs. The [default policy](cli/src/policy/presets/default.yaml) warns on credential access, privilege escalation, and suspicious commands:

```bash
$ malwi x python3 -c "import os; os.getenv('AWS_SECRET_ACCESS_KEY')"
[malwi] warned: AWS_SECRET_ACCESS_KEY

$ malwi x node -e "require('child_process').execSync('ssh user@canvascomputing.org')"
[malwi] warned: ssh user@canvascomputing.org

$ malwi x bash -c 'echo cGF5bG9hZA== | base64 -d | sh'
[malwi] warned: base64 -d
```

## Policies

Write policies in YAML to control what runs inside a process. Each section targets a different attack surface — network, commands, files, environment variables, or runtime functions. Rules can allow, deny, warn, or prompt for review.

> See [POLICY.md](docs/POLICY.md) for the full specification.

```bash
$ malwi x -p policy.yaml -- node app.js
```

```yaml
# policy.yaml — lock down a Node.js web app

version: 1

# Network — only allow your API and npm registry
network:
  allow: ["api.canvascomputing.org/**", "registry.npmjs.org/**"]
  deny: ["169.254.169.254/**", "*/**"]
  protocols: [https]

# Commands — block reverse shells, prompt on privilege escalation
commands:
  allow: [node, git, npm]
  deny: [curl, wget, nc, ncat, ssh, crontab, base64]
  warn: [docker, pip]
  review: [sudo]

# Files — protect credentials
files:
  deny: ["~/.ssh/**", "~/.aws/**", "*.pem", "*.key"]

# Environment variables — block secret exfiltration
envvars:
  deny: ["*SECRET*", "*PASSWORD*", "AWS_*"]
  warn: ["*TOKEN*", "*API_KEY*"]

# Node.js — block eval and shell-outs, log network calls
nodejs:
  deny: [eval, child_process.exec, child_process.execSync]
  log: [fetch, http.request, https.request]

# Python — block native library loading and os.system
python:
  deny: [ctypes.CDLL, os.system, os.popen]
  warn: [subprocess.run, subprocess.Popen.__init__]

# Native symbols — block credential interception and raw networking
symbols:
  deny: [getpass, crypt, dlopen, syscall]
```

## Auto-policies

When `malwi` detects a known command, it automatically applies a tailored [policy](cli/src/policy/presets/). The policy file is written to `~/.config/malwi/policies/` on first use — edit it to customise.

#### <a id="openclaw"></a><img src="images/openclaw.png" alt="OpenClaw" height="20"> [OpenClaw](https://docs.openclaw.ai/)

([policy](cli/src/policy/presets/openclaw.yaml)) An OpenClaw agent connects to many external APIs. This policy guards the agent's own process — a compromised dependency can steal API keys, inject code, or open a reverse shell before any external safeguard sees it. Outbound traffic is limited to known providers; everything else is blocked.

> This policy does not protect against prompt injection or unsafe model outputs — only what the agent code itself does at runtime.

```bash
malwi x openclaw gateway
malwi x openclaw doctor
```

#### <a id="comfyui"></a><img src="images/comfyui.png" alt="ComfyUI" height="20"> [ComfyUI](https://docs.comfy.org/)

([policy](cli/src/policy/presets/comfyui.yaml)) Custom nodes can run arbitrary Python — a malicious one could load native libraries directly, exfiltrate your code to a remote, or steal stored credentials. This policy restricts network access to model hosting and package registries, and blocks the escape hatches that bypass Python-level controls.

```bash
malwi x python main.py # inside a ComfyUI directory
malwi x python3 -m comfy --port 8188
malwi x comfyui --listen
```

#### <a id="npm-install"></a><img src="images/npm.png" alt="npm" height="20"> [npm-install](https://www.npmjs.com/)

([policy](cli/src/policy/presets/npm-install.yaml)) npm install can execute arbitrary scripts from any package in the dependency tree. A single malicious package can eval code, spawn shells, and exfiltrate SSH keys or tokens. This policy limits network to the npm registry and blocks everything an install script shouldn't need.

```bash
malwi x npm install express
malwi x npm add lodash
malwi x npm ci
```

#### <a id="pip-install"></a><img src="images/pypi.png" alt="PyPI" height="20"> [pip-install](https://pypi.org/)

([policy](cli/src/policy/presets/pip-install.yaml)) Installing a package executes arbitrary code with full access to your machine — a malicious package can steal credentials and send them to a remote server before you ever import it. This policy locks network to PyPI and blocks the common exfiltration paths.

```bash
malwi x pip install flask
malwi x pip3 install requests
malwi x python3 -m pip install six
```

#### <a id="bash-execution"></a><img src="images/bash.png" alt="Bash" height="20"> [bash-execution](https://www.gnu.org/software/bash/)

([policy](cli/src/policy/presets/bash-install.yaml)) A remote shell script can establish persistence, exfiltrate data, or escalate privileges before you've read a single line. This policy blocks dangerous commands and prompts for review on anything that needs sudo.

```bash
curl -fsSL https://www.canvascomputing.org/install-demo.sh | malwi x bash
```

## How It Works

`malwi` injects a tracing agent into the target process at startup. The agent hooks function calls across runtimes — Node.js, Python, Bash, and native symbols — and reports every intercepted call back to the CLI over a local HTTP channel. The CLI evaluates each call against the loaded policy and decides whether to allow, deny, warn, or prompt for review. The agent is loaded via `DYLD_INSERT_LIBRARIES` (macOS) or `LD_PRELOAD` (Linux) — no source code changes or recompilation required. Tracing propagates automatically to child processes.

```
┌──────────────────────────────────────────────────────┐
│ malwi CLI (server)                                   │
│                                                      │
│ ┌──────────┐  ┌──────────────┐  ┌──────────────────┐ │
│ │ Spawner  │  │ Policy Engine│  │ Output / Review  │ │
│ └────┬─────┘  └──────▲───────┘  └────────▲─────────┘ │
│      │               │                   │           │
│      │ inject        │ evaluate          │ display   │
│      │               │                   │           │
└──────┼───────────────┼───────────────────┼───────────┘
       │               │ HTTP              │
       ▼               │ (trace events)    │
┌──────────────────────┼───────────────────┼───────────┐
│ Target Process       │                   │           │
│                      │                   │           │
│ ┌────────────────────┴───────────────────┴─────────┐ │
│ │ malwi Agent (client)                             │ │
│ │                                                  │ │
│ │ ┌─────────┐ ┌────────┐ ┌───────┐ ┌────────────┐  │ │
│ │ │ Node.js │ │ Python │ │ Bash  │ │  Binary    │  │ │
│ │ │ hooks   │ │ hooks  │ │ hooks │ │  Symbols   │  │ │
│ │ └─────────┘ └────────┘ └───────┘ └────────────┘  │ │
│ └────────────────────┬─────────────────────────────┘ │
│                      │ hook                          │
│ ┌────────────────────▼─────────────────────────────┐ │
│ │ Application code                                 │ │
│ └──────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────┘
```

| Features | Explanation |
|:--|:--|
| **Runtime Interception** | Allow/deny runtime functions, network access, commands, files, and environment variables by pattern |
| **Native Function Hooking** | Hooks binary symbols in the target process |
| **System Library Interception** | Intercept libc/libSystem calls |
| **Subprocess Propagation** | Tracing propagates automatically to all subprocesses |
| **Thread-Aware Tracing** | Per-thread tracing with independent policy evaluation |
| **Deep HTTP Inspection** | Extracts URLs and arguments from HTTP calls for policy matching. **Node.js:** http/https, axios, got, node-fetch. **Python:** requests, httpx, aiohttp, urllib3, http.client, urllib.request, websockets, dns.resolver |

| ⚠️ Limitations | Explanation | Mitigation |
|:--|:--|:--|
| **Direct Syscall Detection** | Inline `SVC`/`SYSCALL` instructions bypass libc hooks. The `syscall()` libc wrapper is denied in bash-install policy; full inline detection via the `syscalls:` section is available for hardened deployments | `in planning` |
| **[SIP-Protected Child Processes](#macos-system-integrity-protection-sip)** | On macOS, malicious code can shell out to SIP-protected binaries (e.g. `/usr/bin/curl`) which strip `DYLD_INSERT_LIBRARIES` — the child runs untraced, so network calls, file reads, and other operations inside it are invisible to `malwi` | `in planning` |
| **Indirect File Access** | Symlinks (`ln -s ~/.ssh /tmp/x`) or the file protocol (`curl file://`) can reach protected files without triggering `open()` deny patterns | `in progress`: AI based detection |

## macOS System Integrity Protection (SIP)

macOS SIP prevents `DYLD_INSERT_LIBRARIES` from loading into binaries under certain paths.

| SIP | Paths |
|--|-------|
| ✅ `malwi` works here | `/usr/local`, `/opt`, `~` |
| **⚠️ SIP-protected** | `/System`, `/usr`, `/bin`, `/sbin`, `/var`, `/Applications` |

> Security researchers may disable SIP at their own risk.

### Example Python Installation

Install Python to `/usr/local`:

```bash
V=3.13.2  # check https://www.python.org/downloads/source/ for latest

curl -fsSO https://www.python.org/ftp/python/$V/Python-$V.tgz
tar xf Python-$V.tgz && cd Python-$V
./configure --prefix=/usr/local && make && sudo make install
```

```bash
malwi x /usr/local/bin/python3
```

### Example Node.js Installation

Install Node.js to `/usr/local`:

```bash
V=22.14.0  # check https://nodejs.org/en/download for latest LTS
ARCH=$(uname -m)

curl -fsSO https://nodejs.org/dist/v$V/node-v$V-darwin-$ARCH.tar.gz
tar xf node-v$V-darwin-$ARCH.tar.gz
sudo cp -r node-v$V-darwin-$ARCH/{bin,include,lib,share} /usr/local/
```

```bash
malwi x /usr/local/bin/node
```

### Example Bash Installation

Install Bash to `/usr/local`:

```bash
V=5.2.37  # check https://ftp.gnu.org/gnu/bash/ for latest

curl -fsSO https://ftp.gnu.org/gnu/bash/bash-$V.tar.gz
tar xf bash-$V.tar.gz && cd bash-$V
./configure --prefix=/usr/local && make && sudo make install
```

```bash
malwi x /usr/local/bin/bash
```

## Security

To report a vulnerability, email [security@canvascomputing.org](mailto:security@canvascomputing.org). See [SECURITY.md](.github/SECURITY.md) for details.

A full dependency listing is automatically regenerated on every build when `Cargo.lock` or `package-lock.json` change. See [`DEPENDENCIES.md`](DEPENDENCIES.md).

## Development

See [DEVELOPMENT.md](docs/DEVELOPMENT.md).
