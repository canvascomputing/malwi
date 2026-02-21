## 👹 `malwi` - Detect Evil Code

<div align="center">
  <img src="logo.png" alt="malwi logo" width="200">
  <h3>Stop Supply-Chain Attacks in Node.js, Python, Bash</h3>
  <p><a href="#openclaw"><img src="images/openclaw.png" alt="OpenClaw" height="16"></a> <a href="#openclaw">OpenClaw</a> &ensp;·&ensp; <a href="#comfyui"><img src="images/comfyui.png" alt="ComfyUI" height="16"></a> <a href="#comfyui">ComfyUI</a> &ensp;·&ensp; <a href="#npm-install"><img src="images/npm.png" alt="npm" height="16"></a> <a href="#npm-install">npm-install</a> &ensp;·&ensp; <a href="#pip-install"><img src="images/pypi.png" alt="PyPI" height="16"></a> <a href="#pip-install">pip-install</a> &ensp;·&ensp; <a href="#bash-execution"><img src="images/bash.png" alt="Bash" height="16"></a> <a href="#bash-execution">bash-execution</a></p>
</div>

<div align="center">

Advanced cyberattacks threaten critical infrastructure, digital sovereignty, and the freedom of societies. Campaigns like the Shai-Hulud npm attacks (2025) demonstrated how simple it is to misuse the trust in open-source software. `malwi` intercepts Python, Node.js and Bash code at runtime, blocking unauthorized network calls and sensitive file access before damage is done. `malwi` contains curated policies built from supply-chain security research and let's you create your own.

**Compatibility**: `Python 3.10-3.14` · `Node.js 21-25` · `Bash 4.4-5.3` · `macOS arm64, arm64e` ([⚠️ SIP](#macos-system-integrity-protection-sip)) and `Linux arm64, x86_64`

</div>

## Installation

```
pip install --user malwi
```

## Demo

A policy controls what `malwi` allows, denies, warns about, or logs. The default policy warns on credential access, privilege escalation, and suspicious commands:

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
# policy.yaml

version: 1
# Data exfiltration — only allow your API, block everything else
network:
  allow: ["api.canvascomputing.org/**"]
  deny: ["*/**"]

# Reverse shells and payload downloads
commands:
  deny: [nc, ncat, curl, wget, crontab, ssh]
  review: [sudo]

# Credential theft
files:
  deny: ["~/.ssh/**", "~/.aws/**", "*.pem", "*.key"]
envvars:
  deny: ["*SECRET*", "*TOKEN*", "AWS_*"]

# Runtime control bypass
nodejs:
  deny: [child_process.exec, child_process.execSync]
python:
  deny: [ctypes.CDLL]
symbols:
  deny: [dlopen, dlsym]
```

## How It Works

`malwi` injects a tracing agent into the target process at startup. The agent hooks function calls across runtimes — Node.js, Python, Bash, and native symbols — and reports every intercepted call back to the CLI over a local HTTP channel. The CLI evaluates each call against the loaded policy and decides whether to allow, deny, warn, or prompt for review. The agent is loaded via `DYLD_INSERT_LIBRARIES` (macOS) or `LD_PRELOAD` (Linux) — no source code changes or recompilation required. Tracing propagates automatically to child processes.

```
┌──────────────────────────────────────────────────────┐
│ malwi CLI                                            │
│                                                      │
│ ┌──────────┐  ┌──────────────┐  ┌──────────────────┐ │
│ │ Spawner  │  │ Policy Engine│  │ Output / Review  │ │
│ └────┬─────┘  └──────▲───────┘  └────────▲─────────┘ │
│      │               │                   │           │
│      │ inject        │ evaluate          │ display   │
│      ▼               │                   │           │
│ ┌────────────────────┴───────────────────┴────────┐  │
│ │               HTTP (localhost)                  │  │
│ └────────────────────▲────────────────────────────┘  │
└──────────────────────┼───────────────────────────────┘
                       │ report
┌──────────────────────┼───────────────────────────────┐
│ Target Process       │                               │
│                      │                               │
│ ┌────────────────────▼─────────────────────────────┐ │
│ │ malwi Agent                                      │ │
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
| **Native Function Hooking** | Hooks C/system functions in the target process |
| **System Library Interception** | Intercept libc/libSystem calls |
| **Subprocess Propagation** | Tracing propagates automatically to all subprocesses |
| **Thread-Aware Tracing** | Per-thread tracing with independent policy evaluation |
| **Deep HTTP Inspection** | Extracts URLs and arguments from HTTP calls for policy matching. **Node.js:** http/https, axios, got, node-fetch. **Python:** requests, httpx, aiohttp, urllib3, http.client, urllib.request, websockets, dns.resolver |
| ⚠️ **Direct Syscall Detection** | Not yet supported. Will detect inline `SVC`/`SYSCALL` instructions that bypass libc/libSystem calls |

## Auto-policies

When `malwi` detects a known command, it automatically applies a tailored [policy](cli/src/policies/). The policy file is written to `~/.config/malwi/policies/` on first use — edit it to customise.

#### <a id="openclaw"></a><img src="images/openclaw.png" alt="OpenClaw" height="20"> [OpenClaw](https://docs.openclaw.ai/)

([policy](cli/src/policies/openclaw.yaml)) An OpenClaw agent connects to many external APIs. This policy guards the agent's own process — a compromised dependency can steal API keys, inject code, or open a reverse shell before any external safeguard sees it. Outbound traffic is limited to known providers; everything else is blocked.

> This policy does not protect against prompt injection or unsafe model outputs — only what the agent code itself does at runtime.

```bash
malwi x openclaw gateway
malwi x node /usr/local/lib/node_modules/openclaw/dist/openclaw.mjs doctor
malwi x openclaw.mjs gateway
```

#### <a id="comfyui"></a><img src="images/comfyui.png" alt="ComfyUI" height="20"> [ComfyUI](https://docs.comfy.org/)

([policy](cli/src/policies/comfyui.yaml)) Custom nodes can run arbitrary Python — a malicious one could load native libraries directly, exfiltrate your code to a remote, or steal stored credentials. This policy restricts network access to model hosting and package registries, and blocks the escape hatches that bypass Python-level controls.

```bash
malwi x python main.py # inside a ComfyUI directory
malwi x python3 -m comfy --port 8188
malwi x comfyui --listen
```

#### <a id="npm-install"></a><img src="images/npm.png" alt="npm" height="20"> [npm-install](https://www.npmjs.com/)

([policy](cli/src/policies/npm-install.yaml)) npm install can execute arbitrary scripts from any package in the dependency tree. A single malicious package can eval code, spawn shells, and exfiltrate SSH keys or tokens. This policy limits network to the npm registry and blocks everything an install script shouldn't need.

```bash
malwi x npm install express
malwi x npm add lodash
malwi x npm ci
```

#### <a id="pip-install"></a><img src="images/pypi.png" alt="PyPI" height="20"> [pip-install](https://pypi.org/)

([policy](cli/src/policies/pip-install.yaml)) Installing a package executes arbitrary code with full access to your machine — a malicious package can steal credentials and send them to a remote server before you ever import it. This policy locks network to PyPI and blocks the common exfiltration paths.

```bash
malwi x pip install flask
malwi x pip3 install requests
malwi x python3 -m pip install six
```

#### <a id="bash-execution"></a><img src="images/bash.png" alt="Bash" height="20"> [bash-execution](https://www.gnu.org/software/bash/)

([policy](cli/src/policies/bash-install.yaml)) A remote shell script can establish persistence, exfiltrate data, or escalate privileges before you've read a single line. This policy blocks dangerous commands and prompts for review on anything that needs sudo.

```bash
curl -fsSL https://www.canvascomputing.org/install-demo.sh | malwi x bash
```

## macOS System Integrity Protection (SIP)

macOS SIP prevents `DYLD_INSERT_LIBRARIES` from loading into binaries under certain paths.

| SIP | Paths |
|--|-------|
| ✅ `malwi` works here | `/usr/local`, `/opt`, `~` |
| **⚠️ SIP-protected** | `/System`, `/usr`, `/bin`, `/sbin`, `/var`, `/Applications` |

> Security researchers may disable SIP at their own risk.

### Example Bash Installation

This is how you could install a particular bash version in `/usr/local`:

```bash
V=5.2.37  # check https://ftp.gnu.org/gnu/bash/ for latest

curl -fsSO https://ftp.gnu.org/gnu/bash/bash-$V.tar.gz

# verify (requires gpg)
curl -fsSO https://ftp.gnu.org/gnu/bash/bash-$V.tar.gz.sig
gpg --keyserver keyserver.ubuntu.com --recv-keys 7C0135FB088AAF6C66C650B9BB5869F064EA74AB
gpg --verify bash-$V.tar.gz.sig bash-$V.tar.gz

# build and install
tar xf bash-$V.tar.gz && cd bash-$V
./configure --prefix=/usr/local && make && sudo make install

# set as default shell (optional)
sudo bash -c 'echo /usr/local/bin/bash >> /etc/shells'
chsh -s /usr/local/bin/bash
```

Trace execution with `malwi`:

```bash
malwi x /usr/local/bin/bash
```

## Development

See [DEVELOPMENT.md](docs/DEVELOPMENT.md).

