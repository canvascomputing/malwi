//! Rust-native policy presets using macros and shared const slices.
//!
//! Replaces the 7 YAML preset files with Rust functions that compose
//! policies from shared pattern groups, eliminating duplication and
//! making the taxonomy the single source of truth.

use super::parser::{AllowDenySection, PolicyFile, Rule, SectionValue};

// ---------------------------------------------------------------------------
// rules! macro — builds Vec<Rule> from shared const slices and inline literals
// ---------------------------------------------------------------------------

macro_rules! rules {
    () => { Vec::new() };
    (@push $v:ident;) => {};
    (@push $v:ident; ..$group:expr, $($rest:tt)*) => {
        $v.extend($group.iter().map(|p| Rule::Simple(p.to_string())));
        rules!(@push $v; $($rest)*);
    };
    (@push $v:ident; ..$group:expr) => {
        $v.extend($group.iter().map(|p| Rule::Simple(p.to_string())));
    };
    (@push $v:ident; $pattern:expr, $($rest:tt)*) => {
        $v.push(Rule::Simple($pattern.to_string()));
        rules!(@push $v; $($rest)*);
    };
    (@push $v:ident; $pattern:expr) => {
        $v.push(Rule::Simple($pattern.to_string()));
    };
    ($($input:tt)*) => {{
        let mut v: Vec<Rule> = Vec::new();
        rules!(@push v; $($input)*);
        v
    }};
}

// ---------------------------------------------------------------------------
// Shared const slices — pattern groups used by multiple presets
// ---------------------------------------------------------------------------

/// Credential files: SSH keys, cloud credentials, PEM/key files.
const CREDENTIAL_FILES: &[&str] = &[
    "~/.ssh/**",
    "*/.ssh/**",
    "~/.aws/**",
    "*/.aws/**",
    "~/.config/gcloud/**",
    "~/.azure/**",
    "~/.gnupg/**",
    "~/.config/gh/**",
    "*/.kube/config",
    "*.pem",
    "*.key",
    "*id_rsa*",
    "*id_ed25519*",
];

/// macOS/Linux keyring storage.
const KEYRINGS: &[&str] = &[
    "~/Library/Keychains/**",
    "~/Library/Cookies/**",
    "~/.local/share/keyrings/**",
    "~/.local/share/kwalletd/**",
];

/// Browser credential databases.
const BROWSER_DATA: &[&str] = &[
    "~/Library/Application Support/Google/Chrome/*/Login Data*",
    "~/Library/Application Support/Firefox/Profiles/**/*.sqlite",
    "~/.mozilla/firefox/**/*.sqlite",
    "~/.config/google-chrome/*/Login Data*",
];

/// macOS/Linux persistence paths.
const PERSISTENCE_FILES: &[&str] = &[
    "~/Library/LaunchAgents/**",
    "/Library/LaunchDaemons/**",
    "/Library/LaunchAgents/**",
    "~/.config/autostart/**",
    "~/.config/systemd/user/**",
    "/etc/cron.d/**",
    "/etc/cron.daily/**",
    "/etc/crontab",
    "~/.crontab",
    "/etc/ld.so.preload",
];

/// Shell profile files (persistence vector).
const SHELL_PROFILES: &[&str] = &["~/.bashrc", "~/.zshrc", "~/.profile", "~/.bash_profile"];

/// Sensitive environment variables.
const SENSITIVE_ENVVARS: &[&str] = &[
    "*SECRET*",
    "*TOKEN*",
    "*PASSWORD*",
    "*API_KEY*",
    "*PRIVATE_KEY*",
    "AWS_*",
    "GITHUB_*",
    "GCP_*",
    "AZURE_*",
    "OPENAI_*",
    "ANTHROPIC_*",
    "HF_TOKEN",
];

/// Anti-tracing environment variables.
const ANTI_TRACING_ENVVARS: &[&str] = &["DYLD_INSERT_LIBRARIES", "LD_PRELOAD"];

/// Dangerous native symbols (credential interception, symlink bypass, raw syscall).
const DANGEROUS_SYMBOLS: &[&str] = &["getpass", "crypt", "symlink", "link", "syscall"];

/// Networking native symbols (for air-gap total block).
const NETWORKING_SYMBOLS: &[&str] = &[
    "socket",
    "connect",
    "sendto",
    "send",
    "bind",
    "listen",
    "accept",
    "accept4",
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname2",
];

/// Warn-baseline commands shared across most presets.
const WARN_BASELINE: &[&str] = &[
    // Scripting interpreters
    "osascript",
    "swift",
    "java",
    // Data exfiltration
    "open",
    "sqlite3",
    // Credential/config readers (macOS)
    "plutil",
    "defaults",
    // Anti-tracing
    "kill",
    "pkill",
    "killall",
    // Linux scripting interpreters
    "gjs",
    // D-Bus access
    "dbus-send",
    "gdbus",
    "busctl",
    // Data exfiltration (Linux)
    "xdg-open",
    // Linux credential/keyring
    "secret-tool",
    "kwallet-query",
    "kwalletcli",
    "keyctl",
    "pass",
    // Reconnaissance
    "locate",
    "mlocate",
    "plocate",
    // Security bypass (Linux MAC)
    "setenforce",
    "aa-disable",
    "apparmor_parser",
    "chattr",
    "setcap",
    "getcap",
    "debugfs",
    "mount",
    "chroot",
    "unshare",
    "nsenter",
    // Kernel/module manipulation
    "insmod",
    "modprobe",
    "rmmod",
    "kexec",
    // Process memory/injection
    "strace",
    "ltrace",
    "gdb",
    "gcore",
    // Privilege escalation (Linux)
    "pkexec",
    "newgrp",
];

// ---------------------------------------------------------------------------
// Helper to build a PolicyFile from sections
// ---------------------------------------------------------------------------

fn policy(sections: Vec<(&str, SectionValue)>) -> PolicyFile {
    PolicyFile {
        version: 1,
        sections: sections
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        includes: Vec::new(),
    }
}

fn ad(section: AllowDenySection) -> SectionValue {
    SectionValue::AllowDeny(section)
}

// ---------------------------------------------------------------------------
// Preset functions
// ---------------------------------------------------------------------------

/// Default observe-mode policy: warn/log, no blocking.
pub fn default_policy() -> PolicyFile {
    policy(vec![
        (
            "symbols",
            ad(AllowDenySection {
                warn: rules!["getpass", "crypt"],
                ..Default::default()
            }),
        ),
        (
            "python",
            ad(AllowDenySection {
                warn: rules![
                    "getpass.getpass",
                    "keyring.get_password",
                    "keyring.set_password",
                    "ctypes.CDLL",
                    "ctypes.cdll.LoadLibrary"
                ],
                log: rules![
                    "socket.create_connection",
                    "socket.socket.connect",
                    "urllib.request.urlopen",
                    "requests.Session.request",
                    "http.client.HTTPConnection.request",
                    "http.client.HTTPSConnection.request",
                    "ssl.wrap_socket",
                    "ssl.SSLContext.wrap_socket"
                ],
                ..Default::default()
            }),
        ),
        (
            "nodejs",
            ad(AllowDenySection {
                log: rules![
                    "dns.lookup",
                    "dns.resolve",
                    "net.connect",
                    "tls.connect",
                    "fetch",
                    "http.request",
                    "https.request",
                    "http.get",
                    "https.get"
                ],
                ..Default::default()
            }),
        ),
        (
            "commands",
            ad(AllowDenySection {
                warn: rules![
                    // Privilege escalation
                    "sudo",
                    "su",
                    "doas",
                    // Remote access
                    "ssh",
                    "scp",
                    "sftp",
                    // Raw networking
                    "nc",
                    "ncat",
                    "socat",
                    "telnet",
                    // Encoding tools
                    "base64",
                    "xxd",
                    // Persistence mechanisms
                    "crontab",
                    "launchctl",
                    "systemctl",
                    ..WARN_BASELINE
                ],
                log: rules!["curl", "wget", "git", "npm", "pip", "gem", "cargo", "docker", "nmap"],
                ..Default::default()
            }),
        ),
        (
            "network",
            ad(AllowDenySection {
                warn: rules![
                    "169.254.169.254/**",
                    "metadata.google.internal/**",
                    "*.onion",
                    "*.i2p",
                    "*.bit",
                    "*.loki"
                ],
                log: rules!["*", "*/**", "*:*"],
                ..Default::default()
            }),
        ),
        (
            "files",
            ad(AllowDenySection {
                warn: rules![
                    ..CREDENTIAL_FILES,
                    "~/.local/share/keyrings/**",
                    "~/.local/share/kwalletd/**",
                    "~/.config/autostart/**",
                    "~/.config/systemd/user/**",
                    "/etc/ld.so.preload",
                    "/proc/*/environ"
                ],
                ..Default::default()
            }),
        ),
        (
            "envvars",
            ad(AllowDenySection {
                warn: rules![..SENSITIVE_ENVVARS, ..ANTI_TRACING_ENVVARS],
                ..Default::default()
            }),
        ),
    ])
}

/// npm install policy: restrict to npmjs.org, block credential access.
pub fn npm_install() -> PolicyFile {
    policy(vec![
        (
            "nodejs",
            ad(AllowDenySection {
                allow: rules![
                    "dns.lookup",
                    "dns.resolve",
                    "net.connect",
                    "tls.connect",
                    "fetch",
                    "http.request",
                    "https.request",
                    "http.get",
                    "https.get"
                ],
                deny: rules!["eval", "vm.runInContext", "vm.runInNewContext"],
                ..Default::default()
            }),
        ),
        (
            "commands",
            ad(AllowDenySection {
                allow: rules!["node", "sh", "bash", "git"],
                deny: rules![
                    "curl", "wget", "ssh", "nc", "ncat", "*sudo*", "python*", "perl", "ruby"
                ],
                warn: rules![..WARN_BASELINE],
                ..Default::default()
            }),
        ),
        (
            "network",
            ad(AllowDenySection {
                allow: rules!["registry.npmjs.org/**", "*.npmjs.org/**"],
                ..Default::default()
            }),
        ),
        (
            "symbols",
            ad(AllowDenySection {
                warn: rules![..DANGEROUS_SYMBOLS],
                ..Default::default()
            }),
        ),
        (
            "files",
            ad(AllowDenySection {
                deny: rules![
                    ..CREDENTIAL_FILES,
                    ..KEYRINGS,
                    ..PERSISTENCE_FILES,
                    ..BROWSER_DATA,
                    ..SHELL_PROFILES
                ],
                ..Default::default()
            }),
        ),
        (
            "envvars",
            ad(AllowDenySection {
                deny: rules![..SENSITIVE_ENVVARS, ..ANTI_TRACING_ENVVARS],
                ..Default::default()
            }),
        ),
    ])
}

/// pip install policy: restrict to pypi.org, block credential access.
pub fn pip_install() -> PolicyFile {
    policy(vec![
        (
            "python",
            ad(AllowDenySection {
                allow: rules![
                    "socket.create_connection",
                    "socket.socket.connect",
                    "ssl.SSLSocket.connect",
                    "urllib.request.urlopen",
                    "http.client.HTTPConnection.request",
                    "http.client.HTTPSConnection.request"
                ],
                ..Default::default()
            }),
        ),
        (
            "commands",
            ad(AllowDenySection {
                allow: rules!["git"],
                deny: rules![
                    "curl", "wget", "ssh", "nc", "ncat", "*sudo*", "sh", "bash", "perl", "ruby"
                ],
                warn: rules![..WARN_BASELINE],
                ..Default::default()
            }),
        ),
        (
            "network",
            ad(AllowDenySection {
                allow: rules![
                    "pypi.org/**",
                    "*.pypi.org/**",
                    "files.pythonhosted.org/**",
                    "*.pythonhosted.org/**"
                ],
                ..Default::default()
            }),
        ),
        (
            "symbols",
            ad(AllowDenySection {
                warn: rules![..DANGEROUS_SYMBOLS],
                ..Default::default()
            }),
        ),
        (
            "files",
            ad(AllowDenySection {
                deny: rules![
                    ..CREDENTIAL_FILES,
                    ..KEYRINGS,
                    ..PERSISTENCE_FILES,
                    ..BROWSER_DATA,
                    ..SHELL_PROFILES
                ],
                ..Default::default()
            }),
        ),
        (
            "envvars",
            ad(AllowDenySection {
                deny: rules![..SENSITIVE_ENVVARS, ..ANTI_TRACING_ENVVARS],
                ..Default::default()
            }),
        ),
    ])
}

/// ComfyUI policy: AI image generation, Python threat model.
pub fn comfyui() -> PolicyFile {
    policy(vec![
        (
            "python",
            ad(AllowDenySection {
                deny: rules![
                    "getpass.getpass",
                    "keyring.get_password",
                    "keyring.set_password",
                    "os.system",
                    "os.popen",
                    "ctypes.CDLL",
                    "ctypes.cdll.LoadLibrary",
                    "ctypes.WinDLL"
                ],
                ..Default::default()
            }),
        ),
        (
            "commands",
            ad(AllowDenySection {
                allow: rules![
                    "git clone *",
                    "git pull *",
                    "git fetch *",
                    "git checkout *",
                    "git submodule *",
                    "git status",
                    "git status *",
                    "git version",
                    "git rev-parse *",
                    "git log *",
                    "git diff *",
                    "git describe *",
                    "git branch",
                    "git branch *",
                    "git show *",
                    "git config *",
                    "git ls-remote *",
                    "git remote -v",
                    "pip install *",
                    "pip3 install *",
                    "pip freeze",
                    "pip list",
                    "pip show *",
                    "python -m pip *",
                    "python3 -m pip *",
                    "uv pip *",
                    "uv sync *",
                    "uv run *",
                    "python3 -I *",
                    "python -I *",
                    "python3 -c *",
                    "python -c *",
                    "python3 --version",
                    "python --version",
                    "nvidia-smi",
                    "nvidia-smi *"
                ],
                ..Default::default()
            }),
        ),
        (
            "symbols",
            ad(AllowDenySection {
                warn: rules!["getpass", "crypt", "keyring", "symlink", "link", "syscall"],
                ..Default::default()
            }),
        ),
        (
            "network",
            ad(AllowDenySection {
                allow: rules![
                    "huggingface.co/**",
                    "*.huggingface.co/**",
                    "civitai.com/**",
                    "*.civitai.com/**",
                    "github.com/**",
                    "*.githubusercontent.com/**",
                    "codeload.github.com/**",
                    "pypi.org/**",
                    "*.pypi.org/**",
                    "files.pythonhosted.org/**",
                    "*.pythonhosted.org/**",
                    "127.0.0.1:*/**",
                    "localhost:*/**",
                    "0.0.0.0:*/**"
                ],
                protocols: vec!["https".into(), "http".into(), "wss".into(), "ws".into()],
                ..Default::default()
            }),
        ),
        (
            "files",
            ad(AllowDenySection {
                deny: rules![
                    ..CREDENTIAL_FILES,
                    ..KEYRINGS,
                    ..PERSISTENCE_FILES,
                    ..BROWSER_DATA,
                    ..SHELL_PROFILES
                ],
                ..Default::default()
            }),
        ),
        (
            "envvars",
            ad(AllowDenySection {
                allow: rules!["HF_HUB_*", "HF_TOKEN_PATH"],
                warn: rules![
                    "*_SECRET*",
                    "*_TOKEN",
                    "*_TOKEN_*",
                    "*_PASSWORD",
                    "*_PASSWORD_*",
                    "*_API_KEY",
                    "*_API_KEY_*",
                    "*_PRIVATE_KEY*"
                ],
                deny: rules![
                    // Cloud provider credentials
                    "AWS_SECRET_ACCESS_KEY",
                    "AWS_ACCESS_KEY_ID",
                    "AWS_SESSION_TOKEN",
                    "AWS_SECURITY_TOKEN",
                    "GCP_SERVICE_ACCOUNT_KEY",
                    "GOOGLE_APPLICATION_CREDENTIALS",
                    "GOOGLE_API_KEY",
                    "AZURE_CLIENT_SECRET",
                    "AZURE_CLIENT_ID",
                    // AI/ML provider keys
                    "OPENAI_API_KEY",
                    "ANTHROPIC_API_KEY",
                    "HF_TOKEN",
                    "STABILITY_API_KEY",
                    "REPLICATE_API_TOKEN",
                    "CIVITAI_API_TOKEN",
                    // Code hosting / package registries
                    "GITHUB_TOKEN",
                    "NPM_TOKEN",
                    // Messaging integrations
                    "DISCORD_TOKEN",
                    "DISCORD_WEBHOOK_URL",
                    "TELEGRAM_BOT_TOKEN",
                    // Other credentials
                    "DATABASE_URL",
                    "SSH_PRIVATE_KEY",
                    "STRIPE_SECRET_KEY",
                    // Injection vectors
                    ..ANTI_TRACING_ENVVARS
                ],
                ..Default::default()
            }),
        ),
    ])
}

/// Openclaw policy: multi-channel AI gateway.
pub fn openclaw() -> PolicyFile {
    policy(vec![
        (
            "nodejs",
            ad(AllowDenySection {
                allow: rules![
                    "dns.lookup",
                    "dns.resolve",
                    "net.connect",
                    "net.createServer",
                    "tls.connect",
                    "fetch",
                    "http.request",
                    "https.request",
                    "http.get",
                    "https.get",
                    "http.createServer",
                    "https.createServer"
                ],
                deny: rules![
                    "eval",
                    "vm.runInContext",
                    "vm.runInNewContext",
                    "vm.compileFunction",
                    "child_process.exec",
                    "child_process.execSync"
                ],
                ..Default::default()
            }),
        ),
        (
            "commands",
            ad(AllowDenySection {
                allow: rules![
                    "node",
                    "git",
                    "npm",
                    "npx",
                    "pnpm",
                    "corepack",
                    "launchctl",
                    "systemctl",
                    "schtasks",
                    "docker",
                    "ssh",
                    "openssl",
                    "ffmpeg",
                    "ffprobe",
                    "security",
                    "sw_vers",
                    "sysctl",
                    "scutil",
                    "defaults",
                    "lsof",
                    "brew",
                    "gcloud",
                    "taskkill"
                ],
                deny: rules![
                    "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "scp", "python*",
                    "perl", "ruby", "base64", "xxd", "pbcopy", "xclip", "crontab"
                ],
                warn: {
                    let mut w = rules!["sh", "bash"];
                    // Warn baseline minus "defaults" (allowed for openclaw)
                    for &cmd in WARN_BASELINE {
                        if cmd != "defaults" {
                            w.push(Rule::Simple(cmd.to_string()));
                        }
                    }
                    w
                },
                review: rules!["sudo", "su", "doas"],
                ..Default::default()
            }),
        ),
        (
            "network",
            ad(AllowDenySection {
                allow: rules![
                    "openclaw.ai/**",
                    "*.openclaw.ai/**",
                    "registry.npmjs.org/**",
                    "*.npmjs.org/**",
                    "github.com/**",
                    "*.githubusercontent.com/**",
                    "api.anthropic.com/**",
                    "api.openai.com/**",
                    "slack.com/**",
                    "*.slack.com/**",
                    "api.telegram.org/**",
                    "discord.com/**",
                    "*.discord.com/**",
                    "gateway.discord.gg/**",
                    "graph.facebook.com/**",
                    "127.0.0.1:*/**",
                    "localhost:*/**"
                ],
                protocols: vec!["https".into(), "http".into(), "wss".into(), "ws".into()],
                ..Default::default()
            }),
        ),
        (
            "symbols",
            ad(AllowDenySection {
                warn: rules![..DANGEROUS_SYMBOLS],
                ..Default::default()
            }),
        ),
        (
            "files",
            ad(AllowDenySection {
                deny: rules![
                    ..CREDENTIAL_FILES,
                    ..KEYRINGS,
                    ..PERSISTENCE_FILES,
                    ..BROWSER_DATA,
                    ..SHELL_PROFILES
                ],
                ..Default::default()
            }),
        ),
        (
            "envvars",
            ad(AllowDenySection {
                deny: rules![
                    "*SECRET*",
                    "*PASSWORD*",
                    "*PRIVATE_KEY*",
                    "AWS_*",
                    "GITHUB_*",
                    "GCP_*",
                    "AZURE_*",
                    ..ANTI_TRACING_ENVVARS
                ],
                warn: rules![
                    "*TOKEN*",
                    "*API_KEY*",
                    "OPENAI_*",
                    "ANTHROPIC_*",
                    "CLAUDE_*",
                    "OPENCLAW_*",
                    "HF_TOKEN"
                ],
                ..Default::default()
            }),
        ),
    ])
}

/// Bash install script policy: curl/wget allowed, interpreters blocked.
pub fn bash_install() -> PolicyFile {
    policy(vec![
        (
            "commands",
            ad(AllowDenySection {
                allow: rules![
                    // Download tools
                    "curl",
                    "wget",
                    // Package managers
                    "apt",
                    "apt-get",
                    "yum",
                    "dnf",
                    "brew",
                    "pacman",
                    "apk",
                    "zypper",
                    "dpkg",
                    "rpm",
                    "snap",
                    "flatpak",
                    "pip",
                    "pip3",
                    "npm",
                    "gem",
                    // Build tools
                    "make",
                    "cmake",
                    "gcc",
                    "g++",
                    "cc",
                    "cargo",
                    "rustup",
                    "go",
                    // File and text utilities
                    "tar",
                    "unzip",
                    "gzip",
                    "gunzip",
                    "bzip2",
                    "xz",
                    "cp",
                    "mv",
                    "rm",
                    "mkdir",
                    "install",
                    "cat",
                    "tee",
                    "sed",
                    "awk",
                    "grep",
                    "cut",
                    "sort",
                    "head",
                    "tail",
                    "wc",
                    "tr",
                    "find",
                    "dirname",
                    "basename",
                    "mktemp",
                    "realpath",
                    "readlink",
                    // Checksum and verification
                    "sha256sum",
                    "sha1sum",
                    "md5sum",
                    "shasum",
                    "gpg",
                    "gpgv",
                    // System info
                    "uname",
                    "arch",
                    "id",
                    "whoami",
                    "hostname",
                    "getconf",
                    "sw_vers",
                    "lsb_release",
                    "dpkg-architecture",
                    // Process control
                    "true",
                    "false",
                    "test",
                    "[",
                    "sleep",
                    "env",
                    "printenv",
                    "which",
                    "command",
                    "type",
                    // Version managers
                    "git",
                    "nvm",
                    "rbenv",
                    "pyenv",
                    "asdf",
                    "volta",
                    "python -m venv *",
                    "python3 -m venv *",
                    // Shell utilities
                    "chmod",
                    "chown",
                    "chgrp",
                    "touch",
                    "date",
                    "echo",
                    "printf",
                    "tput",
                    "stty"
                ],
                deny: rules![
                    // Interpreters
                    "python*",
                    "perl",
                    "ruby",
                    "node",
                    // Raw networking
                    "nc",
                    "ncat",
                    "netcat",
                    "socat",
                    "telnet",
                    // DNS exfiltration
                    "dig",
                    "nslookup",
                    "host",
                    // Persistence
                    "crontab",
                    "at",
                    "launchctl",
                    "systemctl",
                    // Clipboard
                    "pbcopy",
                    "pbpaste",
                    "xclip",
                    "xsel",
                    // Remote access
                    "ssh",
                    "scp",
                    "sftp",
                    // macOS keychain
                    "security",
                    // File access bypass
                    "dd",
                    // Data exfiltration / staging
                    "ditto",
                    "zip",
                    "rsync",
                    // Encrypted channels
                    "openssl"
                ],
                warn: rules!["eval", "ln", "base64", "xxd", "rev", ..WARN_BASELINE],
                review: rules!["sudo", "su", "doas"],
                ..Default::default()
            }),
        ),
        (
            "files",
            ad(AllowDenySection {
                deny: rules![
                    ..CREDENTIAL_FILES,
                    "~/.local/share/keyrings/**",
                    "~/.local/share/kwalletd/**",
                    // Shell profiles (extended set for bash-install)
                    "~/.bashrc",
                    "~/.bash_profile",
                    "~/.zshrc",
                    "~/.zprofile",
                    "~/.profile",
                    "~/.login",
                    // macOS persistence
                    "~/Library/LaunchAgents/**",
                    "~/Library/LaunchDaemons/*",
                    "/Library/LaunchDaemons/**",
                    "/Library/LaunchAgents/**",
                    // macOS credential/browser stores
                    "~/Library/Keychains/**",
                    "~/Library/Cookies/**",
                    "~/Library/Application Support/Google/Chrome/*/Login Data*",
                    "~/Library/Application Support/Firefox/Profiles/**/*.sqlite",
                    // Linux autostart/systemd
                    "~/.config/autostart/**",
                    "~/.config/systemd/user/**",
                    // Linux persistence (extended)
                    "/etc/cron*",
                    "/etc/systemd/**",
                    "/etc/udev/rules.d/**",
                    "/etc/init.d/**",
                    "/var/spool/cron/**",
                    "~/.crontab",
                    // System-level preload
                    "/etc/ld.so.preload",
                    "/etc/ld.so.conf",
                    "/etc/ld.so.conf.d/**",
                    // Git hooks
                    ".git/hooks/*",
                    "*/.git/hooks/*",
                    // System files
                    "/etc/passwd",
                    "/etc/shadow",
                    // Browser data
                    "*/Google/Chrome/**",
                    "*/Firefox/**",
                    "*/Safari/**",
                    "~/.mozilla/firefox/**/*.sqlite",
                    "~/.config/google-chrome/*/Login Data*",
                    // Shared memory
                    "/dev/shm/*",
                    // Process information
                    "/proc/*/environ",
                    "/proc/*/maps",
                    "/proc/*/mem"
                ],
                ..Default::default()
            }),
        ),
        (
            "network",
            ad(AllowDenySection {
                protocols: vec!["https".into(), "http".into()],
                ..Default::default()
            }),
        ),
        (
            "symbols",
            ad(AllowDenySection {
                warn: rules![..DANGEROUS_SYMBOLS],
                ..Default::default()
            }),
        ),
        (
            "envvars",
            ad(AllowDenySection {
                deny: rules![..SENSITIVE_ENVVARS, ..ANTI_TRACING_ENVVARS],
                ..Default::default()
            }),
        ),
    ])
}

/// Air-gap policy: total network isolation.
pub fn air_gap() -> PolicyFile {
    policy(vec![
        (
            "network",
            ad(AllowDenySection {
                deny: rules!["*", "*/**", "*:*"],
                ..Default::default()
            }),
        ),
        (
            "commands",
            ad(AllowDenySection {
                deny: rules![
                    // HTTP/download
                    "curl",
                    "wget",
                    "aria2c",
                    // Remote access
                    "ssh",
                    "scp",
                    "sftp",
                    "ftp",
                    "rsync",
                    // Raw networking
                    "nc",
                    "ncat",
                    "netcat",
                    "socat",
                    "telnet",
                    "openssl",
                    // Network recon
                    "nmap",
                    "ping",
                    "ping6",
                    "traceroute",
                    "tracepath",
                    // DNS
                    "dig",
                    "nslookup",
                    "host",
                    // Privilege escalation
                    "sudo",
                    "su",
                    "doas",
                    // Network configuration
                    "ip",
                    "ifconfig",
                    "iptables",
                    "nft",
                    "route",
                    // Data staging
                    "ditto",
                    "zip"
                ],
                warn: rules![..WARN_BASELINE],
                ..Default::default()
            }),
        ),
        (
            "symbols",
            ad(AllowDenySection {
                deny: rules![..NETWORKING_SYMBOLS, "syscall", "getpass", "crypt"],
                ..Default::default()
            }),
        ),
        (
            "files",
            ad(AllowDenySection {
                deny: rules![
                    ..CREDENTIAL_FILES,
                    ..KEYRINGS,
                    ..PERSISTENCE_FILES,
                    ..BROWSER_DATA,
                    ..SHELL_PROFILES
                ],
                ..Default::default()
            }),
        ),
        (
            "envvars",
            ad(AllowDenySection {
                deny: rules![..SENSITIVE_ENVVARS, ..ANTI_TRACING_ENVVARS],
                ..Default::default()
            }),
        ),
    ])
}

// ---------------------------------------------------------------------------
// YAML serializer — converts PolicyFile to YAML for user-facing config files
// ---------------------------------------------------------------------------

/// Serialize a `PolicyFile` to valid YAML.
pub fn policy_to_yaml(policy: &PolicyFile, name: &str) -> String {
    let mut out = String::with_capacity(2048);

    // Header
    out.push_str(&format!("# {} policy — generated by malwi\n", name));
    out.push_str(&format!("version: {}\n", policy.version));

    // Stable section ordering for deterministic output
    let section_order = [
        "symbols", "python", "nodejs", "commands", "network", "files", "envvars",
    ];

    for &name in &section_order {
        if let Some(section) = policy.sections.get(name) {
            out.push('\n');
            write_section(&mut out, name, section);
        }
    }

    // Any sections not in the standard order
    let mut extra: Vec<_> = policy
        .sections
        .keys()
        .filter(|k| !section_order.contains(&k.as_str()))
        .collect();
    extra.sort();
    for name in extra {
        out.push('\n');
        write_section(&mut out, name, &policy.sections[name]);
    }

    out
}

fn write_section(out: &mut String, name: &str, section: &SectionValue) {
    match section {
        SectionValue::AllowDeny(ad) => {
            out.push_str(&format!("{}:\n", name));
            write_rules_list(out, "allow", &ad.allow);
            write_rules_list(out, "deny", &ad.deny);
            write_rules_list(out, "warn", &ad.warn);
            write_rules_list(out, "log", &ad.log);
            write_rules_list(out, "review", &ad.review);
            write_rules_list(out, "noop", &ad.noop);
            if !ad.protocols.is_empty() {
                out.push_str(&format!("  protocols: [{}]\n", ad.protocols.join(", ")));
            }
        }
        SectionValue::List(items) => {
            out.push_str(&format!("{}:\n", name));
            for item in items {
                out.push_str(&format!("  - {}\n", yaml_quote(item)));
            }
        }
        SectionValue::RuleList(rules) => {
            out.push_str(&format!("{}:\n", name));
            for rule in rules {
                write_rule(out, rule, "  ");
            }
        }
    }
}

fn write_rules_list(out: &mut String, key: &str, rules: &[Rule]) {
    if rules.is_empty() {
        return;
    }
    out.push_str(&format!("  {}:\n", key));
    for rule in rules {
        write_rule(out, rule, "    ");
    }
}

fn write_rule(out: &mut String, rule: &Rule, indent: &str) {
    match rule {
        Rule::Simple(s) => {
            out.push_str(&format!("{}- {}\n", indent, yaml_quote(s)));
        }
        Rule::WithConstraints {
            pattern,
            constraints,
        } => {
            let quoted: Vec<String> = constraints.iter().map(|c| yaml_quote(c)).collect();
            out.push_str(&format!(
                "{}- {}: [{}]\n",
                indent,
                yaml_quote(pattern),
                quoted.join(", ")
            ));
        }
    }
}

/// Quote a YAML string value if it contains special characters.
fn yaml_quote(s: &str) -> String {
    // Needs quoting if: contains special chars, starts with *, or looks like a YAML value
    let needs_quoting = s.contains('*')
        || s.contains(':')
        || s.contains('#')
        || s.contains('{')
        || s.contains('}')
        || s.contains('[')
        || s.contains(']')
        || s.contains(',')
        || s.contains('&')
        || s.contains('!')
        || s.contains('|')
        || s.contains('>')
        || s.contains('\'')
        || s.contains('"')
        || s.contains('%')
        || s.contains('@')
        || s.contains('`')
        || s == "true"
        || s == "false"
        || s == "null"
        || s == "yes"
        || s == "no"
        || s == "on"
        || s == "off"
        || s.starts_with(' ')
        || s.ends_with(' ')
        || s.is_empty();

    if needs_quoting {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::engine::PolicyEngine;
    use crate::policy::parser::parse_policy;

    #[test]
    fn test_rules_macro_empty() {
        let r: Vec<Rule> = rules![];
        assert!(r.is_empty());
    }

    #[test]
    fn test_rules_macro_literals() {
        let r = rules!["a", "b", "c"];
        assert_eq!(r.len(), 3);
        assert!(matches!(&r[0], Rule::Simple(s) if s == "a"));
        assert!(matches!(&r[1], Rule::Simple(s) if s == "b"));
        assert!(matches!(&r[2], Rule::Simple(s) if s == "c"));
    }

    #[test]
    fn test_rules_macro_spread() {
        const GROUP: &[&str] = &["x", "y"];
        let r = rules![..GROUP];
        assert_eq!(r.len(), 2);
        assert!(matches!(&r[0], Rule::Simple(s) if s == "x"));
    }

    #[test]
    fn test_rules_macro_mixed() {
        const GROUP: &[&str] = &["x", "y"];
        let r = rules!["a", ..GROUP, "z"];
        assert_eq!(r.len(), 4);
        assert!(matches!(&r[0], Rule::Simple(s) if s == "a"));
        assert!(matches!(&r[1], Rule::Simple(s) if s == "x"));
        assert!(matches!(&r[2], Rule::Simple(s) if s == "y"));
        assert!(matches!(&r[3], Rule::Simple(s) if s == "z"));
    }

    #[test]
    fn test_rules_macro_trailing_spread() {
        const GROUP: &[&str] = &["a", "b"];
        let r = rules!["z", ..GROUP];
        assert_eq!(r.len(), 3);
        assert!(matches!(&r[2], Rule::Simple(s) if s == "b"));
    }

    #[test]
    fn test_yaml_serializer_round_trip() {
        let policy = npm_install();
        let yaml = policy_to_yaml(&policy, "npm-install");

        // Parse it back
        let parsed = parse_policy(&yaml).expect("generated YAML must parse");
        assert_eq!(parsed.version, 1);

        // Compile and verify a key behavior
        let engine = PolicyEngine::from_yaml(&yaml).expect("generated YAML must compile");
        let d = engine.evaluate_file("~/.ssh/id_rsa");
        assert_eq!(d.action, crate::policy::engine::PolicyAction::Deny);
    }

    #[test]
    fn test_yaml_serializer_round_trip_comfyui() {
        let policy = comfyui();
        let yaml = policy_to_yaml(&policy, "comfyui");

        let engine = PolicyEngine::from_yaml(&yaml).expect("comfyui YAML must compile");

        // Verify protocols
        assert_eq!(
            engine.evaluate_protocol("https").action,
            crate::policy::engine::PolicyAction::Allow
        );
        assert_eq!(
            engine.evaluate_protocol("tcp").action,
            crate::policy::engine::PolicyAction::Deny
        );
    }

    #[test]
    fn test_yaml_quote_special_chars() {
        assert_eq!(yaml_quote("simple"), "simple");
        assert_eq!(yaml_quote("*.ssh/**"), "\"*.ssh/**\"");
        assert_eq!(yaml_quote("true"), "\"true\"");
        assert_eq!(yaml_quote("["), "\"[\"");
    }

    #[test]
    fn test_all_presets_produce_valid_yaml() {
        let presets: Vec<(&str, PolicyFile)> = vec![
            ("default", default_policy()),
            ("npm-install", npm_install()),
            ("pip-install", pip_install()),
            ("comfyui", comfyui()),
            ("openclaw", openclaw()),
            ("bash-install", bash_install()),
            ("air-gap", air_gap()),
        ];

        for (name, policy) in presets {
            let yaml = policy_to_yaml(&policy, name);
            let parsed = parse_policy(&yaml)
                .unwrap_or_else(|e| panic!("{} YAML failed to parse: {}", name, e));
            assert_eq!(parsed.version, 1, "{} version mismatch", name);

            let _engine = PolicyEngine::from_yaml(&yaml)
                .unwrap_or_else(|e| panic!("{} YAML failed to compile: {}", name, e));
        }
    }
}
