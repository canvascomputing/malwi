//! Command taxonomy — single source of truth for command classification.
//!
//! Parses `taxonomy.yaml` (embedded at compile time) into a cached `Taxonomy`
//! struct. Provides `lookup()` for command category + trait queries and
//! canonical lists of sensitive file patterns, envvar patterns, symbols, and
//! network patterns.

use std::collections::HashMap;
use std::sync::OnceLock;

use malwi_policy::{parse_yaml, YamlValue};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Semantic traits describing what a command can do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Trait {
    ReadOnly,
    SideEffects,
    Network,
    CodeExecution,
    PrivilegeEsc,
    Persistence,
    CredentialAccess,
    ProcessControl,
    Encoding,
    SecurityBypass,
    KernelAccess,
    ContainerEscape,
    Reconnaissance,
    Exfiltration,
}

/// Primary behavioral category (determines triage engine routing).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Category {
    Safe,
    Build,
    Text,
    Package,
    FileOperation,
    Threat,
}

/// Sensitive file patterns grouped by sub-category.
pub struct TaxonomyFiles {
    pub credentials: Vec<String>,
    pub credential_dbs: Vec<String>,
    pub shell_profiles: Vec<String>,
    pub git_hooks: Vec<String>,
    pub browser: Vec<String>,
    pub system: Vec<String>,
    pub persistence: Vec<String>,
    pub keyrings: Vec<String>,
    pub proc: Vec<String>,
}

/// Environment variable patterns grouped by sub-category.
pub struct TaxonomyEnvvars {
    pub sensitive: Vec<String>,
    pub anti_tracing: Vec<String>,
}

/// Native symbol names for policy generation.
pub struct TaxonomySymbols {
    pub shared: Vec<String>,
    pub air_gap_extra: Vec<String>,
}

/// Network patterns for policy generation.
pub struct TaxonomyNetwork {
    pub deny: Vec<String>,
    pub warn: Vec<String>,
}

/// Parsed taxonomy data (shared + current-OS commands merged).
pub struct Taxonomy {
    commands: HashMap<String, (Category, Vec<Trait>)>,
    pub files: TaxonomyFiles,
    pub envvars: TaxonomyEnvvars,
    pub symbols: TaxonomySymbols,
    pub network: TaxonomyNetwork,
}

impl Taxonomy {
    /// Look up a command by basename.
    pub fn lookup(&self, name: &str) -> Option<(&Category, &[Trait])> {
        self.commands.get(name).map(|(c, t)| (c, t.as_slice()))
    }
}

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

static TAXONOMY: OnceLock<Taxonomy> = OnceLock::new();

/// Get the parsed taxonomy (lazy-initialized on first call).
pub fn get() -> &'static Taxonomy {
    TAXONOMY.get_or_init(|| parse_taxonomy(include_str!("presets/taxonomy.yaml")))
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

fn parse_trait(s: &str) -> Option<Trait> {
    match s {
        "read_only" => Some(Trait::ReadOnly),
        "side_effects" => Some(Trait::SideEffects),
        "network" => Some(Trait::Network),
        "code_execution" => Some(Trait::CodeExecution),
        "privilege_esc" => Some(Trait::PrivilegeEsc),
        "persistence" => Some(Trait::Persistence),
        "credential_access" => Some(Trait::CredentialAccess),
        "process_control" => Some(Trait::ProcessControl),
        "encoding" => Some(Trait::Encoding),
        "security_bypass" => Some(Trait::SecurityBypass),
        "kernel_access" => Some(Trait::KernelAccess),
        "container_escape" => Some(Trait::ContainerEscape),
        "reconnaissance" => Some(Trait::Reconnaissance),
        "exfiltration" => Some(Trait::Exfiltration),
        _ => None,
    }
}

fn parse_category(s: &str) -> Option<Category> {
    match s {
        "safe" => Some(Category::Safe),
        "build" => Some(Category::Build),
        "text" => Some(Category::Text),
        "package" => Some(Category::Package),
        "file_operation" => Some(Category::FileOperation),
        "threat" => Some(Category::Threat),
        _ => None,
    }
}

/// Extract trait annotations from YAML comment lines.
///
/// Scans raw text for lines like `- echo  # read_only` and builds
/// a mapping from command name to trait list.
fn extract_traits(raw: &str) -> HashMap<String, Vec<Trait>> {
    let mut map = HashMap::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        // Match lines like: - command_name  # trait1, trait2
        if let Some(rest) = trimmed.strip_prefix("- ") {
            if let Some(hash_pos) = rest.find('#') {
                let cmd_part = rest[..hash_pos].trim();
                let comment = rest[hash_pos + 1..].trim();
                // Unquote command name
                let cmd = unquote(cmd_part);
                if cmd.is_empty() {
                    continue;
                }
                let traits: Vec<Trait> = comment
                    .split(',')
                    .filter_map(|s| parse_trait(s.trim()))
                    .collect();
                if !traits.is_empty() {
                    map.insert(cmd, traits);
                }
            }
        }
    }
    map
}

fn unquote(s: &str) -> String {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn parse_taxonomy(raw: &str) -> Taxonomy {
    let trait_map = extract_traits(raw);
    let root = parse_yaml(raw).expect("taxonomy.yaml parse error");

    let root_map = as_mapping(&root);

    // --- Commands ---
    let mut commands = HashMap::new();
    if let Some(cmds_val) = find_key(root_map, "commands") {
        let cmds_map = as_mapping(cmds_val);

        // Always load "shared"
        if let Some(shared) = find_key(cmds_map, "shared") {
            load_commands(as_mapping(shared), &trait_map, &mut commands);
        }

        // Merge current OS
        let os_key = if cfg!(target_os = "macos") {
            "macos"
        } else if cfg!(target_os = "linux") {
            "linux"
        } else {
            ""
        };
        if !os_key.is_empty() {
            if let Some(os_val) = find_key(cmds_map, os_key) {
                load_commands(as_mapping(os_val), &trait_map, &mut commands);
            }
        }
    }

    // --- Files ---
    let files = parse_files(root_map);

    // --- Envvars ---
    let envvars = parse_envvars(root_map);

    // --- Symbols ---
    let symbols = parse_symbols(root_map);

    // --- Network ---
    let network = parse_network(root_map);

    Taxonomy {
        commands,
        files,
        envvars,
        symbols,
        network,
    }
}

/// Load commands from an OS-or-shared mapping (category -> command list).
fn load_commands(
    category_map: &[(String, YamlValue)],
    trait_map: &HashMap<String, Vec<Trait>>,
    out: &mut HashMap<String, (Category, Vec<Trait>)>,
) {
    for (cat_name, cat_val) in category_map {
        let category = match parse_category(cat_name) {
            Some(c) => c,
            None => continue,
        };
        for cmd in as_string_list(cat_val) {
            let traits = trait_map.get(&cmd).cloned().unwrap_or_default();
            out.insert(cmd, (category, traits));
        }
    }
}

/// Parse the `files:` section into TaxonomyFiles.
fn parse_files(root: &[(String, YamlValue)]) -> TaxonomyFiles {
    let mut files = TaxonomyFiles {
        credentials: Vec::new(),
        credential_dbs: Vec::new(),
        shell_profiles: Vec::new(),
        git_hooks: Vec::new(),
        browser: Vec::new(),
        system: Vec::new(),
        persistence: Vec::new(),
        keyrings: Vec::new(),
        proc: Vec::new(),
    };

    let files_val = match find_key(root, "files") {
        Some(v) => v,
        None => return files,
    };
    let files_map = as_mapping(files_val);

    let os_key = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        ""
    };

    // Load shared + OS-specific
    for section_key in &["shared", os_key] {
        if section_key.is_empty() {
            continue;
        }
        if let Some(section) = find_key(files_map, section_key) {
            let section_map = as_mapping(section);
            for (sub_name, sub_val) in section_map {
                let patterns = as_string_list(sub_val);
                match sub_name.as_str() {
                    "credentials" => files.credentials.extend(patterns),
                    "credential_dbs" => files.credential_dbs.extend(patterns),
                    "shell_profiles" => files.shell_profiles.extend(patterns),
                    "git_hooks" => files.git_hooks.extend(patterns),
                    "browser" => files.browser.extend(patterns),
                    "system" => files.system.extend(patterns),
                    "persistence" => files.persistence.extend(patterns),
                    "keyrings" => files.keyrings.extend(patterns),
                    "proc" => files.proc.extend(patterns),
                    _ => {}
                }
            }
        }
    }

    files
}

/// Parse the `envvars:` section into TaxonomyEnvvars.
fn parse_envvars(root: &[(String, YamlValue)]) -> TaxonomyEnvvars {
    let mut envvars = TaxonomyEnvvars {
        sensitive: Vec::new(),
        anti_tracing: Vec::new(),
    };

    let envvars_val = match find_key(root, "envvars") {
        Some(v) => v,
        None => return envvars,
    };
    let envvars_map = as_mapping(envvars_val);

    let os_key = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        ""
    };

    for section_key in &["shared", os_key] {
        if section_key.is_empty() {
            continue;
        }
        if let Some(section) = find_key(envvars_map, section_key) {
            let section_map = as_mapping(section);
            for (sub_name, sub_val) in section_map {
                let patterns = as_string_list(sub_val);
                match sub_name.as_str() {
                    "sensitive" => envvars.sensitive.extend(patterns),
                    "anti_tracing" => envvars.anti_tracing.extend(patterns),
                    _ => {}
                }
            }
        }
    }

    envvars
}

/// Parse the `symbols:` section into TaxonomySymbols.
fn parse_symbols(root: &[(String, YamlValue)]) -> TaxonomySymbols {
    let mut symbols = TaxonomySymbols {
        shared: Vec::new(),
        air_gap_extra: Vec::new(),
    };

    let sym_val = match find_key(root, "symbols") {
        Some(v) => v,
        None => return symbols,
    };
    let sym_map = as_mapping(sym_val);

    if let Some(shared) = find_key(sym_map, "shared") {
        symbols.shared = as_string_list(shared);
    }
    if let Some(extra) = find_key(sym_map, "air_gap_extra") {
        symbols.air_gap_extra = as_string_list(extra);
    }

    symbols
}

/// Parse the `network:` section into TaxonomyNetwork.
fn parse_network(root: &[(String, YamlValue)]) -> TaxonomyNetwork {
    let mut network = TaxonomyNetwork {
        deny: Vec::new(),
        warn: Vec::new(),
    };

    let net_val = match find_key(root, "network") {
        Some(v) => v,
        None => return network,
    };
    let net_map = as_mapping(net_val);

    if let Some(deny) = find_key(net_map, "deny") {
        network.deny = as_string_list(deny);
    }
    if let Some(warn) = find_key(net_map, "warn") {
        network.warn = as_string_list(warn);
    }

    network
}

// ---------------------------------------------------------------------------
// YAML helpers
// ---------------------------------------------------------------------------

fn as_mapping(val: &YamlValue) -> &[(String, YamlValue)] {
    match val {
        YamlValue::Mapping(pairs) => pairs,
        _ => &[],
    }
}

fn find_key<'a>(pairs: &'a [(String, YamlValue)], key: &str) -> Option<&'a YamlValue> {
    pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn as_string_list(val: &YamlValue) -> Vec<String> {
    match val {
        YamlValue::Sequence(items) => items
            .iter()
            .filter_map(|item| match item {
                YamlValue::String(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_parses_clean() {
        // Ensure the embedded YAML parses without error
        let _tax = get();
    }

    #[test]
    fn lookup_safe_commands() {
        let tax = get();
        assert_eq!(tax.lookup("echo").unwrap().0, &Category::Safe);
        assert_eq!(tax.lookup("ls").unwrap().0, &Category::Safe);
        assert_eq!(tax.lookup("whoami").unwrap().0, &Category::Safe);
    }

    #[test]
    fn lookup_build_commands() {
        let tax = get();
        assert_eq!(tax.lookup("make").unwrap().0, &Category::Build);
        assert_eq!(tax.lookup("gcc").unwrap().0, &Category::Build);
        assert_eq!(tax.lookup("rustc").unwrap().0, &Category::Build);
    }

    #[test]
    fn lookup_text_commands() {
        let tax = get();
        assert_eq!(tax.lookup("grep").unwrap().0, &Category::Text);
        assert_eq!(tax.lookup("sed").unwrap().0, &Category::Text);
        assert_eq!(tax.lookup("jq").unwrap().0, &Category::Text);
    }

    #[test]
    fn lookup_package_commands() {
        let tax = get();
        assert_eq!(tax.lookup("git").unwrap().0, &Category::Package);
        assert_eq!(tax.lookup("npm").unwrap().0, &Category::Package);
        assert_eq!(tax.lookup("cargo").unwrap().0, &Category::Package);
    }

    #[test]
    fn lookup_file_operation_commands() {
        let tax = get();
        assert_eq!(tax.lookup("cat").unwrap().0, &Category::FileOperation);
        assert_eq!(tax.lookup("cp").unwrap().0, &Category::FileOperation);
        assert_eq!(tax.lookup("tar").unwrap().0, &Category::FileOperation);
    }

    #[test]
    fn lookup_threat_commands() {
        let tax = get();
        assert_eq!(tax.lookup("curl").unwrap().0, &Category::Threat);
        assert_eq!(tax.lookup("python").unwrap().0, &Category::Threat);
        assert_eq!(tax.lookup("sudo").unwrap().0, &Category::Threat);
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let tax = get();
        assert!(tax.lookup("nonexistent_command_xyz").is_none());
    }

    #[test]
    fn traits_parsed_from_comments() {
        let tax = get();
        let (_, traits) = tax.lookup("curl").unwrap();
        assert!(traits.contains(&Trait::Network));

        let (_, traits) = tax.lookup("python").unwrap();
        assert!(traits.contains(&Trait::CodeExecution));

        let (_, traits) = tax.lookup("sudo").unwrap();
        assert!(traits.contains(&Trait::PrivilegeEsc));
    }

    #[test]
    fn multi_trait_commands() {
        let tax = get();
        let (_, traits) = tax.lookup("docker").unwrap();
        assert!(traits.contains(&Trait::CodeExecution));
        assert!(traits.contains(&Trait::Network));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_commands_merged() {
        let tax = get();
        assert_eq!(tax.lookup("sw_vers").unwrap().0, &Category::Safe);
        assert_eq!(tax.lookup("osascript").unwrap().0, &Category::Threat);
        assert_eq!(tax.lookup("brew").unwrap().0, &Category::Package);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_commands_merged() {
        let tax = get();
        assert_eq!(tax.lookup("lsb_release").unwrap().0, &Category::Safe);
        assert_eq!(tax.lookup("systemctl").unwrap().0, &Category::Threat);
        assert_eq!(tax.lookup("apt").unwrap().0, &Category::Package);
    }

    #[test]
    fn no_duplicate_names() {
        // The HashMap naturally deduplicates, but verify no OS command
        // overwrites a shared one with a different category.
        let raw = include_str!("presets/taxonomy.yaml");
        let trait_map = extract_traits(raw);
        let root = parse_yaml(raw).unwrap();
        let root_map = as_mapping(&root);
        let cmds_val = find_key(root_map, "commands").unwrap();
        let cmds_map = as_mapping(cmds_val);

        // Collect all shared commands
        let mut shared = HashMap::new();
        if let Some(s) = find_key(cmds_map, "shared") {
            load_commands(as_mapping(s), &trait_map, &mut shared);
        }

        // Check OS sections don't conflict with shared
        for os in &["macos", "linux"] {
            if let Some(os_val) = find_key(cmds_map, os) {
                for (cat_name, cat_val) in as_mapping(os_val) {
                    let category = match parse_category(cat_name) {
                        Some(c) => c,
                        None => continue,
                    };
                    for cmd in as_string_list(cat_val) {
                        if let Some((existing_cat, _)) = shared.get(&cmd) {
                            assert_eq!(
                                *existing_cat, category,
                                "OS '{}' puts '{}' in {:?} but shared has {:?}",
                                os, cmd, category, existing_cat
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn all_threats_have_traits() {
        let tax = get();
        for (cmd, (cat, traits)) in &tax.commands {
            if *cat == Category::Threat {
                assert!(!traits.is_empty(), "threat command '{}' has no traits", cmd);
            }
        }
    }

    #[test]
    fn credential_dbs_present() {
        let tax = get();
        assert!(tax.files.credential_dbs.contains(&"Login Data".to_string()));
        assert!(tax
            .files
            .credential_dbs
            .contains(&"cookies.sqlite".to_string()));
    }

    #[test]
    fn sensitive_envvars_present() {
        let tax = get();
        assert!(tax.envvars.sensitive.contains(&"*SECRET*".to_string()));
        assert!(tax.envvars.sensitive.contains(&"*TOKEN*".to_string()));
    }

    #[test]
    fn symbols_present() {
        let tax = get();
        assert!(tax.symbols.shared.contains(&"getpass".to_string()));
        assert!(tax.symbols.shared.contains(&"socket".to_string()));
        assert!(tax
            .symbols
            .air_gap_extra
            .contains(&"getaddrinfo".to_string()));
    }

    #[test]
    fn network_patterns_present() {
        let tax = get();
        assert!(tax.network.deny.contains(&"169.254.169.254/**".to_string()));
        assert!(tax.network.warn.contains(&"*.onion".to_string()));
    }
}
