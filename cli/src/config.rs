//! Policy management: list, reset, and default policy paths.

use std::path::{Path, PathBuf};

use anyhow::Result;

/// Get the XDG config base directory (~/.config or $XDG_CONFIG_HOME).
fn config_base_dir() -> Result<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        Ok(PathBuf::from(xdg))
    } else {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        Ok(home.join(".config"))
    }
}

/// Get the default policy file path: ~/.config/malwi/policies/default.yaml
pub(crate) fn default_policy_path() -> Result<PathBuf> {
    Ok(policies_dir()?.join("default.yaml"))
}

/// Get the auto-policy directory: ~/.config/malwi/policies/
/// Creates the directory if it doesn't exist.
pub(crate) fn policies_dir() -> Result<PathBuf> {
    let dir = config_base_dir()?.join("malwi").join("policies");
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

/// Create the default policy file if it doesn't exist, or regenerate it if
/// the on-disk copy was written by an older version and uses stale section names.
pub(crate) fn ensure_default_policy(path: &Path) -> Result<()> {
    if path.exists() {
        // Try to load — if it fails validation, the file is stale.
        let contents = std::fs::read_to_string(path)?;
        if malwi_policy::PolicyEngine::from_yaml(&contents).is_ok() {
            return Ok(());
        }
        log::debug!("Regenerating stale default policy at {}", path.display());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        path,
        crate::default_policy::DEFAULT_SECURITY_YAML.trim_start(),
    )?;
    Ok(())
}

/// List all policy YAML files in ~/.config/malwi/policies/.
pub(crate) fn list_policies() -> Result<()> {
    let dir = policies_dir()?;
    let mut found = false;
    let mut entries: Vec<_> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
        })
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        println!("{}", entry.path().display());
        found = true;
    }
    if !found {
        println!("{} (no policies)", dir.display());
    }
    Ok(())
}

/// Rewrite all policies from built-in templates.
pub(crate) fn reset_policies() -> Result<()> {
    let dir = policies_dir()?;

    let names = [
        "default",
        "npm-install",
        "pip-install",
        "comfyui",
        "openclaw",
        "bash-install",
        "air-gap",
        "base",
    ];

    for name in &names {
        let yaml = if *name == "default" {
            crate::default_policy::DEFAULT_SECURITY_YAML
                .trim_start()
                .to_string()
        } else {
            crate::auto_policy::embedded_policy(name)
                .ok_or_else(|| anyhow::anyhow!("No embedded template for '{}'", name))?
        };
        let path = dir.join(format!("{}.yaml", name));
        std::fs::write(&path, &yaml)?;
        println!("{}", path.display());
    }

    Ok(())
}

/// Write a single policy from its embedded template.
pub(crate) fn write_policy(name: &str) -> Result<()> {
    let yaml = if name == "default" {
        crate::default_policy::DEFAULT_SECURITY_YAML
            .trim_start()
            .to_string()
    } else {
        crate::auto_policy::embedded_policy(name).ok_or_else(|| {
            anyhow::anyhow!(
                "Unknown policy '{}'. Available: default, npm-install, pip-install, comfyui, openclaw, bash-install, air-gap, base",
                name
            )
        })?
    };

    let dir = policies_dir()?;
    let path = dir.join(format!("{}.yaml", name));
    std::fs::write(&path, &yaml)?;
    println!("{}", path.display());
    Ok(())
}
