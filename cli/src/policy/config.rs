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
        if super::PolicyEngine::from_yaml(&contents).is_ok() {
            return Ok(());
        }
        log::debug!("Regenerating stale default policy at {}", path.display());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, super::templates::DEFAULT_SECURITY_YAML.trim_start())?;
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
    ];

    for name in &names {
        let yaml = if *name == "default" {
            super::templates::DEFAULT_SECURITY_YAML
                .trim_start()
                .to_string()
        } else {
            super::templates::embedded_policy(name)
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
        super::templates::DEFAULT_SECURITY_YAML
            .trim_start()
            .to_string()
    } else {
        super::templates::embedded_policy(name).ok_or_else(|| {
            anyhow::anyhow!(
                "Unknown policy '{}'. Available: default, npm-install, pip-install, comfyui, openclaw, bash-install, air-gap",
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::{Mutex, MutexGuard};

    /// Serialize all config tests since they mutate process-global env vars.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock_env() -> (MutexGuard<'static, ()>, PathBuf) {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join("malwi_test_config");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        std::env::set_var("XDG_CONFIG_HOME", &tmp);
        (guard, tmp)
    }

    fn unlock_env(_guard: MutexGuard<'static, ()>, tmp: &Path) {
        std::env::remove_var("XDG_CONFIG_HOME");
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn test_policies_dir_creates_missing() {
        let (guard, tmp) = lock_env();
        let dir = policies_dir().unwrap();
        assert!(dir.exists());
        assert!(dir.ends_with("malwi/policies"));
        unlock_env(guard, &tmp);
    }

    #[test]
    fn test_list_policies() {
        let (guard, tmp) = lock_env();
        let dir = policies_dir().unwrap();
        fs::write(dir.join("a.yaml"), "version: 1\n").unwrap();
        fs::write(dir.join("b.yaml"), "version: 1\n").unwrap();
        list_policies().unwrap();
        unlock_env(guard, &tmp);
    }

    #[test]
    fn test_write_single_policy() {
        let (guard, tmp) = lock_env();
        write_policy("npm-install").unwrap();
        let dir = policies_dir().unwrap();
        let path = dir.join("npm-install.yaml");
        assert!(path.exists());
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("version: 1"));
        unlock_env(guard, &tmp);
    }

    #[test]
    fn test_write_unknown_policy() {
        let (guard, tmp) = lock_env();
        let result = write_policy("nonexistent");
        assert!(result.is_err());
        unlock_env(guard, &tmp);
    }

    #[test]
    fn test_reset_policies() {
        let (guard, tmp) = lock_env();
        reset_policies().unwrap();
        let dir = policies_dir().unwrap();
        let expected = [
            "default",
            "npm-install",
            "pip-install",
            "comfyui",
            "openclaw",
            "bash-install",
            "air-gap",
        ];
        for name in &expected {
            let path = dir.join(format!("{}.yaml", name));
            assert!(path.exists(), "missing policy: {}", name);
        }
        unlock_env(guard, &tmp);
    }
}
