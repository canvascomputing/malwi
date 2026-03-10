//! Embedded agent library extraction.
//!
//! When the agent library is available at compile time, it is embedded into
//! the CLI binary via `include_bytes!()`. At runtime, if the agent library
//! can't be found through normal search paths (e.g., pipx installs), this
//! module extracts the embedded copy to a cache directory.

#[cfg(all(embedded_agent, target_os = "macos"))]
static AGENT_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libmalwi_agent.dylib"));

#[cfg(all(embedded_agent, target_os = "linux"))]
static AGENT_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libmalwi_agent.so"));

#[cfg(all(embedded_agent, target_os = "windows"))]
static AGENT_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/malwi_agent.dll"));

#[cfg(not(embedded_agent))]
static AGENT_BYTES: &[u8] = &[];

/// Whether the agent library was embedded at compile time.
pub fn has_embedded_agent() -> bool {
    !AGENT_BYTES.is_empty()
}

/// Extract the embedded agent library to a cache directory.
///
/// Returns the absolute path to the extracted library, or `None` if:
/// - No agent was embedded at compile time
/// - Extraction failed (disk full, permissions, etc.)
///
/// The library is cached at `~/.cache/malwi/agent/libmalwi_agent-{version}.{ext}`
/// and reused across runs. Cache invalidation is version-based: upgrading
/// malwi automatically uses a new filename.
pub fn extract_embedded_agent() -> Option<String> {
    if !has_embedded_agent() {
        return None;
    }

    let lib_name = malwi_intercept::platform::agent_lib_name();
    let version = env!("CARGO_PKG_VERSION");

    // Build versioned filename: libmalwi_agent-0.0.26.dylib
    let (stem, ext) = lib_name.rsplit_once('.')?;
    let versioned_name = format!("{}-{}.{}", stem, version, ext);

    // Determine cache directory: ~/.cache/malwi/agent/
    let cache_dir = dirs_cache().join("malwi").join("agent");

    let dest = cache_dir.join(&versioned_name);

    // Skip extraction if cached file exists with correct size
    if dest.exists() {
        if let Ok(metadata) = std::fs::metadata(&dest) {
            if metadata.len() == AGENT_BYTES.len() as u64 {
                log::debug!("Using cached embedded agent: {}", dest.display());
                return Some(dest.to_string_lossy().to_string());
            }
        }
    }

    // Create cache directory
    if let Err(e) = std::fs::create_dir_all(&cache_dir) {
        log::warn!("Failed to create agent cache dir {:?}: {}", cache_dir, e);
        return None;
    }

    // Write agent library
    if let Err(e) = std::fs::write(&dest, AGENT_BYTES) {
        log::warn!("Failed to extract embedded agent to {:?}: {}", dest, e);
        return None;
    }

    // Set executable permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(&dest) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&dest, perms);
        }
    }

    log::info!(
        "Extracted embedded agent ({} bytes) to {}",
        AGENT_BYTES.len(),
        dest.display()
    );
    Some(dest.to_string_lossy().to_string())
}

/// Platform-appropriate cache directory ($HOME/.cache on Unix, temp as fallback).
fn dirs_cache() -> std::path::PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        return std::path::PathBuf::from(home).join(".cache");
    }
    std::env::temp_dir()
}
