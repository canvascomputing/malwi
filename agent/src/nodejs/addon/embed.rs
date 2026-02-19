//! V8 introspection addon embedding and extraction.
//!
//! This module handles:
//! - Embedding prebuilt addon binaries per Node.js version
//! - Runtime detection of Node.js major version
//! - Extracting the appropriate addon to a temp file
//!
//! ## Architecture
//!
//! The addon is loaded via direct dlopen/dlsym (in hooks.rs), NOT through
//! Node.js's process.dlopen. This allows us to call the addon's C FFI
//! exports without going through JavaScript.
//!
//! The addon is still a valid Node.js addon but we only use its C exports:
//! - malwi_addon_enable_tracing()
//! - malwi_addon_add_filter()
//! - etc.

#![allow(dead_code)]

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use log::{debug, info, warn};

use crate::native;
use crate::nodejs::symbols;

// =============================================================================
// EMBEDDED ADDON BINARIES (per-version conditional includes)
// =============================================================================

// darwin-arm64 (macOS Apple Silicon)
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod embedded {
    #[cfg(has_v8_addon_node21)]
    pub static NODE21: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/darwin-arm64/node21/v8_introspect.node");
    #[cfg(not(has_v8_addon_node21))]
    pub static NODE21: &[u8] = &[];

    #[cfg(has_v8_addon_node22)]
    pub static NODE22: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/darwin-arm64/node22/v8_introspect.node");
    #[cfg(not(has_v8_addon_node22))]
    pub static NODE22: &[u8] = &[];

    #[cfg(has_v8_addon_node23)]
    pub static NODE23: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/darwin-arm64/node23/v8_introspect.node");
    #[cfg(not(has_v8_addon_node23))]
    pub static NODE23: &[u8] = &[];

    #[cfg(has_v8_addon_node24)]
    pub static NODE24: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/darwin-arm64/node24/v8_introspect.node");
    #[cfg(not(has_v8_addon_node24))]
    pub static NODE24: &[u8] = &[];

    #[cfg(has_v8_addon_node25)]
    pub static NODE25: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/darwin-arm64/node25/v8_introspect.node");
    #[cfg(not(has_v8_addon_node25))]
    pub static NODE25: &[u8] = &[];
}

// darwin-x64 (macOS Intel)
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod embedded {
    #[cfg(has_v8_addon_node21)]
    pub static NODE21: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/darwin-x64/node21/v8_introspect.node");
    #[cfg(not(has_v8_addon_node21))]
    pub static NODE21: &[u8] = &[];

    #[cfg(has_v8_addon_node22)]
    pub static NODE22: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/darwin-x64/node22/v8_introspect.node");
    #[cfg(not(has_v8_addon_node22))]
    pub static NODE22: &[u8] = &[];

    #[cfg(has_v8_addon_node23)]
    pub static NODE23: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/darwin-x64/node23/v8_introspect.node");
    #[cfg(not(has_v8_addon_node23))]
    pub static NODE23: &[u8] = &[];

    #[cfg(has_v8_addon_node24)]
    pub static NODE24: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/darwin-x64/node24/v8_introspect.node");
    #[cfg(not(has_v8_addon_node24))]
    pub static NODE24: &[u8] = &[];

    #[cfg(has_v8_addon_node25)]
    pub static NODE25: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/darwin-x64/node25/v8_introspect.node");
    #[cfg(not(has_v8_addon_node25))]
    pub static NODE25: &[u8] = &[];
}

// linux-x64
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod embedded {
    #[cfg(has_v8_addon_node21)]
    pub static NODE21: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/linux-x64/node21/v8_introspect.node");
    #[cfg(not(has_v8_addon_node21))]
    pub static NODE21: &[u8] = &[];

    #[cfg(has_v8_addon_node22)]
    pub static NODE22: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/linux-x64/node22/v8_introspect.node");
    #[cfg(not(has_v8_addon_node22))]
    pub static NODE22: &[u8] = &[];

    #[cfg(has_v8_addon_node23)]
    pub static NODE23: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/linux-x64/node23/v8_introspect.node");
    #[cfg(not(has_v8_addon_node23))]
    pub static NODE23: &[u8] = &[];

    #[cfg(has_v8_addon_node24)]
    pub static NODE24: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/linux-x64/node24/v8_introspect.node");
    #[cfg(not(has_v8_addon_node24))]
    pub static NODE24: &[u8] = &[];

    #[cfg(has_v8_addon_node25)]
    pub static NODE25: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/linux-x64/node25/v8_introspect.node");
    #[cfg(not(has_v8_addon_node25))]
    pub static NODE25: &[u8] = &[];
}

// linux-arm64
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod embedded {
    #[cfg(has_v8_addon_node21)]
    pub static NODE21: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/linux-arm64/node21/v8_introspect.node");
    #[cfg(not(has_v8_addon_node21))]
    pub static NODE21: &[u8] = &[];

    #[cfg(has_v8_addon_node22)]
    pub static NODE22: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/linux-arm64/node22/v8_introspect.node");
    #[cfg(not(has_v8_addon_node22))]
    pub static NODE22: &[u8] = &[];

    #[cfg(has_v8_addon_node23)]
    pub static NODE23: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/linux-arm64/node23/v8_introspect.node");
    #[cfg(not(has_v8_addon_node23))]
    pub static NODE23: &[u8] = &[];

    #[cfg(has_v8_addon_node24)]
    pub static NODE24: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/linux-arm64/node24/v8_introspect.node");
    #[cfg(not(has_v8_addon_node24))]
    pub static NODE24: &[u8] = &[];

    #[cfg(has_v8_addon_node25)]
    pub static NODE25: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/linux-arm64/node25/v8_introspect.node");
    #[cfg(not(has_v8_addon_node25))]
    pub static NODE25: &[u8] = &[];
}

// windows-x64
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod embedded {
    #[cfg(has_v8_addon_node21)]
    pub static NODE21: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/windows-x64/node21/v8_introspect.node");
    #[cfg(not(has_v8_addon_node21))]
    pub static NODE21: &[u8] = &[];

    #[cfg(has_v8_addon_node22)]
    pub static NODE22: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/windows-x64/node22/v8_introspect.node");
    #[cfg(not(has_v8_addon_node22))]
    pub static NODE22: &[u8] = &[];

    #[cfg(has_v8_addon_node23)]
    pub static NODE23: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/windows-x64/node23/v8_introspect.node");
    #[cfg(not(has_v8_addon_node23))]
    pub static NODE23: &[u8] = &[];

    #[cfg(has_v8_addon_node24)]
    pub static NODE24: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/windows-x64/node24/v8_introspect.node");
    #[cfg(not(has_v8_addon_node24))]
    pub static NODE24: &[u8] = &[];

    #[cfg(has_v8_addon_node25)]
    pub static NODE25: &[u8] =
        include_bytes!("../../../../node-addon/prebuilt/windows-x64/node25/v8_introspect.node");
    #[cfg(not(has_v8_addon_node25))]
    pub static NODE25: &[u8] = &[];
}

// Fallback for completely unsupported platforms (not macOS/Linux/Windows x86_64/aarch64)
#[cfg(not(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "macos", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64"),
    all(target_os = "windows", target_arch = "x86_64"),
)))]
mod embedded {
    pub static NODE21: &[u8] = &[];
    pub static NODE22: &[u8] = &[];
    pub static NODE23: &[u8] = &[];
    pub static NODE24: &[u8] = &[];
    pub static NODE25: &[u8] = &[];
}

// =============================================================================
// STATE
// =============================================================================

/// Whether the addon has been loaded (via FFI, not JS)
static ADDON_LOADED: AtomicBool = AtomicBool::new(false);

/// Cached addon path after extraction
static ADDON_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Cached detected Node.js version.
///
/// Version detection results are cached to avoid repeated attempts.
/// Early detection (during library constructor) may fail because Node.js
/// static initialization hasn't run yet.
static DETECTED_VERSION: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

// =============================================================================
// VERSION DETECTION
// =============================================================================

// std::string memory layout differs between C++ standard libraries:
//
// libstdc++ (Linux) - 64-bit:
//   struct basic_string {
//       char* data_ptr;        // offset 0:  pointer to string data
//       size_t length;         // offset 8:  string length
//       union {
//           char local_buf[16]; // offset 16: inline buffer for short strings (SSO)
//           size_t capacity;
//       };
//   };
//
// libc++ (macOS) - 64-bit:
//   Short strings (SSO) have inline data starting near offset 0-1.
//   The layout is more complex but short strings can be read by scanning
//   from the start for a null terminator.
//
// Node.js version strings (e.g., "24.13.0") always fit in SSO on both platforms.

/// libstdc++ (Linux) std::string layout constants
#[cfg(target_os = "linux")]
mod std_string {
    pub const LENGTH_OFFSET: usize = 8;
    pub const SSO_BUFFER_OFFSET: usize = 16;
    pub const SSO_MAX_LENGTH: usize = 15;
}

/// Detect Node.js version by reading the `node::per_process::metadata` symbol.
///
/// The metadata struct's first field is `versions.node`, a std::string containing
/// the Node.js version (e.g., "24.13.0"). We read this directly from memory.
///
/// Returns None if:
/// - The symbol isn't exported (older Node.js or stripped binary)
/// - Static initialization hasn't run yet (called too early in process startup)
fn detect_version_from_metadata() -> Option<u32> {
    let addr = native::find_export(None, symbols::PER_PROCESS_METADATA).ok()?;
    debug!("Metadata symbol at {:#x}", addr);

    #[cfg(target_os = "linux")]
    {
        detect_version_libstdcxx(addr)
    }

    #[cfg(target_os = "macos")]
    {
        detect_version_libcxx(addr)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // Fallback: try libc++ approach first (simpler), then libstdc++
        detect_version_libcxx(addr).or_else(|| detect_version_libstdcxx(addr))
    }
}

/// Detect version using libstdc++ std::string layout (Linux).
///
/// libstdc++ stores:
/// - length at offset 8
/// - SSO buffer at offset 16
#[cfg(any(
    target_os = "linux",
    not(any(target_os = "linux", target_os = "macos"))
))]
fn detect_version_libstdcxx(addr: usize) -> Option<u32> {
    // Read the std::string structure (32 bytes covers pointer + length + SSO buffer)
    let mut bytes = [0u8; 32];
    unsafe {
        std::ptr::copy_nonoverlapping(addr as *const u8, bytes.as_mut_ptr(), 32);
    }
    debug!("Metadata bytes (libstdc++): {:02x?}", &bytes);

    // Extract string length from offset 8
    let length_bytes: [u8; 8] = bytes[std_string::LENGTH_OFFSET..std_string::LENGTH_OFFSET + 8]
        .try_into()
        .ok()?;
    let len = u64::from_le_bytes(length_bytes) as usize;

    if len == 0 || len > 32 {
        debug!("Metadata not initialized (length={})", len);
        return None;
    }

    if len > std_string::SSO_MAX_LENGTH {
        debug!("Version string unexpectedly long (length={})", len);
        return None;
    }

    // Read version string from SSO buffer at offset 16
    let sso_start = std_string::SSO_BUFFER_OFFSET;
    let sso_end = sso_start + len;
    let version_str = std::str::from_utf8(&bytes[sso_start..sso_end]).ok()?;

    // Parse major version (e.g., "24.13.0" -> 24)
    let major: u32 = version_str.split('.').next()?.parse().ok()?;

    debug!("Detected Node.js {} (full version: {})", major, version_str);
    Some(major)
}

/// Detect version using libc++ std::string layout (macOS).
///
/// libc++ SSO strings have inline data starting near offset 0.
/// We scan from the start for a null terminator.
#[cfg(any(
    target_os = "macos",
    not(any(target_os = "linux", target_os = "macos"))
))]
fn detect_version_libcxx(addr: usize) -> Option<u32> {
    let mut bytes = [0u8; 16];
    unsafe {
        std::ptr::copy_nonoverlapping(addr as *const u8, bytes.as_mut_ptr(), 15);
    }
    debug!("Metadata bytes (libc++): {:02x?}", &bytes);

    // Find null terminator
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(15);
    if len == 0 {
        debug!("Metadata not initialized (empty string)");
        return None;
    }

    let version_str = std::str::from_utf8(&bytes[..len]).ok()?;

    // Parse major version (e.g., "24.13.0" -> 24)
    let major: u32 = version_str.split('.').next()?.parse().ok()?;

    debug!("Detected Node.js {} (full version: {})", major, version_str);
    Some(major)
}

/// Detect Node.js major version from the running process.
///
/// Reads from `node::per_process::metadata` symbol.
/// Results are cached after first successful detection.
pub fn detect_node_version() -> Option<u32> {
    if let Some(&version) = DETECTED_VERSION.get() {
        return Some(version);
    }

    if let Some(major) = detect_version_from_metadata() {
        info!("Node.js {} detected from metadata", major);
        let _ = DETECTED_VERSION.set(major);
        return Some(major);
    }

    warn!("Node.js version detection failed");
    None
}

/// Get the version bucket for a given Node.js major version.
///
/// Version buckets group compatible Node.js versions:
/// - node21: Node.js 21.x
/// - node22: Node.js 22.x
/// - node23: Node.js 23.x
/// - node24: Node.js 24.x
/// - node25: Node.js 25.x+
fn version_bucket(major_version: u32) -> Option<&'static str> {
    match major_version {
        21 => Some("node21"),
        22 => Some("node22"),
        23 => Some("node23"),
        24 => Some("node24"),
        25.. => Some("node25"),
        _ => None,
    }
}

/// Get the embedded addon bytes for a version bucket.
fn get_embedded_bytes(bucket: &str) -> &'static [u8] {
    match bucket {
        "node21" => embedded::NODE21,
        "node22" => embedded::NODE22,
        "node23" => embedded::NODE23,
        "node24" => embedded::NODE24,
        "node25" => embedded::NODE25,
        _ => &[],
    }
}

// =============================================================================
// ADDON EXTRACTION
// =============================================================================

/// Calculate a short hash of a string for stable path naming.
fn calculate_short_hash(s: &str) -> String {
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    format!("{:08x}", hasher.finish() as u32)
}

/// All embedded addon version buckets and their bytes.
const ALL_EMBEDDED_ADDONS: &[(&str, &[u8])] = &[
    ("node21", embedded::NODE21),
    ("node22", embedded::NODE22),
    ("node23", embedded::NODE23),
    ("node24", embedded::NODE24),
    ("node25", embedded::NODE25),
];

fn get_all_embedded_addons() -> &'static [(&'static str, &'static [u8])] {
    ALL_EMBEDDED_ADDONS
}

/// Cached addon directory after extraction
static ADDON_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Extract ALL embedded addons to a stable temp directory.
///
/// Uses socket hash for stable path that works for child processes.
/// The directory structure is:
///   /tmp/malwi-addons-{hash}/node21/v8_introspect.node
///   /tmp/malwi-addons-{hash}/node22/v8_introspect.node
///   etc.
///
/// # Returns
/// - Some(path) with the addon directory path
/// - None if extraction failed
pub fn extract_all_addons() -> Option<PathBuf> {
    // Return cached path if available
    if let Some(path) = ADDON_DIR.get() {
        return Some(path.clone());
    }

    // Use socket hash for stable path that works for child processes
    let socket = std::env::var("MALWI_URL").unwrap_or_default();
    let hash = calculate_short_hash(&socket);
    let addon_dir = std::env::temp_dir().join(format!("malwi-addons-{}", hash));

    let mut extracted_count = 0;
    for (bucket, bytes) in get_all_embedded_addons() {
        if bytes.is_empty() {
            continue; // Skip missing versions
        }

        let bucket_dir = addon_dir.join(bucket);
        let path = bucket_dir.join("v8_introspect.node");

        // Skip if already exists and has correct size
        if path.exists() {
            if let Ok(metadata) = std::fs::metadata(&path) {
                if metadata.len() == bytes.len() as u64 {
                    extracted_count += 1;
                    continue;
                }
            }
        }

        // Create directory
        if let Err(e) = std::fs::create_dir_all(&bucket_dir) {
            warn!("Failed to create addon dir {:?}: {}", bucket_dir, e);
            continue;
        }

        // Write addon
        if let Err(e) = std::fs::write(&path, bytes) {
            warn!("Failed to extract addon to {:?}: {}", path, e);
            continue;
        }

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(&path) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o700);
                let _ = std::fs::set_permissions(&path, perms);
            }
        }

        debug!("Extracted addon {} ({} bytes)", bucket, bytes.len());
        extracted_count += 1;
    }

    if extracted_count == 0 {
        warn!("No addons could be extracted");
        return None;
    }

    info!(
        "Extracted {} addon versions to {:?}",
        extracted_count, addon_dir
    );

    // Cache the path
    let _ = ADDON_DIR.set(addon_dir.clone());

    Some(addon_dir)
}

/// Extract the embedded addon to a temporary file.
///
/// # Returns
/// - Some(path) with the extracted addon path
/// - None if extraction failed or no addon is available
fn extract_addon(bucket: &str) -> Option<PathBuf> {
    let bytes = get_embedded_bytes(bucket);

    // Check if we have a real addon (not empty placeholder)
    if bytes.is_empty() {
        debug!("No addon binary available for bucket: {}", bucket);
        return None;
    }

    // Create temp file path: /tmp/malwi-v8-addon-{bucket}-{pid}.node
    let path = std::env::temp_dir().join(format!(
        "malwi-v8-addon-{}-{}.node",
        bucket,
        std::process::id()
    ));

    // Write addon to temp file
    if let Err(e) = std::fs::write(&path, bytes) {
        warn!("Failed to extract addon to {:?}: {}", path, e);
        return None;
    }

    // Set restrictive permissions on Unix (owner read/write/execute only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(&path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o700);
            if let Err(e) = std::fs::set_permissions(&path, perms) {
                warn!("Failed to set restrictive permissions on addon: {}", e);
            }
        }
    }

    info!("Extracted addon ({} bytes) to {:?}", bytes.len(), path);
    Some(path)
}

// =============================================================================
// PUBLIC API
// =============================================================================

/// Get the path to the V8 introspection addon.
///
/// This function:
/// 1. Detects the Node.js version
/// 2. Selects the matching embedded addon
/// 3. Extracts it to a temporary file
///
/// The path is cached after first extraction.
///
/// # Note
/// Call this from outside trace hooks to avoid V8 reentrancy.
///
/// # Returns
/// - Some(path) with the addon path
/// - None if no addon is available for this platform/version
pub fn get_addon_path() -> Option<PathBuf> {
    // Return cached path if available
    if let Some(path) = ADDON_PATH.get() {
        return Some(path.clone());
    }

    // Detect Node.js version
    let node_version = detect_node_version()?;

    // Get version bucket
    let bucket = match version_bucket(node_version) {
        Some(b) => b,
        None => {
            warn!(
                "Unsupported Node.js version {} - V8 addon not available",
                node_version
            );
            return None;
        }
    };

    // Extract addon
    let path = extract_addon(bucket)?;

    // Cache the path
    let _ = ADDON_PATH.set(path.clone());

    Some(path)
}

/// Check if the addon is loaded.
pub fn is_addon_loaded() -> bool {
    ADDON_LOADED.load(Ordering::SeqCst)
}

/// Mark the addon as loaded (called by hooks.rs after successful FFI init).
pub fn set_addon_loaded(loaded: bool) {
    ADDON_LOADED.store(loaded, Ordering::SeqCst);
}

/// Load the addon - DEPRECATED, use filters::initialize() instead.
///
/// This exists for backwards compatibility but does nothing.
/// The addon is now loaded via direct FFI in filters.rs.
pub fn load_addon() -> bool {
    warn!("load_addon() is deprecated - use filters::initialize() instead");
    is_addon_loaded()
}

// =============================================================================
// CLEANUP
// =============================================================================

/// Clean up stale addon files from previous runs.
///
/// This removes temp files matching the pattern:
/// `malwi-v8-addon-{version}-{pid}.node`
/// where the PID is no longer running.
pub fn cleanup_stale_addons() {
    let temp_dir = std::env::temp_dir();

    let entries = match std::fs::read_dir(&temp_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        // Match pattern: malwi-v8-addon-{version}-{pid}.node
        if !name.starts_with("malwi-v8-addon-") || !name.ends_with(".node") {
            continue;
        }

        // Extract PID from filename
        let parts: Vec<&str> = name.trim_end_matches(".node").split('-').collect();
        if parts.len() < 5 {
            continue;
        }

        let pid_str = parts[parts.len() - 1];
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Skip current process
        if pid == std::process::id() {
            continue;
        }

        // Check if process is still running
        #[cfg(unix)]
        let is_running = unsafe { libc::kill(pid as i32, 0) == 0 };
        #[cfg(windows)]
        let is_running = false; // TODO: implement for Windows

        if !is_running {
            debug!("Removing stale addon file: {:?}", path);
            let _ = std::fs::remove_file(&path);
        }
    }
}
