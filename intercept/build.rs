//! Build script for malwi-intercept.
//!
//! Links against the frida-gum devkit (static library) and generates FFI
//! bindings via bindgen. The devkit is automatically downloaded from GitHub
//! releases if not found locally.
//!
//! Set FRIDA_GUM_DEVKIT environment variable to use a custom devkit path.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_FRIDA_VERSION: &str = "17.5.2";

/// Known SHA-256 hashes for Frida-gum devkit archives.
/// Format: (version, os, arch) -> hex digest
const KNOWN_HASHES: &[(&str, &str, &str, &str)] = &[
    (
        "17.5.2",
        "macos",
        "arm64",
        "fee460f96bf5f248ef910ed05abe4eb0546cefd4a900548d538622fe4ab00bfe",
    ),
    (
        "17.5.2",
        "macos",
        "x86_64",
        "18e592fc1e0fb9c21f9dea2d4457e40371fdc26b66ca4e81c96af2c424e83d89",
    ),
    (
        "17.5.2",
        "linux",
        "x86_64",
        "aeb1040dfa01c3625353c468f6ee3ce009ba039b336073eca1f0394297e68fc4",
    ),
    (
        "17.5.2",
        "linux",
        "arm64",
        "de19422a37d6a1fd012febdc03e6c76a77ffa32663ecb56308211827544cfc52",
    ),
    (
        "17.5.2",
        "windows",
        "x86_64",
        "fcc89145bb5c713855c3282fe6d85bc07db55b8f7163de93e3d595af70ac4051",
    ),
];

fn main() {
    println!("cargo:rerun-if-env-changed=FRIDA_GUM_DEVKIT");
    println!("cargo:rerun-if-env-changed=FRIDA_VERSION");

    let devkit = find_or_download_devkit();

    // Link the static library
    println!("cargo:rustc-link-search=native={}", devkit.display());
    println!("cargo:rustc-link-lib=static=frida-gum");

    // Link system dependencies
    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=dl");
        println!("cargo:rustc-link-lib=rt");
        println!("cargo:rustc-link-lib=m");
        println!("cargo:rustc-link-lib=resolv");
    }

    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=bsm");
        println!("cargo:rustc-link-lib=resolv");
    }

    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-lib=kernel32");
        println!("cargo:rustc-link-lib=user32");
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=ole32");
        println!("cargo:rustc-link-lib=shell32");
        println!("cargo:rustc-link-lib=dbghelp");
    }

    // Generate bindings
    let header = devkit.join("frida-gum.h");
    println!("cargo:rerun-if-changed={}", header.display());

    #[allow(unused_mut)]
    let mut builder = bindgen::Builder::default()
        .header(header.to_string_lossy())
        .clang_arg(format!("-I{}", devkit.display()));

    // On Linux, we need to help clang find system headers
    #[cfg(target_os = "linux")]
    {
        let arch = env::consts::ARCH;
        let gcc_triple = match arch {
            "x86_64" => "x86_64-linux-gnu",
            "aarch64" => "aarch64-linux-gnu",
            _ => "x86_64-linux-gnu",
        };

        let gcc_base = format!("/usr/lib/gcc/{}", gcc_triple);
        if let Ok(entries) = std::fs::read_dir(&gcc_base) {
            let mut versions: Vec<_> = entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| {
                    n.chars()
                        .next()
                        .map(|c| c.is_ascii_digit())
                        .unwrap_or(false)
                })
                .collect();
            versions.sort_by(|a, b| b.cmp(a));

            if let Some(version) = versions.first() {
                let include_path = format!("{}/{}/include", gcc_base, version);
                if Path::new(&include_path).exists() {
                    builder = builder.clang_arg(format!("-I{}", include_path));
                }
            }
        }
    }

    let bindings = builder
        // gum functions and types
        .allowlist_function("gum_.*")
        .allowlist_type("Gum.*")
        .allowlist_var("GUM_.*")
        // GLib functions we need
        .allowlist_function("g_object_unref")
        .allowlist_function("g_object_ref")
        .allowlist_function("g_error_free")
        .allowlist_function("g_clear_error")
        .allowlist_type("GObject")
        .allowlist_type("GType")
        .allowlist_type("GList")
        .allowlist_type("GError")
        // GLib types
        .allowlist_type("gpointer")
        .allowlist_type("gconstpointer")
        .allowlist_type("gboolean")
        .allowlist_type("gchar")
        .allowlist_type("guint")
        .allowlist_type("gint")
        .allowlist_type("gsize")
        .allowlist_type("gssize")
        .allowlist_type("guint8")
        .allowlist_type("guint16")
        .allowlist_type("guint32")
        .allowlist_type("guint64")
        .allowlist_type("gint8")
        .allowlist_type("gint16")
        .allowlist_type("gint32")
        .allowlist_type("gint64")
        // Capstone register types used by writers/relocators
        .allowlist_type("arm64_reg")
        .allowlist_var("ARM64_REG_.*")
        .allowlist_type("x86_reg")
        .allowlist_var("X86_REG_.*")
        // Use Rust types where possible
        .size_t_is_usize(true)
        .derive_debug(true)
        .derive_default(true)
        .generate()
        .expect("Failed to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Failed to write bindings");
}

/// Get the persistent home-directory cache path for the devkit.
fn home_cache_dir() -> Option<PathBuf> {
    let home = env::var("HOME").or_else(|_| env::var("USERPROFILE")).ok()?;
    let (os, arch) = get_platform();
    let version = env::var("FRIDA_VERSION").unwrap_or_else(|_| DEFAULT_FRIDA_VERSION.to_string());
    Some(
        PathBuf::from(home)
            .join(".cache")
            .join("malwi")
            .join("frida-gum")
            .join(format!("{}-{}-{}", version, os, arch)),
    )
}

/// Check if a cache directory has a valid devkit with matching version marker.
fn is_cache_valid(cache_dir: &Path) -> bool {
    if !cache_dir.join("frida-gum.h").exists() {
        return false;
    }
    let version = env::var("FRIDA_VERSION").unwrap_or_else(|_| DEFAULT_FRIDA_VERSION.to_string());
    match fs::read_to_string(cache_dir.join(".version")) {
        Ok(v) => v.trim() == version,
        Err(_) => false,
    }
}

/// Write a version marker to a cache directory.
fn write_version_marker(cache_dir: &Path) {
    let version = env::var("FRIDA_VERSION").unwrap_or_else(|_| DEFAULT_FRIDA_VERSION.to_string());
    let _ = fs::write(cache_dir.join(".version"), version);
}

/// Find an existing devkit or download one.
fn find_or_download_devkit() -> PathBuf {
    // 1. Check environment variable
    if let Ok(path) = env::var("FRIDA_GUM_DEVKIT") {
        let p = PathBuf::from(&path);
        if p.join("frida-gum.h").exists() {
            return p;
        }
    }

    // 2. Check common locations
    let candidates = [
        "/usr/local/lib/frida-gum-devkit",
        "/opt/frida-gum-devkit",
        "frida-gum-devkit",
    ];

    for path in candidates {
        let p = PathBuf::from(path);
        if p.join("frida-gum.h").exists() {
            return p;
        }
    }

    // 3. Check home-directory persistent cache
    if let Some(home_cache) = home_cache_dir() {
        if is_cache_valid(&home_cache) {
            return home_cache;
        }
    }

    // 4. Check OUT_DIR cache (fallback for sandboxed CI)
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let cache_dir = PathBuf::from(&out_dir).join("frida-gum-devkit");
    if cache_dir.join("frida-gum.h").exists() {
        return cache_dir;
    }

    // 5. Download devkit — prefer home cache, fall back to OUT_DIR
    let download_dir = home_cache_dir().unwrap_or(cache_dir);
    download_devkit(&download_dir);
    write_version_marker(&download_dir);
    download_dir
}

/// Get platform identifiers for release URLs.
fn get_platform() -> (&'static str, &'static str) {
    let os = match env::consts::OS {
        "macos" => "macos",
        "linux" => "linux",
        "windows" => "windows",
        other => panic!("Unsupported OS: {}", other),
    };

    let arch = match env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "arm64",
        other => panic!("Unsupported architecture: {}", other),
    };

    (os, arch)
}

/// Look up the expected SHA-256 hash for a devkit archive.
fn expected_hash(version: &str, os: &str, arch: &str) -> Option<&'static str> {
    KNOWN_HASHES
        .iter()
        .find(|(v, o, a, _)| *v == version && *o == os && *a == arch)
        .map(|(_, _, _, h)| *h)
}

/// Compute SHA-256 hex digest of a file.
fn sha256_file(path: &Path) -> String {
    #[cfg(not(target_os = "windows"))]
    {
        let output = Command::new("shasum")
            .args(["-a", "256"])
            .arg(path)
            .output()
            .or_else(|_| Command::new("sha256sum").arg(path).output())
            .expect("Failed to run shasum or sha256sum");
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.split_whitespace().next().unwrap_or("").to_string()
    }
    #[cfg(target_os = "windows")]
    {
        let script = format!(
            "(Get-FileHash -Path '{}' -Algorithm SHA256).Hash.ToLower()",
            path.display()
        );
        let output = Command::new("powershell")
            .args(["-Command", &script])
            .output()
            .expect("Failed to run PowerShell for hash verification");
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }
}

/// Download and extract the devkit.
fn download_devkit(dest: &Path) {
    let (os, arch) = get_platform();
    let version = env::var("FRIDA_VERSION").unwrap_or_else(|_| DEFAULT_FRIDA_VERSION.to_string());
    let url = format!(
        "https://github.com/frida/frida/releases/download/{version}/frida-gum-devkit-{version}-{os}-{arch}.tar.xz",
        version = version,
        os = os,
        arch = arch
    );

    eprintln!("Downloading devkit {} for {}-{}", version, os, arch);

    fs::create_dir_all(dest).expect("Failed to create devkit directory");

    let archive_path = dest.join("devkit.tar.xz");

    #[cfg(not(target_os = "windows"))]
    {
        let status = Command::new("curl")
            .args(["-sSL", "-o"])
            .arg(&archive_path)
            .arg(&url)
            .status()
            .expect("Failed to execute curl. Make sure curl is installed.");

        if !status.success() {
            panic!(
                "Failed to download devkit.\n\
                 URL: {}\n\
                 You can manually download and extract to: {}",
                url,
                dest.display()
            );
        }
    }

    #[cfg(target_os = "windows")]
    {
        let script = format!(
            r#"
            $ProgressPreference = 'SilentlyContinue'
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri '{}' -OutFile '{}'
            "#,
            url,
            archive_path.display()
        );

        let status = Command::new("powershell")
            .args(["-ExecutionPolicy", "Bypass", "-Command", &script])
            .status()
            .expect("Failed to execute PowerShell");

        if !status.success() {
            panic!(
                "Failed to download devkit.\n\
                 URL: {}\n\
                 You can manually download and extract to: {}",
                url,
                dest.display()
            );
        }
    }

    // Verify SHA-256 hash
    let actual_hash = sha256_file(&archive_path);
    if let Some(expected) = expected_hash(&version, os, arch) {
        if actual_hash != expected {
            let _ = fs::remove_file(&archive_path);
            panic!(
                "SHA-256 hash mismatch for devkit!\n\
                 Expected: {}\n\
                 Got:      {}\n\
                 The downloaded archive may be corrupted or tampered with.\n\
                 URL: {}",
                expected, actual_hash, url
            );
        }
    } else {
        eprintln!(
            "No known hash for devkit {}-{}-{}, skipping verification (SHA-256: {})",
            version, os, arch, actual_hash
        );
    }

    // Extract the verified archive
    #[cfg(not(target_os = "windows"))]
    {
        let status = Command::new("tar")
            .args(["-xJf"])
            .arg(&archive_path)
            .arg("-C")
            .arg(dest)
            .status()
            .expect("Failed to execute tar");

        if !status.success() {
            panic!("Failed to extract devkit archive");
        }
    }

    #[cfg(target_os = "windows")]
    {
        let status = Command::new("tar")
            .args(["-xf"])
            .arg(&archive_path)
            .arg("-C")
            .arg(dest)
            .status()
            .expect("Failed to execute tar");

        if !status.success() {
            panic!("Failed to extract devkit archive");
        }
    }

    // Clean up archive
    let _ = fs::remove_file(&archive_path);

    // Verify extraction
    if !dest.join("frida-gum.h").exists() {
        panic!(
            "Downloaded devkit is missing frida-gum.h.\n\
             Expected at: {}\n\
             The archive may have a different structure.",
            dest.join("frida-gum.h").display()
        );
    }

    eprintln!("Devkit downloaded successfully to {}", dest.display());
}
