//! Build script for V8 addon embedding
//!
//! Detects platform and sets per-version cfg flags for conditional compilation.
//! Each Node.js version gets its own `has_v8_addon_nodeXX` flag, so contributors
//! who only have some versions installed still get JS tracing for those versions.

fn main() {
    // Declare custom cfg flags to avoid warnings
    println!("cargo::rustc-check-cfg=cfg(has_v8_addon)");
    for version in ["node21", "node22", "node23", "node24", "node25"] {
        println!("cargo::rustc-check-cfg=cfg(has_v8_addon_{version})");
    }
    println!("cargo:rerun-if-changed=../node-addon/prebuilt");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    let platform = match (target_os.as_str(), target_arch.as_str()) {
        ("macos", "aarch64") => "darwin-arm64",
        ("macos", "x86_64") => "darwin-x64",
        ("linux", "x86_64") => "linux-x64",
        ("linux", "aarch64") => "linux-arm64",
        ("windows", "x86_64") => "windows-x64",
        _ => {
            println!(
                "cargo:warning=V8 addon: unsupported platform {}-{}",
                target_os, target_arch
            );
            return;
        }
    };

    let prebuilt_dir = format!("../node-addon/prebuilt/{}", platform);
    let mut has_any = false;
    let mut found = Vec::new();

    for version in ["node21", "node22", "node23", "node24", "node25"] {
        let addon_path = format!("{}/{}/v8_introspect.node", prebuilt_dir, version);
        if std::path::Path::new(&addon_path).exists() {
            println!("cargo:rustc-cfg=has_v8_addon_{version}");
            found.push(version);
            has_any = true;
        }
    }

    if has_any {
        println!("cargo:rustc-cfg=has_v8_addon");
    } else {
        println!(
            "cargo:warning=V8 addon: no prebuilt binaries found for {}",
            platform
        );
    }
}
