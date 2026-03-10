use std::env;
use std::path::PathBuf;

fn main() {
    // Declare custom cfg so the compiler doesn't warn about it
    println!("cargo::rustc-check-cfg=cfg(embedded_agent)");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let lib_name = match target_os.as_str() {
        "macos" => "libmalwi_agent.dylib",
        "windows" => "malwi_agent.dll",
        _ => "libmalwi_agent.so",
    };

    // Search order for the agent library
    let mut search_paths: Vec<PathBuf> = Vec::new();

    // 1. Explicit env var override
    if let Ok(path) = env::var("MALWI_AGENT_LIB_PATH") {
        search_paths.push(PathBuf::from(path));
    }

    // 2. target/{TARGET}/release/ (cross-compilation)
    if let Ok(target) = env::var("TARGET") {
        search_paths.push(
            PathBuf::from("../target")
                .join(&target)
                .join("release")
                .join(lib_name),
        );
    }

    // 3. target/release/ and target/debug/
    search_paths.push(PathBuf::from("../target/release").join(lib_name));
    search_paths.push(PathBuf::from("../target/debug").join(lib_name));

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    for candidate in &search_paths {
        if candidate.exists() {
            let dest = out_dir.join(lib_name);
            if let Err(e) = std::fs::copy(candidate, &dest) {
                println!(
                    "cargo:warning=Failed to copy agent library to OUT_DIR: {}",
                    e
                );
                continue;
            }
            println!("cargo:rustc-cfg=embedded_agent");
            println!(
                "cargo:warning=Embedding agent library from {}",
                candidate.display()
            );
            // Re-run if the agent library changes
            println!("cargo:rerun-if-changed={}", candidate.display());
            return;
        }
    }

    println!("cargo:warning=Agent library not found — building without embedded agent");
    // Re-run if any of the expected locations change
    for candidate in &search_paths {
        println!("cargo:rerun-if-changed={}", candidate.display());
    }
}
