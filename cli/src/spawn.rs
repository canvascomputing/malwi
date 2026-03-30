//! Spawn a process with the agent library preloaded.

use anyhow::{Context, Result};
use log::debug;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use crate::{RED, RESET};

/// Find a program in PATH (Unix-only replacement for `which` crate).
fn find_in_path(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?
        .to_str()?
        .split(':')
        .map(|dir| PathBuf::from(dir).join(program))
        .find(|path| path.is_file())
}

/// Check if a binary is SIP-restricted on macOS.
///
/// SIP-restricted binaries (like those in /usr/bin/) have the `restricted` flag
/// which causes the kernel to strip DYLD_INSERT_LIBRARIES, preventing injection.
#[cfg(target_os = "macos")]
fn check_sip_restriction(program: &str) -> Option<String> {
    // Resolve to full path
    let path = if Path::new(program).exists() {
        Path::new(program).to_path_buf()
    } else {
        find_in_path(program)?
    };

    // Use stat to get file flags
    let path_cstr = std::ffi::CString::new(path.to_string_lossy().as_bytes()).ok()?;
    let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };

    let result = unsafe { libc::stat(path_cstr.as_ptr(), &mut stat_buf) };
    if result != 0 {
        return None;
    }

    // SF_RESTRICTED = 0x00080000 (restricted flag indicating SIP protection)
    const SF_RESTRICTED: u32 = 0x00080000;

    if (stat_buf.st_flags & SF_RESTRICTED) != 0 {
        Some(path.to_string_lossy().to_string())
    } else {
        None
    }
}

/// Resolve `#!/usr/bin/env <interpreter>` shebangs to avoid SIP restrictions.
///
/// **Why this is needed:**
/// On macOS, `/usr/bin/env` has the `restricted` flag (System Integrity Protection).
/// When a script like `npm` uses `#!/usr/bin/env node`, the kernel invokes
/// `/usr/bin/env` first, which strips `DYLD_INSERT_LIBRARIES` before executing
/// the actual interpreter. This prevents our agent from being injected.
///
/// **Solution:**
/// Detect scripts with `#!/usr/bin/env <interpreter>` shebangs, resolve the
/// interpreter to its actual path (e.g., `/usr/local/bin/node`), and spawn
/// the interpreter directly with the script as an argument. This bypasses
/// the SIP-protected `/usr/bin/env` entirely.
///
/// Returns `Some((interpreter_path, script_path))` if resolution succeeded,
/// or `None` if the program is not a script or doesn't use `/usr/bin/env`.
fn resolve_env_shebang(program: &str) -> Option<(String, String)> {
    // First, resolve the program to a full path (handles both "npm" and "/usr/local/bin/npm")
    let path = if Path::new(program).is_file() {
        Path::new(program).to_path_buf()
    } else {
        // Try to find it in PATH
        find_in_path(program)?
    };

    // Try to read the first line
    let file = File::open(&path).ok()?;
    let mut reader = BufReader::new(file);
    let mut first_line = String::new();
    reader.read_line(&mut first_line).ok()?;

    // Check for #!/usr/bin/env <interpreter>
    let shebang = first_line.trim();
    if !shebang.starts_with("#!/usr/bin/env ") {
        return None;
    }

    // Extract the interpreter name (e.g., "node", "python3")
    let interpreter = shebang.strip_prefix("#!/usr/bin/env ")?.trim();
    if interpreter.is_empty() {
        return None;
    }

    // Handle interpreters with arguments (e.g., "python3 -u")
    let interpreter_name = interpreter.split_whitespace().next()?;

    // Find the actual interpreter path using PATH lookup
    let interpreter_path = find_in_path(interpreter_name)?;

    // Get the canonical path to the script
    let script_path = path.canonicalize().ok()?;

    debug!(
        "Resolved shebang: {} -> {} {}",
        program,
        interpreter_path.display(),
        script_path.display()
    );

    Some((
        interpreter_path.to_string_lossy().to_string(),
        script_path.to_string_lossy().to_string(),
    ))
}

/// Find the agent library path.
fn find_agent_library() -> Result<String> {
    use malwi_intercept::platform::{agent_lib_name, installed_lib_paths};
    use std::path::PathBuf;

    let lib_name = agent_lib_name();

    // Build search paths dynamically
    let mut candidates: Vec<PathBuf> = vec![
        // Development builds (relative to CWD)
        format!("./target/release/{}", lib_name).into(),
        format!("./target/debug/{}", lib_name).into(),
    ];

    // Search relative to the executable (works for pip-installed binaries)
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            // {prefix}/bin/../lib/ -> {prefix}/lib/
            candidates.push(exe_dir.join("..").join("lib").join(&lib_name));
        }
        // Resolve symlinks (e.g., pipx: ~/.local/bin/malwi → venv/bin/malwi)
        if let Ok(resolved) = exe_path.canonicalize() {
            if resolved != exe_path {
                if let Some(exe_dir) = resolved.parent() {
                    candidates.push(exe_dir.join("..").join("lib").join(&lib_name));
                }
            }
        }
    }

    // Add platform-specific installed paths
    for install_path in installed_lib_paths() {
        candidates.push(install_path.join(&lib_name));
    }

    for candidate in &candidates {
        if candidate.exists() {
            // Return absolute path (required for agent injection)
            let abs_path = candidate
                .canonicalize()
                .with_context(|| format!("Failed to canonicalize path: {:?}", candidate))?;
            return Ok(abs_path.to_string_lossy().to_string());
        }
    }

    // Check MALWI_AGENT_LIB environment variable
    if let Ok(path) = std::env::var("MALWI_AGENT_LIB") {
        let p = std::path::Path::new(&path);
        if p.exists() {
            let abs_path = p
                .canonicalize()
                .with_context(|| format!("Failed to canonicalize path: {}", path))?;
            return Ok(abs_path.to_string_lossy().to_string());
        }
    }

    // Final fallback: extract embedded agent library
    if let Some(path) = crate::embedded_agent::extract_embedded_agent() {
        return Ok(path);
    }

    anyhow::bail!(
        "Agent library not found. Build with 'cargo build --release' or set MALWI_AGENT_LIB"
    )
}

/// Spawn a process with agent injection (macOS only).
///
/// This spawns the process suspended with DYLD_INSERT_LIBRARIES set,
/// then resumes the process. The agent is loaded automatically.
#[cfg(target_os = "macos")]
pub fn spawn_with_injection(program: &str, args: &[String], url: &str) -> Result<libc::pid_t> {
    let agent_lib = find_agent_library()?;
    debug!("Agent library: {}", agent_lib);

    // Resolve #!/usr/bin/env shebangs to bypass SIP restrictions
    let (actual_program, mut actual_args): (String, Vec<String>) =
        if let Some((interpreter, script)) = resolve_env_shebang(program) {
            // Prepend the script path to the original args
            let mut new_args = vec![script];
            new_args.extend(args.iter().cloned());
            (interpreter, new_args)
        } else {
            (program.to_string(), args.to_vec())
        };

    // Check if the resolved binary is SIP-protected - if so, exit early
    if let Some(restricted_path) = check_sip_restriction(&actual_program) {
        eprintln!(
            "{}[malwi] Error: '{}' is SIP-protected and cannot be traced.\nUse binaries in unprotected paths (/usr/local, /opt, ~) or disable SIP.{}",
            RED, restricted_path, RESET
        );
        std::process::exit(1);
    }

    // Node.js tracing uses frida-gum hooks exclusively (V8 --trace flag,
    // Runtime_TraceEnter/Exit, codegen gate). No NODE_OPTIONS or --require
    // wrapper needed — this avoids interfering with child Node.js processes
    // (npm, npx) and eliminates the N-API boundary crossing issues.

    // Spawn the process with agent library preloaded via DYLD_INSERT_LIBRARIES
    let pid = crate::native_spawn::spawn_suspended(
        &actual_program,
        &actual_args,
        Some(&agent_lib),
        Some(url),
    )?;
    debug!("Spawned process with agent preloaded, PID {}", pid);

    // Resume the process
    if let Err(e) = crate::native_spawn::resume_process(pid) {
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        return Err(e.context(format!("Failed to resume process {} after spawn", pid)));
    }

    Ok(pid as libc::pid_t)
}

/// Spawn a process with agent injection using LD_PRELOAD (Linux).
///
/// This spawns the process suspended with LD_PRELOAD set,
/// then resumes the process. The agent is loaded automatically.
#[cfg(target_os = "linux")]
pub fn spawn_with_injection(program: &str, args: &[String], url: &str) -> Result<libc::pid_t> {
    let agent_lib = find_agent_library()?;
    debug!("Agent library: {}", agent_lib);

    // Resolve #!/usr/bin/env shebangs (for consistency with macOS, though
    // Linux doesn't have SIP restrictions - still useful for other reasons)
    let (actual_program, mut actual_args): (String, Vec<String>) =
        if let Some((interpreter, script)) = resolve_env_shebang(program) {
            let mut new_args = vec![script];
            new_args.extend(args.iter().cloned());
            (interpreter, new_args)
        } else {
            (program.to_string(), args.to_vec())
        };

    // Spawn the process with agent library preloaded via LD_PRELOAD
    let pid = crate::native_spawn::spawn_suspended(
        &actual_program,
        &actual_args,
        Some(&agent_lib),
        Some(url),
    )?;
    debug!("Spawned process with agent preloaded, PID {}", pid);

    // Resume the process
    if let Err(e) = crate::native_spawn::resume_process(pid) {
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        return Err(e.context(format!("Failed to resume process {} after spawn", pid)));
    }

    Ok(pid as libc::pid_t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_agent_library() {
        // This will fail in test environment, which is expected
        let result = find_agent_library();
        // Just verify it doesn't panic
        let _ = result;
    }
}
