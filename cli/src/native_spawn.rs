//! Native process spawning using POSIX APIs.
//!
//! Spawns processes in a suspended state with optional library preloading
//! via platform-specific environment variables:
//! - macOS: DYLD_INSERT_LIBRARIES + DYLD_FORCE_FLAT_NAMESPACE (posix_spawn)
//! - Linux: LD_PRELOAD (fork + SIGSTOP + exec)

use anyhow::{anyhow, Result};
use log::debug;

#[cfg(target_os = "macos")]
use std::ffi::CString;
#[cfg(target_os = "macos")]
use std::path::Path;
#[cfg(target_os = "macos")]
use std::ptr;

/// Resolve a program name to its full path by searching PATH.
///
/// If the program is already an absolute path or contains a path separator,
/// it is returned as-is. Otherwise, the PATH environment variable is searched.
#[cfg(target_os = "macos")]
fn resolve_program_path(program: &str) -> Result<String> {
    let path = Path::new(program);

    // If it's already absolute or contains a directory component, use as-is
    if path.is_absolute() || program.contains('/') {
        return Ok(program.to_string());
    }

    // Search PATH
    if let Ok(path_env) = std::env::var("PATH") {
        for dir in path_env.split(':') {
            let candidate = Path::new(dir).join(program);
            if candidate.is_file() {
                // Check if executable (on Unix)
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = candidate.metadata() {
                    if metadata.permissions().mode() & 0o111 != 0 {
                        return Ok(candidate.to_string_lossy().to_string());
                    }
                }
            }
        }
    }

    Err(anyhow!("Program '{}' not found in PATH", program))
}

/// Spawn a process in suspended state with optional library preloading.
///
/// Returns the PID of the spawned process. The process must be resumed
/// using `resume_process()`.
#[cfg(target_os = "macos")]
pub fn spawn_suspended(
    program: &str,
    args: &[String],
    agent_lib: Option<&str>,
    url: Option<&str>,
) -> Result<u32> {
    use libc::{
        posix_spawn, posix_spawnattr_destroy, posix_spawnattr_init, posix_spawnattr_setflags,
        posix_spawnattr_t, POSIX_SPAWN_START_SUSPENDED,
    };

    if let Some(lib) = agent_lib {
        debug!("Setting library preload for: {}", lib);
    }
    if let Some(u) = url {
        debug!("Setting MALWI_URL={}", u);
    }

    // Resolve program path (posix_spawn doesn't search PATH)
    let resolved_program = resolve_program_path(program)?;

    // Convert program to CString
    let program_cstr = CString::new(resolved_program.as_str())
        .map_err(|_| anyhow!("Invalid program path: contains null byte"))?;

    // Build argv: [program, ...args, NULL]
    let mut argv_cstrs: Vec<CString> = Vec::with_capacity(args.len() + 2);
    argv_cstrs.push(program_cstr.clone());
    for arg in args {
        argv_cstrs.push(
            CString::new(arg.as_str())
                .map_err(|_| anyhow!("Invalid argument: contains null byte"))?,
        );
    }

    let mut argv_ptrs: Vec<*mut libc::c_char> = argv_cstrs
        .iter()
        .map(|s| s.as_ptr() as *mut libc::c_char)
        .collect();
    argv_ptrs.push(ptr::null_mut());

    // Build environment
    let mut env_entries: Vec<CString> = Vec::new();

    // Inherit current environment, excluding our special variables
    for (key, value) in std::env::vars() {
        // Skip variables we'll set ourselves
        if key.starts_with("DYLD_") || key == "MALWI_URL" {
            continue;
        }
        if let Ok(entry) = CString::new(format!("{}={}", key, value)) {
            env_entries.push(entry);
        }
    }

    // Add library preload
    if let Some(lib) = agent_lib {
        env_entries.push(
            CString::new(format!("DYLD_INSERT_LIBRARIES={}", lib))
                .map_err(|_| anyhow!("Invalid library path"))?,
        );
        env_entries
            .push(CString::new("DYLD_FORCE_FLAT_NAMESPACE=1").expect("static string"));
    }

    // Add server URL
    if let Some(u) = url {
        env_entries.push(
            CString::new(format!("MALWI_URL={}", u)).map_err(|_| anyhow!("Invalid URL"))?,
        );
    }

    let mut envp_ptrs: Vec<*mut libc::c_char> = env_entries
        .iter()
        .map(|s| s.as_ptr() as *mut libc::c_char)
        .collect();
    envp_ptrs.push(ptr::null_mut());

    // Initialize spawn attributes
    let mut attr: posix_spawnattr_t = unsafe { std::mem::zeroed() };

    unsafe {
        let ret = posix_spawnattr_init(&mut attr);
        if ret != 0 {
            return Err(anyhow!(
                "posix_spawnattr_init failed: {}",
                std::io::Error::from_raw_os_error(ret)
            ));
        }

        // Set POSIX_SPAWN_START_SUSPENDED flag to spawn process in suspended state
        let ret =
            posix_spawnattr_setflags(&mut attr, POSIX_SPAWN_START_SUSPENDED as libc::c_short);
        if ret != 0 {
            posix_spawnattr_destroy(&mut attr);
            return Err(anyhow!(
                "posix_spawnattr_setflags failed: {}",
                std::io::Error::from_raw_os_error(ret)
            ));
        }
    }

    // Spawn the process
    let mut pid: libc::pid_t = 0;
    let result = unsafe {
        posix_spawn(
            &mut pid,
            program_cstr.as_ptr(),
            ptr::null(),  // file_actions - inherit file descriptors
            &attr,
            argv_ptrs.as_ptr() as *const *mut libc::c_char,
            envp_ptrs.as_ptr() as *const *mut libc::c_char,
        )
    };

    // Cleanup attributes
    unsafe {
        posix_spawnattr_destroy(&mut attr);
    }

    if result != 0 {
        return Err(anyhow!(
            "posix_spawn failed for '{}': {}",
            resolved_program,
            std::io::Error::from_raw_os_error(result)
        ));
    }

    debug!("Spawned process '{}' with PID {} (suspended)", program, pid);
    Ok(pid as u32)
}

/// Spawn a process in suspended state with optional library preloading.
///
/// Linux implementation uses fork + raise(SIGSTOP) + exec pattern.
#[cfg(target_os = "linux")]
pub fn spawn_suspended(
    program: &str,
    args: &[String],
    agent_lib: Option<&str>,
    url: Option<&str>,
) -> Result<u32> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    if let Some(lib) = agent_lib {
        debug!("Setting library preload for: {}", lib);
    }
    if let Some(u) = url {
        debug!("Setting MALWI_URL={}", u);
    }

    // We use a simpler approach: fork, child raises SIGSTOP, then execs
    let pid = unsafe { libc::fork() };

    match pid {
        -1 => Err(anyhow!(
            "fork failed: {}",
            std::io::Error::last_os_error()
        )),
        0 => {
            // Child process

            // Set LD_PRELOAD for library injection
            if let Some(lib) = agent_lib {
                std::env::set_var("LD_PRELOAD", lib);
            }

            // Set server URL
            if let Some(u) = url {
                std::env::set_var("MALWI_URL", u);
            }

            // Stop ourselves - parent will resume us after setup
            unsafe {
                libc::raise(libc::SIGSTOP);
            }

            // Now exec the target program
            let mut cmd = Command::new(program);
            cmd.args(args);

            // exec replaces this process
            let err = cmd.exec();
            eprintln!("exec failed for '{}': {}", program, err);
            std::process::exit(127);
        }
        child_pid => {
            // Parent process

            // Wait for child to stop itself
            let mut status: libc::c_int = 0;
            let wait_result =
                unsafe { libc::waitpid(child_pid, &mut status, libc::WUNTRACED) };

            if wait_result == -1 {
                // Kill the child if we failed to wait
                unsafe {
                    libc::kill(child_pid, libc::SIGKILL);
                }
                return Err(anyhow!(
                    "waitpid failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            // Check if child stopped (as expected)
            if !libc::WIFSTOPPED(status) {
                return Err(anyhow!(
                    "Child process did not stop as expected (status: {})",
                    status
                ));
            }

            debug!(
                "Spawned process '{}' with PID {} (suspended)",
                program, child_pid
            );
            Ok(child_pid as u32)
        }
    }
}

/// Resume a suspended process.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn resume_process(pid: u32) -> Result<()> {
    let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGCONT) };

    if result != 0 {
        return Err(anyhow!(
            "Failed to resume PID {}: {}",
            pid,
            std::io::Error::last_os_error()
        ));
    }

    debug!("Resumed process {}", pid);
    Ok(())
}

// Fallback for unsupported platforms
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const UNSUPPORTED_MSG: &str = "The 'spawn' command is only supported on macOS and Linux. \
Windows support for process spawning with agent injection is not yet implemented.";

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn spawn_suspended(
    _program: &str,
    _args: &[String],
    _agent_lib: Option<&str>,
    _url: Option<&str>,
) -> Result<u32> {
    anyhow::bail!(UNSUPPORTED_MSG)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn resume_process(_pid: u32) -> Result<()> {
    anyhow::bail!(UNSUPPORTED_MSG)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn test_spawn_and_resume_executes_process() {
        let pid = spawn_suspended("/bin/echo", &["test".to_string()], None, None)
            .expect("spawn failed");

        assert!(pid > 0, "Expected positive PID");

        resume_process(pid).expect("resume failed");

        let mut status: libc::c_int = 0;
        unsafe {
            libc::waitpid(pid as libc::pid_t, &mut status, 0);
        }

        assert!(
            libc::WIFEXITED(status),
            "Process should have exited normally"
        );
    }
}
