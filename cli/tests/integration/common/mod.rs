//! Common test utilities for integration tests.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::Once;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

/// Counter for skipped Node.js tests
pub static NODEJS_SKIPS: AtomicUsize = AtomicUsize::new(0);
/// Counter for skipped Python tests
pub static PYTHON_SKIPS: AtomicUsize = AtomicUsize::new(0);
/// Counter for skipped Bash tests
pub static BASH_SKIPS: AtomicUsize = AtomicUsize::new(0);

/// Search PATH for an executable by name.
pub fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?
        .to_str()?
        .split(':')
        .map(|dir| PathBuf::from(dir).join(name))
        .find(|p| p.is_file())
}

/// Supported runtime types for testing
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Runtime {
    Node,
    Python,
    Bash,
}

impl Runtime {
    /// Subdirectory name under MALWI_TEST_BINARIES/{arch}/{os}/
    pub fn subdir(&self) -> &'static str {
        match self {
            Runtime::Node => "node",
            Runtime::Python => "python",
            Runtime::Bash => "bash",
        }
    }

    /// Get the skip counter for this runtime
    pub fn skip_counter(&self) -> &'static AtomicUsize {
        match self {
            Runtime::Node => &NODEJS_SKIPS,
            Runtime::Python => &PYTHON_SKIPS,
            Runtime::Bash => &BASH_SKIPS,
        }
    }

    /// Name for display in messages
    pub fn name(&self) -> &'static str {
        match self {
            Runtime::Node => "Node.js",
            Runtime::Python => "Python",
            Runtime::Bash => "Bash",
        }
    }

    /// Find this runtime in PATH
    pub fn find_in_path(&self) -> Option<PathBuf> {
        match self {
            Runtime::Node => which("node"),
            Runtime::Python => which("python3"),
            Runtime::Bash => which("bash"),
        }
    }
}

/// Get the version number from a runtime binary.
/// For Node: returns major version (e.g., 23 for v23.11.1)
/// For Python: returns minor version (e.g., 12 for 3.12.0)
pub fn get_runtime_version(runtime: Runtime, binary: &Path) -> Option<u32> {
    match runtime {
        Runtime::Node => get_node_major_version(binary),
        Runtime::Python => get_python_minor_version(binary),
        Runtime::Bash => get_bash_major_version(binary),
    }
}

/// Find all binaries for a runtime from MALWI_TEST_BINARIES, project binaries/, or PATH
pub fn find_all_runtimes(runtime: Runtime) -> Vec<PathBuf> {
    let base = if let Ok(val) = std::env::var("MALWI_TEST_BINARIES") {
        Some(PathBuf::from(val))
    } else {
        // Auto-detect: project-root/binaries/
        let project_binaries = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("binaries");
        if project_binaries.is_dir() {
            Some(project_binaries)
        } else {
            None
        }
    };

    if let Some(base) = base {
        let (arch, os) = current_platform();
        let dir = base.join(arch).join(os).join(runtime.subdir());
        if dir.is_dir() {
            let binaries = discover_runtime_binaries(runtime, &dir);
            if !binaries.is_empty() {
                return binaries;
            }
        }
    }

    // Fallback: use PATH
    runtime.find_in_path().into_iter().collect()
}

/// Discover runtime binaries in a directory
fn discover_runtime_binaries(runtime: Runtime, dir: &Path) -> Vec<PathBuf> {
    let mut binaries = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Some(binary) = match_runtime_entry(runtime, &entry) {
                binaries.push(binary);
            }
        }
    }
    binaries.sort();
    binaries
}

/// Match a directory entry to a runtime binary
fn match_runtime_entry(runtime: Runtime, entry: &std::fs::DirEntry) -> Option<PathBuf> {
    let name = entry.file_name().to_string_lossy().to_string();
    let path = entry.path();

    match runtime {
        Runtime::Node => {
            if name.starts_with("node") {
                if path.is_file() {
                    return Some(path);
                } else if path.is_dir() {
                    let binary = path.join("bin").join("node");
                    if binary.is_file() {
                        return Some(binary);
                    }
                }
            }
        }
        Runtime::Python => {
            if name.starts_with("python3.") {
                // Standalone binary (e.g., python3.12)
                if path.is_file() {
                    return Some(path);
                }
                // Directory with bin/ subdirectory
                if path.is_dir() {
                    // Try exact name first (e.g., python3.12/bin/python3.12)
                    let binary = path.join("bin").join(&name);
                    if binary.is_file() {
                        return Some(binary);
                    }
                    // Try minor version (e.g., python3.14.3/bin/python3.14)
                    if let Some(dot2) = name.rfind('.') {
                        let minor_name = &name[..dot2];
                        if minor_name.contains('.') {
                            let binary = path.join("bin").join(minor_name);
                            if binary.is_file() {
                                return Some(binary);
                            }
                        }
                    }
                }
            }
        }
        Runtime::Bash => {
            // Match files like "bash-5.3", "bash-5.2", "bash-5.1" (direct executables)
            if name.starts_with("bash") && path.is_file() {
                return Some(path);
            }
        }
    }
    None
}

/// Helper macro to iterate over all available runtime versions.
/// Continues testing all versions even if some fail, then reports failures.
///
/// Usage:
///   for_each_runtime!(Runtime::Node, node => { ... });
///   for_each_runtime!(Runtime::Node, node, max_version: 23 => { ... });
///   for_each_runtime!(Runtime::Python, python => { ... });
///   for_each_runtime!(Runtime::Python, python, max_version: 12 => { ... });
#[macro_export]
macro_rules! for_each_runtime {
    ($runtime:expr, $var:ident => $body:block) => {{
        $crate::for_each_runtime!($runtime, $var, max_version: 9999 => $body);
    }};
    ($runtime:expr, $var:ident, max_version: $max:expr => $body:block) => {{
        let runtime = $runtime;
        let all_binaries = $crate::common::find_all_runtimes(runtime);
        let binaries: Vec<_> = all_binaries.into_iter().filter(|b| {
            $crate::common::get_runtime_version(runtime, b).map(|v| v <= $max).unwrap_or(true)
        }).collect();

        if binaries.is_empty() {
            runtime.skip_counter().fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            println!("SKIPPED: No compatible {} found (need version <= {})", runtime.name(), $max);
            return;
        }

        let total_versions = binaries.len();
        let mut tested_versions: Vec<String> = Vec::new();
        let mut failures: Vec<(std::path::PathBuf, String)> = Vec::new();

        for $var in &binaries {
            let version = $crate::common::get_runtime_version(runtime, $var);
            let version_str = version
                .map(|v| format!("v{}", v))
                .unwrap_or_else(|| "unknown".to_string());
            println!("Testing with: {} ({})", $var.display(), version_str);

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let $var = $var.clone();
                $body
            }));
            if let Err(e) = result {
                let msg = if let Some(s) = e.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = e.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown panic".to_string()
                };
                println!("FAILED: {}", msg);
                failures.push(($var.clone(), msg));
            } else {
                tested_versions.push(version_str);
            }
        }

        // Print per-test summary
        if total_versions > 1 {
            println!("=== {} Summary: {}/{} versions passed ({}) ===",
                runtime.name(),
                tested_versions.len(),
                total_versions,
                tested_versions.join(", "));
        }

        if !failures.is_empty() {
            panic!("Test failed for {} {} version(s):\n{}",
                failures.len(),
                runtime.name(),
                failures.iter()
                    .map(|(p, m)| format!("  - {}: {}", p.display(), m))
                    .collect::<Vec<_>>()
                    .join("\n"));
        }
    }};
}

/// Helper macro to iterate over all available Node.js versions.
/// Delegates to for_each_runtime! for backward compatibility.
#[macro_export]
macro_rules! skip_if_no_node {
    ($node:ident => $body:block) => {{
        $crate::for_each_runtime!($crate::common::Runtime::Node, $node => $body);
    }};
    ($node:ident, max_major: $max:expr => $body:block) => {{
        $crate::for_each_runtime!($crate::common::Runtime::Node, $node, max_version: $max => $body);
    }};
}

/// Helper macro to iterate over all available Python versions.
/// Delegates to for_each_runtime! for backward compatibility.
#[macro_export]
macro_rules! skip_if_no_python {
    ($python:ident => $body:block) => {{
        $crate::for_each_runtime!($crate::common::Runtime::Python, $python => $body);
    }};
    ($python:ident, max_minor: $max:expr => $body:block) => {{
        $crate::for_each_runtime!($crate::common::Runtime::Python, $python, max_version: $max => $body);
    }};
}

/// Helper macro to iterate over all available Bash versions.
/// Delegates to for_each_runtime!.
#[macro_export]
macro_rules! skip_if_no_bash {
    ($bash:ident => $body:block) => {{
        $crate::for_each_runtime!($crate::common::Runtime::Bash, $bash => $body);
    }};
    ($bash:ident, max_major: $max:expr => $body:block) => {{
        $crate::for_each_runtime!($crate::common::Runtime::Bash, $bash, max_version: $max => $body);
    }};
}

/// Helper macro that picks only the first discovered binary for a runtime.
/// Use for tests that verify runtime-agnostic behavior (policy enforcement,
/// libc symbol hooks) where multi-version expansion is unnecessary.
#[macro_export]
macro_rules! skip_if_no_node_primary {
    ($node:ident => $body:block) => {{
        let all = $crate::common::find_all_runtimes($crate::common::Runtime::Node);
        if all.is_empty() {
            $crate::common::NODEJS_SKIPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            println!("SKIPPED: No Node.js found");
            return;
        }
        let $node = all[0].clone();
        println!("Testing with: {} (primary)", $node.display());
        $body
    }};
}

#[macro_export]
macro_rules! skip_if_no_python_primary {
    ($python:ident => $body:block) => {{
        let all = $crate::common::find_all_runtimes($crate::common::Runtime::Python);
        if all.is_empty() {
            $crate::common::PYTHON_SKIPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            println!("SKIPPED: No Python found");
            return;
        }
        let $python = all[0].clone();
        println!("Testing with: {} (primary)", $python.display());
        $body
    }};
}

#[macro_export]
macro_rules! skip_if_no_bash_primary {
    ($bash:ident => $body:block) => {{
        let all = $crate::common::find_all_runtimes($crate::common::Runtime::Bash);
        if all.is_empty() {
            $crate::common::BASH_SKIPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            println!("SKIPPED: No Bash found");
            return;
        }
        let $bash = all[0].clone();
        println!("Testing with: {} (primary)", $bash.display());
        $body
    }};
}

/// Strip ANSI escape codes from a string.
pub fn strip_ansi_codes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip escape sequence
            if chars.peek() == Some(&'[') {
                chars.next(); // consume '['
                              // Skip until we hit a letter (end of escape sequence)
                while let Some(&next) = chars.peek() {
                    chars.next();
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Path to the malwi binary
pub fn tracer_binary() -> PathBuf {
    // cargo test builds the binary and sets this env var
    PathBuf::from(env!("CARGO_BIN_EXE_malwi"))
}

/// Path to test programs directory
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("tests")
}

/// Path to a specific fixture
pub fn fixture(name: &str) -> PathBuf {
    fixtures_dir().join(name)
}

/// Check if macOS SIP is enabled by testing the SF_RESTRICTED flag on /bin/sh.
#[cfg(target_os = "macos")]
pub fn is_sip_enabled() -> bool {
    use std::ffi::CString;
    let path = CString::new("/bin/sh").unwrap();
    unsafe {
        let mut stat_buf: libc::stat = std::mem::zeroed();
        if libc::stat(path.as_ptr(), &mut stat_buf) == 0 {
            const SF_RESTRICTED: u32 = 0x00080000;
            (stat_buf.st_flags & SF_RESTRICTED) != 0
        } else {
            true // assume SIP enabled if stat fails
        }
    }
}

/// Build test fixtures if needed (runs `make` at most once per test binary)
pub fn build_fixtures() {
    static BUILD_ONCE: Once = Once::new();
    BUILD_ONCE.call_once(|| {
        let status = Command::new("make")
            .current_dir(fixtures_dir())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("failed to run make");
        assert!(status.success(), "Failed to build test fixtures");
    });
}

/// Detect current platform (arch, os)
fn current_platform() -> (&'static str, &'static str) {
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    };
    let os = if cfg!(target_os = "macos") {
        "mac"
    } else {
        "linux"
    };
    (arch, os)
}

/// Extract Python minor version from binary path or by running it.
/// Returns minor version, e.g. 12 for Python 3.12
pub fn get_python_minor_version(python: &std::path::Path) -> Option<u32> {
    // Try to extract from path first (e.g., .../python3.12/bin/python3.12)
    let path_str = python.to_string_lossy();
    for segment in path_str.split(&['/', '\\'][..]) {
        if let Some(rest) = segment.strip_prefix("python3.") {
            // Extract digits until non-digit
            let minor_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(minor) = minor_str.parse() {
                return Some(minor);
            }
        }
    }

    // Fallback: run python --version
    let output = Command::new(python).arg("--version").output().ok()?;
    let version_str = String::from_utf8_lossy(&output.stdout);
    // Parse "Python 3.12.0" format
    let version_str = version_str.trim();
    let parts: Vec<&str> = version_str.split_whitespace().collect();
    if parts.len() >= 2 {
        let version_parts: Vec<&str> = parts[1].split('.').collect();
        if version_parts.len() >= 2 {
            return version_parts[1].parse().ok();
        }
    }
    None
}

/// Extract Node.js major version from binary path or by running it.
/// Returns major version, e.g. 23 for Node.js v23.11.1
pub fn get_node_major_version(node: &std::path::Path) -> Option<u32> {
    // Try to extract from path first (e.g., .../node-v23.11.1 or .../node23/...)
    let path_str = node.to_string_lossy();
    for segment in path_str.split(&['/', '\\'][..]) {
        // Handle "node-v23.11.1" format
        if let Some(rest) = segment.strip_prefix("node-v") {
            let major_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(major) = major_str.parse() {
                return Some(major);
            }
        }
        // Handle "node23" format
        if let Some(rest) = segment.strip_prefix("node") {
            let major_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !major_str.is_empty() {
                if let Ok(major) = major_str.parse() {
                    return Some(major);
                }
            }
        }
    }

    // Fallback: run node --version
    let output = Command::new(node).arg("--version").output().ok()?;
    let version_str = String::from_utf8_lossy(&output.stdout);
    // Parse "v23.11.1" format
    let version_str = version_str.trim();
    if let Some(rest) = version_str.strip_prefix('v') {
        let major_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        return major_str.parse().ok();
    }
    None
}

/// Find python3 in PATH
pub fn find_python() -> Option<PathBuf> {
    Runtime::Python.find_in_path()
}

/// Find all Python binaries - from MALWI_TEST_BINARIES if set, otherwise just PATH
pub fn find_all_pythons() -> Vec<PathBuf> {
    find_all_runtimes(Runtime::Python)
}

/// Find node in PATH
pub fn find_node() -> Option<PathBuf> {
    // Prefer the repo's curated Node binaries (unstripped, consistent symbols),
    // falling back to PATH if not available.
    find_all_nodes().into_iter().next()
}

/// Find all Node.js binaries - from MALWI_TEST_BINARIES if set, otherwise just PATH
pub fn find_all_nodes() -> Vec<PathBuf> {
    find_all_runtimes(Runtime::Node)
}

/// Find all Bash binaries - from MALWI_TEST_BINARIES if set, otherwise just PATH
pub fn find_all_bashes() -> Vec<PathBuf> {
    find_all_runtimes(Runtime::Bash)
}

/// Find one preferred Bash binary for tests that should not fan out across all versions.
pub fn find_primary_bash() -> Option<PathBuf> {
    find_all_bashes().into_iter().next()
}

/// Extract Bash major version from binary path or by running it.
/// Returns major version, e.g. 5 for Bash 5.2
pub fn get_bash_major_version(bash: &std::path::Path) -> Option<u32> {
    // Try to extract from path first (e.g., .../bash-5.2)
    let path_str = bash.to_string_lossy();
    for segment in path_str.split(&['/', '\\'][..]) {
        if let Some(rest) = segment.strip_prefix("bash-") {
            let major_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(major) = major_str.parse() {
                return Some(major);
            }
        }
    }

    // Fallback: run bash --version and parse "GNU bash, version 5.2.0(...)"
    let output = Command::new(bash).arg("--version").output().ok()?;
    let version_str = String::from_utf8_lossy(&output.stdout);
    // Parse "GNU bash, version 5.2.0(1)-release" format
    for line in version_str.lines() {
        if let Some(idx) = line.find("version ") {
            let rest = &line[idx + 8..];
            let major_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(major) = major_str.parse() {
                return Some(major);
            }
        }
    }
    None
}

/// Default timeout for tests. Most tests finish well under this limit;
/// the timeout is a safety net for loaded CI runners.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// Extended timeout for --st (stack trace) tests. Stack trace collection adds
/// overhead: the agent captures V8/Python stack frames per event, and the CLI
/// parses/displays them. These tests are the most sensitive to timing.
pub const STACK_TRACE_TIMEOUT: Duration = Duration::from_secs(20);

/// Event-delivery flush for Python test scripts.
///
/// Append to the end of any Python script that needs traced events
/// to arrive at the CLI before the process exits. The agent's flush
/// thread wakes every 10ms; 100ms gives ~10x margin for the thread
/// to drain queued events and send them over TCP.
///
/// Node.js tests use `setTimeout()` instead — that serves double duty
/// as event-loop keepalive for async operations, so durations are
/// operation-specific and not standardized here.
pub const PY_FLUSH: &str = "\nimport time; time.sleep(0.1)";

/// Run malwi with given arguments and capture output
pub fn run_tracer(args: &[&str]) -> Output {
    run_tracer_with_timeout(args, DEFAULT_TIMEOUT)
}

/// Path to the agent library (release build)
pub fn agent_library() -> PathBuf {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("target/release");

    #[cfg(target_os = "macos")]
    let lib = base.join("libmalwi_agent.dylib");

    #[cfg(target_os = "linux")]
    let lib = base.join("libmalwi_agent.so");

    #[cfg(target_os = "windows")]
    let lib = base.join("malwi_agent.dll");

    lib
}

/// Run malwi with timeout in a specific directory
pub fn run_tracer_with_timeout_in_dir(args: &[&str], timeout: Duration, dir: &Path) -> Output {
    use std::thread;

    let mut cmd = Command::new(tracer_binary());
    cmd.args(args)
        .current_dir(dir)
        .env("MALWI_AGENT_LIB", agent_library())
        .env("MALWI_AGENT_DEBUG", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_child_process_group(&mut cmd);

    let mut child = cmd.spawn().expect("failed to spawn tracer");

    // Drain stdout/stderr in background threads to prevent pipe deadlock.
    // Without this, the child can block on writes when the pipe buffer fills,
    // since we only call try_wait() and don't read until after exit.
    let stdout_pipe = child.stdout.take().unwrap();
    let stderr_pipe = child.stderr.take().unwrap();

    let stdout_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::BufReader::new(stdout_pipe), &mut buf).ok();
        buf
    });
    let stderr_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::BufReader::new(stderr_pipe), &mut buf).ok();
        buf
    });

    // Wait with timeout
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_thread.join().unwrap_or_default();
                let stderr = stderr_thread.join().unwrap_or_default();
                return Output {
                    status,
                    stdout,
                    stderr,
                };
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let status = terminate_child_with_timeout(&mut child);
                    let stdout = stdout_thread.join().unwrap_or_default();
                    let stderr = stderr_thread.join().unwrap_or_default();
                    return Output {
                        status,
                        stdout,
                        stderr,
                    };
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                panic!("Error waiting for tracer: {}", e);
            }
        }
    }
}

/// Run malwi with timeout
pub fn run_tracer_with_timeout(args: &[&str], timeout: Duration) -> Output {
    use std::thread;

    let mut cmd = Command::new(tracer_binary());
    cmd.args(args)
        .current_dir(fixtures_dir())
        .env("MALWI_AGENT_LIB", agent_library())
        .env("MALWI_AGENT_DEBUG", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_child_process_group(&mut cmd);

    let mut child = cmd.spawn().expect("failed to spawn tracer");

    // Drain stdout/stderr in background threads to prevent pipe deadlock.
    // Without this, the child can block on writes when the pipe buffer fills,
    // since we only call try_wait() and don't read until after exit.
    let stdout_pipe = child.stdout.take().unwrap();
    let stderr_pipe = child.stderr.take().unwrap();

    let stdout_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::BufReader::new(stdout_pipe), &mut buf).ok();
        buf
    });
    let stderr_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::BufReader::new(stderr_pipe), &mut buf).ok();
        buf
    });

    // Wait with timeout
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_thread.join().unwrap_or_default();
                let stderr = stderr_thread.join().unwrap_or_default();
                return Output {
                    status,
                    stdout,
                    stderr,
                };
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let status = terminate_child_with_timeout(&mut child);
                    let stdout = stdout_thread.join().unwrap_or_default();
                    let stderr = stderr_thread.join().unwrap_or_default();
                    return Output {
                        status,
                        stdout,
                        stderr,
                    };
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                panic!("Error waiting for tracer: {}", e);
            }
        }
    }
}

/// Run malwi with timeout in non-interactive mode (stdin closed).
/// Useful for tests that must never block on review prompts.
pub fn run_tracer_with_timeout_noninteractive(args: &[&str], timeout: Duration) -> Output {
    use std::thread;

    let mut cmd = Command::new(tracer_binary());
    cmd.args(args)
        .current_dir(fixtures_dir())
        .env("MALWI_AGENT_LIB", agent_library())
        .env("MALWI_AGENT_DEBUG", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_child_process_group(&mut cmd);

    let mut child = cmd.spawn().expect("failed to spawn tracer");

    let stdout_pipe = child.stdout.take().unwrap();
    let stderr_pipe = child.stderr.take().unwrap();

    let stdout_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::BufReader::new(stdout_pipe), &mut buf).ok();
        buf
    });
    let stderr_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::BufReader::new(stderr_pipe), &mut buf).ok();
        buf
    });

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_thread.join().unwrap_or_default();
                let stderr = stderr_thread.join().unwrap_or_default();
                return Output {
                    status,
                    stdout,
                    stderr,
                };
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let status = terminate_child_with_timeout(&mut child);
                    let stdout = stdout_thread.join().unwrap_or_default();
                    let stderr = stderr_thread.join().unwrap_or_default();
                    return Output {
                        status,
                        stdout,
                        stderr,
                    };
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                panic!("Error waiting for tracer: {}", e);
            }
        }
    }
}

/// Check if output contains an ENTER event for a function
pub fn has_enter_event(output: &str, function: &str) -> bool {
    // Look for patterns like "[ENTER] function" or "function → ENTER"
    output
        .lines()
        .any(|line| line.contains(function) && (line.contains("ENTER") || line.contains("→")))
}

/// Check if output contains a LEAVE event for a function
pub fn has_leave_event(output: &str, function: &str) -> bool {
    output
        .lines()
        .any(|line| line.contains(function) && (line.contains("LEAVE") || line.contains("←")))
}

/// Check if output contains a child process event
pub fn has_child_event(output: &str, operation: &str) -> bool {
    // Look for "[CHILD]" events with Fork/Exec/Spawn
    output
        .lines()
        .any(|line| line.contains("[CHILD]") && line.contains(operation))
}

/// Count the number of events for a function
pub fn count_events(output: &str, function: &str) -> usize {
    output
        .lines()
        .filter(|line| line.contains(function))
        .count()
}

/// Extract unique thread IDs from trace output
pub fn extract_thread_ids(output: &str) -> Vec<u64> {
    let mut thread_ids = Vec::new();
    for line in output.lines() {
        // Look for thread ID patterns like "thread=123" or "[tid:123]"
        if let Some(tid_str) = extract_thread_id_from_line(line) {
            if let Ok(tid) = tid_str.parse::<u64>() {
                if !thread_ids.contains(&tid) {
                    thread_ids.push(tid);
                }
            }
        }
    }
    thread_ids
}

fn extract_thread_id_from_line(line: &str) -> Option<&str> {
    // Try different patterns
    if let Some(idx) = line.find("thread=") {
        let rest = &line[idx + 7..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if end > 0 {
            return Some(&rest[..end]);
        }
    }
    if let Some(idx) = line.find("[tid:") {
        let rest = &line[idx + 5..];
        let end = rest.find(']').unwrap_or(rest.len());
        if end > 0 {
            return Some(&rest[..end]);
        }
    }
    None
}

/// Check if output contains stack trace frames (lines starting with "    at ")
pub fn has_stack_trace(output: &str) -> bool {
    let clean = strip_ansi_codes(output);
    clean.lines().any(|line| line.starts_with("    at "))
}

/// Count stack trace frames in output
pub fn count_stack_frames(output: &str) -> usize {
    let clean = strip_ansi_codes(output);
    clean
        .lines()
        .filter(|line| line.starts_with("    at "))
        .count()
}

/// Check if output contains a Python stack frame with expected format: "    at function (file:line)"
pub fn has_python_stack_frame(output: &str, function: &str) -> bool {
    let clean = strip_ansi_codes(output);
    clean.lines().any(|line| {
        line.starts_with("    at ") && line.contains(function) && line.contains(".py:")
        // Python files end in .py
    })
}

/// Check if output contains a Node.js/JavaScript trace event
pub fn has_js_trace_event(output: &str, function: &str) -> bool {
    output
        .lines()
        .any(|line| line.contains("[malwi]") && line.contains(function))
}

/// Count Node.js/JavaScript trace events for a function pattern
pub fn count_js_events(output: &str, pattern: &str) -> usize {
    output
        .lines()
        .filter(|line| line.contains("[malwi]") && line.contains(pattern))
        .count()
}

/// Check if output contains Node.js stack frames (for native hooks with Node.js stack)
pub fn has_nodejs_stack_frame(output: &str, function: &str) -> bool {
    let clean = strip_ansi_codes(output);
    clean.lines().any(|line| {
        line.starts_with("    at ")
            && line.contains(function)
            && (line.contains(".js:") || line.contains("<anonymous>"))
    })
}

/// Run malwi with stdin input (for review mode testing)
pub fn run_tracer_with_stdin(args: &[&str], stdin_input: &str) -> Output {
    use std::io::Write;

    let mut child = Command::new(tracer_binary())
        .args(args)
        .current_dir(fixtures_dir())
        .env("MALWI_AGENT_LIB", agent_library())
        .env("MALWI_AGENT_DEBUG", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn tracer");

    // Write stdin input
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(stdin_input.as_bytes());
    }

    child.wait_with_output().expect("failed to wait for tracer")
}

/// Run malwi with stdin input and a timeout (for review mode hang detection)
pub fn run_tracer_with_stdin_timeout(
    args: &[&str],
    stdin_input: &str,
    timeout: Duration,
) -> Output {
    use std::io::Write;
    use std::thread;

    let mut cmd = Command::new(tracer_binary());
    cmd.args(args)
        .current_dir(fixtures_dir())
        .env("MALWI_AGENT_LIB", agent_library())
        .env("MALWI_AGENT_DEBUG", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_child_process_group(&mut cmd);

    let mut child = cmd.spawn().expect("failed to spawn tracer");

    // Write stdin input then close stdin
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(stdin_input.as_bytes());
    }

    // Drain stdout/stderr in background threads to prevent pipe deadlock
    let stdout_pipe = child.stdout.take().unwrap();
    let stderr_pipe = child.stderr.take().unwrap();

    let stdout_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::BufReader::new(stdout_pipe), &mut buf).ok();
        buf
    });
    let stderr_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::BufReader::new(stderr_pipe), &mut buf).ok();
        buf
    });

    // Wait with timeout
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_thread.join().unwrap_or_default();
                let stderr = stderr_thread.join().unwrap_or_default();
                return Output {
                    status,
                    stdout,
                    stderr,
                };
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let status = terminate_child_with_timeout(&mut child);
                    let stdout = stdout_thread.join().unwrap_or_default();
                    let stderr = stderr_thread.join().unwrap_or_default();
                    return Output {
                        status,
                        stdout,
                        stderr,
                    };
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                panic!("Error waiting for tracer: {}", e);
            }
        }
    }
}

#[cfg(unix)]
fn configure_child_process_group(cmd: &mut Command) {
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn configure_child_process_group(_cmd: &mut Command) {}

fn terminate_child_with_timeout(child: &mut std::process::Child) -> std::process::ExitStatus {
    #[cfg(unix)]
    {
        use std::thread;
        use std::time::Instant;

        if let Ok(Some(status)) = child.try_wait() {
            return status;
        }

        let pgid = child.id() as libc::pid_t;
        unsafe {
            let _ = libc::kill(-pgid, libc::SIGTERM);
        }

        let deadline = Instant::now() + Duration::from_millis(300);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return status,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    thread::sleep(Duration::from_millis(25));
                }
                Err(_) => break,
            }
        }

        unsafe {
            let _ = libc::kill(-pgid, libc::SIGKILL);
        }
        child.wait().expect("failed to wait after timeout kill")
    }

    #[cfg(not(unix))]
    {
        let _ = child.kill();
        child.wait().expect("failed to wait after timeout kill")
    }
}

// ---------------------------------------------------------------------------
// TracerOutput wrapper
// ---------------------------------------------------------------------------

/// Wrapper around `std::process::Output` with convenience methods for test assertions.
pub struct TracerOutput {
    pub inner: Output,
}

impl TracerOutput {
    pub fn new(output: Output) -> Self {
        Self { inner: output }
    }

    /// Decoded stdout with ANSI escape codes stripped.
    pub fn stdout(&self) -> String {
        strip_ansi_codes(&String::from_utf8_lossy(&self.inner.stdout))
    }

    /// Decoded stdout without ANSI stripping (for JSON output).
    pub fn stdout_raw(&self) -> String {
        String::from_utf8_lossy(&self.inner.stdout).into_owned()
    }

    /// Decoded stderr.
    pub fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.inner.stderr).into_owned()
    }

    /// Whether the process exited successfully.
    pub fn success(&self) -> bool {
        self.inner.status.success()
    }

    /// Parse NDJSON lines from raw stdout into a vec of JSON values.
    pub fn json_events(&self) -> Vec<serde_json::Value> {
        parse_json_events(&self.stdout_raw())
    }

    /// Panic with stdout+stderr context if the process failed.
    pub fn assert_success(&self, context: &str) {
        assert!(
            self.success(),
            "{}: process failed\nstdout:\n{}\nstderr:\n{}",
            context,
            self.stdout(),
            self.stderr()
        );
    }

    /// Panic with context if stdout (ANSI-stripped) doesn't contain `pattern`.
    pub fn assert_stdout_contains(&self, pattern: &str, context: &str) {
        let stdout = self.stdout();
        assert!(
            stdout.contains(pattern),
            "{}: stdout does not contain '{}'\nstdout:\n{}\nstderr:\n{}",
            context,
            pattern,
            stdout,
            self.stderr()
        );
    }

    /// True if any `[malwi]` line contains `func` and is a plain trace (not denied/warning).
    pub fn has_traced(&self, func: &str) -> bool {
        has_traced_line(&self.stdout(), func)
    }

    /// True if any `[malwi] denied:` line contains `func`.
    pub fn has_denied(&self, func: &str) -> bool {
        has_denied_line(&self.stdout(), func)
    }

    /// True if any `[malwi] warning:` line contains `func`.
    pub fn has_warning(&self, func: &str) -> bool {
        has_warning_line(&self.stdout(), func)
    }
}

/// True if any `[malwi]` line contains `func` as a plain trace (not denied/warning).
pub fn has_traced_line(stdout: &str, func: &str) -> bool {
    stdout.lines().any(|l| {
        l.contains("[malwi]")
            && l.contains(func)
            && !l.contains("denied:")
            && !l.contains("warning:")
    })
}

/// True if any `[malwi] denied:` line contains `func`.
pub fn has_denied_line(stdout: &str, func: &str) -> bool {
    stdout
        .lines()
        .any(|l| l.contains("[malwi]") && l.contains("denied:") && l.contains(func))
}

/// True if any `[malwi] warning:` line contains `func`.
pub fn has_warning_line(stdout: &str, func: &str) -> bool {
    stdout
        .lines()
        .any(|l| l.contains("[malwi]") && l.contains("warning:") && l.contains(func))
}

/// Split a command string into args, respecting single/double quotes.
///
/// ```ignore
/// shell_split("x -p file -- node -e 'console.log(1)'")
/// // => ["x", "-p", "file", "--", "node", "-e", "console.log(1)"]
/// ```
pub fn shell_split(cmd: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut chars = cmd.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                // Single quotes: no escaping, everything is literal until closing '
                while let Some(inner) = chars.next() {
                    if inner == '\'' {
                        break;
                    }
                    current.push(inner);
                }
            }
            '"' => {
                // Double quotes: backslash escapes \" and \\
                while let Some(inner) = chars.next() {
                    if inner == '"' {
                        break;
                    }
                    if inner == '\\' {
                        if let Some(&next) = chars.peek() {
                            if next == '"' || next == '\\' {
                                current.push(next);
                                chars.next();
                                continue;
                            }
                        }
                    }
                    current.push(inner);
                }
            }
            c if c.is_ascii_whitespace() => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

// ---------------------------------------------------------------------------
// cmd() — run a terminal-style command string
// ---------------------------------------------------------------------------

/// Trace command with execution options.
///
/// The command is a single string — exactly what you'd type in a terminal.
/// Dynamic values are interpolated with `format!`. Execution options
/// (timeout, stdin, env, dir) are chained before `.run()`.
///
/// ```ignore
/// // Simple:
/// cmd("x -s connect -- ./simple_target").run();
///
/// // With dynamic path and code (use format! + sq() for quoting):
/// cmd(&format!("x --py func -- {} -c {}", python.display(), sq(script))).run();
///
/// // With timeout:
/// cmd(&format!("x -p {} -- {} -e {}", p.display(), n.display(), sq(code)))
///     .timeout(secs(10)).run();
///
/// // With stdin:
/// cmd("x -c bash -- bash script.sh").stdin("echo hello\n").run();
///
/// // Non-interactive (stdin closed):
/// cmd(&format!("x -p {} -- {} {}", p.display(), b.display(), s.display()))
///     .noninteractive().timeout(secs(10)).run();
/// ```
pub struct Cmd {
    args: Vec<String>,
    timeout: Option<Duration>,
    stdin_input: Option<String>,
    noninteractive: bool,
    env_vars: Vec<(String, String)>,
    dir: Option<PathBuf>,
}

impl Cmd {
    pub fn timeout(mut self, dur: Duration) -> Self {
        self.timeout = Some(dur);
        self
    }

    pub fn stdin(mut self, input: &str) -> Self {
        self.stdin_input = Some(input.to_string());
        self
    }

    pub fn noninteractive(mut self) -> Self {
        self.noninteractive = true;
        self
    }

    pub fn env(mut self, key: &str, val: &str) -> Self {
        self.env_vars.push((key.to_string(), val.to_string()));
        self
    }

    pub fn dir(mut self, dir: &Path) -> Self {
        self.dir = Some(dir.to_path_buf());
        self
    }

    /// Execute the command and return a `TracerOutput`.
    pub fn run(self) -> TracerOutput {
        let refs: Vec<&str> = self.args.iter().map(|s| s.as_str()).collect();
        let timeout = self.timeout.unwrap_or(DEFAULT_TIMEOUT);

        if !self.env_vars.is_empty() {
            let env: Vec<(&str, &str)> = self
                .env_vars
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            return trace_with_env(&refs, &env, timeout);
        }

        if let Some(input) = &self.stdin_input {
            if self.timeout.is_some() {
                return trace_with_stdin_timeout(&refs, input, timeout);
            }
            return trace_with_stdin(&refs, input);
        }

        if self.noninteractive {
            return trace_with_timeout_noninteractive(&refs, timeout);
        }

        if let Some(dir) = &self.dir {
            return trace_with_timeout_in_dir(&refs, timeout, dir);
        }

        if self.timeout.is_some() {
            return trace_with_timeout(&refs, timeout);
        }

        trace(&refs)
    }
}

/// Start a trace command from a terminal-style string.
pub fn cmd(command: &str) -> Cmd {
    Cmd {
        args: shell_split(command),
        timeout: None,
        stdin_input: None,
        noninteractive: false,
        env_vars: Vec::new(),
        dir: None,
    }
}

/// Shell-quote a string for safe interpolation into a `cmd()` format string.
/// Uses single quotes (falls back to double quotes if the value contains `'`).
pub fn sq(s: impl AsRef<str>) -> String {
    let s = s.as_ref();
    if !s.contains('\'') {
        format!("'{}'", s)
    } else if !s.contains('"') {
        format!("\"{}\"", s)
    } else {
        // Both quote types present — escape single quotes within single-quoted string
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }
}

/// Shorthand for `Duration::from_secs(n)`.
pub fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// Run malwi and return a `TracerOutput`.
pub fn trace(args: &[&str]) -> TracerOutput {
    TracerOutput::new(run_tracer(args))
}

/// Run malwi with timeout and return a `TracerOutput`.
pub fn trace_with_timeout(args: &[&str], timeout: Duration) -> TracerOutput {
    TracerOutput::new(run_tracer_with_timeout(args, timeout))
}

/// Run malwi with timeout in a specific directory and return a `TracerOutput`.
pub fn trace_with_timeout_in_dir(args: &[&str], timeout: Duration, dir: &Path) -> TracerOutput {
    TracerOutput::new(run_tracer_with_timeout_in_dir(args, timeout, dir))
}

/// Run malwi with timeout in non-interactive mode and return a `TracerOutput`.
pub fn trace_with_timeout_noninteractive(args: &[&str], timeout: Duration) -> TracerOutput {
    TracerOutput::new(run_tracer_with_timeout_noninteractive(args, timeout))
}

/// Run malwi with stdin input and return a `TracerOutput`.
pub fn trace_with_stdin(args: &[&str], stdin_input: &str) -> TracerOutput {
    TracerOutput::new(run_tracer_with_stdin(args, stdin_input))
}

/// Run malwi with stdin input + timeout and return a `TracerOutput`.
pub fn trace_with_stdin_timeout(
    args: &[&str],
    stdin_input: &str,
    timeout: Duration,
) -> TracerOutput {
    TracerOutput::new(run_tracer_with_stdin_timeout(args, stdin_input, timeout))
}

// ---------------------------------------------------------------------------
// write_temp_policy
// ---------------------------------------------------------------------------

static POLICY_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Write a temporary policy YAML file and return its path.
/// Uses a unique name per call to avoid conflicts when tests run in parallel.
pub fn write_temp_policy(content: &str) -> (PathBuf, std::fs::File) {
    write_temp_policy_with_prefix("malwi-test-policy", content)
}

/// Write a temporary policy YAML file with a custom filename prefix.
pub fn write_temp_policy_with_prefix(prefix: &str, content: &str) -> (PathBuf, std::fs::File) {
    use std::io::Write;
    let dir = std::env::temp_dir();
    let id = POLICY_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = dir.join(format!("{}-{}-{}.yaml", prefix, std::process::id(), id));
    let mut f = std::fs::File::create(&path).expect("failed to create temp policy file");
    f.write_all(content.as_bytes())
        .expect("failed to write policy");
    f.flush().expect("failed to flush policy");
    (path, f)
}

// ---------------------------------------------------------------------------
// run_tracer_with_env
// ---------------------------------------------------------------------------

/// Run malwi with extra environment variables passed to the child process.
pub fn run_tracer_with_env(args: &[&str], env_vars: &[(&str, &str)], timeout: Duration) -> Output {
    use std::thread;

    let mut cmd = Command::new(tracer_binary());
    cmd.args(args)
        .current_dir(fixtures_dir())
        .env("MALWI_AGENT_LIB", agent_library())
        .env("MALWI_AGENT_DEBUG", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for &(key, val) in env_vars {
        cmd.env(key, val);
    }

    configure_child_process_group(&mut cmd);

    let mut child = cmd.spawn().expect("failed to spawn tracer");

    let stdout_pipe = child.stdout.take().unwrap();
    let stderr_pipe = child.stderr.take().unwrap();

    let stdout_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::BufReader::new(stdout_pipe), &mut buf).ok();
        buf
    });
    let stderr_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::BufReader::new(stderr_pipe), &mut buf).ok();
        buf
    });

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_thread.join().unwrap_or_default();
                let stderr = stderr_thread.join().unwrap_or_default();
                return Output {
                    status,
                    stdout,
                    stderr,
                };
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let status = terminate_child_with_timeout(&mut child);
                    let stdout = stdout_thread.join().unwrap_or_default();
                    let stderr = stderr_thread.join().unwrap_or_default();
                    return Output {
                        status,
                        stdout,
                        stderr,
                    };
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("Error waiting for tracer: {}", e),
        }
    }
}

/// Run malwi with extra env vars and return a `TracerOutput`.
pub fn trace_with_env(args: &[&str], env_vars: &[(&str, &str)], timeout: Duration) -> TracerOutput {
    TracerOutput::new(run_tracer_with_env(args, env_vars, timeout))
}

// ---------------------------------------------------------------------------
// parse_json_events
// ---------------------------------------------------------------------------

/// Parse NDJSON lines from stdout into a vec of JSON values.
pub fn parse_json_events(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}
