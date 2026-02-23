//! Bash process detection and version parsing.
//!
//! Detects bash processes via the `dist_version` global variable
//! (unique to bash, present in versions 4.4+).

use std::ffi::{c_char, CStr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use core::ffi::c_void;
use log::{debug, info, warn};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use malwi_intercept::types::ExportInfo;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use malwi_intercept::CallListener;

use super::hooks;

/// Address of bash's `find_shell_builtin` function, set during setup_bash_hooks.
/// Used to check if a command is a builtin (to avoid double-tracing with shell_execve).
/// Type: fn(*const c_char) -> *const c_void (returns non-null if builtin found)
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) static BASH_FIND_SHELL_BUILTIN: AtomicUsize = AtomicUsize::new(0);

/// Address of bash's `line_number` global variable (int).
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) static BASH_LINE_NUMBER: AtomicUsize = AtomicUsize::new(0);

/// Address of bash's `dollar_vars` global variable (char*[10]).
/// dollar_vars[0] is the script name ($0).
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) static BASH_DOLLAR_VARS: AtomicUsize = AtomicUsize::new(0);

/// Detected bash version string (e.g. "5.2"), set during setup_bash_hooks.
pub(crate) static BASH_VERSION: OnceLock<String> = OnceLock::new();

/// Check if a bash process has been detected.
pub fn is_loaded() -> bool {
    BASH_VERSION.get().is_some()
}

/// Get the detected bash version, if any.
pub fn detected_version() -> Option<&'static str> {
    BASH_VERSION.get().map(|s| s.as_str())
}

/// Check if symbol names match (handles leading underscore differences).
fn symbol_matches(sym_name: &str, symbol: &str) -> bool {
    if sym_name == symbol {
        return true;
    }
    if let Some(stripped) = sym_name.strip_prefix('_') {
        if stripped == symbol {
            return true;
        }
    }
    if let Some(stripped) = symbol.strip_prefix('_') {
        if sym_name == stripped {
            return true;
        }
    }
    false
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn find_symbol_in_symbols(symbols: &[ExportInfo], symbol: &str) -> Option<usize> {
    symbols
        .iter()
        .find(|s| symbol_matches(&s.name, symbol))
        .map(|s| s.address)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn find_symbol_any_module(symbol: &str) -> Option<(String, Vec<ExportInfo>, usize)> {
    // We cannot rely on `current_exe()` in all sandboxed environments. Instead,
    // scan loaded modules for the symbol, then reuse that module's symbols for lookups.
    let modules = malwi_intercept::module::enumerate_modules();
    for m in modules {
        let Ok(symbols) = malwi_intercept::module::enumerate_symbols(&m.name) else {
            continue;
        };
        if let Some(addr) = find_symbol_in_symbols(&symbols, symbol) {
            return Some((m.name, symbols, addr));
        }
    }
    None
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) fn find_bash_symbol(symbols: &[ExportInfo], symbol: &str) -> Option<usize> {
    find_symbol_in_symbols(symbols, symbol)
        .or_else(|| malwi_intercept::module::find_global_export_by_name(symbol).ok())
}

/// Detect bash process and hook execution functions.
///
/// Uses `dist_version` global variable to positively identify bash (unique to bash,
/// present in all versions 4.4+). Then hooks:
/// - `shell_execve`: catches all external commands with resolved path + argv
/// - `execute_command_internal`: catches ALL commands (builtins, functions, externals)
///   by reading the COMMAND* struct for cm_simple commands
/// - `eval_builtin`: catches `eval "code"`
/// - `source_builtin`: catches `source file.sh` / `. file.sh`
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) unsafe fn setup_bash_hooks(
    interceptor: &'static malwi_intercept::Interceptor,
) -> BashHookListeners {
    let mut listeners = BashHookListeners::default();

    // Step 1: Detect bash via dist_version global variable.
    // dist_version is `const char * const` — unique to bash, contains e.g. "5.2"
    let (bash_module_name, bash_symbols, dist_version_addr) =
        if let Some(v) = find_symbol_any_module("dist_version") {
            v
        } else if let Ok(a) = malwi_intercept::module::find_global_export_by_name("dist_version") {
            // Extremely rare, but keeps old behavior if dist_version is exported.
            (String::new(), Vec::new(), a)
        } else {
            return listeners; // Not a bash process
        };

    // Read the version string for logging
    let version_ptr = *(dist_version_addr as *const *const c_char);
    if !version_ptr.is_null() {
        let bash_version = CStr::from_ptr(version_ptr).to_string_lossy();
        info!("Detected bash process, version: {}", bash_version);
        BASH_VERSION.set(bash_version.into_owned()).ok();
    } else {
        info!("Detected bash process (dist_version pointer is null)");
    }
    if !bash_module_name.is_empty() {
        debug!("Bash symbols resolved from module: {}", bash_module_name);
    }

    // Store find_shell_builtin address for use in execute_command_internal hook
    let find_builtin_addr = find_bash_symbol(&bash_symbols, "find_shell_builtin").unwrap_or(0);
    if find_builtin_addr != 0 {
        BASH_FIND_SHELL_BUILTIN.store(find_builtin_addr as usize, Ordering::SeqCst);
        debug!("Found find_shell_builtin at {:#x}", find_builtin_addr);
    }

    // Resolve line_number and dollar_vars for source location tracking
    if let Some(addr) = find_bash_symbol(&bash_symbols, "line_number") {
        BASH_LINE_NUMBER.store(addr, Ordering::SeqCst);
        debug!("Found bash line_number at {:#x}", addr);
    }
    if let Some(addr) = find_bash_symbol(&bash_symbols, "dollar_vars") {
        BASH_DOLLAR_VARS.store(addr, Ordering::SeqCst);
        debug!("Found bash dollar_vars at {:#x}", addr);
    }

    // Step 2: Hook shell_execve (external commands)
    // int shell_execve(char *command, char **args, char **env)
    // Same signature as execve — called right before the actual execve() syscall
    let shell_execve_addr = find_bash_symbol(&bash_symbols, "shell_execve").unwrap_or(0);
    if shell_execve_addr != 0 {
        let listener = CallListener {
            on_enter: Some(hooks::on_shell_execve_enter),
            on_leave: None, // execve doesn't return on success
            user_data: std::ptr::null_mut(),
        };
        if interceptor
            .attach(shell_execve_addr as *mut c_void, listener)
            .is_ok()
        {
            listeners.shell_execve = Some(listener);
            info!(
                "Attached bash monitor to shell_execve() at {:#x}",
                shell_execve_addr
            );
        } else {
            warn!("Failed to attach to shell_execve");
        }
    } else {
        warn!("Bash detected but shell_execve symbol not found");
    }

    // Step 3: Hook execute_command_internal (ALL commands including builtins)
    // int execute_command_internal(COMMAND*, int async, int pipe_in, int pipe_out, struct fd_bitmap*)
    // This catches builtins (echo, cd, export, etc.) that don't go through shell_execve.
    // We read the COMMAND* struct to extract the command name for cm_simple types.
    let exec_cmd_addr = find_bash_symbol(&bash_symbols, "execute_command_internal").unwrap_or(0);
    if exec_cmd_addr != 0 {
        let listener = CallListener {
            on_enter: Some(hooks::on_execute_command_internal_enter),
            on_leave: None,
            user_data: std::ptr::null_mut(),
        };
        if interceptor
            .attach(exec_cmd_addr as *mut c_void, listener)
            .is_ok()
        {
            listeners.exec_cmd = Some(listener);
            info!(
                "Attached bash monitor to execute_command_internal() at {:#x}",
                exec_cmd_addr
            );
        } else {
            warn!("Failed to attach to execute_command_internal");
        }
    } else {
        debug!("execute_command_internal symbol not found in bash");
    }

    // Step 4: Hook eval_builtin (eval "code")
    // int eval_builtin(WORD_LIST *list)
    let eval_addr = find_bash_symbol(&bash_symbols, "eval_builtin").unwrap_or(0);
    if eval_addr != 0 {
        let listener = CallListener {
            on_enter: Some(hooks::on_eval_builtin_enter),
            on_leave: None,
            user_data: std::ptr::null_mut(),
        };
        if interceptor
            .attach(eval_addr as *mut c_void, listener)
            .is_ok()
        {
            listeners.eval = Some(listener);
            info!(
                "Attached bash monitor to eval_builtin() at {:#x}",
                eval_addr
            );
        } else {
            warn!("Failed to attach to eval_builtin");
        }
    } else {
        debug!("eval_builtin symbol not found in bash");
    }

    // Step 5: Hook source_builtin (source/. script.sh)
    // int source_builtin(WORD_LIST *list)
    let source_addr = find_bash_symbol(&bash_symbols, "source_builtin").unwrap_or(0);
    if source_addr != 0 {
        let listener = CallListener {
            on_enter: Some(hooks::on_source_builtin_enter),
            on_leave: None,
            user_data: std::ptr::null_mut(),
        };
        if interceptor
            .attach(source_addr as *mut c_void, listener)
            .is_ok()
        {
            listeners.source = Some(listener);
            info!(
                "Attached bash monitor to source_builtin() at {:#x}",
                source_addr
            );
        } else {
            warn!("Failed to attach to source_builtin");
        }
    } else {
        debug!("source_builtin symbol not found in bash");
    }

    listeners
}

/// Install the find_variable hook for envvar monitoring.
/// Only works if bash was detected (BASH_VERSION is set).
///
/// # Safety
/// The caller must ensure the interceptor is in a valid state for attaching hooks.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) unsafe fn enable_envvar_hook(
    interceptor: &'static malwi_intercept::Interceptor,
    existing: &Option<CallListener>,
) -> Option<CallListener> {
    if existing.is_some() {
        return None; // Already installed
    }
    if BASH_VERSION.get().is_none() {
        return None; // Not a bash process
    }

    // Re-resolve find_variable — use the same detection approach as setup_bash_hooks
    let find_var_addr = malwi_intercept::module::find_global_export_by_name("find_variable")
        .ok()
        .unwrap_or(0);
    if find_var_addr == 0 {
        debug!("find_variable symbol not found for envvar monitoring");
        return None;
    }

    interceptor.begin_transaction();
    let listener = CallListener {
        on_enter: Some(hooks::on_find_variable_enter),
        on_leave: Some(hooks::on_find_variable_leave),
        user_data: std::ptr::null_mut(),
    };
    let result = if interceptor
        .attach(find_var_addr as *mut c_void, listener)
        .is_ok()
    {
        info!(
            "Attached bash envvar monitor to find_variable() at {:#x}",
            find_var_addr
        );
        Some(listener)
    } else {
        warn!("Failed to attach to find_variable for envvar monitoring");
        None
    };
    interceptor.end_transaction();
    result
}

/// Holds the CallListener handles for bash hooks, for the SpawnMonitor to store.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Default)]
pub(crate) struct BashHookListeners {
    pub shell_execve: Option<CallListener>,
    pub exec_cmd: Option<CallListener>,
    pub eval: Option<CallListener>,
    pub source: Option<CallListener>,
}
