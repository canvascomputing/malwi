//! Spawn/exec interception for child process gating.
//!
//! Platform-specific hooks:
//! - macOS: posix_spawn, execve
//! - Linux: execve
//! - Windows: CreateProcessInternalW

use std::cell::Cell;
use std::collections::HashSet;
use std::ffi::{c_char, CStr, CString};
use std::ptr;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::OnceLock;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use core::ffi::c_void;
use log::{debug, info, warn};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use malwi_intercept::types::ExportInfo;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use malwi_intercept::CallListener;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use malwi_intercept::InvocationContext;

#[cfg(target_os = "macos")]
fn agent_debug_enabled() -> bool {
    std::env::var_os("MALWI_AGENT_DEBUG").is_some()
}

/// Address of bash's `find_shell_builtin` function, set during setup_bash_hooks.
/// Used to check if a command is a builtin (to avoid double-tracing with shell_execve).
/// Type: fn(*const c_char) -> *const c_void (returns non-null if builtin found)
#[cfg(any(target_os = "macos", target_os = "linux"))]
static BASH_FIND_SHELL_BUILTIN: AtomicUsize = AtomicUsize::new(0);

/// Address of bash's `line_number` global variable (int).
#[cfg(any(target_os = "macos", target_os = "linux"))]
static BASH_LINE_NUMBER: AtomicUsize = AtomicUsize::new(0);

/// Address of bash's `dollar_vars` global variable (char*[10]).
/// dollar_vars[0] is the script name ($0).
#[cfg(any(target_os = "macos", target_os = "linux"))]
static BASH_DOLLAR_VARS: AtomicUsize = AtomicUsize::new(0);

/// Detected bash version string (e.g. "5.2"), set during setup_bash_hooks.
static BASH_VERSION: OnceLock<String> = OnceLock::new();

/// Whether environment variable monitoring is enabled (set by CLI via HookType::EnvVar config).
#[cfg(any(target_os = "macos", target_os = "linux"))]
static ENVVAR_MONITORING_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable environment variable monitoring (called when EnvVar hook config is received).
pub fn enable_envvar_monitoring() {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    ENVVAR_MONITORING_ENABLED.store(true, Ordering::SeqCst);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = ();
}

/// Check if envvar monitoring is enabled.
pub fn is_envvar_monitoring_enabled() -> bool {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        ENVVAR_MONITORING_ENABLED.load(Ordering::SeqCst)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
thread_local! {
    /// Dedup set for envvar names — reports each variable once per bash command.
    /// Cleared at each execute_command_internal entry.
    static ENVVAR_SEEN: std::cell::RefCell<HashSet<String>> = std::cell::RefCell::new(HashSet::new());

    /// Name pointer from getenv enter callback, consumed in leave callback.
    static GETENV_NAME: Cell<*const c_char> = const { Cell::new(ptr::null()) };

    /// Dedup set for native getenv — reports each variable once per thread lifetime.
    static GETENV_SEEN: std::cell::RefCell<HashSet<String>> = std::cell::RefCell::new(HashSet::new());
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
static ORIGINAL_POSIX_SPAWN: AtomicUsize = AtomicUsize::new(0);

#[cfg(any(target_os = "macos", target_os = "linux"))]
static ORIGINAL_POSIX_SPAWNP: AtomicUsize = AtomicUsize::new(0);

// When we hook `dlsym()` (fishhook-style), we store the original pointer here so
// wrappers can call the real implementation without recursing through our own
// rebinding/interposing layers.
#[cfg(target_os = "macos")]
static ORIGINAL_DLSYM: AtomicUsize = AtomicUsize::new(0);

#[cfg(any(target_os = "macos", target_os = "linux"))]
static ORIGINAL_EXECVE: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_os = "macos")]
static ORIGINAL___EXECVE: AtomicUsize = AtomicUsize::new(0);

#[cfg(any(target_os = "macos", target_os = "linux"))]
thread_local! {
    /// Set by shell_execve hook so the subsequent execve hook skips.
    /// shell_execve internally calls execve — without this both hooks fire.
    static IN_SHELL_EXECVE: Cell<bool> = const { Cell::new(false) };
}

/// Get the detected bash version, if any.
pub fn detected_bash_version() -> Option<&'static str> {
    BASH_VERSION.get().map(|s| s.as_str())
}

/// Information about a spawned/exec'd process.
#[derive(Debug, Clone)]
pub struct SpawnInfo {
    pub child_pid: u32,
    pub path: Option<String>,
    pub argv: Option<Vec<String>>,
    pub native_stack: Vec<usize>,
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
}

/// Callback trait for spawn/exec events.
pub trait SpawnHandler: Send + Sync {
    /// Called when a new process is spawned (posix_spawn, CreateProcess).
    fn on_spawn_created(&self, info: SpawnInfo);

    /// Called just before exec replaces the current process image.
    fn on_exec_imminent(&self, info: SpawnInfo);

    /// Called when a child is spawned in suspended state (for child gating).
    /// The CLI should configure hooks and then call ResumeChild.
    fn on_child_spawned_suspended(&self, info: SpawnInfo);

    /// Returns true if child gating is enabled (spawn children suspended).
    fn is_child_gating_enabled(&self) -> bool;
}

/// Monitor for spawn/exec system calls.
pub struct SpawnMonitor {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    interceptor: &'static malwi_intercept::Interceptor,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    execve_listener: Option<CallListener>,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    posix_spawn_listener: Option<CallListener>,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    posix_spawnp_listener: Option<CallListener>,
    // Fishhook-style rebinding fallback for hardened mappings where inline patching fails.
    #[cfg(target_os = "macos")]
    posix_spawn_rebind: Option<Vec<(usize, usize)>>,
    #[cfg(target_os = "macos")]
    posix_spawnp_rebind: Option<Vec<(usize, usize)>>,
    #[cfg(target_os = "macos")]
    execve_rebind: Option<Vec<(usize, usize)>>,
    /// Bash shell_execve hook listener (detects external commands in bash)
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    bash_shell_execve_listener: Option<CallListener>,
    /// Bash execute_command_internal hook listener (detects ALL commands including builtins)
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    bash_exec_cmd_listener: Option<CallListener>,
    /// Bash eval_builtin hook listener
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    bash_eval_listener: Option<CallListener>,
    /// Bash source_builtin hook listener
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    bash_source_listener: Option<CallListener>,
    /// Bash find_variable hook listener (envvar access detection)
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    bash_find_variable_listener: Option<CallListener>,
    /// Native getenv() hook listener (libc envvar access)
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    getenv_listener: Option<CallListener>,
    #[allow(dead_code)]
    handler: *const dyn SpawnHandler,
}

// Safety: SpawnMonitor uses raw pointers but they're thread-safe
unsafe impl Send for SpawnMonitor {}
unsafe impl Sync for SpawnMonitor {}

impl SpawnMonitor {
    /// Create a new spawn monitor and install hooks.
    ///
    /// # Safety
    /// The handler must remain valid for the lifetime of this monitor.
    pub unsafe fn new<H: SpawnHandler + 'static>(handler: &H) -> Option<Self> {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            let interceptor = malwi_intercept::Interceptor::obtain();
            interceptor.begin_transaction();

            let mut monitor = Self {
                interceptor,
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                execve_listener: None,
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                posix_spawn_listener: None,
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                posix_spawnp_listener: None,
                #[cfg(target_os = "macos")]
                posix_spawn_rebind: None,
                #[cfg(target_os = "macos")]
                posix_spawnp_rebind: None,
                #[cfg(target_os = "macos")]
                execve_rebind: None,
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                bash_shell_execve_listener: None,
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                bash_exec_cmd_listener: None,
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                bash_eval_listener: None,
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                bash_source_listener: None,
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                bash_find_variable_listener: None,
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                getenv_listener: None,
                handler: handler as *const _,
            };

            #[cfg(target_os = "macos")]
            {
                monitor.setup_macos_hooks(handler);
            }
            #[cfg(target_os = "linux")]
            {
                monitor.setup_linux_hooks(handler);
            }

            monitor.setup_bash_hooks();

            interceptor.end_transaction();
            Some(monitor)
        }

        #[cfg(target_os = "windows")]
        {
            warn!("Spawn monitor not supported on Windows");
            let _ = handler;
            None
        }
    }

    #[cfg(target_os = "macos")]
    unsafe fn setup_macos_hooks<H: SpawnHandler + 'static>(&mut self, handler: &H) {
        // On modern macOS, some runtimes call spawn/exec functions through:
        // - regular symbol stubs (handled by import rebinding), and/or
        // - function pointers resolved via dlsym() (requires inline attach).
        //
        // Install both strategies best-effort to maximize coverage.
        let posix_spawn_addr =
            malwi_intercept::module::find_global_export_by_name("posix_spawn").ok();
        let mut posix_spawn_attached = false;
        if let Some(addr) = posix_spawn_addr {
            ORIGINAL_POSIX_SPAWN.store(addr, Ordering::SeqCst);
            let listener = CallListener {
                on_enter: Some(on_posix_spawn_enter),
                on_leave: Some(on_posix_spawn_leave),
                user_data: handler as *const _ as *mut c_void,
            };
            if self
                .interceptor
                .attach(addr as *mut c_void, listener)
                .is_ok()
            {
                self.posix_spawn_listener = Some(listener);
                posix_spawn_attached = true;
                info!("Attached spawn monitor to posix_spawn() at {:#x}", addr);
            }
        }

        // Only rebind if inline attach failed — rebind scans all modules and is slow.
        if !posix_spawn_attached {
            match malwi_intercept::module::rebind_symbol(
                "posix_spawn",
                posix_spawn_rebind_wrapper as *const () as usize,
            ) {
                Ok(patched) => {
                    info!("Rebound posix_spawn in {} locations", patched.len());
                    if agent_debug_enabled() {
                        eprintln!("[malwi-agent] rebound posix_spawn: {} slots", patched.len());
                    }
                    self.posix_spawn_rebind = Some(patched);
                }
                Err(e) => {
                    warn!("Failed to rebind posix_spawn: {e:?}");
                    if posix_spawn_addr.is_none() {
                        warn!("Could not find posix_spawn");
                    }
                }
            }
        }

        // Hook posix_spawnp (PATH-searching variant used by many runtimes).
        let posix_spawnp_addr =
            malwi_intercept::module::find_global_export_by_name("posix_spawnp").ok();
        let mut posix_spawnp_attached = false;
        if let Some(addr) = posix_spawnp_addr {
            ORIGINAL_POSIX_SPAWNP.store(addr, Ordering::SeqCst);
            let listener = CallListener {
                on_enter: Some(on_posix_spawn_enter),
                on_leave: Some(on_posix_spawn_leave),
                user_data: handler as *const _ as *mut c_void,
            };
            if self
                .interceptor
                .attach(addr as *mut c_void, listener)
                .is_ok()
            {
                self.posix_spawnp_listener = Some(listener);
                posix_spawnp_attached = true;
                info!("Attached spawn monitor to posix_spawnp() at {:#x}", addr);
            }
        }
        if !posix_spawnp_attached {
            match malwi_intercept::module::rebind_symbol(
                "posix_spawnp",
                posix_spawnp_rebind_wrapper as *const () as usize,
            ) {
                Ok(patched) => {
                    info!("Rebound posix_spawnp in {} locations", patched.len());
                    if agent_debug_enabled() {
                        eprintln!(
                            "[malwi-agent] rebound posix_spawnp: {} slots",
                            patched.len()
                        );
                    }
                    self.posix_spawnp_rebind = Some(patched);
                }
                Err(e) => {
                    warn!("Failed to rebind posix_spawnp: {e:?}");
                    if posix_spawnp_addr.is_none() {
                        debug!("Could not find posix_spawnp");
                    }
                }
            }
        }

        // Hook execve
        self.setup_execve_hook(handler);
    }

    #[cfg(target_os = "linux")]
    unsafe fn setup_linux_hooks<H: SpawnHandler + 'static>(&mut self, handler: &H) {
        self.setup_posix_spawn_hooks(handler);
        self.setup_execve_hook(handler);
    }

    /// Hook posix_spawn/posix_spawnp via inline attach.
    /// On modern Linux (glibc 2.34+), posix_spawn uses clone3+execveat which
    /// bypasses execve, so we must hook it directly.
    #[cfg(target_os = "linux")]
    unsafe fn setup_posix_spawn_hooks<H: SpawnHandler + 'static>(&mut self, handler: &H) {
        if let Ok(addr) = malwi_intercept::module::find_global_export_by_name("posix_spawn") {
            ORIGINAL_POSIX_SPAWN.store(addr, Ordering::SeqCst);
            let listener = CallListener {
                on_enter: Some(on_posix_spawn_enter),
                on_leave: Some(on_posix_spawn_leave),
                user_data: handler as *const _ as *mut c_void,
            };
            if self
                .interceptor
                .attach(addr as *mut c_void, listener)
                .is_ok()
            {
                self.posix_spawn_listener = Some(listener);
                info!("Attached spawn monitor to posix_spawn() at {:#x}", addr);
            } else {
                warn!("Failed to attach to posix_spawn");
            }
        }

        if let Ok(addr) = malwi_intercept::module::find_global_export_by_name("posix_spawnp") {
            ORIGINAL_POSIX_SPAWNP.store(addr, Ordering::SeqCst);
            let listener = CallListener {
                on_enter: Some(on_posix_spawn_enter),
                on_leave: Some(on_posix_spawn_leave),
                user_data: handler as *const _ as *mut c_void,
            };
            if self
                .interceptor
                .attach(addr as *mut c_void, listener)
                .is_ok()
            {
                self.posix_spawnp_listener = Some(listener);
                info!("Attached spawn monitor to posix_spawnp() at {:#x}", addr);
            } else {
                warn!("Failed to attach to posix_spawnp");
            }
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    unsafe fn setup_execve_hook<H: SpawnHandler + 'static>(&mut self, handler: &H) {
        // Try __execve first (Android), then execve
        #[allow(unused_mut)]
        let mut execve_addr = malwi_intercept::module::find_global_export_by_name("execve").ok();

        #[cfg(target_os = "android")]
        if execve_addr.is_none() {
            execve_addr = malwi_intercept::module::find_global_export_by_name("__execve").ok();
        }

        if let Some(execve_addr) = execve_addr {
            ORIGINAL_EXECVE.store(execve_addr, Ordering::SeqCst);

            // Try inline attach first (fast), fall back to rebind (slow) if attach fails.
            let listener = CallListener {
                on_enter: Some(on_execve_enter),
                on_leave: Some(on_execve_leave),
                user_data: handler as *const _ as *mut c_void,
            };
            let execve_attached = self
                .interceptor
                .attach(execve_addr as *mut c_void, listener)
                .is_ok();
            if execve_attached {
                self.execve_listener = Some(listener);
                info!("Attached spawn monitor to execve() at {:#x}", execve_addr);
            } else {
                warn!("Failed to attach to execve");
            }

            #[cfg(target_os = "macos")]
            if !execve_attached {
                // Only rebind if inline attach failed — rebind scans all modules and is slow.
                match malwi_intercept::module::rebind_symbol(
                    "execve",
                    execve_rebind_wrapper as *const () as usize,
                ) {
                    Ok(patched) => {
                        info!("Rebound execve in {} locations", patched.len());
                        if agent_debug_enabled() {
                            eprintln!("[malwi-agent] rebound execve: {} slots", patched.len());
                        }
                        self.execve_rebind = Some(patched);
                    }
                    Err(e) => warn!("Failed to rebind execve: {e:?}"),
                }

                // Some runtimes call __execve directly; hook it too when present.
                if let Ok(addr) = malwi_intercept::module::find_global_export_by_name("__execve") {
                    ORIGINAL___EXECVE.store(addr, Ordering::SeqCst);
                    match malwi_intercept::module::rebind_symbol(
                        "__execve",
                        __execve_rebind_wrapper as *const () as usize,
                    ) {
                        Ok(patched) => {
                            info!("Rebound __execve in {} locations", patched.len());
                            if agent_debug_enabled() {
                                eprintln!(
                                    "[malwi-agent] rebound __execve: {} slots",
                                    patched.len()
                                );
                            }
                            if self.execve_rebind.is_none() {
                                self.execve_rebind = Some(patched);
                            }
                        }
                        Err(e) => warn!("Failed to rebind __execve: {e:?}"),
                    }
                }
            }
        } else {
            warn!("Could not find execve");
        }
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
    unsafe fn setup_bash_hooks(&mut self) {
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

        fn find_symbol_in_symbols(symbols: &[ExportInfo], symbol: &str) -> Option<usize> {
            symbols
                .iter()
                .find(|s| symbol_matches(&s.name, symbol))
                .map(|s| s.address)
        }

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

        fn find_bash_symbol(symbols: &[ExportInfo], symbol: &str) -> Option<usize> {
            find_symbol_in_symbols(symbols, symbol)
                .or_else(|| malwi_intercept::module::find_global_export_by_name(symbol).ok())
        }

        // Step 1: Detect bash via dist_version global variable.
        // dist_version is `const char * const` — unique to bash, contains e.g. "5.2"
        let (bash_module_name, bash_symbols, dist_version_addr) = if let Some(v) =
            find_symbol_any_module("dist_version")
        {
            v
        } else if let Ok(a) = malwi_intercept::module::find_global_export_by_name("dist_version") {
            // Extremely rare, but keeps old behavior if dist_version is exported.
            (String::new(), Vec::new(), a)
        } else {
            return; // Not a bash process
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
                on_enter: Some(on_shell_execve_enter),
                on_leave: None, // execve doesn't return on success
                user_data: ptr::null_mut(),
            };
            if self
                .interceptor
                .attach(shell_execve_addr as *mut c_void, listener)
                .is_ok()
            {
                self.bash_shell_execve_listener = Some(listener);
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
        let exec_cmd_addr =
            find_bash_symbol(&bash_symbols, "execute_command_internal").unwrap_or(0);
        if exec_cmd_addr != 0 {
            let listener = CallListener {
                on_enter: Some(on_execute_command_internal_enter),
                on_leave: None,
                user_data: ptr::null_mut(),
            };
            if self
                .interceptor
                .attach(exec_cmd_addr as *mut c_void, listener)
                .is_ok()
            {
                self.bash_exec_cmd_listener = Some(listener);
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
                on_enter: Some(on_eval_builtin_enter),
                on_leave: None,
                user_data: ptr::null_mut(),
            };
            if self
                .interceptor
                .attach(eval_addr as *mut c_void, listener)
                .is_ok()
            {
                self.bash_eval_listener = Some(listener);
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

        // Step 4: Hook source_builtin (source/. script.sh)
        // int source_builtin(WORD_LIST *list)
        let source_addr = find_bash_symbol(&bash_symbols, "source_builtin").unwrap_or(0);
        if source_addr != 0 {
            let listener = CallListener {
                on_enter: Some(on_source_builtin_enter),
                on_leave: None,
                user_data: ptr::null_mut(),
            };
            if self
                .interceptor
                .attach(source_addr as *mut c_void, listener)
                .is_ok()
            {
                self.bash_source_listener = Some(listener);
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
    }

    /// Install the find_variable hook for envvar monitoring.
    /// Called after the spawn monitor is created, when an EnvVar hook config is received.
    /// Only works if bash was detected (BASH_VERSION is set).
    ///
    /// # Safety
    /// The caller must ensure the interceptor is in a valid state for attaching hooks.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub unsafe fn enable_envvar_hook(&mut self) {
        if self.bash_find_variable_listener.is_some() {
            return; // Already installed
        }
        if BASH_VERSION.get().is_none() {
            return; // Not a bash process
        }

        // Re-resolve find_variable — use the same detection approach as setup_bash_hooks
        let find_var_addr = malwi_intercept::module::find_global_export_by_name("find_variable")
            .ok()
            .unwrap_or(0);
        if find_var_addr == 0 {
            debug!("find_variable symbol not found for envvar monitoring");
            return;
        }

        self.interceptor.begin_transaction();
        let listener = CallListener {
            on_enter: Some(on_find_variable_enter),
            on_leave: Some(on_find_variable_leave),
            user_data: ptr::null_mut(),
        };
        if self
            .interceptor
            .attach(find_var_addr as *mut c_void, listener)
            .is_ok()
        {
            self.bash_find_variable_listener = Some(listener);
            info!(
                "Attached bash envvar monitor to find_variable() at {:#x}",
                find_var_addr
            );
        } else {
            warn!("Failed to attach to find_variable for envvar monitoring");
        }
        self.interceptor.end_transaction();
    }

    /// Install the native getenv() hook for envvar monitoring.
    /// Hooks libc's getenv to detect C-level environment variable access.
    ///
    /// # Safety
    /// The caller must ensure the interceptor is in a valid state for attaching hooks.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub unsafe fn enable_getenv_hook(&mut self) {
        if self.getenv_listener.is_some() {
            return; // Already installed
        }

        let getenv_addr = match malwi_intercept::module::find_global_export_by_name("getenv") {
            Ok(addr) => addr,
            Err(_) => {
                debug!("getenv symbol not found for native envvar monitoring");
                return;
            }
        };

        self.interceptor.begin_transaction();
        let listener = CallListener {
            on_enter: Some(on_getenv_enter),
            on_leave: Some(on_getenv_leave),
            user_data: ptr::null_mut(),
        };
        if self
            .interceptor
            .attach(getenv_addr as *mut c_void, listener)
            .is_ok()
        {
            self.getenv_listener = Some(listener);
            info!(
                "Attached native envvar monitor to getenv() at {:#x}",
                getenv_addr
            );
        } else {
            warn!("Failed to attach to getenv for envvar monitoring");
        }
        self.interceptor.end_transaction();
    }

    /// Check if the monitor is active.
    pub fn is_active(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            self.posix_spawn_listener.is_some()
                || self.posix_spawnp_listener.is_some()
                || self.execve_listener.is_some()
        }
        #[cfg(target_os = "linux")]
        {
            self.posix_spawn_listener.is_some()
                || self.posix_spawnp_listener.is_some()
                || self.execve_listener.is_some()
        }
        #[cfg(target_os = "windows")]
        {
            false
        }
    }
}

impl Drop for SpawnMonitor {
    fn drop(&mut self) {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            if let Some(l) = &self.execve_listener {
                self.interceptor.detach(l);
            }
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            if let Some(l) = &self.posix_spawn_listener {
                self.interceptor.detach(l);
            }
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            if let Some(l) = &self.posix_spawnp_listener {
                self.interceptor.detach(l);
            }
            #[cfg(target_os = "macos")]
            unsafe {
                if let Some(p) = &self.posix_spawn_rebind {
                    restore_rebinds(p);
                }
                if let Some(p) = &self.posix_spawnp_rebind {
                    restore_rebinds(p);
                }
                if let Some(p) = &self.execve_rebind {
                    restore_rebinds(p);
                }
            }
            if let Some(l) = &self.bash_shell_execve_listener {
                self.interceptor.detach(l);
            }
            if let Some(l) = &self.bash_exec_cmd_listener {
                self.interceptor.detach(l);
            }
            if let Some(l) = &self.bash_eval_listener {
                self.interceptor.detach(l);
            }
            if let Some(l) = &self.bash_source_listener {
                self.interceptor.detach(l);
            }
            if let Some(l) = &self.bash_find_variable_listener {
                self.interceptor.detach(l);
            }
            if let Some(l) = &self.getenv_listener {
                self.interceptor.detach(l);
            }
        }

        debug!("Spawn monitor detached");
    }
}

// ============================================================================
// macOS: posix_spawn hooks
// ============================================================================

#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe extern "C" fn on_posix_spawn_enter(
    context: *mut InvocationContext,
    _user_data: *mut c_void,
) {
    // posix_spawn signature:
    // int posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions,
    //                 const posix_spawnattr_t *attrp, char *const argv[], char *const envp[])

    // Get path argument (arg 1)
    let path_ptr = malwi_intercept::invocation::get_nth_argument(context, 1) as *const c_char;
    let path = if !path_ptr.is_null() {
        Some(CStr::from_ptr(path_ptr).to_string_lossy().into_owned())
    } else {
        None
    };

    // Get argv argument (arg 4)
    let argv_ptr =
        malwi_intercept::invocation::get_nth_argument(context, 4) as *const *const c_char;
    let argv = parse_argv(argv_ptr);

    debug!("posix_spawn() enter: path={:?}, argv={:?}", path, argv);

    // Check review mode BEFORE the spawn completes
    if !check_exec_review(&path, &argv, None, None) {
        // User denied - make posix_spawn fail by replacing path with invalid one
        // Use a static string to ensure it lives long enough
        static BLOCKED_PATH: &[u8] = b"/usr/bin/false\0";
        malwi_intercept::invocation::replace_nth_argument(
            context,
            1, // posix_spawn path is arg 1
            BLOCKED_PATH.as_ptr() as *mut c_void,
        );
        info!("BLOCKED posix_spawn: {:?}", path);
        // Clear context so on_leave doesn't try to notify
        SPAWN_CONTEXT.with(|ctx| {
            *ctx.borrow_mut() = None;
        });
        return;
    }

    let native_stack = should_capture_stack(&path, &argv, context);

    // Store in thread-local for on_leave
    SPAWN_CONTEXT.with(|ctx| {
        *ctx.borrow_mut() = Some(SpawnContext {
            path,
            argv,
            pid_ptr: malwi_intercept::invocation::get_nth_argument(context, 0) as *mut libc::pid_t,
            native_stack,
        });
    });
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe extern "C" fn on_posix_spawn_leave(
    context: *mut InvocationContext,
    _user_data: *mut c_void,
) {
    let result = malwi_intercept::invocation::get_return_value(context) as i32;

    if result != 0 {
        // posix_spawn failed
        SPAWN_CONTEXT.with(|ctx| *ctx.borrow_mut() = None);
        return;
    }

    // Call the global agent's handler methods directly
    if let Some(agent) = crate::Agent::get() {
        SPAWN_CONTEXT.with(|ctx| {
            if let Some(spawn_ctx) = ctx.borrow_mut().take() {
                let child_pid = if !spawn_ctx.pid_ptr.is_null() {
                    *spawn_ctx.pid_ptr as u32
                } else {
                    0
                };

                debug!(
                    "posix_spawn() success: child_pid={}, path={:?}",
                    child_pid, spawn_ctx.path
                );

                agent.on_spawn_created(SpawnInfo {
                    child_pid,
                    path: spawn_ctx.path,
                    argv: spawn_ctx.argv,
                    native_stack: spawn_ctx.native_stack,
                    source_file: None,
                    source_line: None,
                });
            }
        });
    }
}

// ============================================================================
// macOS: import rebinding fallback (fishhook-style)
// ============================================================================

#[cfg(target_os = "macos")]
type PosixSpawnFn = unsafe extern "C" fn(
    pid: *mut libc::pid_t,
    path: *const c_char,
    file_actions: *const libc::posix_spawn_file_actions_t,
    attrp: *const libc::posix_spawnattr_t,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> libc::c_int;

#[cfg(target_os = "macos")]
type ExecveFn = unsafe extern "C" fn(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> libc::c_int;

#[cfg(target_os = "macos")]
unsafe fn resolve_next(symbol: &str) -> usize {
    use std::ffi::CString;
    let c = match CString::new(symbol) {
        Ok(c) => c,
        Err(_) => return 0,
    };

    // Prefer calling the original `dlsym` directly if we have it, otherwise
    // fall back to the libc symbol (which may be rebound/interposed).
    let orig = ORIGINAL_DLSYM.load(Ordering::SeqCst);
    let p = if orig != 0 {
        type DlsymFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
        let f: DlsymFn = core::mem::transmute(orig);
        f(libc::RTLD_NEXT, c.as_ptr())
    } else {
        libc::dlsym(libc::RTLD_NEXT, c.as_ptr())
    };

    p as usize
}

// ============================================================================
// macOS: dlsym rebinding (handles runtimes that resolve function pointers)
// ============================================================================

#[cfg(target_os = "macos")]
pub(crate) unsafe fn install_dlsym_override() {
    // Best-effort: if this fails, spawn/exec monitoring may still work via
    // import rebinding / inline hooks in other places.
    if ORIGINAL_DLSYM.load(Ordering::SeqCst) != 0 {
        return;
    }

    if let Ok(patched) =
        malwi_intercept::module::rebind_symbol("dlsym", dlsym_rebind_wrapper as *const () as usize)
    {
        if let Some((_, original)) = patched.first() {
            ORIGINAL_DLSYM.store(*original, Ordering::SeqCst);
        }
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn posix_spawn_dlsym_wrapper(
    pid: *mut libc::pid_t,
    path: *const c_char,
    file_actions: *const libc::posix_spawn_file_actions_t,
    attrp: *const libc::posix_spawnattr_t,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> libc::c_int {
    posix_spawn_rebind_wrapper(
        pid,
        path,
        file_actions,
        attrp,
        argv as *const *const c_char,
        envp as *const *const c_char,
    )
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn posix_spawnp_dlsym_wrapper(
    pid: *mut libc::pid_t,
    path: *const c_char,
    file_actions: *const libc::posix_spawn_file_actions_t,
    attrp: *const libc::posix_spawnattr_t,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> libc::c_int {
    posix_spawnp_rebind_wrapper(
        pid,
        path,
        file_actions,
        attrp,
        argv as *const *const c_char,
        envp as *const *const c_char,
    )
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn execve_dlsym_wrapper(
    path: *const c_char,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> libc::c_int {
    execve_rebind_wrapper(
        path,
        argv as *const *const c_char,
        envp as *const *const c_char,
    )
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn __execve_dlsym_wrapper(
    path: *const c_char,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> libc::c_int {
    __execve_rebind_wrapper(
        path,
        argv as *const *const c_char,
        envp as *const *const c_char,
    )
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn dlsym_rebind_wrapper(
    handle: *mut c_void,
    symbol: *const c_char,
) -> *mut c_void {
    // Return our spawn/exec wrappers for runtimes that resolve via dlsym.
    if !symbol.is_null() {
        let name = CStr::from_ptr(symbol).to_bytes();
        match name {
            b"posix_spawn" | b"_posix_spawn" => return posix_spawn_dlsym_wrapper as *mut c_void,
            b"posix_spawnp" | b"_posix_spawnp" => return posix_spawnp_dlsym_wrapper as *mut c_void,
            b"execve" | b"_execve" => return execve_dlsym_wrapper as *mut c_void,
            b"__execve" | b"___execve" => return __execve_dlsym_wrapper as *mut c_void,
            _ => {}
        }
    }

    let orig = ORIGINAL_DLSYM.load(Ordering::SeqCst);
    if orig == 0 {
        // If we failed to save it (unexpected), fall back to libc.
        return libc::dlsym(handle, symbol);
    }

    type DlsymFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
    let f: DlsymFn = core::mem::transmute(orig);
    f(handle, symbol)
}

#[cfg(target_os = "macos")]
#[allow(unreachable_code)]
unsafe fn capture_exec_stack(path: &Option<String>, argv: &Option<Vec<String>>) -> Vec<usize> {
    // Only capture when a matching exec filter requests it (set by CLI --st / filter flags).
    let cmd = if let Some(args) = argv.as_ref() {
        malwi_protocol::exec::unwrap_shell_command(args)
            .or_else(|| args.first().map(|s| basename(s)))
    } else {
        path.as_ref().map(|p| basename(p))
    };

    let Some(cmd) = cmd else {
        return Vec::new();
    };

    let (_matches, capture_stack) = crate::exec_filter::check_filter(cmd);
    if !capture_stack {
        return Vec::new();
    }

    // Capture a best-effort native stack from the current frame.
    #[cfg(target_arch = "aarch64")]
    {
        let fp: u64;
        let lr: u64;
        unsafe {
            core::arch::asm!("mov {}, x29", out(reg) fp);
            core::arch::asm!("mov {}, x30", out(reg) lr);
        }
        let ctx = malwi_intercept::types::Arm64CpuContext {
            pc: 0,
            sp: 0,
            nzcv: 0,
            x: [0u64; 29],
            fp,
            lr,
            v: [0u128; 32],
        };
        return malwi_intercept::backtrace::capture_backtrace(&ctx, 64);
    }

    #[cfg(target_arch = "x86_64")]
    {
        let rbp: u64;
        unsafe {
            core::arch::asm!("mov {}, rbp", out(reg) rbp);
        }
        let ctx = malwi_intercept::types::X86_64CpuContext {
            rip: 0,
            rsp: 0,
            rflags: 0,
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
        };
        return malwi_intercept::backtrace::capture_backtrace(&ctx, 64);
    }

    Vec::new()
}

#[cfg(target_os = "macos")]
unsafe fn restore_rebinds(patched: &[(usize, usize)]) {
    let page_sz = libc::sysconf(libc::_SC_PAGESIZE) as usize;
    for (slot, original) in patched {
        let slot_ptr = *slot as *mut usize;
        let page = (slot_ptr as usize) & !(page_sz - 1);
        let page_ptr = page as *mut libc::c_void;
        let _ = libc::mprotect(page_ptr, page_sz, libc::PROT_READ | libc::PROT_WRITE);
        core::ptr::write_unaligned(slot_ptr, *original);
    }
}

#[cfg(target_os = "macos")]
pub(crate) unsafe extern "C" fn posix_spawn_rebind_wrapper(
    pid: *mut libc::pid_t,
    path: *const c_char,
    file_actions: *const libc::posix_spawn_file_actions_t,
    attrp: *const libc::posix_spawnattr_t,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> libc::c_int {
    if agent_debug_enabled() {
        eprintln!("[malwi-agent] posix_spawn wrapper called");
    }
    let mut original = ORIGINAL_POSIX_SPAWN.load(Ordering::SeqCst);
    if original == 0 {
        original = resolve_next("posix_spawn");
        ORIGINAL_POSIX_SPAWN.store(original, Ordering::SeqCst);
    }
    let original: PosixSpawnFn = core::mem::transmute(original);

    let path_s = if !path.is_null() {
        Some(CStr::from_ptr(path).to_string_lossy().into_owned())
    } else {
        None
    };
    let argv_v = parse_argv(argv);

    if !check_exec_review(&path_s, &argv_v, None, None) {
        return libc::EACCES;
    }

    let rc = original(pid, path, file_actions, attrp, argv, envp);
    if rc == 0 {
        if let Some(agent) = crate::Agent::get() {
            let child_pid = if !pid.is_null() { *pid as u32 } else { 0 };
            let native_stack = capture_exec_stack(&path_s, &argv_v);
            agent.on_spawn_created(SpawnInfo {
                child_pid,
                path: path_s,
                argv: argv_v,
                native_stack,
                source_file: None,
                source_line: None,
            });
        }
    }
    rc
}

#[cfg(target_os = "macos")]
pub(crate) unsafe extern "C" fn posix_spawnp_rebind_wrapper(
    pid: *mut libc::pid_t,
    path: *const c_char,
    file_actions: *const libc::posix_spawn_file_actions_t,
    attrp: *const libc::posix_spawnattr_t,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> libc::c_int {
    if agent_debug_enabled() {
        eprintln!("[malwi-agent] posix_spawnp wrapper called");
    }
    let mut original = ORIGINAL_POSIX_SPAWNP.load(Ordering::SeqCst);
    if original == 0 {
        original = resolve_next("posix_spawnp");
        ORIGINAL_POSIX_SPAWNP.store(original, Ordering::SeqCst);
    }
    let original: PosixSpawnFn = core::mem::transmute(original);

    let path_s = if !path.is_null() {
        Some(CStr::from_ptr(path).to_string_lossy().into_owned())
    } else {
        None
    };
    let argv_v = parse_argv(argv);

    if !check_exec_review(&path_s, &argv_v, None, None) {
        return libc::EACCES;
    }

    let rc = original(pid, path, file_actions, attrp, argv, envp);
    if rc == 0 {
        if let Some(agent) = crate::Agent::get() {
            let child_pid = if !pid.is_null() { *pid as u32 } else { 0 };
            let native_stack = capture_exec_stack(&path_s, &argv_v);
            agent.on_spawn_created(SpawnInfo {
                child_pid,
                path: path_s,
                argv: argv_v,
                native_stack,
                source_file: None,
                source_line: None,
            });
        }
    }
    rc
}

#[cfg(target_os = "macos")]
pub(crate) unsafe extern "C" fn execve_rebind_wrapper(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> libc::c_int {
    if agent_debug_enabled() {
        eprintln!("[malwi-agent] execve wrapper called");
    }
    // Skip if shell_execve already handled this (it calls execve internally).
    if IN_SHELL_EXECVE.with(|f| f.get()) {
        IN_SHELL_EXECVE.with(|f| f.set(false));
    } else {
        let path_s = if !path.is_null() {
            Some(CStr::from_ptr(path).to_string_lossy().into_owned())
        } else {
            None
        };
        let argv_v = parse_argv(argv);

        if !check_exec_review(&path_s, &argv_v, None, None) {
            *libc::__error() = libc::EACCES;
            return -1;
        }

        if let Some(agent) = crate::Agent::get() {
            let pid = std::process::id();
            let native_stack = capture_exec_stack(&path_s, &argv_v);
            agent.on_exec_imminent(SpawnInfo {
                child_pid: pid,
                path: path_s,
                argv: argv_v,
                native_stack,
                source_file: None,
                source_line: None,
            });
        }
    }

    let mut original = ORIGINAL_EXECVE.load(Ordering::SeqCst);
    if original == 0 {
        original = resolve_next("execve");
        ORIGINAL_EXECVE.store(original, Ordering::SeqCst);
    }
    let original: ExecveFn = core::mem::transmute(original);
    original(path, argv, envp)
}

#[cfg(target_os = "macos")]
pub(crate) unsafe extern "C" fn __execve_rebind_wrapper(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> libc::c_int {
    if agent_debug_enabled() {
        eprintln!("[malwi-agent] __execve wrapper called");
    }
    // Same behavior as execve_rebind_wrapper, but calls the original __execve.
    if IN_SHELL_EXECVE.with(|f| f.get()) {
        IN_SHELL_EXECVE.with(|f| f.set(false));
    } else {
        let path_s = if !path.is_null() {
            Some(CStr::from_ptr(path).to_string_lossy().into_owned())
        } else {
            None
        };
        let argv_v = parse_argv(argv);

        if !check_exec_review(&path_s, &argv_v, None, None) {
            *libc::__error() = libc::EACCES;
            return -1;
        }

        if let Some(agent) = crate::Agent::get() {
            let pid = std::process::id();
            let native_stack = capture_exec_stack(&path_s, &argv_v);
            agent.on_exec_imminent(SpawnInfo {
                child_pid: pid,
                path: path_s,
                argv: argv_v,
                native_stack,
                source_file: None,
                source_line: None,
            });
        }
    }

    let mut original = ORIGINAL___EXECVE.load(Ordering::SeqCst);
    if original == 0 {
        original = resolve_next("__execve");
        ORIGINAL___EXECVE.store(original, Ordering::SeqCst);
    }
    let original: ExecveFn = core::mem::transmute(original);
    original(path, argv, envp)
}

// ============================================================================
// Review Mode Support for Exec
// ============================================================================

/// Check review mode for exec and wait for user decision.
/// Returns true if allowed, false if denied.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn check_exec_review(
    path: &Option<String>,
    argv: &Option<Vec<String>>,
    source_file: Option<&str>,
    source_line: Option<u32>,
) -> bool {
    let Some(agent) = crate::Agent::get() else {
        return true; // Allow if no agent
    };

    if !agent.is_review_mode() {
        return true;
    }

    // Extract effective command: unwrap shell wrappers like sh -c "curl ..."
    let cmd = if let Some(args) = argv.as_ref() {
        malwi_protocol::exec::unwrap_shell_command(args)
            .or_else(|| args.first().map(|s| basename(s)))
    } else {
        path.as_ref().map(|p| basename(p))
    };

    let Some(cmd) = cmd else {
        return true; // Allow if no command to check
    };

    if !crate::exec_filter::has_filters() {
        return true; // No exec filters, skip review
    }

    let (matches, _) = crate::exec_filter::check_filter(cmd);
    if !matches {
        return true; // Doesn't match filter, skip review
    }

    // Build trace event for the exec
    let event = crate::tracing::event::exec_event(cmd, argv.clone())
        .source_location(source_file.map(|s| s.to_string()), source_line)
        .build();

    // Wait for user decision
    agent.await_review_decision(event).is_allowed()
}

/// Extract the basename from a path.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn basename(path: &str) -> &str {
    std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
}

// ============================================================================
// Unix: execve hooks
// ============================================================================

#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe extern "C" fn on_execve_enter(context: *mut InvocationContext, _user_data: *mut c_void) {
    // execve signature: int execve(const char *path, char *const argv[], char *const envp[])

    // Skip if shell_execve already handled this (it calls execve internally)
    if IN_SHELL_EXECVE.with(|f| f.get()) {
        IN_SHELL_EXECVE.with(|f| f.set(false));
        return;
    }

    let path_ptr = malwi_intercept::invocation::get_nth_argument(context, 0) as *const c_char;
    let path = if !path_ptr.is_null() {
        Some(CStr::from_ptr(path_ptr).to_string_lossy().into_owned())
    } else {
        None
    };

    let argv_ptr =
        malwi_intercept::invocation::get_nth_argument(context, 1) as *const *const c_char;
    let argv = parse_argv(argv_ptr);

    debug!("execve() enter: path={:?}, argv={:?}", path, argv);

    // Check review mode BEFORE the exec completes
    if !check_exec_review(&path, &argv, None, None) {
        // User denied - make execve fail by replacing path with invalid one
        // Use a static string to ensure it lives long enough
        static BLOCKED_PATH: &[u8] = b"/usr/bin/false\0";
        malwi_intercept::invocation::replace_nth_argument(
            context,
            0,
            BLOCKED_PATH.as_ptr() as *mut c_void,
        );
        info!("BLOCKED exec: {:?}", path);
        return;
    }

    let native_stack = should_capture_stack(&path, &argv, context);

    // Call the global agent's handler methods directly
    // Notify that exec is imminent - after this, the process image will be replaced
    if let Some(agent) = crate::Agent::get() {
        let pid = std::process::id();
        agent.on_exec_imminent(SpawnInfo {
            child_pid: pid,
            path,
            argv,
            native_stack,
            source_file: None,
            source_line: None,
        });
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe extern "C" fn on_execve_leave(_context: *mut InvocationContext, _user_data: *mut c_void) {
    // If we get here, execve failed (otherwise process image would be replaced)
    debug!("execve() failed (returned to caller)");
}

// ============================================================================
// Bash: source location helpers
// ============================================================================

/// Read bash source location from global variables.
/// Returns (script_path, line_number).
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe fn get_bash_source_location() -> (Option<String>, Option<u32>) {
    let line_addr = BASH_LINE_NUMBER.load(Ordering::SeqCst);
    let vars_addr = BASH_DOLLAR_VARS.load(Ordering::SeqCst);

    let line = if line_addr != 0 {
        let n = *(line_addr as *const i32);
        if n > 0 {
            Some(n as u32)
        } else {
            None
        }
    } else {
        None
    };

    let file = if vars_addr != 0 {
        // dollar_vars is char*[10]; dollar_vars[0] = $0 (script name)
        let dollar0 = *(vars_addr as *const *const c_char);
        if !dollar0.is_null() {
            let s = CStr::from_ptr(dollar0).to_string_lossy();
            Some(s.into_owned())
        } else {
            None
        }
    } else {
        None
    };

    (file, line)
}

/// Offset of the `line` field in bash COMMAND struct.
/// COMMAND layout: type(i32@0), flags(i32@4), line(i32@8), ...
#[cfg(any(target_os = "macos", target_os = "linux"))]
const BASH_COMMAND_LINE_OFFSET: usize = 8;

/// Read source location from a COMMAND struct pointer.
/// Uses the COMMAND's line field (more precise than global line_number)
/// and dollar_vars[0] for the filename.
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe fn get_bash_command_source_location(cmd_ptr: *const u8) -> (Option<String>, Option<u32>) {
    let vars_addr = BASH_DOLLAR_VARS.load(Ordering::SeqCst);

    let line = if !cmd_ptr.is_null() {
        let n = *(cmd_ptr.add(BASH_COMMAND_LINE_OFFSET) as *const i32);
        if n > 0 {
            Some(n as u32)
        } else {
            // Fallback: global line_number (COMMAND.line is 0 for some builtins)
            let line_addr = BASH_LINE_NUMBER.load(Ordering::SeqCst);
            if line_addr != 0 {
                let g = *(line_addr as *const i32);
                if g > 0 {
                    Some(g as u32)
                } else {
                    None
                }
            } else {
                None
            }
        }
    } else {
        None
    };

    let file = if vars_addr != 0 {
        let dollar0 = *(vars_addr as *const *const c_char);
        if !dollar0.is_null() {
            let s = CStr::from_ptr(dollar0).to_string_lossy();
            Some(s.into_owned())
        } else {
            None
        }
    } else {
        None
    };

    (file, line)
}

// ============================================================================
// Bash: shell_execve, eval_builtin, source_builtin hooks
// ============================================================================

/// Hook for bash's shell_execve() — catches all external commands.
/// Signature: int shell_execve(char *command, char **args, char **env)
/// Same as execve — called right before the actual execve() syscall in bash's child process.
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe extern "C" fn on_shell_execve_enter(
    context: *mut InvocationContext,
    _user_data: *mut c_void,
) {
    // shell_execve(char *command, char **args, char **env)
    IN_SHELL_EXECVE.with(|f| f.set(true));

    let path_ptr = malwi_intercept::invocation::get_nth_argument(context, 0) as *const c_char;
    let path = if !path_ptr.is_null() {
        Some(CStr::from_ptr(path_ptr).to_string_lossy().into_owned())
    } else {
        None
    };

    let argv_ptr =
        malwi_intercept::invocation::get_nth_argument(context, 1) as *const *const c_char;
    let argv = parse_argv(argv_ptr);

    debug!("shell_execve() enter: path={:?}, argv={:?}", path, argv);

    // Capture source location BEFORE review check so denied events also have it
    let (source_file, source_line) = get_bash_source_location();

    // Check review mode / policy BEFORE the exec completes
    if !check_exec_review(&path, &argv, source_file.as_deref(), source_line) {
        // Block by replacing path with an invalid one
        static BLOCKED_PATH: &[u8] = b"/usr/bin/false\0";
        malwi_intercept::invocation::replace_nth_argument(
            context,
            0,
            BLOCKED_PATH.as_ptr() as *mut c_void,
        );
        info!("BLOCKED bash shell_execve: {:?}", path);
        return;
    }

    let native_stack = should_capture_stack(&path, &argv, context);

    // Send exec event to CLI
    if let Some(agent) = crate::Agent::get() {
        let pid = std::process::id();
        agent.on_exec_imminent(SpawnInfo {
            child_pid: pid,
            path,
            argv,
            native_stack,
            source_file,
            source_line,
        });
    }
}

/// Bash COMMAND struct layout (verified for bash 5.1–5.3, 64-bit):
///   offset 0:  command_type type  (int, 4 bytes) — cm_simple=4
///   offset 4:  int flags          (4 bytes)
///   offset 8:  int line           (4 bytes)
///   offset 16: REDIRECT *redirects (8 bytes, after padding)
///   offset 24: union value        (8 bytes — pointer to sub-struct)
///
/// For cm_simple (type=4), value.Simple points to SIMPLE_COM:
///   offset 0: int flags
///   offset 4: int line
///   offset 8: WORD_LIST *words
///
/// WORD_LIST: { next: *WORD_LIST (offset 0), word: *WORD_DESC (offset 8) }
/// WORD_DESC: { word: *char (offset 0), flags: int (offset 8) }
const BASH_CM_SIMPLE: i32 = 4;
const BASH_COMMAND_TYPE_OFFSET: usize = 0;
const BASH_COMMAND_VALUE_OFFSET: usize = 24;
const BASH_SIMPLE_COM_WORDS_OFFSET: usize = 8;

/// Hook for bash's execute_command_internal() — catches ALL commands (builtins + externals).
///
/// Signature: int execute_command_internal(COMMAND *command, int asynchronous,
///            int pipe_in, int pipe_out, struct fd_bitmap *fds_to_close)
///
/// For cm_simple commands, reads the first word from the COMMAND struct to get the command name.
/// This hook only handles tracing/policy for commands that don't go through shell_execve
/// (i.e., builtins and shell functions). External commands are handled by the shell_execve hook.
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe extern "C" fn on_execute_command_internal_enter(
    context: *mut InvocationContext,
    _user_data: *mut c_void,
) {
    // Clear envvar dedup set at each new bash command
    ENVVAR_SEEN.with(|set| set.borrow_mut().clear());

    // arg 0 = COMMAND *command
    let cmd_ptr = malwi_intercept::invocation::get_nth_argument(context, 0) as *const u8;
    if cmd_ptr.is_null() {
        return;
    }

    // Read command->type (int at offset 0)
    let cmd_type = *(cmd_ptr.add(BASH_COMMAND_TYPE_OFFSET) as *const i32);
    if cmd_type != BASH_CM_SIMPLE {
        return; // Only process simple commands (not for/while/if/etc.)
    }

    // Read command->value.Simple (pointer at offset 24)
    let simple_ptr = *(cmd_ptr.add(BASH_COMMAND_VALUE_OFFSET) as *const *const u8);
    if simple_ptr.is_null() {
        return;
    }

    // Read Simple->words (WORD_LIST* at offset 8)
    let words_ptr = *(simple_ptr.add(BASH_SIMPLE_COM_WORDS_OFFSET) as *const *const u8);
    if words_ptr.is_null() {
        return;
    }

    // Read first word: words->word->word
    let first_word = match read_word_list_first(words_ptr) {
        Some(w) => w,
        None => return,
    };

    // Determine if this is a builtin or shell function.
    // External commands are handled by the shell_execve hook (with resolved path + argv),
    // so we skip them here to avoid double-tracing.
    if first_word.contains('/') {
        return; // Explicit path like /usr/bin/curl — definitely external
    }

    // Use find_shell_builtin to check if it's a builtin
    let find_builtin_addr = BASH_FIND_SHELL_BUILTIN.load(Ordering::SeqCst);
    if find_builtin_addr != 0 {
        let name_cstr = CString::new(first_word.as_str()).ok();
        if let Some(name_cstr) = name_cstr {
            type FindBuiltinFn = unsafe extern "C" fn(*const c_char) -> *const u8;
            let find_builtin: FindBuiltinFn = std::mem::transmute(find_builtin_addr);
            let result = find_builtin(name_cstr.as_ptr());
            if result.is_null() {
                // Not a builtin — it's an external command that shell_execve will handle
                return;
            }
        }
    }

    // Collect all words for argv
    let words = read_word_list_all(words_ptr);

    debug!(
        "execute_command_internal() enter: cm_simple, command={}",
        first_word
    );

    let path = Some(first_word.clone());
    let argv = Some(words);

    // Capture source location BEFORE review check so denied events also have it
    let (source_file, source_line) = get_bash_command_source_location(cmd_ptr);

    // Check review mode / policy
    if !check_exec_review(&path, &argv, source_file.as_deref(), source_line) {
        // Block by replacing the COMMAND pointer with null.
        // execute_command_internal handles null by returning early.
        malwi_intercept::invocation::replace_nth_argument(context, 0, ptr::null_mut());
        info!("BLOCKED bash command: {}", first_word);
        return;
    }

    // Send exec event to CLI (only if exec filters are active)
    if crate::exec_filter::has_filters() {
        let cmd_name = basename(&first_word);
        let (matches, _) = crate::exec_filter::check_filter(cmd_name);
        if matches {
            let native_stack = should_capture_stack(&path, &argv, context);
            if let Some(agent) = crate::Agent::get() {
                let pid = std::process::id();
                agent.on_exec_imminent(SpawnInfo {
                    child_pid: pid,
                    path,
                    argv,
                    native_stack,
                    source_file,
                    source_line,
                });
            }
        }
    }
}

/// Read the first word from a bash WORD_LIST* structure.
///
/// WORD_LIST layout:
///   offset 0: *next (WORD_LIST*)
///   offset 8: *word (WORD_DESC*)
/// WORD_DESC layout:
///   offset 0: *word (char*)
///   offset 8: flags (int)
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe fn read_word_list_first(list_ptr: *const u8) -> Option<String> {
    if list_ptr.is_null() {
        return None;
    }
    // list->word (WORD_DESC*) is at offset 8 (skip next pointer)
    let word_desc_ptr = *(list_ptr.add(8) as *const *const u8);
    if word_desc_ptr.is_null() {
        return None;
    }
    // word_desc->word (char*) is at offset 0
    let word_ptr = *(word_desc_ptr as *const *const c_char);
    if word_ptr.is_null() {
        return None;
    }
    Some(CStr::from_ptr(word_ptr).to_string_lossy().into_owned())
}

/// Collect all words from a bash WORD_LIST* linked list.
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe fn read_word_list_all(mut list_ptr: *const u8) -> Vec<String> {
    let mut words = Vec::new();
    let mut safety = 0;
    while !list_ptr.is_null() && safety < 1000 {
        // list->word (WORD_DESC*) at offset 8
        let word_desc_ptr = *(list_ptr.add(8) as *const *const u8);
        if !word_desc_ptr.is_null() {
            let word_ptr = *(word_desc_ptr as *const *const c_char);
            if !word_ptr.is_null() {
                words.push(CStr::from_ptr(word_ptr).to_string_lossy().into_owned());
            }
        }
        // list->next (WORD_LIST*) at offset 0
        list_ptr = *(list_ptr as *const *const u8);
        safety += 1;
    }
    words
}

/// Hook for bash's eval_builtin() — catches `eval "code"`.
/// Signature: int eval_builtin(WORD_LIST *list)
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe extern "C" fn on_eval_builtin_enter(
    context: *mut InvocationContext,
    _user_data: *mut c_void,
) {
    let list_ptr = malwi_intercept::invocation::get_nth_argument(context, 0) as *const u8;

    let words = read_word_list_all(list_ptr);
    let eval_code = words.join(" ");
    debug!("eval_builtin() enter: code={}", eval_code);

    // Build argv as ["eval", <code>...]
    let mut argv_vec = vec!["eval".to_string()];
    argv_vec.extend(words);
    let path = Some("eval".to_string());
    let argv = Some(argv_vec);

    // Capture source location BEFORE review check so denied events also have it
    let (source_file, source_line) = get_bash_source_location();

    // Check review mode / policy
    if !check_exec_review(&path, &argv, source_file.as_deref(), source_line) {
        // Replace list arg with null — eval_builtin returns immediately for null list
        malwi_intercept::invocation::replace_nth_argument(context, 0, ptr::null_mut());
        info!("BLOCKED bash eval: {}", eval_code);
        return;
    }

    let native_stack = should_capture_stack(&path, &argv, context);

    // Send exec event to CLI
    if let Some(agent) = crate::Agent::get() {
        let pid = std::process::id();
        agent.on_exec_imminent(SpawnInfo {
            child_pid: pid,
            path,
            argv,
            native_stack,
            source_file,
            source_line,
        });
    }
}

/// Hook for bash's source_builtin() — catches `source file.sh` / `. file.sh`.
/// Signature: int source_builtin(WORD_LIST *list)
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe extern "C" fn on_source_builtin_enter(
    context: *mut InvocationContext,
    _user_data: *mut c_void,
) {
    let list_ptr = malwi_intercept::invocation::get_nth_argument(context, 0) as *const u8;

    let filename = read_word_list_first(list_ptr).unwrap_or_default();
    debug!("source_builtin() enter: file={}", filename);

    let path = Some("source".to_string());
    let argv = Some(vec!["source".to_string(), filename.clone()]);

    // Capture source location BEFORE review check so denied events also have it
    let (source_file, source_line) = get_bash_source_location();

    // Check review mode / policy
    if !check_exec_review(&path, &argv, source_file.as_deref(), source_line) {
        // Replace list arg with null — source_builtin returns EX_USAGE for null list
        malwi_intercept::invocation::replace_nth_argument(context, 0, ptr::null_mut());
        info!("BLOCKED bash source: {}", filename);
        return;
    }

    let native_stack = should_capture_stack(&path, &argv, context);

    // Send exec event to CLI
    if let Some(agent) = crate::Agent::get() {
        let pid = std::process::id();
        agent.on_exec_imminent(SpawnInfo {
            child_pid: pid,
            path,
            argv,
            native_stack,
            source_file,
            source_line,
        });
    }
}

// ============================================================================
// Native: getenv() hooks (libc environment variable access detection)
// ============================================================================

/// Enter callback for libc getenv(const char *name).
/// Stores the name pointer for the leave callback.
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe extern "C" fn on_getenv_enter(context: *mut InvocationContext, _user_data: *mut c_void) {
    let name_ptr = malwi_intercept::invocation::get_nth_argument(context, 0) as *const c_char;
    GETENV_NAME.with(|cell| cell.set(name_ptr));
}

/// Leave callback for libc getenv.
/// If return value is non-NULL, the variable exists — check deny filter and send event.
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe extern "C" fn on_getenv_leave(context: *mut InvocationContext, _user_data: *mut c_void) {
    let retval = malwi_intercept::invocation::get_return_value(context) as *const c_char;
    if retval.is_null() {
        return; // Variable doesn't exist — nothing to report
    }

    let name_ptr = GETENV_NAME.with(|cell| cell.get());
    if name_ptr.is_null() {
        return;
    }
    let name = CStr::from_ptr(name_ptr).to_string_lossy();

    // Skip agent-internal variables to avoid noise and infinite recursion
    if name.starts_with("MALWI_") || name == "LD_PRELOAD" || name == "DYLD_INSERT_LIBRARIES" {
        return;
    }

    // Skip if Python or Node.js envvar monitoring is active — those layers are more informative
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        if crate::cpython::is_envvar_monitoring_enabled() {
            return;
        }
        if crate::nodejs::is_envvar_monitoring_enabled() {
            return;
        }
    }

    // Dedup: report each variable once per thread
    let is_new = GETENV_SEEN.with(|set| set.borrow_mut().insert(name.to_string()));
    if !is_new {
        return;
    }

    // Check agent-side deny filter — if blocked, replace return value with NULL
    let blocked = crate::envvar_filter::should_block(&name);
    if blocked {
        malwi_intercept::invocation::replace_return_value(context, ptr::null_mut());
    }

    // Send trace event
    if let Some(agent) = crate::Agent::get() {
        let event = crate::tracing::event::envvar_enter(&name).build();
        let _ = agent.send_event(event);
    }
}

// ============================================================================
// Bash: find_variable hooks (environment variable access detection)
// ============================================================================

// Thread-local storage for the variable name from find_variable's enter callback.
// Used to pass the name to the leave callback.
#[cfg(any(target_os = "macos", target_os = "linux"))]
thread_local! {
    static FIND_VAR_NAME: Cell<*const c_char> = const { Cell::new(ptr::null()) };
}

/// SHELL_VAR struct layout (bash 4.4–5.3, 64-bit):
///   offset 0:  char *name          (8 bytes)
///   offset 8:  char *value         (8 bytes)
///   offset 16: char *exportstr     (8 bytes)
///   offset 24: dynamic_value func  (8 bytes)
///   offset 32: assign_func func    (8 bytes)
///   offset 40: int attributes      (4 bytes) — att_exported = 0x1
#[cfg(any(target_os = "macos", target_os = "linux"))]
const SHELL_VAR_ATTRIBUTES_OFFSET: usize = 40;
#[cfg(any(target_os = "macos", target_os = "linux"))]
const ATT_EXPORTED: i32 = 0x1;

/// Enter callback for bash's find_variable(const char *name).
/// Stores the name pointer for the leave callback.
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe extern "C" fn on_find_variable_enter(
    context: *mut InvocationContext,
    _user_data: *mut c_void,
) {
    let name_ptr = malwi_intercept::invocation::get_nth_argument(context, 0) as *const c_char;
    FIND_VAR_NAME.with(|cell| cell.set(name_ptr));
}

/// Leave callback for bash's find_variable.
/// Checks the return value (SHELL_VAR*) for att_exported flag.
/// If exported, sends an EnvVar trace event.
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe extern "C" fn on_find_variable_leave(
    context: *mut InvocationContext,
    _user_data: *mut c_void,
) {
    let shell_var = malwi_intercept::invocation::get_return_value(context) as *const u8;
    if shell_var.is_null() {
        return; // Variable not found
    }

    // Check att_exported flag at offset 40
    let attributes = *(shell_var.add(SHELL_VAR_ATTRIBUTES_OFFSET) as *const i32);
    if attributes & ATT_EXPORTED == 0 {
        return; // Not an exported (environment) variable — skip
    }

    // Read the name from enter callback
    let name_ptr = FIND_VAR_NAME.with(|cell| cell.get());
    if name_ptr.is_null() {
        return;
    }
    let name = CStr::from_ptr(name_ptr).to_string_lossy();

    // Dedup: skip if already seen in this command
    let is_new = ENVVAR_SEEN.with(|set| set.borrow_mut().insert(name.to_string()));
    if !is_new {
        return;
    }

    // Check agent-side deny filter — if blocked, replace return value with NULL
    // so bash sees the variable as unset (prevents secret leakage).
    let blocked = crate::envvar_filter::should_block(&name);
    if blocked {
        malwi_intercept::invocation::replace_return_value(context, ptr::null_mut());
    }

    // Send trace event regardless (blocked or not — CLI decides display)
    if let Some(agent) = crate::Agent::get() {
        let event = crate::tracing::event::envvar_enter(&name).build();
        let _ = agent.send_event(event);
    }
}

// ============================================================================
// Helper functions
// ============================================================================

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::cell::RefCell;

#[cfg(any(target_os = "macos", target_os = "linux"))]
struct SpawnContext {
    path: Option<String>,
    argv: Option<Vec<String>>,
    pid_ptr: *mut libc::pid_t,
    native_stack: Vec<usize>,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
thread_local! {
    static SPAWN_CONTEXT: RefCell<Option<SpawnContext>> = const { RefCell::new(None) };
}

/// Parse a null-terminated argv array into a Vec<String>.
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe fn parse_argv(argv: *const *const c_char) -> Option<Vec<String>> {
    if argv.is_null() {
        return None;
    }

    let mut result = Vec::new();
    let mut i = 0;

    loop {
        let arg = *argv.add(i);
        if arg.is_null() {
            break;
        }
        result.push(CStr::from_ptr(arg).to_string_lossy().into_owned());
        i += 1;

        // Safety limit
        if i > 1000 {
            break;
        }
    }

    Some(result)
}

/// Check if stack capture is needed for this exec/spawn command.
/// Returns the native stack frames or empty vector.
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe fn should_capture_stack(
    path: &Option<String>,
    argv: &Option<Vec<String>>,
    context: *mut InvocationContext,
) -> Vec<usize> {
    // Extract effective command: unwrap shell wrappers like sh -c "curl ..."
    let cmd = if let Some(args) = argv.as_ref() {
        malwi_protocol::exec::unwrap_shell_command(args)
            .or_else(|| args.first().map(|s| basename(s)))
    } else {
        path.as_ref().map(|p| basename(p))
    };

    let Some(cmd) = cmd else {
        return Vec::new();
    };

    // Check if this command matches a filter with capture_stack enabled
    let (_matches, capture_stack) = crate::exec_filter::check_filter(cmd);
    if capture_stack {
        crate::hooks::capture_backtrace(context)
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_gum;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct TestHandler {
        spawn_called: AtomicBool,
        exec_called: AtomicBool,
        suspended_called: AtomicBool,
        gating_enabled: AtomicBool,
    }

    impl SpawnHandler for TestHandler {
        fn on_spawn_created(&self, _info: SpawnInfo) {
            self.spawn_called.store(true, Ordering::SeqCst);
        }

        fn on_exec_imminent(&self, _info: SpawnInfo) {
            self.exec_called.store(true, Ordering::SeqCst);
        }

        fn on_child_spawned_suspended(&self, _info: SpawnInfo) {
            self.suspended_called.store(true, Ordering::SeqCst);
        }

        fn is_child_gating_enabled(&self) -> bool {
            self.gating_enabled.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn test_spawn_monitor_creation() {
        init_gum();

        let handler = Arc::new(TestHandler {
            spawn_called: AtomicBool::new(false),
            exec_called: AtomicBool::new(false),
            suspended_called: AtomicBool::new(false),
            gating_enabled: AtomicBool::new(false),
        });

        let monitor = unsafe { SpawnMonitor::new(handler.as_ref()) };
        assert!(monitor.is_some(), "Should create spawn monitor");
    }
}
