//! Spawn/exec interception for child process gating.
//!
//! Platform-specific hooks:
//! - macOS: posix_spawn, execve
//! - Linux: execve
//! - Windows: CreateProcessInternalW

use std::cell::Cell;
use std::collections::HashSet;
#[cfg(target_os = "macos")]
use std::ffi::CString;
use std::ffi::{c_char, CStr};
use std::ptr;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "macos")]
use std::sync::OnceLock;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::CallListener;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::InvocationContext;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use core::ffi::c_void;
use log::{debug, info, warn};

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
    /// Name pointer from getenv enter callback, consumed in leave callback.
    static GETENV_NAME: Cell<*const c_char> = const { Cell::new(ptr::null()) };

    /// Dedup set for native getenv — reports each variable once per thread lifetime.
    static GETENV_SEEN: std::cell::RefCell<HashSet<String>> = std::cell::RefCell::new(HashSet::new());
}

/// Saved DYLD_INSERT_LIBRARIES value for selective re-injection into compatible children.
/// Set during agent init, before DYLD vars are stripped from the process environment.
#[cfg(target_os = "macos")]
static AGENT_DYLD_PATH: OnceLock<String> = OnceLock::new();

/// Save the agent library path from DYLD_INSERT_LIBRARIES for later re-injection.
#[cfg(target_os = "macos")]
pub(crate) fn set_agent_dyld_path(path: String) {
    let _ = AGENT_DYLD_PATH.set(path);
}

/// Check whether a binary at the given path is arm64e-only (incompatible with our arm64 agent).
///
/// Reads the Mach-O header to determine architecture:
/// - Thin MH_MAGIC_64: checks cpusubtype for arm64e (subtype 2).
/// - Fat (universal) binary: returns true only if ALL ARM64 slices are arm64e.
/// - Scripts, errors, unknown formats: returns false (assume compatible).
#[cfg(target_os = "macos")]
fn is_arm64e_binary(path: *const c_char) -> bool {
    use std::io::Read;

    const MH_MAGIC_64: u32 = 0xFEED_FACF;
    const FAT_MAGIC: u32 = 0xCAFE_BABE;
    const FAT_MAGIC_64: u32 = 0xCAFE_BABF;
    const CPU_TYPE_ARM64: i32 = 0x0100_000C; // CPU_TYPE_ARM | CPU_ARCH_ABI64
    const CPU_SUBTYPE_ARM64E: i32 = 2;

    if path.is_null() {
        return false;
    }

    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };

    let mut file = match std::fs::File::open(path_str) {
        Ok(f) => f,
        Err(_) => return false,
    };

    // Read enough for: 8-byte header + up to 25 fat_arch_64 entries (32 bytes each) = 808 bytes
    let mut buf = [0u8; 808];
    let n = match file.read(&mut buf) {
        Ok(n) if n >= 8 => n,
        _ => return false,
    };

    // Check for thin 64-bit Mach-O (little-endian on our platform)
    let magic_le = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic_le == MH_MAGIC_64 {
        if n < 12 {
            return false;
        }
        let cputype = i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let cpusubtype = i32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        return cputype == CPU_TYPE_ARM64 && (cpusubtype & 0xFF) == CPU_SUBTYPE_ARM64E;
    }

    // Check for fat (universal) binary — header is always big-endian
    let magic_be = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let arch_size = match magic_be {
        FAT_MAGIC => 20, // fat_arch: cputype(4) + cpusubtype(4) + offset(4) + size(4) + align(4)
        FAT_MAGIC_64 => 32, // fat_arch_64: same fields but offset/size are u64 + reserved
        _ => return false, // Not a Mach-O (script, etc.)
    };

    let nfat = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    let max_archs = nfat.min(25);

    let mut has_arm64 = false;
    let mut all_arm64e = true;

    for i in 0..max_archs {
        let base = 8 + i * arch_size;
        if base + 8 > n {
            break;
        }
        let cputype = i32::from_be_bytes([buf[base], buf[base + 1], buf[base + 2], buf[base + 3]]);
        let cpusubtype =
            i32::from_be_bytes([buf[base + 4], buf[base + 5], buf[base + 6], buf[base + 7]]);

        if cputype == CPU_TYPE_ARM64 {
            has_arm64 = true;
            if (cpusubtype & 0xFF) != CPU_SUBTYPE_ARM64E {
                all_arm64e = false;
            }
        }
    }

    // arm64e-only = has ARM64 slices but none are plain arm64
    has_arm64 && all_arm64e
}

/// Owns the modified envp array and the DYLD CStrings that it references.
/// Must be kept alive until the original posix_spawn/execve call completes.
#[cfg(target_os = "macos")]
struct InjectedEnvp {
    _owned: Vec<CString>,
    ptrs: Vec<*const c_char>,
}

/// Build a modified envp that includes the saved DYLD injection vars.
/// Returns None if no agent DYLD path was saved (nothing to inject).
#[cfg(target_os = "macos")]
unsafe fn build_injected_envp(envp: *const *const c_char) -> Option<InjectedEnvp> {
    let agent_path = AGENT_DYLD_PATH.get()?;

    let dyld_insert = CString::new(format!("DYLD_INSERT_LIBRARIES={}", agent_path)).ok()?;
    let dyld_flat = CString::new("DYLD_FORCE_FLAT_NAMESPACE=1").ok()?;

    let mut ptrs: Vec<*const c_char> = Vec::new();

    // Copy original entries, skipping any existing DYLD vars
    if !envp.is_null() {
        let mut i = 0;
        loop {
            let entry = *envp.add(i);
            if entry.is_null() {
                break;
            }
            let entry_bytes = CStr::from_ptr(entry).to_bytes();
            if !entry_bytes.starts_with(b"DYLD_INSERT_LIBRARIES=")
                && !entry_bytes.starts_with(b"DYLD_FORCE_FLAT_NAMESPACE=")
            {
                ptrs.push(entry);
            }
            i += 1;
            if i > 10000 {
                break;
            }
        }
    }

    // Append our DYLD vars
    ptrs.push(dyld_insert.as_ptr());
    ptrs.push(dyld_flat.as_ptr());
    ptrs.push(ptr::null());

    Some(InjectedEnvp {
        _owned: vec![dyld_insert, dyld_flat],
        ptrs,
    })
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
    pub source_column: Option<u32>,
    pub runtime_stack: Option<crate::RuntimeStack>,
    /// Override hook type for the resulting TraceEvent (e.g. HookType::Bash).
    pub hook_type: Option<crate::HookType>,
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
    interceptor: &'static crate::Interceptor,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    execve_listener: Option<CallListener>,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    posix_spawn_listener: Option<CallListener>,
    #[cfg(target_os = "macos")]
    posix_spawnp_listener: Option<CallListener>,
    /// Bash hook listeners (shell_execve, execute_command_internal, eval, source)
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    bash_listeners: crate::bash::BashHookListeners,
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
            let interceptor = crate::Interceptor::obtain();
            interceptor.begin_transaction();

            let mut monitor = Self {
                interceptor,
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                execve_listener: None,
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                posix_spawn_listener: None,
                #[cfg(target_os = "macos")]
                posix_spawnp_listener: None,
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                bash_listeners: Default::default(),
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

            monitor.bash_listeners = crate::bash::setup_bash_hooks(interceptor);

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
        self.setup_posix_spawn_hooks(handler);
        self.setup_execve_hook(handler);
    }

    /// On Linux, hook posix_spawn + execve but NOT posix_spawnp.
    ///
    /// glibc's `__spawni` (used by `posix_spawnp`) passes an internal
    /// `execvpe` entry point to its `CLONE_VFORK | CLONE_VM` child. When
    /// the child calls `execvpe` → `execve` (hooked), frida-gum's invocation
    /// tracking for the `posix_spawnp` attach trampoline conflicts with the
    /// `execve` trampoline through the shared TLS, corrupting the parent's
    /// return-address bookkeeping and causing `__stack_chk_fail`.
    ///
    /// This doesn't affect `posix_spawn` because its `__spawni` path passes
    /// `execve` directly — same function, one trampoline, no TLS conflict.
    /// Programs using `posix_spawnp` (e.g. `uv`) have their children
    /// detected via LD_PRELOAD re-injection.
    #[cfg(target_os = "linux")]
    unsafe fn setup_linux_hooks<H: SpawnHandler + 'static>(&mut self, handler: &H) {
        self.attach_posix_spawn(handler);
        self.setup_execve_hook(handler);
    }

    /// Hook posix_spawn + posix_spawnp via GumInterceptor attach.
    #[cfg(target_os = "macos")]
    unsafe fn setup_posix_spawn_hooks<H: SpawnHandler + 'static>(&mut self, handler: &H) {
        self.attach_posix_spawn(handler);

        if let Ok(addr) = crate::module::find_global_export_by_name("posix_spawnp") {
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

    /// Attach listener to `posix_spawn` (shared by macOS and Linux).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    unsafe fn attach_posix_spawn<H: SpawnHandler + 'static>(&mut self, handler: &H) {
        if let Ok(addr) = crate::module::find_global_export_by_name("posix_spawn") {
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
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    unsafe fn setup_execve_hook<H: SpawnHandler + 'static>(&mut self, handler: &H) {
        // Try __execve first (Android), then execve
        #[allow(unused_mut)]
        let mut execve_addr = crate::module::find_global_export_by_name("execve").ok();

        #[cfg(target_os = "android")]
        if execve_addr.is_none() {
            execve_addr = crate::module::find_global_export_by_name("__execve").ok();
        }

        if let Some(execve_addr) = execve_addr {
            let listener = CallListener {
                on_enter: Some(on_execve_enter),
                on_leave: Some(on_execve_leave),
                user_data: handler as *const _ as *mut c_void,
            };
            if self
                .interceptor
                .attach(execve_addr as *mut c_void, listener)
                .is_ok()
            {
                self.execve_listener = Some(listener);
                info!("Attached spawn monitor to execve() at {:#x}", execve_addr);
            } else {
                warn!("Failed to attach to execve");
            }
        } else {
            warn!("Could not find execve");
        }
    }

    /// Install the find_variable hook for envvar monitoring.
    /// Delegates to the bash module.
    ///
    /// # Safety
    /// The caller must ensure the interceptor is in a valid state for attaching hooks.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub unsafe fn enable_envvar_hook(&mut self) {
        if let Some(listener) =
            crate::bash::enable_envvar_hook(self.interceptor, &self.bash_find_variable_listener)
        {
            self.bash_find_variable_listener = Some(listener);
        }
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

        let getenv_addr = match crate::module::find_global_export_by_name("getenv") {
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
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            let active = self.posix_spawn_listener.is_some() || self.execve_listener.is_some();
            #[cfg(target_os = "macos")]
            let active = active || self.posix_spawnp_listener.is_some();
            active
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
            if let Some(l) = &self.posix_spawn_listener {
                self.interceptor.detach(l);
            }
            #[cfg(target_os = "macos")]
            if let Some(l) = &self.posix_spawnp_listener {
                self.interceptor.detach(l);
            }
            if let Some(l) = &self.bash_listeners.shell_execve {
                self.interceptor.detach(l);
            }
            if let Some(l) = &self.bash_listeners.exec_cmd {
                self.interceptor.detach(l);
            }
            if let Some(l) = &self.bash_listeners.eval {
                self.interceptor.detach(l);
            }
            if let Some(l) = &self.bash_listeners.source {
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
    if crate::agent_debug_enabled() {
        eprintln!("[malwi-agent] posix_spawn enter");
    }

    // posix_spawn signature:
    // int posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions,
    //                 const posix_spawnattr_t *attrp, char *const argv[], char *const envp[])

    // Get path argument (arg 1)
    let path_ptr = crate::invocation::get_nth_argument(context, 1) as *const c_char;
    let path = if !path_ptr.is_null() {
        Some(CStr::from_ptr(path_ptr).to_string_lossy().into_owned())
    } else {
        None
    };

    // Get argv argument (arg 4)
    let argv_ptr = crate::invocation::get_nth_argument(context, 4) as *const *const c_char;
    let argv = parse_argv(argv_ptr);

    debug!("posix_spawn() enter: path={:?}, argv={:?}", path, argv);

    // Check policy BEFORE the spawn completes
    if !check_exec_policy(&path, &argv, None, None) {
        // User denied - make posix_spawn fail by replacing path with invalid one
        // Use a static string to ensure it lives long enough
        static BLOCKED_PATH: &[u8] = b"/usr/bin/false\0";
        crate::invocation::replace_nth_argument(
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

    // Selectively re-inject DYLD vars for compatible (non-arm64e) children.
    // The agent stripped DYLD from the process environment at init to prevent
    // automatic propagation to arm64e children (which would crash).
    // Only inject after configuration is complete — runtime-internal spawns
    // (e.g. Python 3.14 _osx_support probes) during init must not get the agent.
    #[cfg(target_os = "macos")]
    {
        if crate::AgentPhase::is_configured() && !path_ptr.is_null() && !is_arm64e_binary(path_ptr)
        {
            let envp_ptr = crate::invocation::get_nth_argument(context, 5) as *const *const c_char;
            if let Some(injected) = build_injected_envp(envp_ptr) {
                crate::invocation::replace_nth_argument(
                    context,
                    5,
                    injected.ptrs.as_ptr() as *mut c_void,
                );
                INJECTED_ENVP.with(|c| c.set(Some(injected)));
            }
        }
    }

    let native_stack = should_capture_stack(&path, &argv, context);

    // Store in thread-local for on_leave
    SPAWN_CONTEXT.with(|ctx| {
        *ctx.borrow_mut() = Some(SpawnContext {
            path,
            argv,
            pid_ptr: crate::invocation::get_nth_argument(context, 0) as *mut libc::pid_t,
            native_stack,
        });
    });
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe extern "C" fn on_posix_spawn_leave(
    context: *mut InvocationContext,
    _user_data: *mut c_void,
) {
    // Drop the injected envp — original function has completed.
    #[cfg(target_os = "macos")]
    INJECTED_ENVP.with(|c| c.set(None));

    let result = crate::invocation::get_return_value(context) as i32;

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
                    source_column: None,
                    runtime_stack: None,
                    hook_type: None,
                });
            }
        });
    }
}

// ============================================================================
// Policy Enforcement for Exec
// ============================================================================

/// Check exec policy and block if denied.
/// Returns true if allowed, false if denied.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn check_exec_policy(
    path: &Option<String>,
    argv: &Option<Vec<String>>,
    source_file: Option<&str>,
    source_line: Option<u32>,
) -> bool {
    let Some(agent) = crate::Agent::get() else {
        return true; // Allow if no agent
    };

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

    if !super::filter::has_filters() {
        return true; // No exec filters, skip review
    }

    let (matches, _) = super::filter::check_filter(cmd);
    if !matches {
        return true; // Doesn't match filter, skip review
    }

    // Build trace event for the exec
    let event = crate::tracing::event::exec_event(cmd, argv.clone())
        .source_location(source_file.map(|s| s.to_string()), source_line, None)
        .build();

    // Agent-side policy: evaluate locally
    if let Some(decision) = agent.evaluate_policy(&event) {
        return match decision {
            malwi_protocol::agent_policy::AgentDecision::Block { .. } => {
                // Send event so CLI shows "denied:" line
                let _ = agent.send_event(event);
                false
            }
            malwi_protocol::agent_policy::AgentDecision::Hide => false,
            malwi_protocol::agent_policy::AgentDecision::Suppress => true,
            _ => true,
        };
    }

    true
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
    if crate::agent_debug_enabled() {
        eprintln!("[malwi-agent] execve enter");
    }

    // execve signature: int execve(const char *path, char *const argv[], char *const envp[])

    // Skip if shell_execve already handled this (it calls execve internally)
    if crate::bash::hooks::IN_SHELL_EXECVE.with(|f| f.get()) {
        crate::bash::hooks::IN_SHELL_EXECVE.with(|f| f.set(false));
        return;
    }

    let path_ptr = crate::invocation::get_nth_argument(context, 0) as *const c_char;
    let path = if !path_ptr.is_null() {
        Some(CStr::from_ptr(path_ptr).to_string_lossy().into_owned())
    } else {
        None
    };

    let argv_ptr = crate::invocation::get_nth_argument(context, 1) as *const *const c_char;
    let argv = parse_argv(argv_ptr);

    debug!("execve() enter: path={:?}, argv={:?}", path, argv);

    // Check policy BEFORE the exec completes
    if !check_exec_policy(&path, &argv, None, None) {
        // User denied - make execve fail by replacing path with invalid one
        // Use a static string to ensure it lives long enough
        static BLOCKED_PATH: &[u8] = b"/usr/bin/false\0";
        crate::invocation::replace_nth_argument(context, 0, BLOCKED_PATH.as_ptr() as *mut c_void);
        info!("BLOCKED exec: {:?}", path);
        return;
    }

    // Selectively re-inject DYLD vars for compatible (non-arm64e) children.
    // The agent stripped DYLD from the process environment at init to prevent
    // automatic propagation to arm64e children (which would crash).
    // Only inject after configuration is complete — runtime-internal spawns
    // (e.g. Python 3.14 _osx_support probes) during init must not get the agent.
    #[cfg(target_os = "macos")]
    {
        if crate::AgentPhase::is_configured() && !path_ptr.is_null() && !is_arm64e_binary(path_ptr)
        {
            let envp_ptr = crate::invocation::get_nth_argument(context, 2) as *const *const c_char;
            if let Some(injected) = build_injected_envp(envp_ptr) {
                crate::invocation::replace_nth_argument(
                    context,
                    2,
                    injected.ptrs.as_ptr() as *mut c_void,
                );
                INJECTED_ENVP.with(|c| c.set(Some(injected)));
            }
        }
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
            source_column: None,
            runtime_stack: None,
            hook_type: None,
        });
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe extern "C" fn on_execve_leave(_context: *mut InvocationContext, _user_data: *mut c_void) {
    // Drop the injected envp (only reached if execve failed).
    #[cfg(target_os = "macos")]
    INJECTED_ENVP.with(|c| c.set(None));

    // If we get here, execve failed (otherwise process image would be replaced)
    debug!("execve() failed (returned to caller)");
}

// ============================================================================
// Native: getenv() hooks (libc environment variable access detection)
// ============================================================================

/// Enter callback for libc getenv(const char *name).
/// Stores the name pointer for the leave callback.
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe extern "C" fn on_getenv_enter(context: *mut InvocationContext, _user_data: *mut c_void) {
    let name_ptr = crate::invocation::get_nth_argument(context, 0) as *const c_char;
    GETENV_NAME.with(|cell| cell.set(name_ptr));
}

/// Leave callback for libc getenv.
/// If return value is non-NULL, the variable exists — check deny filter and send event.
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe extern "C" fn on_getenv_leave(context: *mut InvocationContext, _user_data: *mut c_void) {
    let retval = crate::invocation::get_return_value(context) as *const c_char;
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

    // Skip if Python envvar monitoring is active — Python's sys.setprofile
    // provides richer context. Node.js uses native getenv hooks directly
    // (the process.env Proxy was removed for npm/npx compatibility).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        if crate::python::is_envvar_monitoring_enabled() {
            return;
        }
    }

    // Dedup: report each variable once per thread
    let is_new = GETENV_SEEN.with(|set| set.borrow_mut().insert(name.to_string()));
    if !is_new {
        return;
    }

    // Check agent-side deny filter — if blocked, replace return value with NULL
    let blocked = super::envvar::should_block(&name);
    if blocked {
        crate::invocation::replace_return_value(context, ptr::null_mut());
    }

    // Send trace event
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

// Holds the injected envp alive during inline hook execution (on_enter → original → on_leave).
// The CStrings and pointer array must survive until the original function completes.
#[cfg(target_os = "macos")]
thread_local! {
    static INJECTED_ENVP: Cell<Option<InjectedEnvp>> = const { Cell::new(None) };
}

/// Parse a null-terminated argv array into a Vec<String>.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) unsafe fn parse_argv(argv: *const *const c_char) -> Option<Vec<String>> {
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
pub(crate) unsafe fn should_capture_stack(
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
    let (_matches, capture_stack) = super::filter::check_filter(cmd);
    if capture_stack {
        crate::native::capture_backtrace(context)
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
        let _g = crate::lock_hook_tests();
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

    #[cfg(target_os = "macos")]
    mod arm64e_tests {
        use super::*;
        use std::io::Write;

        /// Create a temp file with unique name and return a CString of its path.
        fn write_temp_binary(bytes: &[u8], label: &str) -> (std::path::PathBuf, CString) {
            static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let dir = std::env::temp_dir();
            let name = format!("malwi_test_{}_{}_{}", std::process::id(), label, n);
            let path = dir.join(name);
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(bytes).unwrap();
            let cpath = CString::new(path.to_str().unwrap()).unwrap();
            (path, cpath)
        }

        /// Build a thin MH_MAGIC_64 header with given cputype and cpusubtype.
        fn thin_macho(cputype: i32, cpusubtype: i32) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&0xFEED_FACFu32.to_le_bytes()); // magic
            buf.extend_from_slice(&cputype.to_le_bytes());
            buf.extend_from_slice(&cpusubtype.to_le_bytes());
            buf.extend_from_slice(&[0u8; 20]); // rest of header
            buf
        }

        /// Build a FAT_MAGIC universal binary header with given slices.
        fn fat_macho(slices: &[(i32, i32)]) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes()); // FAT_MAGIC
            buf.extend_from_slice(&(slices.len() as u32).to_be_bytes()); // nfat_arch
            for (cputype, cpusubtype) in slices {
                buf.extend_from_slice(&cputype.to_be_bytes());
                buf.extend_from_slice(&cpusubtype.to_be_bytes());
                buf.extend_from_slice(&[0u8; 12]); // offset, size, align
            }
            buf
        }

        const CPU_TYPE_ARM64: i32 = 0x0100_000C;
        const CPU_TYPE_X86_64: i32 = 0x0100_0007;
        const CPU_SUBTYPE_ARM64_ALL: i32 = 0;
        const CPU_SUBTYPE_ARM64E: i32 = 2;

        #[test]
        fn test_thin_macho_arm64_is_not_arm64e() {
            let bytes = thin_macho(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
            let (path, cpath) = write_temp_binary(&bytes, "macho");
            assert!(!is_arm64e_binary(cpath.as_ptr()));
            let _ = std::fs::remove_file(path);
        }

        #[test]
        fn test_thin_macho_arm64e_detected() {
            let bytes = thin_macho(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E);
            let (path, cpath) = write_temp_binary(&bytes, "macho");
            assert!(is_arm64e_binary(cpath.as_ptr()));
            let _ = std::fs::remove_file(path);
        }

        #[test]
        fn test_thin_macho_x86_64_is_not_arm64e() {
            let bytes = thin_macho(CPU_TYPE_X86_64, 3);
            let (path, cpath) = write_temp_binary(&bytes, "macho");
            assert!(!is_arm64e_binary(cpath.as_ptr()));
            let _ = std::fs::remove_file(path);
        }

        #[test]
        fn test_fat_macho_with_arm64_slice_is_not_arm64e() {
            let bytes = fat_macho(&[
                (CPU_TYPE_X86_64, 3),
                (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL),
            ]);
            let (path, cpath) = write_temp_binary(&bytes, "macho");
            assert!(!is_arm64e_binary(cpath.as_ptr()));
            let _ = std::fs::remove_file(path);
        }

        #[test]
        fn test_fat_macho_arm64e_detected() {
            let bytes = fat_macho(&[(CPU_TYPE_X86_64, 3), (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E)]);
            let (path, cpath) = write_temp_binary(&bytes, "macho");
            assert!(is_arm64e_binary(cpath.as_ptr()));
            let _ = std::fs::remove_file(path);
        }

        #[test]
        fn test_fat_macho_with_both_slices_prefers_non_arm64e() {
            let bytes = fat_macho(&[
                (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E),
                (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL),
            ]);
            let (path, cpath) = write_temp_binary(&bytes, "macho");
            // Has a non-arm64e ARM64 slice → compatible
            assert!(!is_arm64e_binary(cpath.as_ptr()));
            let _ = std::fs::remove_file(path);
        }

        #[test]
        fn test_script_with_shebang_is_not_arm64e() {
            let (path, cpath) = write_temp_binary(b"#!/bin/bash\necho hello\n", "script");
            assert!(!is_arm64e_binary(cpath.as_ptr()));
            let _ = std::fs::remove_file(path);
        }

        #[test]
        fn test_nonexistent_file_is_not_arm64e() {
            let cpath = CString::new("/tmp/malwi_nonexistent_test_file_xyz").unwrap();
            assert!(!is_arm64e_binary(cpath.as_ptr()));
        }

        #[test]
        fn test_null_path_is_not_arm64e() {
            assert!(!is_arm64e_binary(std::ptr::null()));
        }

        #[test]
        fn test_empty_file_is_not_arm64e() {
            let (path, cpath) = write_temp_binary(b"", "empty");
            assert!(!is_arm64e_binary(cpath.as_ptr()));
            let _ = std::fs::remove_file(path);
        }
    }
}
