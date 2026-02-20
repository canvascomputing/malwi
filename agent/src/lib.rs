//! Malwi-trace agent - injected into target process for function hooking.
//!
//! This library is compiled as a cdylib and loaded into the target process
//! via LD_PRELOAD (Linux), DYLD_INSERT_LIBRARIES (macOS), or injection.

pub mod cpython;
pub mod envvar_filter; // Envvar deny patterns for agent-side blocking
pub mod exec_filter; // Exec command filtering for child processes
#[cfg(unix)]
pub mod fork_monitor;
pub mod glob;
pub mod hooks;
pub mod http_client;
pub mod native; // Native symbol resolution and argument formatting
pub mod nodejs; // Node.js tracing (addon, bytecode hooks, filters)
pub mod spawn_monitor;
pub mod stack;
pub mod syscall_monitor;
pub mod tracing; // Shared tracing utilities (thread, time, filter, event)

#[cfg(test)]
mod test_utils;

pub use stack::{StackCapturer, StackFrame};

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

// Flag to signal the agent's background thread to shut down.
// Set by atexit handler when the process is exiting.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
// Ensures /shutdown is only sent once (prevents double-send from both
// atexit handler and background thread).
static SHUTDOWN_SENT: AtomicBool = AtomicBool::new(false);
// Set by the flush thread after it has drained all pending events on shutdown.
// The atexit handler waits on this before sending /shutdown, ensuring events
// are flushed before the CLI's active_agents counter is decremented.
static FLUSH_COMPLETE: AtomicBool = AtomicBool::new(false);

use anyhow::Result;
use log::{debug, error, info, warn};
use malwi_protocol::{ChildOperation, HookConfig, HookType, HostChildInfo};

#[cfg(unix)]
use crate::fork_monitor::{ForkHandler, ForkMonitor};
use crate::hooks::HookManager;
use crate::http_client::HttpClient;
use crate::spawn_monitor::{SpawnHandler, SpawnInfo, SpawnMonitor};

/// Global agent state.
static AGENT: OnceLock<Agent> = OnceLock::new();

/// The agent managing hooks and communication.
pub struct Agent {
    hook_manager: HookManager,
    /// HTTP client for CLI communication — no mutexes needed.
    http: HttpClient,
    /// Channel sender for batched event delivery.
    event_tx: SyncSender<malwi_protocol::TraceEvent>,
    review_mode: AtomicBool,
    /// Cache of functions already blocked in review mode — skip HTTP round-trip on retry.
    /// Keyed by (HookType, function_name) to avoid collisions between runtimes.
    review_blocked_cache: Mutex<HashSet<(HookType, String)>>,
    #[cfg(unix)]
    fork_monitor: Mutex<Option<ForkMonitor>>,
    spawn_monitor: Mutex<Option<SpawnMonitor>>,
    /// Syscall monitor for direct syscall detection (opt-in).
    syscall_monitor: Mutex<Option<syscall_monitor::SyscallMonitor>>,
}

impl Agent {
    /// Create a new agent connected to the CLI via HTTP.
    pub fn new(url: &str) -> Result<Self> {
        let http = HttpClient::new(url);
        let hook_manager = HookManager::new()?;

        // Event batching: hook callbacks push to this channel,
        // a dedicated flush thread drains and sends in batches.
        let (event_tx, event_rx) = mpsc::sync_channel::<malwi_protocol::TraceEvent>(4096);

        // Spawn flush thread with its own HTTP client
        let flush_http = HttpClient::new(url);
        std::thread::spawn(move || {
            event_flush_loop(flush_http, event_rx);
        });

        Ok(Self {
            hook_manager,
            http,
            event_tx,
            review_mode: AtomicBool::new(false),
            review_blocked_cache: Mutex::new(HashSet::new()),
            #[cfg(unix)]
            fork_monitor: Mutex::new(None),
            spawn_monitor: Mutex::new(None),
            syscall_monitor: Mutex::new(None),
        })
    }

    /// Run the agent's main loop.
    /// Polls for shutdown commands from the CLI.
    pub fn run(&self) -> Result<()> {
        info!("Agent started, polling for commands...");

        let mut consecutive_errors: u32 = 0;
        const MAX_CONSECUTIVE_ERRORS: u32 = 5;
        let mut nodejs_version_pending = nodejs::is_loaded();

        loop {
            // Check if shutdown was requested (e.g., by atexit handler)
            if SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
                // Wait for flush thread to drain pending events before sending
                // /shutdown, otherwise the CLI may exit before displaying them.
                let deadline = std::time::Instant::now() + std::time::Duration::from_millis(300);
                while !FLUSH_COMPLETE.load(Ordering::Acquire) {
                    if std::time::Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                if !SHUTDOWN_SENT.swap(true, Ordering::SeqCst) {
                    info!("Shutdown requested, notifying CLI");
                    let _ = self.http.shutdown(std::process::id());
                }
                break;
            }

            // Poll for commands from CLI
            match self.http.poll_command() {
                Ok(Some(cmd)) if cmd == "shutdown" => {
                    info!("Received shutdown command from CLI");
                    break;
                }
                Ok(_) => {
                    consecutive_errors = 0;
                }
                Err(e) => {
                    // Server unreachable — if we're shutting down, that's expected
                    if SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
                        info!("Server unreachable during shutdown (expected)");
                        break;
                    }
                    consecutive_errors += 1;
                    if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                        info!(
                            "Server unreachable after {} attempts, shutting down",
                            consecutive_errors
                        );
                        break;
                    }
                    debug!("Command poll error (attempt {}): {}", consecutive_errors, e);
                }
            }

            // Send Node.js version to CLI once it becomes available.
            // detect_node_version() is a single OnceLock read — negligible overhead.
            if nodejs_version_pending {
                if let Some(v) = nodejs::addon::detect_node_version() {
                    let _ = self.http.send_runtime_info(
                        std::process::id(),
                        "nodejs",
                        &format!("v{}", v),
                    );
                    nodejs_version_pending = false;
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        info!("Agent shutting down");
        Ok(())
    }

    /// Install a hook locally (no HTTP call needed — agent manages hooks directly).
    fn add_hook_local(&self, config: HookConfig) -> Result<()> {
        match config.hook_type {
            HookType::Native => match self.hook_manager.add_hook(&config) {
                Ok(result) => {
                    for (symbol, address) in &result.symbols {
                        debug!("Hooked {} at {:#x}", symbol, address);
                    }
                }
                Err(e) => {
                    warn!("Failed to hook {}: {}", config.symbol, e);
                }
            },
            HookType::Python => {
                cpython::add_python_filter(&config.symbol, config.capture_stack);
                debug!("Added Python filter: {}", config.symbol);
            }
            HookType::Nodejs => {
                nodejs::add_filter(&config.symbol, config.capture_stack);
                debug!("Added Node.js filter: {}", config.symbol);
            }
            HookType::Exec => {
                exec_filter::add_filter(&config.symbol, config.capture_stack);
                self.ensure_monitors_installed();
                // CPython subprocess exec events are best-effort via audit hooks.
                // We may be loaded before Python's exported symbols are visible, so retry.
                cpython::start_audit_registration_task();
                debug!("Added exec filter: {}", config.symbol);
            }
            HookType::DirectSyscall => {
                // DirectSyscall is not a hookable type — handled by syscall_monitor, not Interceptor.
                debug!("Ignoring DirectSyscall hook config for {}", config.symbol);
            }
            HookType::EnvVar => {
                // EnvVar monitoring: hook bash's find_variable if this is a bash process.
                // Set the flag so setup_bash_hooks() will install the hook if the spawn
                // monitor hasn't been created yet.
                spawn_monitor::enable_envvar_monitoring();
                // Individual deny patterns (non-wildcard) are for agent-side blocking.
                if config.symbol != "*" {
                    envvar_filter::add_deny_pattern(&config.symbol);
                    debug!("Added envvar deny pattern: {}", config.symbol);
                }
                // If the spawn monitor already exists, install the hooks now.
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                {
                    let mut guard = self.spawn_monitor.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(monitor) = guard.as_mut() {
                        unsafe {
                            monitor.enable_envvar_hook();
                            monitor.enable_getenv_hook();
                        }
                    }
                }
                // Python envvar monitoring
                if cpython::is_python_loaded() {
                    cpython::enable_envvar_monitoring();
                }
                // Node.js envvar monitoring
                if nodejs::is_loaded() {
                    nodejs::enable_envvar_monitoring();
                }
                debug!("Enabled envvar monitoring");
            }
        }
        Ok(())
    }

    /// Send a trace event to the CLI.
    ///
    /// Pushes to the batch channel for efficient delivery. Falls back to
    /// direct HTTP if the channel is full (backpressure).
    pub fn send_event(&self, event: malwi_protocol::TraceEvent) -> Result<()> {
        match self.event_tx.try_send(event) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(event)) => self.http.send_event(&event),
            Err(TrySendError::Disconnected(event)) => self.http.send_event(&event),
        }
    }

    /// Check if review mode is enabled.
    pub fn is_review_mode(&self) -> bool {
        self.review_mode.load(Ordering::SeqCst)
    }

    /// Wait for user decision in review mode.
    /// Blocks on HTTP response — no condvar needed.
    /// Returns the `ReviewDecision` from the CLI.
    pub fn await_review_decision(
        &self,
        event: malwi_protocol::TraceEvent,
    ) -> malwi_protocol::ReviewDecision {
        // Fast path: already blocked → skip HTTP round-trip
        let key = (event.hook_type.clone(), event.function.clone());
        if let Ok(cache) = self.review_blocked_cache.lock() {
            if cache.contains(&key) {
                return malwi_protocol::ReviewDecision::Block;
            }
        }

        match self.http.review(&event) {
            Ok(decision) => {
                if matches!(decision, malwi_protocol::ReviewDecision::Block) {
                    if let Ok(mut cache) = self.review_blocked_cache.lock() {
                        cache.insert(key);
                    }
                }
                decision
            }
            Err(e) => {
                warn!("Review request failed: {}", e);
                malwi_protocol::ReviewDecision::Allow
            }
        }
    }

    /// Get a reference to the global agent.
    pub fn get() -> Option<&'static Agent> {
        AGENT.get()
    }

    /// Wait for hook configuration to complete.
    ///
    /// Makes a single HTTP call to /configure, installs hooks locally,
    /// then notifies the CLI via /ready.
    pub fn wait_for_configuration(&self) -> Result<()> {
        info!("Requesting configuration from CLI...");

        let pid = std::process::id();
        let nodejs_version = if nodejs::is_loaded() {
            nodejs::addon::detect_node_version()
        } else {
            None
        };

        // Single HTTP call to get all configuration
        let config = self.http.configure(pid, nodejs_version)?;

        // Install hooks locally
        for hook_config in &config.hooks {
            if let Err(e) = self.add_hook_local(hook_config.clone()) {
                warn!("Failed to install hook {}: {}", hook_config.symbol, e);
            }
        }

        // Set review mode
        self.review_mode.store(config.review_mode, Ordering::SeqCst);

        // Enable child gating unconditionally
        self.enable_child_gating_internal();

        // Enable direct syscall detection if any DirectSyscall hook is present
        if config
            .hooks
            .iter()
            .any(|h| h.hook_type == HookType::DirectSyscall)
        {
            self.enable_syscall_monitor();
        }

        // Enumerate loaded modules for CLI-side symbol resolution
        let modules: Vec<malwi_protocol::ModuleInfo> = native::enumerate_modules()
            .into_iter()
            .map(|m| malwi_protocol::ModuleInfo {
                name: m.name,
                path: m.path,
                base_address: m.base_address as u64,
                size: m.size as u64,
            })
            .collect();

        // Gather runtime versions for CLI display
        let python_version = if cpython::is_python_loaded() {
            cpython::version::get().map(|v| v.to_string())
        } else {
            None
        };
        let bash_version = spawn_monitor::detected_bash_version().map(|s| s.to_string());

        // Report ready
        let hooks = self.hook_manager.list_hooks();
        info!(
            "Configuration complete, sending ready with {} hooks and {} modules",
            hooks.len(),
            modules.len()
        );
        self.http.ready(
            pid,
            hooks,
            nodejs_version,
            python_version,
            bash_version,
            modules,
        )?;

        Ok(())
    }

    /// Enable scan+patch syscall monitor for direct syscall detection.
    fn enable_syscall_monitor(&self) {
        let mut guard = self
            .syscall_monitor
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            return;
        }
        match unsafe { syscall_monitor::SyscallMonitor::new() } {
            Some(monitor) => {
                info!("Direct syscall detection enabled (scan+patch)");
                *guard = Some(monitor);
            }
            None => warn!("Failed to enable direct syscall detection"),
        }
    }

    /// Internal: install monitors.
    fn enable_child_gating_internal(&self) {
        #[cfg(unix)]
        self.install_fork_monitor();

        self.install_spawn_monitor();
    }

    /// Ensure spawn/fork monitors are installed (idempotent).
    /// Called during configuration phase when exec filters are added.
    fn ensure_monitors_installed(&self) {
        if self
            .spawn_monitor
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return;
        }

        info!("Installing spawn/fork monitors for exec filtering...");
        self.enable_child_gating_internal();
    }

    #[cfg(unix)]
    fn install_fork_monitor(&self) {
        let mut guard = self.fork_monitor.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            return;
        }
        match unsafe { ForkMonitor::new(self) } {
            Some(monitor) => {
                info!("Fork monitor installed");
                *guard = Some(monitor);
            }
            None => warn!("Failed to install fork monitor"),
        }
    }

    fn install_spawn_monitor(&self) {
        let mut guard = self.spawn_monitor.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            return;
        }
        match unsafe { SpawnMonitor::new(self) } {
            Some(mut monitor) => {
                // If envvar monitoring was requested before the spawn monitor was created,
                // install the find_variable and getenv hooks now.
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                if spawn_monitor::is_envvar_monitoring_enabled() {
                    unsafe {
                        monitor.enable_envvar_hook();
                        monitor.enable_getenv_hook();
                    }
                }
                info!("Spawn monitor installed");
                *guard = Some(monitor);
            }
            None => warn!("Failed to install spawn monitor"),
        }

        // Install dlsym override AFTER spawn monitor hooks are set up.
        // This must happen after find_global_export_by_name() calls in SpawnMonitor::new(),
        // because the override makes dlsym("posix_spawn") return our wrapper addresses.
        #[cfg(target_os = "macos")]
        unsafe {
            spawn_monitor::install_dlsym_override();
        }
    }

    /// Send a child created notification to CLI.
    fn notify_child_created(&self, info: HostChildInfo) {
        debug!(
            "Child created: parent={}, child={}, op={:?}",
            info.parent_pid, info.child_pid, info.operation
        );

        // Only show child events if exec filters are configured
        if !exec_filter::has_filters() {
            debug!("No exec filters configured, hiding child event");
            return;
        }

        // Extract command name from argv[0] or path.
        // Also unwrap shell wrappers (sh -c "curl ...") to check the inner command
        // against the exec filter — policies deny by inner command name (e.g. "curl"),
        // while manual -c flags may use the outer command (e.g. "sh").
        let raw_command = info
            .argv
            .as_ref()
            .and_then(|argv| argv.first())
            .map(|s| basename(s))
            .or_else(|| info.path.as_ref().map(|p| basename(p)));
        let unwrapped = info
            .argv
            .as_ref()
            .and_then(|argv| malwi_protocol::exec::unwrap_shell_command(argv));

        if let Some(cmd) = raw_command {
            let (matches, _) = exec_filter::check_filter(cmd);
            let unwrap_matches = unwrapped
                .map(|u| exec_filter::check_filter(u).0)
                .unwrap_or(false);
            if !matches && !unwrap_matches {
                debug!("Command '{}' does not match exec filter, hiding", cmd);
                return;
            }
        } else if info.operation == ChildOperation::Fork {
            // Bare fork (no path, no argv) — not a command execution.
            // The actual command will arrive in a subsequent Exec event.
            return;
        }

        // Suppress hooks during the HTTP call so the agent's own socket/connect
        // calls aren't intercepted by policy hooks (e.g., air-gap denying socket).
        let was_suppressed = hooks::is_in_hook();
        hooks::set_in_hook(true);
        if let Err(e) = self.http.send_child(&info) {
            warn!("Failed to send child created notification: {}", e);
        }
        hooks::set_in_hook(was_suppressed);
    }
}

/// Flush loop for batched event delivery.
///
/// Collects events from the channel and sends them in batches of up to 64.
/// Uses `recv_timeout` to coalesce events that arrive close together,
/// flushing either when the batch is full or after a 50ms idle period.
fn event_flush_loop(http: HttpClient, rx: mpsc::Receiver<malwi_protocol::TraceEvent>) {
    hooks::suppress_hooks_on_current_thread();
    let mut batch = Vec::with_capacity(64);
    loop {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(event) => {
                batch.push(event);
                // Drain up to 64 without blocking
                while batch.len() < 64 {
                    match rx.try_recv() {
                        Ok(e) => batch.push(e),
                        Err(_) => break,
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
                    // Drain remaining events before exiting
                    while let Ok(e) = rx.try_recv() {
                        batch.push(e);
                    }
                    if !batch.is_empty() {
                        let _ = http.send_events(&batch);
                    }
                    FLUSH_COMPLETE.store(true, Ordering::Release);
                    return;
                }
                // No events arrived — continue waiting
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Channel closed — drain and exit
                while let Ok(e) = rx.try_recv() {
                    batch.push(e);
                }
                if !batch.is_empty() {
                    let _ = http.send_events(&batch);
                }
                FLUSH_COMPLETE.store(true, Ordering::Release);
                return;
            }
        }

        if !batch.is_empty() {
            let _ = http.send_events(&batch);
            batch.clear();
        }

        // Check for shutdown after each batch send, not just on timeout.
        // Without this, the flush thread can't exit promptly when events
        // keep arriving (the Timeout arm is never reached).
        if SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
            while let Ok(e) = rx.try_recv() {
                batch.push(e);
            }
            if !batch.is_empty() {
                let _ = http.send_events(&batch);
            }
            FLUSH_COMPLETE.store(true, Ordering::Release);
            return;
        }
    }
}

/// Extract the basename from a path (platform-independent).
fn basename(path: &str) -> &str {
    std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
}

// Implement ForkHandler for Agent (Unix only)
#[cfg(unix)]
impl ForkHandler for Agent {
    fn on_fork_in_parent(&self, child_pid: u32) {
        let info = HostChildInfo {
            parent_pid: std::process::id(),
            child_pid,
            operation: ChildOperation::Fork,
            path: None,
            argv: None,
            native_stack: vec![],
            source_file: None,
            source_line: None,
        };
        self.notify_child_created(info);
    }

    fn on_fork_in_child(&self) {
        // In the child process after fork:
        // With HTTP, no reconnection ceremony needed — each POST is independent.
        // Just notify the CLI that we're a child process.

        let child_pid = std::process::id();
        let parent_pid = unsafe { libc::getppid() } as u32;

        info!(
            "Fork detected in child process (PID {}), notifying CLI...",
            child_pid
        );

        if let Err(e) = self.http.child_reconnect(parent_pid, child_pid) {
            warn!("Failed to notify CLI of fork: {}", e);
        } else {
            info!(
                "Successfully notified CLI of fork (child PID {})",
                child_pid
            );
        }
    }
}

// Implement SpawnHandler for Agent
impl SpawnHandler for Agent {
    fn on_spawn_created(&self, info: SpawnInfo) {
        let child_info = HostChildInfo {
            parent_pid: std::process::id(),
            child_pid: info.child_pid,
            operation: ChildOperation::Spawn,
            path: info.path,
            argv: info.argv,
            native_stack: info.native_stack,
            source_file: info.source_file,
            source_line: info.source_line,
        };
        self.notify_child_created(child_info);
    }

    fn on_exec_imminent(&self, info: SpawnInfo) {
        let child_info = HostChildInfo {
            parent_pid: std::process::id(),
            child_pid: info.child_pid,
            operation: ChildOperation::Exec,
            path: info.path,
            argv: info.argv,
            native_stack: info.native_stack,
            source_file: info.source_file,
            source_line: info.source_line,
        };
        self.notify_child_created(child_info);
    }

    fn on_child_spawned_suspended(&self, info: SpawnInfo) {
        debug!(
            "Child {} spawned suspended: path={:?}",
            info.child_pid, info.path
        );
        // CLI does not currently handle suspended child events
    }

    fn is_child_gating_enabled(&self) -> bool {
        self.spawn_monitor
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }
}

/// Agent entry point called when the library is loaded.
///
/// The server URL is passed via environment variable MALWI_URL.
///
/// This function blocks synchronously until configuration is complete,
/// ensuring all hooks are installed before main() can run.
#[unsafe(no_mangle)]
pub extern "C" fn malwi_agent_init() -> i32 {
    // Check for MALWI_URL FIRST — before any heavy initialization.
    // When the CLI dlopens the agent library to call malwi_prepare_node_options,
    // this constructor fires but MALWI_URL isn't set. We must return early
    // without initializing the hook subsystem to avoid interfering with the target process.
    let url = match std::env::var("MALWI_URL") {
        Ok(u) => u,
        Err(_) => {
            return 0; // Not an error — expected when dlopened by CLI
        }
    };

    // Initialize logging
    let _ = env_logger::try_init();

    // Initialize hook subsystems early.
    malwi_intercept::init();
    // NOTE: dlsym override (spawn_monitor::install_dlsym_override) is installed
    // AFTER the spawn monitor hooks are set up, not here. Installing it early
    // would poison dlsym("posix_spawn") to return our wrapper address instead
    // of the real libc function, breaking find_global_export_by_name().
    // Register CPython audit hook if CPython is loaded
    if cpython::is_python_loaded() {
        info!("CPython detected, registering audit hook");
        cpython::register_audit_hook();
    }

    // Detect Node.js runtime and enable tracing.
    // Only initialize when JS tracing was requested (NODE_OPTIONS is set by the CLI
    // when --js is used). Unconditional init breaks programs like npm.
    if nodejs::is_loaded() && std::env::var_os("NODE_OPTIONS").is_some() {
        info!("Node.js detected, initializing tracing");
        if nodejs::init_tracing() {
            info!("Node.js JavaScript tracing enabled");
        } else {
            warn!("Failed to initialize Node.js JavaScript tracing");
        }
    }

    match Agent::new(&url) {
        Ok(agent) => {
            info!("Connected to CLI at {}, waiting for configuration...", url);

            // CRITICAL: Block synchronously until configuration is complete
            if let Err(e) = agent.wait_for_configuration() {
                error!("Failed during hook configuration: {}", e);
                return -1;
            }

            info!(
                "Configuration complete, {} hooks installed",
                agent.hook_manager.list_hooks().len()
            );

            // Now store the agent for ongoing event handling
            if AGENT.set(agent).is_err() {
                error!("Agent already initialized");
                return -1;
            }

            // Register atexit handler to signal shutdown when process exits.
            // Sends /shutdown directly because the background thread may not
            // exist (e.g., in forked children where threads don't survive fork).
            extern "C" fn shutdown_handler() {
                // Suppress hooks on the main thread during shutdown.
                // After main() returns, all remaining mallocs are agent
                // bookkeeping (HTTP, cleanup) — not meaningful to the user.
                hooks::suppress_hooks_on_current_thread();
                SHUTDOWN_REQUESTED.store(true, Ordering::Release);
                // Wait for flush thread to drain pending events BEFORE we
                // decrement the CLI's active_agents counter via /shutdown.
                // Bounded timeout in case flush thread is dead (e.g., in
                // forked children where threads don't survive fork).
                let deadline = std::time::Instant::now() + std::time::Duration::from_millis(300);
                while !FLUSH_COMPLETE.load(Ordering::Acquire) {
                    if std::time::Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                // Send shutdown (only once across atexit + bg thread)
                if !SHUTDOWN_SENT.swap(true, Ordering::SeqCst) {
                    if let Some(agent) = Agent::get() {
                        let _ = agent.http.shutdown(std::process::id());
                    }
                }
            }
            unsafe {
                libc::atexit(shutdown_handler);
            }

            // Spawn background thread for command polling
            std::thread::spawn(|| {
                hooks::suppress_hooks_on_current_thread();
                if let Some(agent) = Agent::get() {
                    if let Err(e) = agent.run() {
                        error!("Agent error: {}", e);
                    }
                }
            });

            info!("Agent ready, main() can proceed with hooks active");
            0
        }
        Err(e) => {
            error!("Failed to initialize agent: {}", e);
            -1
        }
    }
}

/// Prepare NODE_OPTIONS for JavaScript tracing.
///
/// This function is called by the CLI BEFORE spawning the child process.
/// It extracts all addon versions, generates a wrapper script, and returns
/// the NODE_OPTIONS value that should be set in the child's environment.
///
/// # Safety
/// The caller must ensure `out_buffer` points to valid memory of at least `buffer_size` bytes.
#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn malwi_prepare_node_options(
    url_ptr: *const std::ffi::c_char,
    out_buffer: *mut std::ffi::c_char,
    buffer_size: usize,
) -> i32 {
    use std::ffi::CStr;

    if url_ptr.is_null() || out_buffer.is_null() || buffer_size == 0 {
        return -1;
    }

    let url = unsafe {
        match CStr::from_ptr(url_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    // Temporarily set MALWI_URL for the wrapper script generation
    std::env::set_var("MALWI_URL", url);

    // Extract all addons and generate wrapper
    let node_options = match prepare_node_options_internal() {
        Some(opts) => opts,
        None => return 0, // No JS tracing available, but not an error
    };

    // Copy to output buffer
    let bytes = node_options.as_bytes();
    if bytes.len() >= buffer_size {
        return -1; // Buffer too small
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buffer.cast::<u8>(), bytes.len());
        *out_buffer.add(bytes.len()) = 0; // Null terminate
    }

    bytes.len() as i32
}

/// Internal function to prepare NODE_OPTIONS.
fn prepare_node_options_internal() -> Option<String> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Extract all addons to stable directory
    let addon_dir = nodejs::addon::embed::extract_all_addons()?;

    // Generate wrapper script
    let url = std::env::var("MALWI_URL").unwrap_or_default();
    let hash = {
        let mut hasher = DefaultHasher::new();
        url.hash(&mut hasher);
        format!("{:08x}", hasher.finish() as u32)
    };

    let wrapper_path = std::env::temp_dir().join(format!("malwi-wrapper-{}.js", hash));
    let wrapper_js = generate_wrapper_script(&addon_dir);

    // Write wrapper if needed
    let should_write = if wrapper_path.exists() {
        match std::fs::read_to_string(&wrapper_path) {
            Ok(existing) => existing != wrapper_js,
            Err(_) => true,
        }
    } else {
        true
    };

    if should_write && std::fs::write(&wrapper_path, &wrapper_js).is_err() {
        return None;
    }

    // Build NODE_OPTIONS value
    let require_opt = format!("--require={}", wrapper_path.display());

    // Preserve existing NODE_OPTIONS
    let node_options = match std::env::var("NODE_OPTIONS") {
        Ok(existing) => format!("{} {}", existing, require_opt),
        Err(_) => require_opt,
    };

    Some(node_options)
}

/// Generate the JS wrapper script content (same as in loader.rs).
fn generate_wrapper_script(addon_dir: &std::path::Path) -> String {
    let addon_dir_str = addon_dir.to_string_lossy().replace('\\', "\\\\");

    format!(
        r#"// Malwi V8 tracing wrapper - auto-generated
(function() {{
    'use strict';

    const path = require('path');
    const Module = require('module');

    // Detect Node.js major version
    const major = parseInt(process.versions.node.split('.')[0], 10);

    // Map version to bucket (must match embed.rs version_bucket())
    const bucket = major >= 25 ? 'node25'
                 : major >= 24 ? 'node24'
                 : major >= 23 ? 'node23'
                 : major >= 22 ? 'node22'
                 : major >= 21 ? 'node21'
                 : null;  // Unsupported versions

    if (!bucket) {{
        if (process.env.MALWI_DEBUG) {{
            console.error('[malwi] Node.js', major, 'is not supported (requires Node 21+)');
        }}
        return;
    }}

    // Build addon path
    const addonPath = path.join('{addon_dir}', bucket, 'v8_introspect.node');

    try {{
        // Load the native addon
        const addon = require(addonPath);

        // Enable tracing FIRST - connects the trace callback from Rust agent
        if (addon.enableTracing) {{
            addon.enableTracing();
        }}

        // Install require hook only when JS filters are configured.
        // Filters are set by the CLI via --js flag and passed through Rust agent state.
        // Without this guard, the require hook breaks npm's module loading.
        if (addon.getFilters) {{
            const filters = addon.getFilters();
            if (filters.length > 0) {{
                if (addon.installRequireHook) {{
                    addon.installRequireHook(Module);
                }}
                for (const f of filters) {{
                    if (addon.addFilter) {{
                        addon.addFilter(f.pattern, f.captureStack);
                    }}
                }}
            }}
        }}

        // Signal that addon is ready (for bytecode deduplication)
        process.env.MALWI_ADDON_READY = '1';

        // Envvar monitoring: wrap process.env with a Proxy that calls checkEnvVar
        if (addon.checkEnvVar) {{
            const _envChecked = new Map();
            const _origEnv = process.env;
            process.env = new Proxy(_origEnv, {{
                get(target, prop, receiver) {{
                    if (typeof prop === 'string' && !prop.startsWith('MALWI_')) {{
                        if (!_envChecked.has(prop)) {{
                            const result = addon.checkEnvVar(prop);
                            _envChecked.set(prop, result === 1);
                        }}
                        if (!_envChecked.get(prop)) return undefined;
                    }}
                    return Reflect.get(target, prop, receiver);
                }},
                set(target, prop, value, receiver) {{
                    return Reflect.set(target, prop, value, receiver);
                }},
                has(target, prop) {{ return Reflect.has(target, prop); }},
                deleteProperty(target, prop) {{ return Reflect.deleteProperty(target, prop); }},
                ownKeys(target) {{ return Reflect.ownKeys(target); }},
                getOwnPropertyDescriptor(target, prop) {{
                    return Reflect.getOwnPropertyDescriptor(target, prop);
                }}
            }});
        }}

        // Debug output if requested
        if (process.env.MALWI_DEBUG) {{
            console.error('[malwi] Addon loaded: Node', major, '(' + bucket + ')');
        }}
    }} catch (e) {{
        // Fallback: bytecode tracing still works
        if (process.env.MALWI_DEBUG) {{
            console.error('[malwi] Addon load failed:', e.message);
        }}
    }}
}})();
"#,
        addon_dir = addon_dir_str
    )
}

/// Constructor attribute for automatic initialization on library load (Linux).
#[cfg(all(target_os = "linux", not(test)))]
#[unsafe(link_section = ".init_array")]
#[used]
static INIT: extern "C" fn() = {
    extern "C" fn init() {
        malwi_agent_init();
    }
    init
};

/// Constructor attribute for automatic initialization on library load (macOS).
#[cfg(all(target_os = "macos", not(test)))]
#[unsafe(link_section = "__DATA,__mod_init_func")]
#[used]
static INIT: extern "C" fn() = {
    extern "C" fn init() {
        malwi_agent_init();
    }
    init
};
