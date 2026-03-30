//! Agent state and initialization for malwi-trace.
//!
//! Contains the Agent struct, global statics, and the `malwi_agent_init()` entry point.

pub mod lifecycle;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use lifecycle::AgentPhase;
use malwi_protocol::message::DisplayEvent;

/// Whether agent debug output is enabled (from MALWI_AGENT_DEBUG env var at init).
static AGENT_DEBUG: AtomicBool = AtomicBool::new(false);

/// Check if agent debug output is enabled.
pub fn agent_debug_enabled() -> bool {
    AGENT_DEBUG.load(Ordering::Relaxed)
}

/// Maximum time to wait for the flush thread to drain pending events during
/// shutdown. Flushes are single-frame writes on a persistent TCP connection —
/// no per-message overhead. The flush thread typically completes in <50ms;
/// this timeout is a safety net for pathological delays.
const FLUSH_DRAIN_TIMEOUT_MS: u64 = 500;

/// Idle timeout for the flush loop's `recv_timeout`. Controls how quickly the
/// flush thread notices shutdown when no events are arriving.
/// At 10ms the thread wakes 100 times/second — negligible CPU impact.
const FLUSH_RECV_TIMEOUT_MS: u64 = 10;

/// Wait for the flush thread to drain pending events, with a bounded timeout.
/// Used before sending /shutdown to ensure the CLI displays all events.
fn wait_for_flush_complete() {
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(FLUSH_DRAIN_TIMEOUT_MS);
    while !AgentPhase::is_flushed() {
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

use anyhow::Result;
use log::{debug, error, info, warn};
use malwi_protocol::{ChildOperation, HookConfig, HookType, HostChildInfo};

use crate::client::Client;
#[cfg(unix)]
use crate::exec::{ForkHandler, ForkMonitor};
use crate::exec::{SpawnHandler, SpawnInfo, SpawnMonitor};
use crate::native::HookManager;

/// Global agent state.
static AGENT: OnceLock<Agent> = OnceLock::new();

/// The agent managing hooks and communication.
pub struct Agent {
    hook_manager: HookManager,
    /// Wire client for CLI communication — no mutexes needed.
    client: Client,
    /// Channel sender for batched event delivery.
    event_tx: SyncSender<malwi_protocol::TraceEvent>,
    /// True in forked child processes — bypass the dead batching channel.
    forked: AtomicBool,
    /// Agent-side policy evaluator (loaded from config file).
    /// When present, the agent evaluates policy locally instead of sending raw events.
    agent_policy: Option<malwi_protocol::agent_policy::AgentPolicy>,
    #[cfg(unix)]
    fork_monitor: Mutex<Option<ForkMonitor>>,
    spawn_monitor: Mutex<Option<SpawnMonitor>>,
}

impl Agent {
    /// Create a new agent connected to the CLI via TCP wire protocol.
    pub fn new(url: &str) -> Result<Self> {
        let client = Client::new(url);
        let hook_manager = HookManager::new()?;

        // Event batching: hook callbacks push to this channel,
        // a dedicated flush thread drains and sends in batches.
        let (event_tx, event_rx) = mpsc::sync_channel::<malwi_protocol::TraceEvent>(4096);

        // Spawn flush thread with its own wire client
        let flush_client = Client::new(url);
        std::thread::spawn(move || {
            event_flush_loop(flush_client, event_rx);
        });

        Ok(Self {
            hook_manager,
            client,
            event_tx,
            forked: AtomicBool::new(false),
            agent_policy: None,
            #[cfg(unix)]
            fork_monitor: Mutex::new(None),
            spawn_monitor: Mutex::new(None),
        })
    }

    /// Send late Node.js version info to the CLI if detected.
    /// Called once from the flush thread when version becomes available.
    fn send_late_nodejs_version(&self) {
        if let Some(v) = crate::nodejs::detected_version() {
            let _ = self
                .client
                .send_runtime_info(std::process::id(), "nodejs", &format!("v{}", v));
        }
    }

    /// Install a hook locally (no wire call needed — agent manages hooks directly).
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
                crate::python::add_filter(&config.symbol, config.capture_stack);
                debug!("Added Python filter: {}", config.symbol);
            }
            HookType::Nodejs => {
                crate::nodejs::add_filter(&config.symbol, config.capture_stack);
                debug!("Added Node.js filter: {}", config.symbol);
            }
            HookType::Exec => {
                crate::exec::filter::add_filter(&config.symbol, config.capture_stack);
                self.ensure_monitors_installed();
                // CPython subprocess exec events are best-effort via audit hooks.
                // We may be loaded before Python's exported symbols are visible, so retry.
                crate::python::start_audit_registration_task();
                debug!("Added exec filter: {}", config.symbol);
            }
            HookType::Bash => {
                // Bash hooks are installed automatically on detection (setup_bash_hooks()),
                // not via HookConfig. No-op arm for exhaustive matching.
            }
            HookType::EnvVar => {
                // EnvVar monitoring: hook bash's find_variable if this is a bash process.
                // Set the flag so setup_bash_hooks() will install the hook if the spawn
                // monitor hasn't been created yet.
                if config.symbol.starts_with('!') {
                    // Allow pattern — bypass deny checks for matching vars
                    crate::exec::envvar::add_allow_pattern(&config.symbol[1..]);
                    debug!("Added envvar allow pattern: {}", &config.symbol[1..]);
                    return Ok(());
                }
                crate::exec::spawn::enable_envvar_monitoring();
                // Individual deny patterns (non-wildcard) are for agent-side blocking.
                if config.symbol != "*" {
                    crate::exec::envvar::add_deny_pattern(&config.symbol);
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
                if crate::python::is_loaded() {
                    crate::python::enable_envvar_monitoring();
                }
                debug!("Enabled envvar monitoring");
            }
        }
        Ok(())
    }

    /// Send a trace event to the CLI.
    ///
    /// When agent-side policy is active, evaluates the event and sends a
    /// DisplayEvent with pre-computed disposition. Otherwise sends raw TraceEvent.
    ///
    /// Pushes to the batch channel for efficient delivery. Falls back to
    /// direct send if the channel is full (backpressure) or after fork
    /// (channel receiver thread is dead).
    pub fn send_event(&self, event: malwi_protocol::TraceEvent) -> Result<()> {
        // Check forked FIRST — after fork, heap allocations in agent_policy's
        // glob patterns may be corrupted. Send raw events directly via TCP.
        if self.forked.load(Ordering::Acquire) {
            return self.client.send_event(&event);
        }

        // Agent-side policy: evaluate locally and send DisplayEvent directly.
        // The batch channel stays as TraceEvent for simplicity — policy events
        // bypass it and go directly via client.send_display_events().
        if let Some(ref policy) = self.agent_policy {
            let decision = policy.evaluate(&event);
            let disposition = match decision {
                malwi_protocol::agent_policy::AgentDecision::Trace => {
                    malwi_protocol::Disposition::Traced
                }
                malwi_protocol::agent_policy::AgentDecision::Block { rule, section } => {
                    malwi_protocol::Disposition::Blocked { rule, section }
                }
                malwi_protocol::agent_policy::AgentDecision::Warn { rule, section } => {
                    malwi_protocol::Disposition::Warning { rule, section }
                }
                malwi_protocol::agent_policy::AgentDecision::Suppress
                | malwi_protocol::agent_policy::AgentDecision::Hide => {
                    // Suppress and Hide events are not sent to CLI
                    return Ok(());
                }
            };
            return self.client.send_display_events(vec![DisplayEvent {
                trace: event,
                disposition,
            }]);
        }

        match self.event_tx.try_send(event) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(event)) => self.client.send_event(&event),
            Err(TrySendError::Disconnected(event)) => self.client.send_event(&event),
        }
    }

    /// Evaluate an event against the agent-side policy (if loaded).
    /// Also returns None in forked children — heap allocations in the policy's
    /// glob patterns may be corrupted if the parent was allocating at fork time.
    pub fn evaluate_policy(
        &self,
        event: &malwi_protocol::TraceEvent,
    ) -> Option<malwi_protocol::agent_policy::AgentDecision> {
        if self.forked.load(Ordering::Acquire) {
            return None;
        }
        self.agent_policy.as_ref().map(|p| p.evaluate(event))
    }

    /// Evaluate just the envvar section of agent-side policy.
    pub fn evaluate_envvar_policy(
        &self,
        name: &str,
    ) -> Option<malwi_protocol::agent_policy::AgentDecision> {
        if self.forked.load(Ordering::Acquire) {
            return None;
        }
        self.agent_policy.as_ref().map(|p| p.evaluate_envvar(name))
    }

    /// Evaluate just the file section of agent-side policy.
    pub fn evaluate_file_policy(
        &self,
        path: &str,
    ) -> Option<malwi_protocol::agent_policy::AgentDecision> {
        if self.forked.load(Ordering::Acquire) {
            return None;
        }
        self.agent_policy.as_ref().map(|p| p.evaluate_file(path))
    }

    /// Get a reference to the global agent.
    pub fn get() -> Option<&'static Agent> {
        AGENT.get()
    }

    /// Wait for hook configuration to complete.
    ///
    /// Reads configuration from the MALWI_CONFIG file (written by CLI before spawn).
    /// Installs hooks locally, then notifies the CLI via a ready message.
    pub fn wait_for_configuration(&mut self) -> Result<()> {
        let agent_config = Self::try_load_config_file()
            .ok_or_else(|| anyhow::anyhow!("MALWI_CONFIG not set or config file unreadable"))?;

        info!("Loaded configuration from file");

        // Install hooks from config file
        for hook_config in &agent_config.hooks {
            if let Err(e) = self.add_hook_local(hook_config.clone()) {
                warn!("Failed to install hook {}: {}", hook_config.symbol, e);
            }
        }

        // Set up agent-side policy evaluator
        let policy = malwi_protocol::agent_policy::AgentPolicy::new(&agent_config.policy);
        self.agent_policy = Some(policy);

        // Install Node.js native C++ callback hooks (fs.readFileSync, dns.lookup, etc.)
        // This runs AFTER filters are registered so the hook table can match them.
        if crate::nodejs::is_loaded() {
            let native_filters = crate::nodejs::filters::get_filters();
            if !native_filters.is_empty() {
                crate::nodejs::hooks::native::install_hooks(&native_filters);
            }
        }

        // Enable child gating unconditionally
        self.enable_child_gating_internal();

        let pid = std::process::id();
        let nodejs_version = if crate::nodejs::is_loaded() {
            crate::nodejs::detected_version()
        } else {
            None
        };

        // Enumerate loaded modules for CLI-side symbol resolution
        let modules: Vec<malwi_protocol::ModuleInfo> = crate::native::enumerate_modules()
            .into_iter()
            .map(|m| malwi_protocol::ModuleInfo {
                name: m.name,
                path: m.path,
                base_address: m.base_address as u64,
                size: m.size as u64,
            })
            .collect();

        // Gather runtime versions for CLI display
        let python_version = if crate::python::is_loaded() {
            crate::python::detected_version().map(|v| v.to_string())
        } else {
            None
        };
        let bash_version = crate::bash::detected_version().map(|s| s.to_string());

        // Report ready
        let hook_list = self.hook_manager.list_hooks();
        info!(
            "Configuration complete, sending ready with {} hooks and {} modules",
            hook_list.len(),
            modules.len()
        );
        self.client.ready(
            pid,
            hook_list,
            nodejs_version,
            python_version,
            bash_version,
            modules,
        )?;

        Ok(())
    }

    /// Try to load configuration from a file (MALWI_CONFIG env var).
    fn try_load_config_file() -> Option<malwi_protocol::agent_config::AgentConfig> {
        let config_path = std::env::var("MALWI_CONFIG").ok()?;
        let yaml = std::fs::read_to_string(&config_path).ok()?;
        match malwi_protocol::agent_config::AgentConfig::from_yaml(&yaml) {
            Ok(config) => {
                info!("Loaded agent config from {}", config_path);
                Some(config)
            }
            Err(e) => {
                warn!("Failed to parse agent config from {}: {}", config_path, e);
                None
            }
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
                if agent_debug_enabled() {
                    eprintln!("[malwi-agent] fork monitor installed");
                }
                *guard = Some(monitor);
            }
            None => {
                warn!("Failed to install fork monitor");
                if agent_debug_enabled() {
                    eprintln!("[malwi-agent] fork monitor installation failed");
                }
            }
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
                if crate::exec::spawn::is_envvar_monitoring_enabled() {
                    unsafe {
                        monitor.enable_envvar_hook();
                        monitor.enable_getenv_hook();
                    }
                }
                info!("Spawn monitor installed");
                if agent_debug_enabled() {
                    eprintln!("[malwi-agent] spawn monitor installed");
                }
                *guard = Some(monitor);
            }
            None => {
                warn!("Failed to install spawn monitor");
                if agent_debug_enabled() {
                    eprintln!("[malwi-agent] spawn monitor installation failed");
                }
            }
        }
    }

    /// Send a child created notification to CLI.
    fn notify_child_created(&self, info: HostChildInfo) {
        debug!(
            "Child created: parent={}, child={}, op={:?}",
            info.parent_pid, info.child_pid, info.operation
        );

        // Only show child events if exec filters are configured
        if !crate::exec::filter::has_filters() {
            debug!("No exec filters configured, hiding child event");
            if agent_debug_enabled() {
                eprintln!("[malwi-agent] notify_child: no exec filters, dropping");
            }
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
            let (matches, _) = crate::exec::filter::check_filter(cmd);
            let unwrap_matches = unwrapped
                .map(|u| crate::exec::filter::check_filter(u).0)
                .unwrap_or(false);
            if !matches && !unwrap_matches {
                debug!("Command '{}' does not match exec filter, hiding", cmd);
                if agent_debug_enabled() {
                    eprintln!("[malwi-agent] notify_child: '{}' filtered out", cmd);
                }
                return;
            }
        } else if info.operation == ChildOperation::Fork {
            // Bare fork (no path, no argv) — not a command execution.
            // The actual command will arrive in a subsequent Exec event.
            return;
        }

        let cmd_label = raw_command.unwrap_or("?");
        match self.client.send_child(&info) {
            Ok(()) => {
                if agent_debug_enabled() {
                    eprintln!("[malwi-agent] send_child ok: {}", cmd_label);
                }
            }
            Err(e) => {
                warn!("Failed to send child created notification: {}", e);
                if agent_debug_enabled() {
                    eprintln!("[malwi-agent] send_child failed for {}: {}", cmd_label, e);
                }
            }
        }
    }
}

/// Flush loop for batched event delivery.
///
/// Collects events from the channel and sends them in batches of up to 64.
/// Uses `recv_timeout` to coalesce events that arrive close together,
/// flushing either when the batch is full or after a `FLUSH_RECV_TIMEOUT_MS` idle period.
fn event_flush_loop(client: Client, rx: mpsc::Receiver<malwi_protocol::TraceEvent>) {
    crate::native::suppress_hooks_on_current_thread();
    let mut batch = Vec::with_capacity(64);
    loop {
        match rx.recv_timeout(Duration::from_millis(FLUSH_RECV_TIMEOUT_MS)) {
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
                if AgentPhase::is_shutting_down() {
                    // Drain remaining events before exiting
                    while let Ok(e) = rx.try_recv() {
                        batch.push(e);
                    }
                    if !batch.is_empty() {
                        let _ = client.send_events(std::mem::take(&mut batch));
                    }
                    AgentPhase::advance(AgentPhase::ShuttingDown, AgentPhase::Flushed);
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
                    let _ = client.send_events(std::mem::take(&mut batch));
                }
                AgentPhase::advance(AgentPhase::ShuttingDown, AgentPhase::Flushed);
                return;
            }
        }

        if !batch.is_empty() {
            let _ = client.send_events(std::mem::take(&mut batch));
        }

        // Check for shutdown after each batch send, not just on timeout.
        // Without this, the flush thread can't exit promptly when events
        // keep arriving (the Timeout arm is never reached).
        if AgentPhase::is_shutting_down() {
            while let Ok(e) = rx.try_recv() {
                batch.push(e);
            }
            if !batch.is_empty() {
                let _ = client.send_events(std::mem::take(&mut batch));
            }
            AgentPhase::advance(AgentPhase::ShuttingDown, AgentPhase::Flushed);
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
            source_column: None,
            runtime_stack: None,
            hook_type: None,
        };
        self.notify_child_created(info);
    }

    fn on_fork_in_child(&self) {
        // Mark as forked so send_event() bypasses the dead batching channel.
        // The flush thread that owns the receiver doesn't survive fork, and
        // the channel's internal mutex may be held by the dead thread.
        self.forked.store(true, Ordering::SeqCst);
        // Drop inherited TCP connection safely. try_lock avoids deadlock
        // if the conn mutex was held by a now-dead thread at fork time.
        // No proactive reconnect — the next send() call will lazily
        // establish a fresh connection via ensure_connected().
        self.client.mark_forked_child();
        // Clear DNS cache — parent's associations are irrelevant in child
        crate::tracing::dns_tracker().mark_forked();
        // Register with CLI via Ready so active_agents is incremented.
        // When exec() replaces this process, CLOEXEC closes the TCP socket,
        // triggering EOF → Disconnected → decrement. The new agent sends
        // its own Ready, keeping the count correct.
        let _ = self
            .client
            .ready(std::process::id(), vec![], None, None, None, vec![]);
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
            source_column: info.source_column,
            runtime_stack: info.runtime_stack,
            hook_type: info.hook_type,
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
            source_column: info.source_column,
            runtime_stack: info.runtime_stack,
            hook_type: info.hook_type,
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

    // Read debug flag once at init time (avoids env var lock on every call)
    AGENT_DEBUG.store(
        std::env::var_os("MALWI_AGENT_DEBUG").is_some(),
        Ordering::Relaxed,
    );

    // Save agent library path for selective re-injection in exec hooks,
    // then strip DYLD vars from the process environment BEFORE main() runs.
    // The agent is already loaded; removing these prevents the host program
    // (e.g. bash) from copying them into its internal env tables and
    // propagating them to every child — which would crash arm64e children.
    #[cfg(target_os = "macos")]
    {
        if let Ok(dyld_path) = std::env::var("DYLD_INSERT_LIBRARIES") {
            crate::exec::spawn::set_agent_dyld_path(dyld_path);
        }
        std::env::remove_var("DYLD_INSERT_LIBRARIES");
        std::env::remove_var("DYLD_FORCE_FLAT_NAMESPACE");
    }

    // Initialize logging
    let _ = env_logger::try_init();

    // Initialize hook subsystems early.
    crate::init();
    // Register CPython audit hook if CPython is loaded.
    // This may succeed even before Py_Initialize() on some builds (e.g.
    // python-build-standalone).  On builds where pre-init hooks are silently
    // lost, start_audit_registration_task() will hook Py_RunMain to
    // re-register post-init.
    if crate::python::is_loaded() {
        info!("CPython detected, registering audit hook");
        let registered = crate::python::register_audit_hook();
        if AGENT_DEBUG.load(Ordering::Relaxed) {
            eprintln!(
                "[malwi-agent] early audit hook registration: {}",
                if registered { "ok" } else { "deferred" }
            );
        }
    }

    // Detect Node.js runtime and enable tracing.
    // Only initialize when JS tracing was requested (NODE_OPTIONS is set by the CLI
    // when --js is used). Unconditional init breaks programs like npm.
    if crate::nodejs::is_loaded() {
        info!("Node.js detected, initializing tracing");
        if crate::nodejs::init_tracing() {
            info!("Node.js JavaScript tracing enabled");
        } else {
            warn!("Failed to initialize Node.js JavaScript tracing");
        }
    }

    // Mark that we're entering configuration phase
    AgentPhase::advance(AgentPhase::Uninitialized, AgentPhase::Configuring);

    match Agent::new(&url) {
        Ok(mut agent) => {
            info!("Connected to CLI at {}, waiting for configuration...", url);

            // CRITICAL: Block synchronously until configuration is complete
            if let Err(e) = agent.wait_for_configuration() {
                error!("Failed during hook configuration: {}", e);
                return -1;
            }

            AgentPhase::advance(AgentPhase::Configuring, AgentPhase::Ready);

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
                // bookkeeping (wire protocol, cleanup) — not meaningful to the user.
                crate::native::suppress_hooks_on_current_thread();
                AgentPhase::request_shutdown();
                // Wait for flush thread to drain pending events BEFORE we
                // decrement the CLI's active_agents counter via /shutdown.
                // Bounded timeout in case flush thread is dead (e.g., in
                // forked children where threads don't survive fork).
                wait_for_flush_complete();
                // Send shutdown (only once across atexit + bg thread)
                if AgentPhase::advance(AgentPhase::Flushed, AgentPhase::ShutdownSent) {
                    if let Some(agent) = Agent::get() {
                        let _ = agent.client.shutdown(std::process::id());
                    }
                }
            }
            unsafe {
                libc::atexit(shutdown_handler);
            }

            // Send late Node.js version if available after a short delay.
            // Version is detected asynchronously via V8 codegen gate.
            if crate::nodejs::is_loaded() {
                std::thread::spawn(|| {
                    crate::native::suppress_hooks_on_current_thread();
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    if let Some(agent) = Agent::get() {
                        agent.send_late_nodejs_version();
                    }
                });
            }

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
    _url_ptr: *const std::ffi::c_char,
    _out_buffer: *mut std::ffi::c_char,
    _buffer_size: usize,
) -> i32 {
    // Node.js tracing now uses frida-gum hooks exclusively (V8 --trace flag,
    // Runtime_TraceEnter/Exit, codegen gate). No NODE_OPTIONS or --require
    // wrapper needed. This function is kept as a no-op for ABI compatibility.
    0
}
