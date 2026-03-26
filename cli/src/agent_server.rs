//! Binary wire server for agent communication.
//!
//! Receives agent messages via length-prefixed TCP using `BinaryCodec`.
//! Each agent connection is a persistent TCP stream on its own tokio task.
//! Communication is unidirectional: agent → CLI only.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use log::debug;
use tokio::io::AsyncReadExt;

use malwi_intercept::wire::{BinaryCodec, Codec};
use malwi_intercept::{
    AgentMessage, Argument, ChildOperation, DisplayEvent, EventType, HookType, HostChildInfo,
    TraceEvent,
};

/// Events sent from the agent server to the main event loop.
pub enum AgentEvent {
    /// Agent connected and ready
    Ready {
        pid: u32,
        hooks: Vec<String>,
        nodejs_version: Option<u32>,
        python_version: Option<String>,
        bash_version: Option<String>,
        modules: Vec<malwi_intercept::ModuleInfo>,
    },
    /// Trace event from agent (raw, no disposition — legacy path)
    Trace(TraceEvent),
    /// Display event with agent-computed disposition (config-file path)
    DisplayTrace(DisplayEvent),
    /// Late runtime info (e.g., Node.js version detected after Ready)
    RuntimeInfo { runtime: String, version: String },
    /// Agent disconnected
    Disconnected { pid: u32 },
}

/// Tracking state shared between AgentServer and the main event loop.
pub struct AgentTracking {
    pub active_count: Arc<AtomicU32>,
}

/// Shared state for the server tasks.
struct SharedState {
    event_tx: tokio::sync::mpsc::Sender<AgentEvent>,
    active_agents: Arc<AtomicU32>,
    /// Suppresses duplicate exec events caused by libc PATH iteration.
    /// Key: (child_pid, command_basename).
    seen_events: Mutex<HashSet<(u32, String)>>,
}

/// Binary wire server for agent communication.
pub struct AgentServer {
    listener: tokio::net::TcpListener,
    url: String,
    shared: Arc<SharedState>,
}

/// Create a TcpListener bound to 127.0.0.1:0 with SO_REUSEADDR set before bind.
#[cfg(unix)]
fn create_reuse_addr_listener() -> Result<tokio::net::TcpListener> {
    use std::os::unix::io::FromRawFd;

    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            anyhow::bail!("socket() failed: {}", std::io::Error::last_os_error());
        }

        let optval: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );

        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
            sin_zero: [0; 8],
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
        };

        if libc::bind(
            fd,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) < 0
        {
            let err = std::io::Error::last_os_error();
            libc::close(fd);
            anyhow::bail!("bind() failed: {}", err);
        }

        if libc::listen(fd, 128) < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(fd);
            anyhow::bail!("listen() failed: {}", err);
        }

        let std_listener = std::net::TcpListener::from_raw_fd(fd);
        std_listener.set_nonblocking(true)?;
        Ok(tokio::net::TcpListener::from_std(std_listener)?)
    }
}

impl AgentServer {
    /// Create a new agent server bound to a random port.
    pub fn new(
        event_tx: tokio::sync::mpsc::Sender<AgentEvent>,
        tracking: AgentTracking,
    ) -> Result<Self> {
        let listener = create_reuse_addr_listener()?;
        let port = listener.local_addr()?.port();
        let url = format!("http://127.0.0.1:{}", port);

        let shared = Arc::new(SharedState {
            event_tx,
            active_agents: tracking.active_count,
            seen_events: Mutex::new(HashSet::new()),
        });

        Ok(Self {
            listener,
            url,
            shared,
        })
    }

    /// Get the server URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Run the server, accepting connections until all agents disconnect.
    pub async fn run(self) {
        loop {
            let (stream, _) = match self.listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    debug!("Accept error: {}", e);
                    continue;
                }
            };
            let shared = self.shared.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_agent_connection(stream, &shared).await {
                    debug!("Agent connection error: {}", e);
                }
            });
        }
    }
}

/// Handle a single agent TCP connection using the binary wire protocol.
async fn handle_agent_connection(
    mut stream: tokio::net::TcpStream,
    shared: &SharedState,
) -> Result<()> {
    stream.set_nodelay(true)?;

    let codec = BinaryCodec;

    // Track the PID for this connection (set on first Ready)
    let mut agent_pid: Option<u32> = None;
    // Track whether the agent sent a clean Shutdown message
    let mut shutdown_received = false;
    // Track whether this connection incremented active_agents.
    // Only connections that incremented should send Disconnected (which triggers a decrement).
    let mut counted = false;

    // Message loop: read length-prefixed frames
    loop {
        // Read 4-byte frame length with 30s timeout
        let mut len_buf = [0u8; 4];
        match tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                debug!("Agent read error: {}", e);
                break;
            }
            Err(_) => {
                debug!("Agent read timed out");
                break;
            }
        }

        let frame_len = u32::from_be_bytes(len_buf) as usize;
        if frame_len > 64 * 1024 * 1024 {
            debug!("Frame too large: {} bytes", frame_len);
            break;
        }

        // Read payload
        let mut payload = vec![0u8; frame_len];
        if !payload.is_empty() {
            match tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut payload))
                .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    debug!("Agent payload read error: {}", e);
                    break;
                }
                Err(_) => {
                    debug!("Agent payload read timed out");
                    break;
                }
            }
        }

        // Decode the message
        let msg = match codec.decode_agent_msg(&payload) {
            Ok(m) => m,
            Err(e) => {
                debug!("Invalid agent message: {}", e);
                continue;
            }
        };

        handle_message(
            msg,
            shared,
            &mut agent_pid,
            &mut shutdown_received,
            &mut counted,
        )
        .await?;
    }

    // Connection dropped (EOF or error) — send Disconnected if no clean Shutdown
    // and this connection actually incremented active_agents.
    if let Some(pid) = agent_pid {
        if !shutdown_received && counted {
            let _ = shared.event_tx.send(AgentEvent::Disconnected { pid }).await;
        }
    }

    Ok(())
}

/// Handle a single agent message.
async fn handle_message(
    msg: AgentMessage,
    shared: &SharedState,
    agent_pid: &mut Option<u32>,
    shutdown_received: &mut bool,
    counted: &mut bool,
) -> Result<()> {
    match msg {
        AgentMessage::Ready(req) => {
            debug!(
                "Agent PID {} ready with {} hooks",
                req.pid,
                req.hooks_installed.len()
            );

            *agent_pid = Some(req.pid);

            // Increment active agents if not already counted for this connection
            if !*counted {
                shared.active_agents.fetch_add(1, Ordering::SeqCst);
                *counted = true;
            }

            let _ = shared
                .event_tx
                .send(AgentEvent::Ready {
                    pid: req.pid,
                    hooks: req.hooks_installed,
                    nodejs_version: req.nodejs_version,
                    python_version: req.python_version,
                    bash_version: req.bash_version,
                    modules: req.modules,
                })
                .await;
        }
        AgentMessage::Runtime(req) => {
            debug!(
                "Agent PID {} runtime info: {}={}",
                req.pid, req.runtime, req.version
            );

            let _ = shared
                .event_tx
                .send(AgentEvent::RuntimeInfo {
                    runtime: req.runtime,
                    version: req.version,
                })
                .await;
        }
        AgentMessage::Event(event) => {
            let _ = shared.event_tx.send(AgentEvent::Trace(event)).await;
        }
        AgentMessage::Events(events) => {
            for event in events {
                let _ = shared.event_tx.send(AgentEvent::Trace(event)).await;
            }
        }
        AgentMessage::Child(info) => {
            // Bare fork events (no path, no argv) are process duplication, not command execution.
            if info.operation == ChildOperation::Fork && info.argv.is_none() && info.path.is_none()
            {
                return Ok(());
            }

            // Suppress duplicates from libc PATH iteration
            let cmd_name = extract_cmd_name(&info);

            // Only dedup events with a real child_pid. Audit-sourced events
            // (child_pid == 0) don't have PATH iteration duplicates.
            if info.child_pid != 0 {
                let mut seen = shared.seen_events.lock().unwrap_or_else(|e| e.into_inner());
                if !seen.insert((info.child_pid, cmd_name.clone())) {
                    return Ok(());
                }
            }

            let event = child_info_to_trace_event(info, cmd_name.clone());
            debug!("Child event queued: cmd={}", cmd_name);
            let _ = shared.event_tx.send(AgentEvent::Trace(event)).await;
        }
        AgentMessage::DisplayEvents(events) => {
            for de in events {
                let _ = shared.event_tx.send(AgentEvent::DisplayTrace(de)).await;
            }
        }
        AgentMessage::Shutdown(req) => {
            debug!("Agent PID {} shutting down", req.pid);
            *shutdown_received = true;

            if let Ok(mut seen) = shared.seen_events.lock() {
                seen.retain(|(pid, _)| *pid != req.pid);
            }

            // Only send Disconnected if this connection incremented active_agents.
            if *counted {
                let _ = shared
                    .event_tx
                    .send(AgentEvent::Disconnected { pid: req.pid })
                    .await;
            }
        }
    }
    Ok(())
}

/// Extract the command basename from a HostChildInfo.
fn extract_cmd_name(info: &HostChildInfo) -> String {
    info.argv
        .as_ref()
        .and_then(|argv| argv.first())
        .map(|s| basename(s).to_string())
        .or_else(|| info.path.as_ref().map(|p| basename(p).to_string()))
        .unwrap_or_else(|| "?".to_string())
}

/// Convert a HostChildInfo into a TraceEvent at the server boundary.
fn child_info_to_trace_event(info: HostChildInfo, cmd_name: String) -> TraceEvent {
    let arguments: Vec<Argument> = info
        .argv
        .as_ref()
        .map(|argv| {
            argv.iter()
                .map(|a| Argument {
                    raw_value: 0,
                    display: Some(a.clone()),
                })
                .collect()
        })
        .unwrap_or_default();

    TraceEvent {
        hook_type: info.hook_type.unwrap_or(HookType::Exec),
        event_type: EventType::Enter,
        function: cmd_name,
        arguments,
        native_stack: info.native_stack,
        runtime_stack: info.runtime_stack,
        source_file: info.source_file,
        source_line: info.source_line,
        ..Default::default()
    }
}

/// Extract the basename from a path.
fn basename(path: &str) -> &str {
    std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
}
