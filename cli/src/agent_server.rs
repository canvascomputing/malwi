//! WebSocket server for agent communication.
//!
//! Receives agent messages via WebSocket using `malwi-websocket`.
//! Each agent connection is a persistent WebSocket on its own thread.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::Result;
use log::debug;

use malwi_protocol::{
    AgentMessage, Argument, ChildOperation, CliMessage, ConfigureResponse, EventType, HookConfig,
    HookType, HostChildInfo, ReviewDecision, TraceEvent,
};
use malwi_websocket::{
    build_server_handshake_response, parse_client_handshake_with_len, Connection, ConnectionConfig,
    Event, HandshakeParseConfig, Message, PeerRole,
};

/// Events sent from the WebSocket server to the main event loop.
pub enum AgentEvent {
    /// Agent connected and ready
    Ready {
        pid: u32,
        hooks: Vec<String>,
        nodejs_version: Option<u32>,
        python_version: Option<String>,
        bash_version: Option<String>,
        modules: Vec<malwi_protocol::ModuleInfo>,
    },
    /// Trace event from agent
    Trace(TraceEvent),
    /// Late runtime info (e.g., Node.js version detected after Ready)
    RuntimeInfo { runtime: String, version: String },
    /// Agent disconnected
    Disconnected { pid: u32 },
    /// Review mode decision request (agent blocks on WS response)
    ReviewRequest {
        event: TraceEvent,
        response_tx: Sender<ReviewDecision>,
    },
}

/// Shared state for the WebSocket server threads.
struct SharedState {
    hook_configs: Vec<HookConfig>,
    review_mode: bool,
    event_tx: SyncSender<AgentEvent>,
    active_agents: Arc<AtomicU32>,
    /// Suppresses duplicate exec events caused by libc PATH iteration.
    /// Key: (child_pid, command_basename).
    seen_events: Mutex<HashSet<(u32, String)>>,
    /// PIDs that connected via reconnect. Used to avoid double-counting
    /// active_agents when a reconnected child does exec (which triggers a second
    /// configure for the same PID from the fresh agent).
    reconnected_pids: Mutex<HashSet<u32>>,
}

/// WebSocket server for agent communication.
pub struct AgentServer {
    listener: std::net::TcpListener,
    url: String,
    shared: Arc<SharedState>,
}

/// Create a TcpListener bound to 127.0.0.1:0 with SO_REUSEADDR set before bind.
#[cfg(unix)]
fn create_reuse_addr_listener() -> Result<std::net::TcpListener> {
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

        Ok(std::net::TcpListener::from_raw_fd(fd))
    }
}

impl AgentServer {
    /// Create a new agent server bound to a random port.
    pub fn new(
        hook_configs: Vec<HookConfig>,
        review_mode: bool,
        event_tx: SyncSender<AgentEvent>,
        active_agents: Arc<AtomicU32>,
    ) -> Result<Self> {
        let listener = create_reuse_addr_listener()?;
        let port = listener.local_addr()?.port();
        let url = format!("http://127.0.0.1:{}", port);

        let shared = Arc::new(SharedState {
            hook_configs,
            review_mode,
            event_tx,
            active_agents,
            seen_events: Mutex::new(HashSet::new()),
            reconnected_pids: Mutex::new(HashSet::new()),
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

    /// Run the WebSocket server, accepting connections until all agents disconnect.
    pub fn run(self) {
        for stream in self.listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    debug!("Accept error: {}", e);
                    continue;
                }
            };
            let shared = self.shared.clone();
            thread::spawn(move || {
                if let Err(e) = handle_agent_connection(stream, &shared) {
                    debug!("Agent connection error: {}", e);
                }
            });
        }
    }
}

/// Handle a single agent WebSocket connection.
fn handle_agent_connection(mut stream: TcpStream, shared: &SharedState) -> Result<()> {
    stream.set_nodelay(true)?;

    // 1. Read WebSocket upgrade request
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf)?;
    if n == 0 {
        anyhow::bail!("empty handshake");
    }
    let (request, _consumed) =
        parse_client_handshake_with_len(&buf[..n], HandshakeParseConfig::default())
            .map_err(|e| anyhow::anyhow!("WS handshake parse failed: {}", e))?;

    // 2. Send 101 upgrade response
    let response = build_server_handshake_response(&request, None, &[])
        .map_err(|e| anyhow::anyhow!("WS handshake response failed: {}", e))?;
    stream.write_all(&response)?;

    // 3. Create WebSocket connection state machine
    let mut conn = Connection::new(ConnectionConfig {
        role: PeerRole::Server,
        ..ConnectionConfig::default()
    });

    // Track the PID for this connection (set on first Configure or Reconnect)
    let mut agent_pid: Option<u32> = None;
    // Track whether the agent sent a clean Shutdown message
    let mut shutdown_received = false;
    // Track whether this connection incremented active_agents.
    // Only connections that incremented should send Disconnected (which triggers a decrement).
    let mut counted = false;

    // 4. Message loop
    let mut read_buf = vec![0u8; 64 * 1024];
    loop {
        let n = match stream.read(&mut read_buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                debug!("Agent read error: {}", e);
                break;
            }
        };

        let events = match conn.ingest(&read_buf[..n], None) {
            Ok(events) => events,
            Err(e) => {
                debug!("WS protocol error: {}", e);
                break;
            }
        };

        for event in events {
            match event {
                Event::Message(Message::Text(text)) => {
                    let msg: AgentMessage = match serde_json::from_str(&text) {
                        Ok(m) => m,
                        Err(e) => {
                            debug!("Invalid agent message: {}", e);
                            continue;
                        }
                    };
                    handle_message(
                        msg,
                        &mut conn,
                        &mut stream,
                        shared,
                        &mut agent_pid,
                        &mut shutdown_received,
                        &mut counted,
                    )?;
                }
                Event::CloseReceived(_) | Event::Closed => {
                    // Send Disconnected if we had a PID, no clean Shutdown, and
                    // this connection actually incremented active_agents.
                    if let Some(pid) = agent_pid {
                        if !shutdown_received && counted {
                            let _ = shared.event_tx.send(AgentEvent::Disconnected { pid });
                        }
                    }
                    return Ok(());
                }
                _ => {} // Ping/pong handled by Connection
            }
        }

        // Flush any outbound frames (pongs, responses)
        flush_outbox(&mut conn, &mut stream)?;
    }

    // Connection dropped (EOF or error) — send Disconnected if no clean Shutdown
    // and this connection actually incremented active_agents.
    if let Some(pid) = agent_pid {
        if !shutdown_received && counted {
            let _ = shared.event_tx.send(AgentEvent::Disconnected { pid });
        }
    }

    Ok(())
}

/// Flush all queued outbound WebSocket frames to the stream.
fn flush_outbox(conn: &mut Connection, stream: &mut TcpStream) -> Result<()> {
    while let Some(bytes) = conn.poll_outbound() {
        stream.write_all(&bytes)?;
    }
    Ok(())
}

/// Handle a single agent message.
fn handle_message(
    msg: AgentMessage,
    conn: &mut Connection,
    stream: &mut TcpStream,
    shared: &SharedState,
    agent_pid: &mut Option<u32>,
    shutdown_received: &mut bool,
    counted: &mut bool,
) -> Result<()> {
    match msg {
        AgentMessage::Configure(req) => {
            debug!(
                "Agent PID {} requesting configuration (nodejs_version: {:?})",
                req.pid, req.nodejs_version
            );

            *agent_pid = Some(req.pid);

            let already_counted = shared
                .reconnected_pids
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&req.pid);
            if !already_counted {
                shared.active_agents.fetch_add(1, Ordering::SeqCst);
                *counted = true;
            }

            let resp = CliMessage::ConfigureResponse(ConfigureResponse {
                hooks: shared.hook_configs.clone(),
                review_mode: shared.review_mode,
            });
            let json = serde_json::to_string(&resp)?;
            conn.send_message(Message::Text(json), None)
                .map_err(|e| anyhow::anyhow!("WS send failed: {}", e))?;
            flush_outbox(conn, stream)?;
        }
        AgentMessage::Ready(req) => {
            debug!(
                "Agent PID {} ready with {} hooks",
                req.pid,
                req.hooks_installed.len()
            );

            let _ = shared.event_tx.send(AgentEvent::Ready {
                pid: req.pid,
                hooks: req.hooks_installed,
                nodejs_version: req.nodejs_version,
                python_version: req.python_version,
                bash_version: req.bash_version,
                modules: req.modules,
            });
        }
        AgentMessage::Runtime(req) => {
            debug!(
                "Agent PID {} runtime info: {}={}",
                req.pid, req.runtime, req.version
            );

            let _ = shared.event_tx.send(AgentEvent::RuntimeInfo {
                runtime: req.runtime,
                version: req.version,
            });
        }
        AgentMessage::Event(event) => {
            let _ = shared.event_tx.send(AgentEvent::Trace(event));
        }
        AgentMessage::Events(events) => {
            for event in events {
                let _ = shared.event_tx.send(AgentEvent::Trace(event));
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
            {
                let mut seen = shared.seen_events.lock().unwrap_or_else(|e| e.into_inner());
                if !seen.insert((info.child_pid, cmd_name.clone())) {
                    return Ok(());
                }
            }

            let event = child_info_to_trace_event(info, cmd_name);
            let _ = shared.event_tx.send(AgentEvent::Trace(event));
        }
        AgentMessage::Reconnect(req) => {
            debug!(
                "Child PID {} reconnected (parent {})",
                req.child_pid, req.parent_pid
            );

            *agent_pid = Some(req.child_pid);

            shared.active_agents.fetch_add(1, Ordering::SeqCst);
            *counted = true;
            shared
                .reconnected_pids
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(req.child_pid);

            // Send Ready event for the child (it inherits hooks from parent)
            let _ = shared.event_tx.send(AgentEvent::Ready {
                pid: req.child_pid,
                hooks: vec![],
                nodejs_version: None,
                python_version: None,
                bash_version: None,
                modules: vec![],
            });
        }
        AgentMessage::Review { request_id, event } => {
            // Create oneshot channel, send to main loop, block for response
            let (response_tx, response_rx) = std::sync::mpsc::channel::<ReviewDecision>();
            let _ = shared
                .event_tx
                .send(AgentEvent::ReviewRequest { event, response_tx });

            // Block until main thread decides
            let decision = response_rx.recv().unwrap_or(ReviewDecision::Allow);

            let resp = CliMessage::ReviewResponse {
                request_id,
                decision,
            };
            let json = serde_json::to_string(&resp)?;
            conn.send_message(Message::Text(json), None)
                .map_err(|e| anyhow::anyhow!("WS send failed: {}", e))?;
            flush_outbox(conn, stream)?;
        }
        AgentMessage::Shutdown(req) => {
            debug!("Agent PID {} shutting down", req.pid);
            *shutdown_received = true;

            if let Ok(mut seen) = shared.seen_events.lock() {
                seen.retain(|(pid, _)| *pid != req.pid);
            }
            if let Ok(mut pids) = shared.reconnected_pids.lock() {
                pids.remove(&req.pid);
            }

            // Only send Disconnected if this connection incremented active_agents.
            // Without this, a forked child that exec's (Reconnect +1, WS close -1)
            // followed by the exec'd process (Configure already_counted, Shutdown -1)
            // would undercount and cause premature CLI exit.
            if *counted {
                let _ = shared
                    .event_tx
                    .send(AgentEvent::Disconnected { pid: req.pid });
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
        hook_type: HookType::Exec,
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
