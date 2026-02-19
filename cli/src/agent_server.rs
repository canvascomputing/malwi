//! HTTP server for agent communication.
//!
//! Receives agent requests via an HTTP server using `tiny_http`.
//! Each agent endpoint maps to a specific URL path.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::Result;
use log::debug;
use tiny_http::{Response, Server};

use malwi_protocol::{
    Argument, ChildOperation, ChildReconnectRequest, CommandResponse, ConfigureRequest,
    ConfigureResponse, EventType, HookConfig, HookType, HostChildInfo, ReadyRequest,
    ReviewDecision, ReviewRequest, ReviewResponse, RuntimeInfoRequest, ShutdownRequest, TraceEvent,
};

/// Events sent from the HTTP server to the main event loop.
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
    /// Review mode decision request (agent blocks on HTTP response)
    ReviewRequest {
        event: TraceEvent,
        response_tx: Sender<ReviewDecision>,
    },
}

/// Shared state for the HTTP server threads.
struct SharedState {
    hook_configs: Vec<HookConfig>,
    review_mode: bool,
    event_tx: SyncSender<AgentEvent>,
    active_agents: Arc<AtomicU32>,
    shutdown_command: AtomicBool,
    /// Suppresses duplicate exec events caused by libc PATH iteration.
    /// Key: (child_pid, command_basename).
    seen_events: Mutex<HashSet<(u32, String)>>,
    /// PIDs that connected via /child/reconnect. Used to avoid double-counting
    /// active_agents when a reconnected child does exec (which triggers a second
    /// /configure for the same PID from the fresh agent).
    reconnected_pids: Mutex<HashSet<u32>>,
}

/// HTTP server for agent communication.
pub struct AgentServer {
    server: Server,
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
        // Create socket with SO_REUSEADDR to avoid port reuse collisions
        // during high-parallelism test runs where TIME_WAIT sockets accumulate.
        let listener = create_reuse_addr_listener()?;

        let server = Server::from_listener(listener, None)
            .map_err(|e| anyhow::anyhow!("Failed to create HTTP server: {}", e))?;

        let port = server
            .server_addr()
            .to_ip()
            .map(|a| a.port())
            .ok_or_else(|| anyhow::anyhow!("Failed to get server port"))?;

        let url = format!("http://127.0.0.1:{}", port);

        let shared = Arc::new(SharedState {
            hook_configs,
            review_mode,
            event_tx,
            active_agents,
            shutdown_command: AtomicBool::new(false),
            seen_events: Mutex::new(HashSet::new()),
            reconnected_pids: Mutex::new(HashSet::new()),
        });

        Ok(Self {
            server,
            url,
            shared,
        })
    }

    /// Get the server URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Run the HTTP server, processing requests until shutdown.
    ///
    /// Requests are handled inline on the listener thread for speed.
    /// Only `/review` is spawned on a separate thread because it blocks
    /// waiting for user input.
    pub fn run(self) {
        for request in self.server.incoming_requests() {
            if self.shared.shutdown_command.load(Ordering::SeqCst) {
                let _ =
                    request.respond(Response::from_string("shutting down").with_status_code(503));
                break;
            }

            if request.url() == "/review" && request.method().as_str() == "POST" {
                let shared = self.shared.clone();
                thread::spawn(move || {
                    handle_request(request, &shared);
                });
            } else {
                handle_request(request, &self.shared);
            }

            // Check after handling — shutdown handler sets the flag,
            // and we need to exit before blocking on the next accept().
            if self.shared.shutdown_command.load(Ordering::SeqCst) {
                break;
            }
        }
    }
}

fn handle_request(request: tiny_http::Request, shared: &SharedState) {
    let url = request.url().to_string();
    let method = request.method().to_string();

    match (method.as_str(), url.as_str()) {
        ("POST", "/configure") => handle_configure(request, shared),
        ("POST", "/ready") => handle_ready(request, shared),
        ("POST", "/runtime") => handle_runtime_info(request, shared),
        ("POST", "/event") => handle_event(request, shared),
        ("POST", "/events") => handle_events(request, shared),
        ("POST", "/child") => handle_child(request, shared),
        ("POST", "/child/reconnect") => handle_child_reconnect(request, shared),
        ("POST", "/review") => handle_review(request, shared),
        ("POST", "/shutdown") => handle_shutdown(request, shared),
        ("GET", "/command") => handle_command(request, shared),
        _ => {
            let _ = request.respond(Response::from_string("Not Found").with_status_code(404));
        }
    }
}

fn read_json<T: for<'de> serde::Deserialize<'de>>(request: &mut tiny_http::Request) -> Result<T> {
    let mut body = String::new();
    request.as_reader().read_to_string(&mut body)?;
    Ok(serde_json::from_str(&body)?)
}

fn respond_json<T: serde::Serialize>(request: tiny_http::Request, data: &T) {
    match serde_json::to_string(data) {
        Ok(json) => {
            let response = Response::from_string(json).with_header(
                "Content-Type: application/json"
                    .parse::<tiny_http::Header>()
                    .unwrap(),
            );
            let _ = request.respond(response);
        }
        Err(e) => {
            log::error!("Failed to serialize response: {}", e);
            let _ = request
                .respond(Response::from_string("Internal Server Error").with_status_code(500));
        }
    }
}

fn respond_ok(request: tiny_http::Request) {
    let _ = request.respond(Response::from_string("OK"));
}

fn respond_error(request: tiny_http::Request, msg: &str) {
    let _ = request.respond(Response::from_string(msg).with_status_code(400));
}

fn handle_configure(mut request: tiny_http::Request, shared: &SharedState) {
    let req: ConfigureRequest = match read_json(&mut request) {
        Ok(r) => r,
        Err(e) => {
            respond_error(request, &format!("Invalid request: {}", e));
            return;
        }
    };

    debug!(
        "Agent PID {} requesting configuration (nodejs_version: {:?})",
        req.pid, req.nodejs_version
    );

    // If this PID already has an active_agents increment from /child/reconnect,
    // skip the second increment. This handles fork+exec where the forked child
    // reconnects (incrementing once), then exec replaces the process image and
    // the fresh agent sends /configure (which would otherwise increment again).
    let already_counted = shared
        .reconnected_pids
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&req.pid);
    if !already_counted {
        shared.active_agents.fetch_add(1, Ordering::SeqCst);
    }

    let resp = ConfigureResponse {
        hooks: shared.hook_configs.clone(),
        review_mode: shared.review_mode,
    };

    respond_json(request, &resp);
}

fn handle_ready(mut request: tiny_http::Request, shared: &SharedState) {
    let req: ReadyRequest = match read_json(&mut request) {
        Ok(r) => r,
        Err(e) => {
            respond_error(request, &format!("Invalid request: {}", e));
            return;
        }
    };

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

    respond_ok(request);
}

fn handle_runtime_info(mut request: tiny_http::Request, shared: &SharedState) {
    let req: RuntimeInfoRequest = match read_json(&mut request) {
        Ok(r) => r,
        Err(e) => {
            respond_error(request, &format!("Invalid request: {}", e));
            return;
        }
    };

    debug!(
        "Agent PID {} runtime info: {}={}",
        req.pid, req.runtime, req.version
    );

    let _ = shared.event_tx.send(AgentEvent::RuntimeInfo {
        runtime: req.runtime,
        version: req.version,
    });

    respond_ok(request);
}

fn handle_event(mut request: tiny_http::Request, shared: &SharedState) {
    let event: TraceEvent = match read_json(&mut request) {
        Ok(e) => e,
        Err(e) => {
            respond_error(request, &format!("Invalid event: {}", e));
            return;
        }
    };

    let _ = shared.event_tx.send(AgentEvent::Trace(event));
    respond_ok(request);
}

fn handle_events(mut request: tiny_http::Request, shared: &SharedState) {
    let events: Vec<TraceEvent> = match read_json(&mut request) {
        Ok(e) => e,
        Err(e) => {
            respond_error(request, &format!("Invalid events: {}", e));
            return;
        }
    };

    for event in events {
        let _ = shared.event_tx.send(AgentEvent::Trace(event));
    }
    respond_ok(request);
}

fn handle_child(mut request: tiny_http::Request, shared: &SharedState) {
    let info: HostChildInfo = match read_json(&mut request) {
        Ok(i) => i,
        Err(e) => {
            respond_error(request, &format!("Invalid child info: {}", e));
            return;
        }
    };

    // Bare fork events (no path, no argv) are process duplication, not command
    // execution.  The actual command arrives in a subsequent Exec event.
    if info.operation == ChildOperation::Fork && info.argv.is_none() && info.path.is_none() {
        respond_ok(request);
        return;
    }

    // Suppress duplicates from libc PATH iteration (one logical command
    // triggers multiple execve attempts with the same child PID).
    let cmd_name = extract_cmd_name(&info);
    {
        let mut seen = shared.seen_events.lock().unwrap_or_else(|e| e.into_inner());
        if !seen.insert((info.child_pid, cmd_name.clone())) {
            respond_ok(request);
            return;
        }
    }

    let event = child_info_to_trace_event(info, cmd_name);
    let _ = shared.event_tx.send(AgentEvent::Trace(event));
    respond_ok(request);
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

/// Convert a HostChildInfo into a TraceEvent at the HTTP boundary.
///
/// The function name is set to basename(argv[0]) and arguments are the raw argv.
/// Shell unwrapping (e.g., `sh -c "curl ..."` → `curl`) is handled separately
/// in policy evaluation so that display and manual filters see the raw command.
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
        runtime_stack: None,
        network_info: None,
        source_file: info.source_file,
        source_line: info.source_line,
    }
}

/// Extract the basename from a path.
fn basename(path: &str) -> &str {
    std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
}

fn handle_child_reconnect(mut request: tiny_http::Request, shared: &SharedState) {
    let req: ChildReconnectRequest = match read_json(&mut request) {
        Ok(r) => r,
        Err(e) => {
            respond_error(request, &format!("Invalid request: {}", e));
            return;
        }
    };

    debug!(
        "Child PID {} reconnected (parent {})",
        req.child_pid, req.parent_pid
    );

    shared.active_agents.fetch_add(1, Ordering::SeqCst);
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

    respond_ok(request);
}

fn handle_review(mut request: tiny_http::Request, shared: &SharedState) {
    let req: ReviewRequest = match read_json(&mut request) {
        Ok(r) => r,
        Err(e) => {
            respond_error(request, &format!("Invalid review request: {}", e));
            return;
        }
    };

    // Create channel for main thread to send back the decision
    let (response_tx, response_rx) = std::sync::mpsc::channel::<ReviewDecision>();

    // Send to main thread for policy evaluation / user prompt
    let _ = shared.event_tx.send(AgentEvent::ReviewRequest {
        event: req.event,
        response_tx,
    });

    // Block until main thread decides
    let decision = response_rx.recv().unwrap_or(ReviewDecision::Allow);

    respond_json(request, &ReviewResponse { decision });
}

fn handle_shutdown(mut request: tiny_http::Request, shared: &SharedState) {
    let req: ShutdownRequest = match read_json(&mut request) {
        Ok(r) => r,
        Err(e) => {
            respond_error(request, &format!("Invalid request: {}", e));
            return;
        }
    };

    debug!("Agent PID {} shutting down", req.pid);

    if let Ok(mut seen) = shared.seen_events.lock() {
        seen.retain(|(pid, _)| *pid != req.pid);
    }
    if let Ok(mut pids) = shared.reconnected_pids.lock() {
        pids.remove(&req.pid);
    }

    // NOTE: active_agents is decremented in the main event loop when
    // Disconnected is processed, not here. This guarantees all preceding
    // events in the channel have been handled before the count drops.
    let _ = shared
        .event_tx
        .send(AgentEvent::Disconnected { pid: req.pid });

    respond_ok(request);
}

fn handle_command(request: tiny_http::Request, shared: &SharedState) {
    let command = if shared.shutdown_command.load(Ordering::SeqCst) {
        Some("shutdown".to_string())
    } else {
        None
    };

    respond_json(request, &CommandResponse { command });
}
