//! WebSocket client for agent-to-CLI communication.
//!
//! Uses `malwi-websocket` over raw `TcpStream` for localhost transport.
//! Maintains a persistent WebSocket connection with automatic reconnection.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Result;
use log::debug;

use malwi_protocol::{
    protocol::ModuleInfo, AgentMessage, ChildReconnectRequest, CliMessage, ConfigureRequest,
    ConfigureResponse, HostChildInfo, ReadyRequest, ReviewDecision, RuntimeInfoRequest,
    ShutdownRequest, TraceEvent,
};
use malwi_websocket::{
    build_client_handshake_request, parse_server_handshake_response_with_len,
    ClientHandshakeRequest, Connection, ConnectionConfig, Event, HandshakeParseConfig, Message,
    PeerRole,
};

/// Maximum number of retries for initial connection.
const INIT_MAX_RETRIES: u32 = 5;

/// Internal WebSocket connection state.
struct WsConnection {
    stream: TcpStream,
    ws: Connection,
}

/// WebSocket client for communicating with the CLI server.
///
/// Maintains a persistent WebSocket connection. The connection is
/// wrapped in a Mutex to allow shared access from multiple threads.
pub struct HttpClient {
    addr: String,
    conn: Mutex<Option<WsConnection>>,
    next_review_id: AtomicU32,
}

/// Generate a WebSocket key from system time and PID.
/// Must be valid base64-encoded 16 bytes per RFC 6455.
fn generate_ws_key() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id() as u128;
    // Build 16 bytes from nanos + pid
    let bytes: [u8; 16] = {
        let mut b = [0u8; 16];
        let n = nanos.to_le_bytes();
        let p = pid.to_le_bytes();
        b[..8].copy_from_slice(&n[..8]);
        b[8..12].copy_from_slice(&p[..4]);
        // Mix in some variation
        let t2 = (nanos >> 64).to_le_bytes();
        b[12..16].copy_from_slice(&t2[..4]);
        b
    };
    base64_encode(&bytes)
}

/// Simple base64 encoding for 16 bytes (no external dependency needed).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(ALPHABET[(n >> 18) as usize & 0x3F] as char);
        result.push(ALPHABET[(n >> 12) as usize & 0x3F] as char);
        if chunk.len() > 1 {
            result.push(ALPHABET[(n >> 6) as usize & 0x3F] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[n as usize & 0x3F] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Generate a simple mask key from a counter.
fn mask_key_from_counter(counter: u32) -> [u8; 4] {
    counter.to_le_bytes()
}

impl HttpClient {
    /// Create a new client pointing at the CLI server.
    pub fn new(url: &str) -> Self {
        // Extract host:port from URL like "http://127.0.0.1:12345"
        let addr = url.strip_prefix("http://").unwrap_or(url).to_string();

        HttpClient {
            addr,
            conn: Mutex::new(None),
            next_review_id: AtomicU32::new(1),
        }
    }

    /// Establish a WebSocket connection with retry.
    fn connect_with_retry(&self, max_retries: u32) -> Result<()> {
        let mut last_err = None;
        for attempt in 0..=max_retries {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(50 * (1 << attempt.min(4))));
            }
            match self.try_connect() {
                Ok(ws_conn) => {
                    *self.conn.lock().unwrap_or_else(|e| e.into_inner()) = Some(ws_conn);
                    return Ok(());
                }
                Err(e) => {
                    debug!("Connect attempt {}/{}: {}", attempt + 1, max_retries + 1, e);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap())
    }

    /// Single connection attempt: TCP connect → WS handshake.
    fn try_connect(&self) -> Result<WsConnection> {
        let mut stream = TcpStream::connect_timeout(&self.addr.parse()?, Duration::from_secs(10))?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        // Build and send WebSocket upgrade request
        let key = generate_ws_key();
        let handshake_req = ClientHandshakeRequest {
            host: self.addr.clone(),
            path: "/".to_string(),
            key: key.clone(),
            origin: None,
            protocols: vec![],
            extensions: vec![],
        };
        let request_bytes = build_client_handshake_request(&handshake_req)
            .map_err(|e| anyhow::anyhow!("WS handshake build failed: {}", e))?;
        stream.write_all(&request_bytes)?;

        // Read upgrade response
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf)?;
        if n == 0 {
            anyhow::bail!("Server closed connection during handshake");
        }
        let (response, _) =
            parse_server_handshake_response_with_len(&buf[..n], HandshakeParseConfig::default())
                .map_err(|e| anyhow::anyhow!("WS handshake parse failed: {}", e))?;
        response
            .validate_server_response(&key)
            .map_err(|e| anyhow::anyhow!("WS handshake validation failed: {}", e))?;

        let ws = Connection::new(ConnectionConfig {
            role: PeerRole::Client,
            ..ConnectionConfig::default()
        });

        Ok(WsConnection { stream, ws })
    }

    /// Ensure a connection exists, connecting if needed.
    fn ensure_connected(&self) -> Result<()> {
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            return Ok(());
        }
        drop(guard);
        self.connect_with_retry(INIT_MAX_RETRIES)
    }

    /// Send a fire-and-forget message.
    fn send(&self, msg: &AgentMessage) -> Result<()> {
        let _guard = crate::native::HookSuppressGuard::new();
        self.ensure_connected()?;

        let mut lock = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let ws_conn = lock
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("not connected"))?;

        let json = serde_json::to_string(msg)?;
        let mask = mask_key_from_counter(self.next_review_id.fetch_add(1, Ordering::Relaxed));
        ws_conn
            .ws
            .send_message(Message::Text(json), Some(mask))
            .map_err(|e| anyhow::anyhow!("WS send failed: {}", e))?;

        // Flush outbox
        while let Some(bytes) = ws_conn.ws.poll_outbound() {
            ws_conn.stream.write_all(&bytes)?;
        }
        Ok(())
    }

    /// Send a message and wait for a response.
    fn send_and_recv(&self, msg: &AgentMessage) -> Result<CliMessage> {
        let _guard = crate::native::HookSuppressGuard::new();
        self.ensure_connected()?;

        let mut lock = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let ws_conn = lock
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("not connected"))?;

        // Send
        let json = serde_json::to_string(msg)?;
        let mask = mask_key_from_counter(self.next_review_id.fetch_add(1, Ordering::Relaxed));
        ws_conn
            .ws
            .send_message(Message::Text(json), Some(mask))
            .map_err(|e| anyhow::anyhow!("WS send failed: {}", e))?;
        while let Some(bytes) = ws_conn.ws.poll_outbound() {
            ws_conn.stream.write_all(&bytes)?;
        }

        // Read until we get a text message response
        let mut buf = vec![0u8; 8192];
        loop {
            let n = ws_conn.stream.read(&mut buf)?;
            if n == 0 {
                anyhow::bail!("connection closed while waiting for response");
            }
            let events = ws_conn
                .ws
                .ingest(&buf[..n], None)
                .map_err(|e| anyhow::anyhow!("WS ingest failed: {}", e))?;

            // Flush any auto-generated frames (pongs)
            while let Some(bytes) = ws_conn.ws.poll_outbound() {
                ws_conn.stream.write_all(&bytes)?;
            }

            for event in events {
                if let Event::Message(Message::Text(text)) = event {
                    return Ok(serde_json::from_str(&text)?);
                }
            }
        }
    }

    /// Request configuration from the CLI.
    /// Retries with backoff to handle race between agent init and CLI server start.
    pub fn configure(&self, pid: u32, nodejs_version: Option<u32>) -> Result<ConfigureResponse> {
        // Ensure connection with retry (server may not be ready yet)
        self.connect_with_retry(INIT_MAX_RETRIES)?;

        let msg = AgentMessage::Configure(ConfigureRequest {
            pid,
            nodejs_version,
        });
        match self.send_and_recv(&msg)? {
            CliMessage::ConfigureResponse(resp) => Ok(resp),
            other => anyhow::bail!("unexpected response to configure: {:?}", other),
        }
    }

    /// Notify CLI that hooks are installed.
    pub fn ready(
        &self,
        pid: u32,
        hooks_installed: Vec<String>,
        nodejs_version: Option<u32>,
        python_version: Option<String>,
        bash_version: Option<String>,
        modules: Vec<ModuleInfo>,
    ) -> Result<()> {
        let msg = AgentMessage::Ready(ReadyRequest {
            pid,
            hooks_installed,
            nodejs_version,
            python_version,
            bash_version,
            modules,
        });
        self.send(&msg)
    }

    /// Send a trace event.
    pub fn send_event(&self, event: &TraceEvent) -> Result<()> {
        self.send(&AgentMessage::Event(event.clone()))
    }

    /// Send a batch of trace events.
    pub fn send_events(&self, events: &[TraceEvent]) -> Result<()> {
        self.send(&AgentMessage::Events(events.to_vec()))
    }

    /// Send a child process notification.
    pub fn send_child(&self, info: &HostChildInfo) -> Result<()> {
        self.send(&AgentMessage::Child(info.clone()))
    }

    /// Request a review decision. Blocks until the CLI user decides.
    pub fn review(&self, event: &TraceEvent) -> Result<ReviewDecision> {
        let request_id = self.next_review_id.fetch_add(1, Ordering::Relaxed);
        let msg = AgentMessage::Review {
            request_id,
            event: event.clone(),
        };
        match self.send_and_recv(&msg)? {
            CliMessage::ReviewResponse { decision, .. } => Ok(decision),
            other => anyhow::bail!("unexpected response to review: {:?}", other),
        }
    }

    /// Check if the WebSocket connection is still alive.
    /// Returns true if connected, false if connection is dead or absent.
    pub fn is_connected(&self) -> bool {
        let mut lock = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ws_conn) = lock.as_mut() {
            // Try a non-blocking peek to detect closed connection
            let _ = ws_conn.stream.set_nonblocking(true);
            let mut peek_buf = [0u8; 1];
            let alive = match ws_conn.stream.peek(&mut peek_buf) {
                Ok(0) => false,                                                   // EOF = closed
                Ok(_) => true,                                                    // Data available
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => true, // No data but alive
                Err(_) => false,                                                  // Error = dead
            };
            let _ = ws_conn.stream.set_nonblocking(false);
            alive
        } else {
            false
        }
    }

    /// Send a late runtime info notification.
    pub fn send_runtime_info(&self, pid: u32, runtime: &str, version: &str) -> Result<()> {
        self.send(&AgentMessage::Runtime(RuntimeInfoRequest {
            pid,
            runtime: runtime.to_string(),
            version: version.to_string(),
        }))
    }

    /// Notify CLI of agent shutdown.
    pub fn shutdown(&self, pid: u32) -> Result<()> {
        self.send(&AgentMessage::Shutdown(ShutdownRequest { pid }))
    }

    /// Notify CLI of child reconnection after fork.
    /// Drops the inherited connection and creates a fresh one.
    pub fn child_reconnect(&self, parent_pid: u32, child_pid: u32) -> Result<()> {
        // Drop inherited connection from parent (avoid shared socket state)
        *self.conn.lock().unwrap_or_else(|e| e.into_inner()) = None;
        // Establish fresh WS connection
        self.connect_with_retry(INIT_MAX_RETRIES)?;
        // Send reconnect message
        self.send(&AgentMessage::Reconnect(ChildReconnectRequest {
            parent_pid,
            child_pid,
        }))
    }
}
