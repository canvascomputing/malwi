//! Binary wire client for agent-to-CLI communication.
//!
//! Uses length-prefixed TCP with `BinaryCodec` from `malwi-protocol`.
//! Maintains a persistent TCP connection with automatic reconnection.

use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use crate::tracing::ForkSafeMutex;

use anyhow::Result;
use log::debug;

use crate::wire::{read_frame, write_frame, BinaryCodec, Codec};
use crate::{
    protocol::ModuleInfo, AgentMessage, ChildReconnectRequest, CliMessage, ConfigureRequest,
    ConfigureResponse, HostChildInfo, ReadyRequest, ReviewDecision, RuntimeInfoRequest,
    ShutdownRequest, TraceEvent,
};

/// Maximum number of retries for initial connection.
const INIT_MAX_RETRIES: u32 = 5;

/// TCP client for communicating with the CLI server.
///
/// Maintains a persistent TCP connection. The connection is
/// wrapped in a `ForkSafeMutex` to allow shared access from multiple
/// threads and safe operation after `fork()`.
pub struct Client {
    addr: String,
    conn: ForkSafeMutex<Option<TcpStream>>,
    next_review_id: AtomicU32,
    codec: BinaryCodec,
}

impl Client {
    /// Create a new client pointing at the CLI server.
    pub fn new(url: &str) -> Self {
        // Extract host:port from URL like "http://127.0.0.1:12345"
        let addr = url.strip_prefix("http://").unwrap_or(url).to_string();

        Client {
            addr,
            conn: ForkSafeMutex::new(None),
            next_review_id: AtomicU32::new(1),
            codec: BinaryCodec,
        }
    }

    /// Mark this client as running in a forked child process.
    ///
    /// Drops the inherited TCP connection and switches the internal mutex
    /// to non-blocking mode. No proactive reconnect — the next `send()`
    /// will lazily connect via `ensure_connected()`.
    pub fn mark_forked_child(&self) {
        self.conn.mark_forked();
    }

    /// Establish a TCP connection with retry.
    fn connect_with_retry(&self, max_retries: u32) -> Result<()> {
        let mut last_err = None;
        for attempt in 0..=max_retries {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(50 * (1 << attempt.min(4))));
            }
            match self.try_connect() {
                Ok(stream) => {
                    *self.conn.lock()? = Some(stream);
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

    /// Single connection attempt: TCP connect only (no handshake needed).
    fn try_connect(&self) -> Result<TcpStream> {
        let stream = TcpStream::connect_timeout(&self.addr.parse()?, Duration::from_secs(10))?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        Ok(stream)
    }

    /// Ensure a connection exists, connecting if needed.
    fn ensure_connected(&self) -> Result<()> {
        let guard = self.conn.lock()?;
        if guard.is_some() {
            return Ok(());
        }
        drop(guard);
        self.connect_with_retry(INIT_MAX_RETRIES)
    }

    /// Send a fire-and-forget message.
    ///
    /// On write failure the broken connection is dropped so the next call
    /// reconnects via `ensure_connected()` instead of writing to a dead stream.
    fn send(&self, msg: &AgentMessage) -> Result<()> {
        let _guard = crate::native::HookSuppressGuard::new();
        self.ensure_connected()?;

        let mut lock = self.conn.lock()?;
        let stream = lock
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("not connected"))?;

        let mut buf = Vec::new();
        self.codec.encode_agent_msg(msg, &mut buf);
        if let Err(e) = write_frame(stream, &buf).and_then(|()| stream.flush()) {
            *lock = None;
            return Err(e.into());
        }
        Ok(())
    }

    /// Send a message and wait for a response.
    ///
    /// On write/read failure the broken connection is dropped so the next
    /// call reconnects instead of writing to a dead stream.
    fn send_and_recv(&self, msg: &AgentMessage) -> Result<CliMessage> {
        let _guard = crate::native::HookSuppressGuard::new();
        self.ensure_connected()?;

        let mut lock = self.conn.lock()?;
        let stream = lock
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("not connected"))?;

        // Send
        let mut buf = Vec::new();
        self.codec.encode_agent_msg(msg, &mut buf);
        if let Err(e) = write_frame(stream, &buf).and_then(|()| stream.flush()) {
            *lock = None;
            return Err(e.into());
        }

        // Read response
        match read_frame(stream) {
            Ok(payload) => Ok(self.codec.decode_cli_msg(&payload)?),
            Err(e) => {
                *lock = None;
                Err(e.into())
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
    ///
    /// Takes ownership of the batch to avoid cloning on the hot path.
    pub fn send_events(&self, events: Vec<TraceEvent>) -> Result<()> {
        self.send(&AgentMessage::Events(events))
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

    /// Check if the TCP connection is still alive.
    /// Returns true if connected, false if connection is dead or absent.
    pub fn is_connected(&self) -> bool {
        let mut lock = match self.conn.lock() {
            Ok(guard) => guard,
            Err(_) => return false,
        };
        if let Some(stream) = lock.as_mut() {
            // Try a non-blocking peek to detect closed connection
            let _ = stream.set_nonblocking(true);
            let mut peek_buf = [0u8; 1];
            let alive = match stream.peek(&mut peek_buf) {
                Ok(0) => false,                                                   // EOF = closed
                Ok(_) => true,                                                    // Data available
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => true, // No data but alive
                Err(_) => false,                                                  // Error = dead
            };
            let _ = stream.set_nonblocking(false);
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

    /// Notify CLI that a forked child has reconnected.
    pub fn send_reconnect(&self, parent_pid: u32, child_pid: u32) -> Result<()> {
        self.send(&AgentMessage::Reconnect(ChildReconnectRequest {
            parent_pid,
            child_pid,
        }))
    }

    /// Notify CLI of agent shutdown.
    pub fn shutdown(&self, pid: u32) -> Result<()> {
        self.send(&AgentMessage::Shutdown(ShutdownRequest { pid }))
    }
}
