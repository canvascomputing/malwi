//! Binary wire client for agent-to-CLI communication.
//!
//! Uses length-prefixed TCP with `BinaryCodec` from `malwi-protocol`.
//! Maintains a persistent TCP connection with automatic reconnection.
//! Communication is unidirectional: agent → CLI only (fire-and-forget).

use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

use crate::tracing::ForkSafeMutex;

use anyhow::Result;
use log::debug;

use crate::wire::{write_frame, BinaryCodec, Codec};
use crate::{
    protocol::ModuleInfo, AgentMessage, HostChildInfo, ReadyRequest, RuntimeInfoRequest,
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

    /// Notify CLI that hooks are installed and agent is ready.
    pub fn ready(
        &self,
        pid: u32,
        hooks_installed: Vec<String>,
        nodejs_version: Option<u32>,
        python_version: Option<String>,
        bash_version: Option<String>,
        modules: Vec<ModuleInfo>,
    ) -> Result<()> {
        // Ensure connection with retry (server may not be ready yet)
        self.connect_with_retry(INIT_MAX_RETRIES)?;

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

    /// Send a batch of display events (with pre-computed disposition).
    pub fn send_display_events(&self, events: Vec<crate::message::DisplayEvent>) -> Result<()> {
        self.send(&AgentMessage::DisplayEvents(events))
    }

    /// Send a child process notification.
    pub fn send_child(&self, info: &HostChildInfo) -> Result<()> {
        self.send(&AgentMessage::Child(info.clone()))
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
}
