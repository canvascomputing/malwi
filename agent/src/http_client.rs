//! HTTP client for agent-to-CLI communication.
//!
//! Uses raw `TcpStream` for localhost HTTP to minimize dependencies.
//! Each operation is a single independent HTTP request — no shared stream,
//! no mutexes, no reconnection ceremony after fork.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Result;
use log::debug;

use malwi_protocol::{
    ChildReconnectRequest, CommandResponse, ConfigureRequest, ConfigureResponse, HostChildInfo,
    ReadyRequest, ReviewDecision, ReviewRequest, ReviewResponse, RuntimeInfoRequest,
    ShutdownRequest, TraceEvent, protocol::ModuleInfo,
};

/// HTTP client for communicating with the CLI server.
///
/// Uses raw `TcpStream` with HTTP/1.1 keep-alive for connection pooling.
/// Endpoint URLs are precomputed to avoid per-request formatting.
/// Falls back to reconnection on any I/O error.
pub struct HttpClient {
    addr: String,
    conn: Mutex<Option<TcpStream>>,
    path_configure: String,
    path_ready: String,
    path_event: String,
    path_events: String,
    path_child: String,
    path_child_reconnect: String,
    path_review: String,
    path_command: String,
    path_runtime: String,
    path_shutdown: String,
}

/// Maximum number of retries for initial connection endpoints (/configure, /ready).
const INIT_MAX_RETRIES: u32 = 5;

/// Read a complete HTTP response from a stream.
/// Returns (status_code, body).
fn read_http_response(stream: &mut TcpStream) -> Result<(u16, String)> {
    // Read headers byte-by-byte until we find \r\n\r\n
    let mut header_buf = Vec::with_capacity(512);
    let mut prev = [0u8; 4];
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte)?;
        header_buf.push(byte[0]);
        prev[0] = prev[1];
        prev[1] = prev[2];
        prev[2] = prev[3];
        prev[3] = byte[0];
        if prev == [b'\r', b'\n', b'\r', b'\n'] {
            break;
        }
        if header_buf.len() > 8192 {
            anyhow::bail!("HTTP response headers too large");
        }
    }

    let header_str = String::from_utf8_lossy(&header_buf);

    // Parse status code from first line
    let status_line = header_str.lines().next().unwrap_or("");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Find Content-Length
    let content_length: usize = header_str
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|line| line.split(':').nth(1))
        .and_then(|val| val.trim().parse().ok())
        .unwrap_or(0);

    // Check for chunked transfer encoding
    let is_chunked = header_str
        .lines()
        .any(|line| {
            line.to_ascii_lowercase().starts_with("transfer-encoding:")
                && line.to_ascii_lowercase().contains("chunked")
        });

    // Read body
    let body = if is_chunked {
        read_chunked_body(stream)?
    } else if content_length > 0 {
        let mut body_buf = vec![0u8; content_length];
        stream.read_exact(&mut body_buf)?;
        String::from_utf8_lossy(&body_buf).to_string()
    } else {
        String::new()
    };

    Ok((status_code, body))
}

/// Read a chunked transfer-encoding body.
fn read_chunked_body(stream: &mut TcpStream) -> Result<String> {
    let mut body = Vec::new();
    loop {
        // Read chunk size line
        let mut size_line = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte)?;
            if byte[0] == b'\n' && size_line.last() == Some(&b'\r') {
                size_line.pop(); // remove \r
                break;
            }
            size_line.push(byte[0]);
        }
        let size_str = String::from_utf8_lossy(&size_line);
        let chunk_size = usize::from_str_radix(size_str.trim(), 16).unwrap_or(0);
        if chunk_size == 0 {
            // Read trailing \r\n
            let mut trailer = [0u8; 2];
            let _ = stream.read_exact(&mut trailer);
            break;
        }
        let mut chunk = vec![0u8; chunk_size];
        stream.read_exact(&mut chunk)?;
        body.extend_from_slice(&chunk);
        // Read trailing \r\n after chunk data
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf)?;
    }
    Ok(String::from_utf8_lossy(&body).to_string())
}

impl HttpClient {
    /// Create a new HTTP client pointing at the CLI server.
    pub fn new(url: &str) -> Self {
        // Extract host:port from URL like "http://127.0.0.1:12345"
        let addr = url
            .strip_prefix("http://")
            .unwrap_or(url)
            .to_string();

        HttpClient {
            addr: addr.clone(),
            conn: Mutex::new(None),
            path_configure: "/configure".to_string(),
            path_ready: "/ready".to_string(),
            path_event: "/event".to_string(),
            path_events: "/events".to_string(),
            path_child: "/child".to_string(),
            path_child_reconnect: "/child/reconnect".to_string(),
            path_review: "/review".to_string(),
            path_command: "/command".to_string(),
            path_runtime: "/runtime".to_string(),
            path_shutdown: "/shutdown".to_string(),
        }
    }

    /// Get or create a TCP connection with keep-alive.
    fn get_conn(&self, timeout: Duration) -> Result<TcpStream> {
        // Try to reuse existing connection
        if let Some(stream) = self.conn.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
            return Ok(stream);
        }

        // Create new connection
        let stream = TcpStream::connect_timeout(
            &self.addr.parse()?,
            timeout,
        )?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    /// Return a connection to the pool for reuse.
    fn return_conn(&self, stream: TcpStream) {
        *self.conn.lock().unwrap_or_else(|e| e.into_inner()) = Some(stream);
    }

    /// Send an HTTP POST request and return the response body.
    fn post(&self, path: &str, body: &str, timeout: Duration) -> Result<String> {
        // Try with existing connection first, then retry with new connection
        for attempt in 0..2 {
            let mut stream = match self.get_conn(timeout) {
                Ok(s) => s,
                Err(e) if attempt == 0 => {
                    // Connection pool had a stale connection, retry
                    debug!("Stale connection, reconnecting: {}", e);
                    continue;
                }
                Err(e) => return Err(e),
            };

            let request = format!(
                "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                path, self.addr, body.len(), body
            );

            if let Err(e) = stream.write_all(request.as_bytes()) {
                if attempt == 0 {
                    debug!("Write failed, reconnecting: {}", e);
                    continue;
                }
                return Err(e.into());
            }

            match read_http_response(&mut stream) {
                Ok((status, resp_body)) => {
                    if (200..300).contains(&status) {
                        self.return_conn(stream);
                        return Ok(resp_body);
                    }
                    self.return_conn(stream);
                    anyhow::bail!("HTTP {} from POST {}: {}", status, path, resp_body);
                }
                Err(e) if attempt == 0 => {
                    debug!("Read failed, reconnecting: {}", e);
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        anyhow::bail!("Failed to POST {} after retries", path)
    }

    /// Send an HTTP GET request and return the response body.
    fn get(&self, path: &str, timeout: Duration) -> Result<String> {
        for attempt in 0..2 {
            let mut stream = match self.get_conn(timeout) {
                Ok(s) => s,
                Err(e) if attempt == 0 => {
                    debug!("Stale connection, reconnecting: {}", e);
                    continue;
                }
                Err(e) => return Err(e),
            };

            let request = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                path, self.addr
            );

            if let Err(e) = stream.write_all(request.as_bytes()) {
                if attempt == 0 {
                    debug!("Write failed, reconnecting: {}", e);
                    continue;
                }
                return Err(e.into());
            }

            match read_http_response(&mut stream) {
                Ok((status, resp_body)) => {
                    if (200..300).contains(&status) {
                        self.return_conn(stream);
                        return Ok(resp_body);
                    }
                    self.return_conn(stream);
                    anyhow::bail!("HTTP {} from GET {}: {}", status, path, resp_body);
                }
                Err(e) if attempt == 0 => {
                    debug!("Read failed, reconnecting: {}", e);
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        anyhow::bail!("Failed to GET {} after retries", path)
    }

    /// POST with retry and exponential backoff. Used for initial connection
    /// endpoints where the CLI server may not be listening yet.
    fn post_with_retry(&self, path: &str, body: &str, max_retries: u32) -> Result<String> {
        let mut last_err = None;
        for attempt in 0..=max_retries {
            if attempt > 0 {
                // Backoff: 50ms, 100ms, 200ms, 400ms, 800ms (capped)
                std::thread::sleep(Duration::from_millis(50 * (1 << attempt.min(4))));
            }
            match self.post(path, body, Duration::from_secs(10)) {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    debug!("POST {} attempt {}/{} failed: {}", path, attempt + 1, max_retries + 1, e);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap())
    }

    /// Request configuration from the CLI (POST /configure).
    /// Retries with backoff to handle race between agent init and CLI server start.
    pub fn configure(
        &self,
        pid: u32,
        nodejs_version: Option<u32>,
    ) -> Result<ConfigureResponse> {
        let req = ConfigureRequest {
            pid,
            nodejs_version,
        };
        let json = serde_json::to_string(&req)?;
        let body = self.post_with_retry(&self.path_configure, &json, INIT_MAX_RETRIES)?;
        Ok(serde_json::from_str(&body)?)
    }

    /// Notify CLI that hooks are installed (POST /ready).
    /// Retries with backoff to handle race between agent init and CLI server start.
    pub fn ready(
        &self,
        pid: u32,
        hooks_installed: Vec<String>,
        nodejs_version: Option<u32>,
        python_version: Option<String>,
        bash_version: Option<String>,
        modules: Vec<ModuleInfo>,
    ) -> Result<()> {
        let req = ReadyRequest {
            pid,
            hooks_installed,
            nodejs_version,
            python_version,
            bash_version,
            modules,
        };
        let json = serde_json::to_string(&req)?;
        self.post_with_retry(&self.path_ready, &json, INIT_MAX_RETRIES)?;
        Ok(())
    }

    /// Send a trace event (POST /event).
    pub fn send_event(&self, event: &TraceEvent) -> Result<()> {
        let json = serde_json::to_string(event)?;
        self.post(&self.path_event, &json, Duration::from_secs(5))?;
        Ok(())
    }

    /// Send a batch of trace events (POST /events).
    pub fn send_events(&self, events: &[TraceEvent]) -> Result<()> {
        let json = serde_json::to_string(events)?;
        self.post(&self.path_events, &json, Duration::from_secs(5))?;
        Ok(())
    }

    /// Send a child process notification (POST /child).
    pub fn send_child(&self, info: &HostChildInfo) -> Result<()> {
        let json = serde_json::to_string(info)?;
        self.post(&self.path_child, &json, Duration::from_secs(5))?;
        Ok(())
    }

    /// Request a review decision (POST /review).
    /// Blocks until the CLI user decides.
    pub fn review(&self, event: &TraceEvent) -> Result<ReviewDecision> {
        let req = ReviewRequest {
            event: event.clone(),
        };
        let json = serde_json::to_string(&req)?;
        let body = self.post(&self.path_review, &json, Duration::from_secs(300))?;
        let resp: ReviewResponse = serde_json::from_str(&body)?;
        Ok(resp.decision)
    }

    /// Poll for pending commands (GET /command).
    pub fn poll_command(&self) -> Result<Option<String>> {
        let body = self.get(&self.path_command, Duration::from_secs(2))?;
        let resp: CommandResponse = serde_json::from_str(&body)?;
        Ok(resp.command)
    }

    /// Send a late runtime info notification (POST /runtime).
    pub fn send_runtime_info(&self, pid: u32, runtime: &str, version: &str) -> Result<()> {
        let req = RuntimeInfoRequest {
            pid,
            runtime: runtime.to_string(),
            version: version.to_string(),
        };
        let json = serde_json::to_string(&req)?;
        self.post(&self.path_runtime, &json, Duration::from_secs(5))?;
        Ok(())
    }

    /// Notify CLI of agent shutdown (POST /shutdown).
    pub fn shutdown(&self, pid: u32) -> Result<()> {
        let req = ShutdownRequest { pid };
        let json = serde_json::to_string(&req)?;
        self.post(&self.path_shutdown, &json, Duration::from_secs(2))?;
        Ok(())
    }

    /// Notify CLI of child reconnection after fork (POST /child/reconnect).
    pub fn child_reconnect(&self, parent_pid: u32, child_pid: u32) -> Result<()> {
        let req = ChildReconnectRequest {
            parent_pid,
            child_pid,
        };
        let json = serde_json::to_string(&req)?;
        debug!(
            "Child reconnect: parent={}, child={}",
            parent_pid, child_pid
        );
        self.post(&self.path_child_reconnect, &json, Duration::from_secs(5))?;
        Ok(())
    }
}
