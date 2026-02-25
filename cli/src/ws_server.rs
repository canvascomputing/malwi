//! External WebSocket server for browser/dashboard clients.
//!
//! Accepts WebSocket connections on a user-specified port and broadcasts
//! enriched TraceEvents as JSON text frames. Each connected client receives
//! all post-policy events via a tokio broadcast channel.

use std::sync::Arc;

use log::debug;
use malwi_protocol::TraceEvent;
use malwi_websocket::{
    build_server_handshake_response, parse_client_handshake_with_len, Connection, ConnectionConfig,
    Event, HandshakeParseConfig, Message, PeerRole,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;

/// External WebSocket server for browser clients.
pub struct WsServer {
    listener: tokio::net::TcpListener,
    broadcast_tx: broadcast::Sender<Arc<TraceEvent>>,
}

impl WsServer {
    /// Create a new WS server bound to the given port.
    pub fn new(
        port: u16,
        broadcast_tx: broadcast::Sender<Arc<TraceEvent>>,
    ) -> anyhow::Result<Self> {
        let addr = format!("127.0.0.1:{}", port);
        let std_listener = std::net::TcpListener::bind(&addr)?;
        std_listener.set_nonblocking(true)?;
        let listener = tokio::net::TcpListener::from_std(std_listener)?;
        debug!("External WS server listening on ws://{}", addr);
        Ok(Self {
            listener,
            broadcast_tx,
        })
    }

    /// Run the server, accepting connections until the listener is closed.
    pub async fn run(self) {
        loop {
            let (stream, _) = match self.listener.accept().await {
                Ok(s) => s,
                Err(_) => continue,
            };
            let sub_rx = self.broadcast_tx.subscribe();
            tokio::spawn(async move {
                if let Err(e) = handle_ws_client(stream, sub_rx).await {
                    debug!("WS client error: {}", e);
                }
            });
        }
    }
}

/// Handle a single WebSocket client connection.
async fn handle_ws_client(
    mut stream: tokio::net::TcpStream,
    mut sub_rx: broadcast::Receiver<Arc<TraceEvent>>,
) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;

    // Read WS handshake
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        anyhow::bail!("empty handshake");
    }
    let (request, _) = parse_client_handshake_with_len(&buf[..n], HandshakeParseConfig::default())
        .map_err(|e| anyhow::anyhow!("WS handshake parse failed: {}", e))?;

    // Send 101 response
    let response = build_server_handshake_response(&request, None, &[])
        .map_err(|e| anyhow::anyhow!("WS handshake response failed: {}", e))?;
    stream.write_all(&response).await?;

    // Create WS connection state
    let mut conn = Connection::new(ConnectionConfig {
        role: PeerRole::Server,
        ..ConnectionConfig::default()
    });

    let mut read_buf = vec![0u8; 4096];
    loop {
        tokio::select! {
            // Check for incoming data from client (ping/pong/close)
            result = stream.read(&mut read_buf) => {
                match result {
                    Ok(0) => break, // Client disconnected
                    Ok(n) => {
                        let events = match conn.ingest(&read_buf[..n], None) {
                            Ok(events) => events,
                            Err(_) => break,
                        };
                        for event in events {
                            match event {
                                Event::CloseReceived(_) | Event::Closed => return Ok(()),
                                _ => {}
                            }
                        }
                        // Flush any auto-generated frames (pongs)
                        while let Some(bytes) = conn.poll_outbound() {
                            if stream.write_all(&bytes).await.is_err() {
                                return Ok(());
                            }
                        }
                    }
                    Err(_) => break,
                }
            }

            // Send events from broadcast channel
            result = sub_rx.recv() => {
                match result {
                    Ok(trace_event) => {
                        let json = serde_json::to_string(trace_event.as_ref())?;
                        if conn.send_message(Message::Text(json), None).is_err() {
                            break;
                        }
                        // Flush all
                        while let Some(bytes) = conn.poll_outbound() {
                            if stream.write_all(&bytes).await.is_err() {
                                return Ok(());
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
        }
    }

    Ok(())
}
