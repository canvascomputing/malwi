//! External WebSocket server for browser/dashboard clients.
//!
//! Accepts WebSocket connections on a user-specified port and broadcasts
//! enriched TraceEvents as JSON text frames. Each connected client receives
//! all post-policy events via the fan-out subscription mechanism.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::thread;

use log::debug;
use malwi_protocol::TraceEvent;
use malwi_websocket::{
    build_server_handshake_response, parse_client_handshake_with_len, Connection, ConnectionConfig,
    Event, HandshakeParseConfig, Message, PeerRole,
};

/// Control messages for the event fan-out bus.
pub enum BusControl {
    Subscribe(SyncSender<Arc<TraceEvent>>),
}

/// External WebSocket server for browser clients.
pub struct WsServer {
    listener: TcpListener,
    control_tx: SyncSender<BusControl>,
}

impl WsServer {
    /// Create a new WS server bound to the given port.
    pub fn new(port: u16, control_tx: SyncSender<BusControl>) -> anyhow::Result<Self> {
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr)?;
        debug!("External WS server listening on ws://{}", addr);
        Ok(Self {
            listener,
            control_tx,
        })
    }

    /// Run the server, accepting connections until the listener is closed.
    pub fn run(self) {
        for stream in self.listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let control_tx = self.control_tx.clone();
            thread::spawn(move || {
                if let Err(e) = handle_ws_client(stream, control_tx) {
                    debug!("WS client error: {}", e);
                }
            });
        }
    }
}

/// Handle a single WebSocket client connection.
fn handle_ws_client(
    mut stream: TcpStream,
    control_tx: SyncSender<BusControl>,
) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;

    // Read WS handshake
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf)?;
    if n == 0 {
        anyhow::bail!("empty handshake");
    }
    let (request, _) = parse_client_handshake_with_len(&buf[..n], HandshakeParseConfig::default())
        .map_err(|e| anyhow::anyhow!("WS handshake parse failed: {}", e))?;

    // Send 101 response
    let response = build_server_handshake_response(&request, None, &[])
        .map_err(|e| anyhow::anyhow!("WS handshake response failed: {}", e))?;
    stream.write_all(&response)?;

    // Create WS connection state
    let mut conn = Connection::new(ConnectionConfig {
        role: PeerRole::Server,
        ..ConnectionConfig::default()
    });

    // Register as subscriber via BusControl
    let (sub_tx, sub_rx): (SyncSender<Arc<TraceEvent>>, Receiver<Arc<TraceEvent>>) =
        sync_channel(256);
    let _ = control_tx.send(BusControl::Subscribe(sub_tx));

    // Set stream to non-blocking so we can multiplex reading from both sub_rx and stream
    stream.set_nonblocking(true)?;

    let mut read_buf = vec![0u8; 4096];
    loop {
        // Check for incoming data from client (ping/pong/close)
        match stream.read(&mut read_buf) {
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
                    if stream.write_all(&bytes).is_err() {
                        return Ok(());
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data from client, that's fine
            }
            Err(_) => break,
        }

        // Send events from subscriber channel
        match sub_rx.recv_timeout(std::time::Duration::from_millis(50)) {
            Ok(trace_event) => {
                let json = serde_json::to_string(trace_event.as_ref())?;
                if conn.send_message(Message::Text(json), None).is_err() {
                    break;
                }
                // Drain additional events without blocking
                while let Ok(event) = sub_rx.try_recv() {
                    let json = serde_json::to_string(event.as_ref())?;
                    if conn.send_message(Message::Text(json), None).is_err() {
                        return Ok(());
                    }
                }
                // Flush all
                while let Some(bytes) = conn.poll_outbound() {
                    if stream.write_all(&bytes).is_err() {
                        return Ok(());
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // No events, continue
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                // Main loop shut down
                break;
            }
        }
    }

    Ok(())
}
