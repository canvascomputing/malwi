use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};

use malwi::agent_server::AgentServer;
use malwi_protocol::{AgentMessage, Argument, EventType, HookConfig, TraceEvent};
use malwi_websocket::{
    build_client_handshake_request, parse_server_handshake_response_with_len,
    ClientHandshakeRequest, Connection, ConnectionConfig, HandshakeParseConfig, Message, PeerRole,
};

fn make_event(_i: u64) -> TraceEvent {
    TraceEvent {
        hook_type: malwi_protocol::HookType::Native,
        event_type: EventType::Enter,
        function: "malloc".to_string(),
        arguments: vec![Argument {
            raw_value: 4096,
            display: Some("4096".to_string()),
        }],
        native_stack: vec![0x7fff00001000],
        ..Default::default()
    }
}

fn make_hook_configs() -> Vec<HookConfig> {
    vec![HookConfig {
        hook_type: malwi_protocol::HookType::Native,
        symbol: "malloc".to_string(),
        arg_count: Some(1),
        capture_return: false,
        capture_stack: false,
    }]
}

/// Spin up a server + drain task, return the URL and keep the runtime alive.
fn setup_server() -> (String, tokio::runtime::Runtime) {
    let rt = tokio::runtime::Runtime::new().expect("create tokio runtime");
    let (tx, mut rx) = tokio::sync::mpsc::channel(4096);
    let active = Arc::new(AtomicU32::new(0));
    let server = rt
        .block_on(async { AgentServer::new(make_hook_configs(), false, tx, active) })
        .expect("create server");
    let url = server.url().to_string();
    rt.spawn(async move { server.run().await });
    rt.spawn(async move { while rx.recv().await.is_some() {} });
    (url, rt)
}

/// Extract host:port from a URL like "http://127.0.0.1:12345"
fn addr_from_url(url: &str) -> &str {
    url.strip_prefix("http://").unwrap_or(url)
}

/// Generate a simple mask key from a counter.
fn mask_key(counter: u32) -> [u8; 4] {
    counter.to_le_bytes()
}

/// Perform WebSocket handshake and return (stream, ws_connection).
fn ws_connect(addr: &str) -> (TcpStream, Connection) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_nodelay(true).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // Build and send client handshake
    let key = "dGhlIHNhbXBsZSBub25jZQ==".to_string(); // Fixed key for benchmarks
    let req = ClientHandshakeRequest {
        host: addr.to_string(),
        path: "/".to_string(),
        key: key.clone(),
        origin: None,
        protocols: vec![],
        extensions: vec![],
    };
    let req_bytes = build_client_handshake_request(&req).unwrap();
    stream.write_all(&req_bytes).unwrap();

    // Read and validate server response
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).unwrap();
    let (response, _) =
        parse_server_handshake_response_with_len(&buf[..n], HandshakeParseConfig::default())
            .unwrap();
    response.validate_server_response(&key).unwrap();

    let conn = Connection::new(ConnectionConfig {
        role: PeerRole::Client,
        ..ConnectionConfig::default()
    });

    (stream, conn)
}

/// Send a WebSocket text message and flush.
fn ws_send(stream: &mut TcpStream, conn: &mut Connection, text: &str, mask_counter: u32) {
    conn.send_message(
        Message::Text(text.to_string()),
        Some(mask_key(mask_counter)),
    )
    .unwrap();
    while let Some(bytes) = conn.poll_outbound() {
        stream.write_all(&bytes).unwrap();
    }
}

fn bench_throughput(c: &mut Criterion) {
    // Single event roundtrip
    {
        let (url, _rt) = setup_server();
        let addr = addr_from_url(&url);
        let (mut stream, mut conn) = ws_connect(addr);
        c.bench_function("single_event_roundtrip", |b| {
            let event = make_event(0);
            let msg = AgentMessage::Event(event);
            let json = serde_json::to_string(&msg).unwrap();
            let mut counter = 0u32;
            b.iter(|| {
                counter = counter.wrapping_add(1);
                ws_send(&mut stream, &mut conn, &json, counter);
            });
        });
    }

    // Burst 100 events
    {
        let (url, _rt) = setup_server();
        let addr = addr_from_url(&url);
        let (mut stream, mut conn) = ws_connect(addr);
        c.bench_function("burst_100_events", |b| {
            let mut counter = 0u32;
            b.iter(|| {
                for i in 0..100u64 {
                    let event = make_event(i);
                    let msg = AgentMessage::Event(event);
                    let json = serde_json::to_string(&msg).unwrap();
                    counter = counter.wrapping_add(1);
                    ws_send(&mut stream, &mut conn, &json, counter);
                }
            });
        });
    }

    // Batch 64 events via Events message
    {
        let (url, _rt) = setup_server();
        let addr = addr_from_url(&url);
        let (mut stream, mut conn) = ws_connect(addr);
        let batch: Vec<TraceEvent> = (0..64).map(make_event).collect();
        let msg = AgentMessage::Events(batch);
        let batch_json = serde_json::to_string(&msg).unwrap();
        c.bench_function("batch_64_events", |b| {
            let mut counter = 0u32;
            b.iter(|| {
                counter = counter.wrapping_add(1);
                ws_send(&mut stream, &mut conn, &batch_json, counter);
            });
        });
    }
}

criterion_group!(benches, bench_throughput);
criterion_main!(benches);
