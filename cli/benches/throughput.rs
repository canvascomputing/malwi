use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::AtomicU32;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};

use malwi_protocol::{Argument, EventType, HookConfig, TraceEvent};
use malwi_trace::agent_server::AgentServer;

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
        runtime_stack: None,
        network_info: None,
        source_file: None,
        source_line: None,
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

/// Spin up a server + drain thread, return the URL.
/// Server and drain threads run as daemons (not joined).
fn setup_server() -> String {
    let (tx, rx) = mpsc::sync_channel(4096);
    let active = Arc::new(AtomicU32::new(0));
    let server = AgentServer::new(make_hook_configs(), false, tx, active).expect("create server");
    let url = server.url().to_string();
    thread::spawn(move || server.run());
    thread::spawn(move || while rx.recv().is_ok() {});
    url
}

/// Extract host:port from a URL like "http://127.0.0.1:12345"
fn addr_from_url(url: &str) -> &str {
    url.strip_prefix("http://").unwrap_or(url)
}

/// Send an HTTP POST with keep-alive and return the stream for reuse.
fn http_post(stream: &mut TcpStream, addr: &str, path: &str, body: &str) {
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        path, addr, body.len(), body
    );
    stream.write_all(request.as_bytes()).unwrap();

    // Read response headers
    let mut header_buf = Vec::with_capacity(256);
    let mut prev = [0u8; 4];
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).unwrap();
        header_buf.push(byte[0]);
        prev[0] = prev[1];
        prev[1] = prev[2];
        prev[2] = prev[3];
        prev[3] = byte[0];
        if prev == [b'\r', b'\n', b'\r', b'\n'] {
            break;
        }
    }

    // Parse Content-Length and read body
    let header_str = String::from_utf8_lossy(&header_buf);
    let content_length: usize = header_str
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|line| line.split(':').nth(1))
        .and_then(|val| val.trim().parse().ok())
        .unwrap_or(0);

    if content_length > 0 {
        let mut body_buf = vec![0u8; content_length];
        stream.read_exact(&mut body_buf).unwrap();
    }
}

fn bench_throughput(c: &mut Criterion) {
    // Single event roundtrip
    {
        let url = setup_server();
        let addr = addr_from_url(&url);
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_nodelay(true).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        c.bench_function("single_event_roundtrip", |b| {
            let event = make_event(0);
            let json = serde_json::to_string(&event).unwrap();
            b.iter(|| {
                http_post(&mut stream, addr, "/event", &json);
            });
        });
    }

    // Burst 100 events
    {
        let url = setup_server();
        let addr = addr_from_url(&url);
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_nodelay(true).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        c.bench_function("burst_100_events", |b| {
            b.iter(|| {
                for i in 0..100u64 {
                    let event = make_event(i);
                    let json = serde_json::to_string(&event).unwrap();
                    http_post(&mut stream, addr, "/event", &json);
                }
            });
        });
    }

    // Batch 64 events via /events endpoint
    {
        let url = setup_server();
        let addr = addr_from_url(&url);
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_nodelay(true).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let batch: Vec<TraceEvent> = (0..64).map(make_event).collect();
        let batch_json = serde_json::to_string(&batch).unwrap();
        c.bench_function("batch_64_events", |b| {
            b.iter(|| {
                http_post(&mut stream, addr, "/events", &batch_json);
            });
        });
    }
}

criterion_group!(benches, bench_throughput);
criterion_main!(benches);
