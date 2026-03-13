use std::collections::HashSet;
use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};

use malwi::agent_server::AgentServer;
use malwi_intercept::wire::{write_frame, BinaryCodec, Codec};
use malwi_intercept::{AgentMessage, Argument, EventType, HookConfig, TraceEvent};

fn make_event(_i: u64) -> TraceEvent {
    TraceEvent {
        hook_type: malwi_intercept::HookType::Native,
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
        hook_type: malwi_intercept::HookType::Native,
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
    let reconnected = Arc::new(Mutex::new(HashSet::new()));
    let server = rt
        .block_on(async { AgentServer::new(make_hook_configs(), false, vec![], tx, active, reconnected) })
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

/// Connect a raw TCP stream to the server (no handshake needed).
fn tcp_connect(addr: &str) -> TcpStream {
    let stream = TcpStream::connect(addr).unwrap();
    stream.set_nodelay(true).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
}

/// Encode and send a binary wire frame.
fn wire_send(stream: &mut TcpStream, codec: &BinaryCodec, msg: &AgentMessage) {
    let mut buf = Vec::new();
    codec.encode_agent_msg(msg, &mut buf);
    write_frame(stream, &buf).unwrap();
    stream.flush().unwrap();
}

fn bench_throughput(c: &mut Criterion) {
    let codec = BinaryCodec;

    // Single event roundtrip
    {
        let (url, _rt) = setup_server();
        let addr = addr_from_url(&url);
        let mut stream = tcp_connect(addr);
        let event = make_event(0);
        let msg = AgentMessage::Event(event);
        c.bench_function("single_event_roundtrip", |b| {
            b.iter(|| {
                wire_send(&mut stream, &codec, &msg);
            });
        });
    }

    // Burst 100 events
    {
        let (url, _rt) = setup_server();
        let addr = addr_from_url(&url);
        let mut stream = tcp_connect(addr);
        c.bench_function("burst_100_events", |b| {
            b.iter(|| {
                for i in 0..100u64 {
                    let event = make_event(i);
                    let msg = AgentMessage::Event(event);
                    wire_send(&mut stream, &codec, &msg);
                }
            });
        });
    }

    // Batch 64 events via Events message
    {
        let (url, _rt) = setup_server();
        let addr = addr_from_url(&url);
        let mut stream = tcp_connect(addr);
        let batch: Vec<TraceEvent> = (0..64).map(make_event).collect();
        let msg = AgentMessage::Events(batch);
        c.bench_function("batch_64_events", |b| {
            b.iter(|| {
                wire_send(&mut stream, &codec, &msg);
            });
        });
    }
}

criterion_group!(benches, bench_throughput);
criterion_main!(benches);
