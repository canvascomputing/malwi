use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};

use malwi::agent_server::{AgentServer, AgentTracking};
use malwi_intercept::wire::{write_frame, BinaryCodec, Codec};
use malwi_intercept::{AgentMessage, Argument, EventType, TraceEvent};

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

/// Spin up a server + drain task, return the URL and keep the runtime alive.
fn setup_server() -> (String, tokio::runtime::Runtime) {
    let rt = tokio::runtime::Runtime::new().expect("create tokio runtime");
    let (tx, mut rx) = tokio::sync::mpsc::channel(4096);
    let active = Arc::new(AtomicU32::new(0));
    let tracking = AgentTracking {
        active_count: active,
    };
    let server = rt
        .block_on(async { AgentServer::new(tx, tracking) })
        .expect("create server");
    let url = server.url().to_string();
    rt.spawn(async move { server.run().await });
    rt.spawn(async move { while rx.recv().await.is_some() {} });
    (url, rt)
}

fn bench_wire_throughput(c: &mut Criterion) {
    let (url, _rt) = setup_server();
    let addr = url.strip_prefix("http://").unwrap();
    let codec = BinaryCodec;

    // Pre-encode N events
    let n = 1000u64;
    let frames: Vec<Vec<u8>> = (0..n)
        .map(|i| {
            let msg = AgentMessage::Event(make_event(i));
            let mut buf = Vec::new();
            codec.encode_agent_msg(&msg, &mut buf);
            buf
        })
        .collect();

    c.bench_function(&format!("wire_send_{n}_events"), |b| {
        b.iter(|| {
            let mut stream =
                TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5))
                    .expect("connect");
            stream.set_nodelay(true).ok();
            for frame in &frames {
                write_frame(&mut stream, frame).expect("write");
            }
            stream.flush().expect("flush");
        });
    });

    // Bench batched sending (64 events per batch)
    let batch_frames: Vec<Vec<u8>> = frames
        .chunks(64)
        .map(|chunk| {
            let events: Vec<TraceEvent> = chunk
                .iter()
                .map(|frame| match codec.decode_agent_msg(frame).unwrap() {
                    AgentMessage::Event(e) => e,
                    _ => unreachable!(),
                })
                .collect();
            let msg = AgentMessage::Events(events);
            let mut buf = Vec::new();
            codec.encode_agent_msg(&msg, &mut buf);
            buf
        })
        .collect();

    c.bench_function(&format!("wire_send_{n}_events_batched64"), |b| {
        b.iter(|| {
            let mut stream =
                TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5))
                    .expect("connect");
            stream.set_nodelay(true).ok();
            for frame in &batch_frames {
                write_frame(&mut stream, frame).expect("write");
            }
            stream.flush().expect("flush");
        });
    });
}

criterion_group!(benches, bench_wire_throughput);
criterion_main!(benches);
