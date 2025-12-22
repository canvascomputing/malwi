use criterion::{black_box, criterion_group, criterion_main, Criterion};

use malwi_protocol::glob::matches_glob;
use malwi_protocol::{
    Argument, EventType, NativeFrame, NodejsFrame, RuntimeStack, TraceEvent,
};

fn make_event() -> TraceEvent {
    TraceEvent {
        hook_type: malwi_protocol::HookType::Native,
        timestamp_ns: 123456789,
        thread_id: 42,
        event_type: EventType::Enter,
        function: "fs.readFileSync".to_string(),
        module: "fs".to_string(),
        address: 0x7fff12345678,
        arguments: vec![
            Argument {
                index: 0,
                raw_value: 0x1000,
                display: Some("/etc/passwd".to_string()),
                type_hint: Some("string".to_string()),
            },
            Argument {
                index: 1,
                raw_value: 0x2000,
                display: Some("utf8".to_string()),
                type_hint: Some("string".to_string()),
            },
            Argument {
                index: 2,
                raw_value: 0,
                display: None,
                type_hint: None,
            },
        ],
        native_stack: vec![
            NativeFrame { address: 0x7fff00001000, symbol: Some("readFileSync".to_string()), module: Some("fs.node".to_string()), offset: Some(0x100) },
            NativeFrame { address: 0x7fff00002000, symbol: Some("uv_fs_read".to_string()), module: Some("libuv.dylib".to_string()), offset: Some(0x200) },
            NativeFrame { address: 0x7fff00003000, symbol: Some("read".to_string()), module: Some("libsystem_kernel.dylib".to_string()), offset: Some(0x50) },
            NativeFrame { address: 0x7fff00004000, symbol: None, module: Some("node".to_string()), offset: Some(0x4000) },
            NativeFrame { address: 0x7fff00005000, symbol: Some("_start".to_string()), module: Some("node".to_string()), offset: Some(0) },
        ],
        runtime_stack: Some(RuntimeStack::Nodejs(vec![
            NodejsFrame { function: "readFileSync".to_string(), script: "node:fs".to_string(), line: 450, column: 12, is_user_javascript: false },
            NodejsFrame { function: "loadConfig".to_string(), script: "/app/config.js".to_string(), line: 23, column: 5, is_user_javascript: true },
            NodejsFrame { function: "main".to_string(), script: "/app/index.js".to_string(), line: 10, column: 1, is_user_javascript: true },
        ])),
        network_info: None,
    }
}

fn bench_glob(c: &mut Criterion) {
    c.bench_function("glob_exact_match", |b| {
        b.iter(|| matches_glob(black_box("malloc"), black_box("malloc")))
    });

    c.bench_function("glob_wildcard_prefix", |b| {
        b.iter(|| matches_glob(black_box("fs.*"), black_box("fs.readFileSync")))
    });

    c.bench_function("glob_wildcard_both", |b| {
        b.iter(|| matches_glob(black_box("*alloc*"), black_box("zone_realloc")))
    });
}

fn bench_serialization(c: &mut Criterion) {
    let event = make_event();
    let json = serde_json::to_string(&event).unwrap();

    c.bench_function("event_serialize", |b| {
        b.iter(|| serde_json::to_string(black_box(&event)).unwrap())
    });

    c.bench_function("event_deserialize", |b| {
        b.iter(|| serde_json::from_str::<TraceEvent>(black_box(&json)).unwrap())
    });

    let batch: Vec<TraceEvent> = (0..64).map(|i| {
        let mut e = make_event();
        e.timestamp_ns = i;
        e
    }).collect();

    c.bench_function("event_batch_serialize_64", |b| {
        b.iter(|| serde_json::to_string(black_box(&batch)).unwrap())
    });
}

criterion_group!(benches, bench_glob, bench_serialization);
criterion_main!(benches);
