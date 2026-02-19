use criterion::{black_box, criterion_group, criterion_main, Criterion};

use malwi_protocol::glob::matches_glob;
use malwi_protocol::{
    Argument, EventType, NodejsFrame, RuntimeStack, TraceEvent,
};

fn make_event() -> TraceEvent {
    TraceEvent {
        hook_type: malwi_protocol::HookType::Native,
        event_type: EventType::Enter,
        function: "fs.readFileSync".to_string(),
        arguments: vec![
            Argument {
                raw_value: 0x1000,
                display: Some("/etc/passwd".to_string()),
            },
            Argument {
                raw_value: 0x2000,
                display: Some("utf8".to_string()),
            },
            Argument {
                raw_value: 0,
                display: None,
            },
        ],
        native_stack: vec![
            0x7fff00001000,
            0x7fff00002000,
            0x7fff00003000,
            0x7fff00004000,
            0x7fff00005000,
        ],
        runtime_stack: Some(RuntimeStack::Nodejs(vec![
            NodejsFrame { function: "readFileSync".to_string(), script: "node:fs".to_string(), line: 450, column: 12, is_user_javascript: false },
            NodejsFrame { function: "loadConfig".to_string(), script: "/app/config.js".to_string(), line: 23, column: 5, is_user_javascript: true },
            NodejsFrame { function: "main".to_string(), script: "/app/index.js".to_string(), line: 10, column: 1, is_user_javascript: true },
        ])),
        network_info: None,
        source_file: None,
        source_line: None,
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

    let batch: Vec<TraceEvent> = (0..64).map(|_| make_event()).collect();

    c.bench_function("event_batch_serialize_64", |b| {
        b.iter(|| serde_json::to_string(black_box(&batch)).unwrap())
    });
}

criterion_group!(benches, bench_glob, bench_serialization);
criterion_main!(benches);
