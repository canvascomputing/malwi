use criterion::{black_box, criterion_group, criterion_main, Criterion};

use malwi_agent::tracing::filter::{check_filter, Filter, FilterManager};

fn make_filters(count: usize) -> Vec<Filter> {
    let patterns = [
        "fs.*", "http.*", "net.*", "crypto.*", "os.*",
        "path.*", "url.*", "dns.*", "tls.*", "zlib.*",
        "stream.*", "buffer.*", "events.*", "util.*", "vm.*",
        "child_process.*", "cluster.*", "worker_threads.*", "perf_hooks.*", "async_hooks.*",
    ];
    (0..count)
        .map(|i| Filter::new(patterns[i % patterns.len()], i % 3 == 0))
        .collect()
}

fn bench_check_filter(c: &mut Criterion) {
    // 1 filter, matching
    {
        let filters = vec![Filter::new("fs.*", true)];
        c.bench_function("check_filter_1", |b| {
            b.iter(|| check_filter(black_box(&filters), black_box("fs.readFileSync")))
        });
    }

    // 5 filters, match on 3rd
    {
        let filters = make_filters(5);
        c.bench_function("check_filter_5", |b| {
            b.iter(|| check_filter(black_box(&filters), black_box("net.connect")))
        });
    }

    // 20 filters, match on last
    {
        let filters = make_filters(20);
        c.bench_function("check_filter_20", |b| {
            b.iter(|| check_filter(black_box(&filters), black_box("async_hooks.createHook")))
        });
    }

    // 10 filters, no match
    {
        let filters = make_filters(10);
        c.bench_function("check_filter_miss", |b| {
            b.iter(|| check_filter(black_box(&filters), black_box("unknown.function")))
        });
    }
}

fn bench_filter_manager(c: &mut Criterion) {
    // FilterManager.check() including RwLock acquire
    {
        let manager = FilterManager::new("Bench");
        for f in make_filters(10) {
            manager.add(&f.pattern, f.capture_stack);
        }
        c.bench_function("filter_manager_check", |b| {
            b.iter(|| manager.check(black_box("fs.readFileSync")))
        });
    }

    // Concurrent 4-thread check
    {
        let manager = std::sync::Arc::new(FilterManager::new("Bench"));
        for f in make_filters(10) {
            manager.add(&f.pattern, f.capture_stack);
        }

        c.bench_function("filter_manager_concurrent_4", |b| {
            b.iter(|| {
                let handles: Vec<_> = (0..4)
                    .map(|_| {
                        let m = manager.clone();
                        std::thread::spawn(move || {
                            for _ in 0..100 {
                                black_box(m.check("fs.readFileSync"));
                            }
                        })
                    })
                    .collect();
                for h in handles {
                    h.join().unwrap();
                }
            })
        });
    }
}

criterion_group!(benches, bench_check_filter, bench_filter_manager);
criterion_main!(benches);
