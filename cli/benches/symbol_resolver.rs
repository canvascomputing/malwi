use criterion::{black_box, criterion_group, criterion_main, Criterion};

use malwi_protocol::protocol::ModuleInfo;
use malwi_trace::symbol_resolver::SymbolResolver;
use malwi_protocol::NativeFrame;

fn make_modules(count: usize) -> Vec<ModuleInfo> {
    (0..count)
        .map(|i| {
            let base = (i as u64 + 1) * 0x100000;
            ModuleInfo {
                name: format!("libmodule_{}.dylib", i),
                path: format!("/nonexistent/libmodule_{}.dylib", i),
                base_address: base,
                size: 0x80000,
            }
        })
        .collect()
}

fn make_frame(addr: usize) -> NativeFrame {
    NativeFrame {
        address: addr,
        symbol: None,
        module: None,
        offset: None,
    }
}

fn bench_module_lookup(c: &mut Criterion) {
    // 10 modules — simple program
    {
        let modules = make_modules(10);
        let mut resolver = SymbolResolver::new();
        resolver.add_module_map(1, modules);
        // Address in the 5th module
        let addr = 5 * 0x100000 + 0x1000;
        c.bench_function("module_lookup_10", |b| {
            b.iter(|| {
                let frame = make_frame(black_box(addr as usize));
                resolver.resolve_frame(&frame);
            })
        });
    }

    // 50 modules — typical Node.js/Python process
    {
        let modules = make_modules(50);
        let mut resolver = SymbolResolver::new();
        resolver.add_module_map(1, modules);
        let addr = 25 * 0x100000 + 0x1000;
        c.bench_function("module_lookup_50", |b| {
            b.iter(|| {
                let frame = make_frame(black_box(addr as usize));
                resolver.resolve_frame(&frame);
            })
        });
    }

    // 200 modules — large application
    {
        let modules = make_modules(200);
        let mut resolver = SymbolResolver::new();
        resolver.add_module_map(1, modules);
        let addr = 150 * 0x100000 + 0x1000;
        c.bench_function("module_lookup_200", |b| {
            b.iter(|| {
                let frame = make_frame(black_box(addr as usize));
                resolver.resolve_frame(&frame);
            })
        });
    }
}

fn bench_resolve_frames(c: &mut Criterion) {
    // Build a resolver with 50 modules (no real symbol files — measures lookup only)
    let modules = make_modules(50);
    let mut resolver = SymbolResolver::new();
    resolver.add_module_map(1, modules);

    // 10-frame stack trace across different modules
    let frames: Vec<NativeFrame> = (0..10)
        .map(|i| make_frame(((i * 5 + 1) * 0x100000 + 0x2000) as usize))
        .collect();

    c.bench_function("resolve_10_frames", |b| {
        b.iter(|| {
            for f in black_box(&frames) {
                resolver.resolve_frame(f);
            }
        })
    });
}

criterion_group!(benches, bench_module_lookup, bench_resolve_frames);
criterion_main!(benches);
