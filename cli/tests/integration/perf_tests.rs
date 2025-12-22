//! Performance measurement tests.
//!
//! These are not micro-benchmarks (use `cargo bench` for those).
//! These measure end-to-end tracing overhead against real executables.

use std::time::{Duration, Instant};

use crate::common::{build_fixtures, fixture, run_tracer_with_timeout, strip_ansi_codes};

#[test]
fn test_perf_native_tracing_throughput() {
    build_fixtures();

    let multithread = fixture("multithread");
    if !multithread.exists() {
        eprintln!("SKIPPED: multithread fixture not found");
        return;
    }
    let multithread_str = multithread.to_string_lossy();

    // Run uninstrumented baseline
    let baseline_start = Instant::now();
    let _ = run_tracer_with_timeout(
        &["--", &multithread_str],
        Duration::from_secs(10),
    );
    let baseline_ms = baseline_start.elapsed().as_millis();

    // Run with tracing enabled — hook multithread_marker and malloc
    let traced_start = Instant::now();
    let output = run_tracer_with_timeout(
        &["x", "-s", "multithread_marker", "-s", "malloc", &multithread_str],
        Duration::from_secs(10),
    );
    let traced_ms = traced_start.elapsed().as_millis();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let clean_stdout = strip_ansi_codes(&stdout);

    // Count trace event lines (lines containing [malwi])
    let event_count = clean_stdout
        .lines()
        .filter(|line| line.contains("[malwi]"))
        .count();

    let overhead_pct = if baseline_ms > 0 {
        ((traced_ms as f64 / baseline_ms as f64) - 1.0) * 100.0
    } else {
        0.0
    };
    let events_per_sec = if traced_ms > 0 {
        event_count as f64 / (traced_ms as f64 / 1000.0)
    } else {
        0.0
    };

    eprintln!("=== Performance: Native Tracing ===");
    eprintln!("  Baseline:      {}ms", baseline_ms);
    eprintln!("  Traced:        {}ms", traced_ms);
    eprintln!("  Overhead:      {:.1}%", overhead_pct);
    eprintln!("  Events:        {}", event_count);
    eprintln!("  Events/sec:    {:.0}", events_per_sec);

    assert!(event_count > 0, "Should capture trace events");
}
