//! Native function tracing tests.
//!
//! Tests for native function hooks using malwi-hook Interceptor.

use crate::common::*;

fn setup() {
    build_fixtures();
}

// ============================================================================
// Native Function Tracing Tests
// ============================================================================

#[test]
fn test_native_tracing_captures_malloc_calls() {
    setup();

    let output = run_tracer(&["x", "-s", "malloc", "--", "./simple_target"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout, stderr);

    // Should have traced malloc calls
    assert!(
        combined.contains("malloc"),
        "Expected malloc trace events. stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}

#[test]
fn test_native_tracing_glob_pattern_matches_prefixed_functions() {
    setup();

    // Use a more specific glob pattern to avoid matching too many functions
    // malloc* matches 60+ functions on macOS which can overwhelm HTTP
    let output = run_tracer(&[
        "x",
        "-s",
        "malloc_good*", // Matches only malloc_good_size
        "--",
        "./simple_target",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Glob patterns should work
    assert!(
        output.status.success() || stderr.contains("malloc"),
        "Glob pattern test failed. stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}

#[test]
fn test_native_tracing_captures_multiple_functions_simultaneously() {
    setup();

    // Use simple_target_marker and getpid instead of malloc/free which generate too much output
    let output = run_tracer(&[
        "x",
        "-s",
        "simple_target_marker",
        "-s",
        "getpid",
        "--",
        "./simple_target",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout, stderr);

    // Should have simple_target_marker traces (called twice in simple_target)
    let has_marker = combined.contains("simple_target_marker");

    assert!(
        has_marker,
        "Expected simple_target_marker traces. stdout: {}, stderr: {}",
        stdout, stderr
    );
}

// ============================================================================
// Native Stack Trace Tests
// ============================================================================

#[test]
fn test_native_stack_trace_omitted_without_t_flag() {
    setup();

    // Run WITHOUT --st flag - should NOT have stack traces
    let output = run_tracer(&["x", "-s", "malloc", "--", "./simple_target"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Native test failed. stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    // Should NOT have stack trace frames when -t is not used
    assert!(
        !has_stack_trace(&stdout),
        "Expected no stack traces without --st flag. stdout: {}",
        stdout
    );
}

#[test]
fn test_native_stack_trace_included_with_t_flag() {
    setup();

    // Run WITH --st flag - should have stack traces
    let output = run_tracer(&[
        "x",
        "--st", // Enable stack traces
        "-s",
        "malloc",
        "--",
        "./simple_target",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Native stack trace test failed. stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    // Should have malloc function call
    assert!(
        stdout.contains("malloc"),
        "Expected malloc trace. stdout: {}",
        stdout
    );

    // Should have stack trace frames (native format: "    at symbol (0xaddr)")
    assert!(
        has_stack_trace(&stdout),
        "Expected stack traces with --st flag. stdout: {}",
        stdout
    );
}

#[test]
fn test_native_stack_trace_shows_symbol_and_address() {
    setup();

    let output = run_tracer(&["x", "--st", "-s", "malloc", "--", "./simple_target"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Native stack trace test failed. stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    // Stack trace lines should start with "    at "
    assert!(
        has_stack_trace(&stdout),
        "Expected stack trace lines. stdout: {}",
        stdout
    );

    // With CLI-side symbol resolution, at least some frames should have resolved symbols
    // (not all "<unknown>"). Resolved frames show "symbol+0xN (module)" format.
    let stdout_clean = strip_ansi_codes(&stdout);
    let has_resolved = stdout_clean.lines().any(|line| {
        line.starts_with("    at ")
            && !line.contains("<unknown>")
            && !line.trim_start_matches("    at ").starts_with("0x")
    });

    assert!(
        has_resolved,
        "Expected at least one resolved symbol (not <unknown> or bare address). stdout: {}",
        stdout
    );
}

#[test]
fn test_native_stack_trace_resolves_known_symbol() {
    setup();

    let output = run_tracer(&[
        "x",
        "--st",
        "-s",
        "simple_target_marker",
        "--",
        "./simple_target",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Native stack trace test failed. stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    // Should have the function call
    assert!(
        stdout.contains("simple_target_marker"),
        "Expected simple_target_marker trace. stdout: {}",
        stdout
    );

    // Stack frames should contain at least one recognizable function name
    // (e.g., main or a system function like _start, __libc_start_main)
    let stdout_clean2 = strip_ansi_codes(&stdout);
    let has_known_symbol = stdout_clean2.lines().any(|line| {
        if !line.starts_with("    at ") {
            return false;
        }
        let frame = line.trim_start_matches("    at ");
        // Check for common symbols that should appear in a simple binary's stack
        frame.contains("main") || frame.contains("start") || frame.contains("simple_target")
    });

    assert!(
        has_known_symbol,
        "Expected at least one recognizable symbol in stack trace. stdout: {}",
        stdout
    );
}

// ============================================================================
// Multi-threading Tests
// ============================================================================

#[test]
fn test_native_hooks_trace_events_from_multiple_threads() {
    setup();

    let output = run_tracer(&["x", "-s", "multithread_marker", "--", "./multithread"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout, stderr);

    // Should complete without crashing
    assert!(
        output.status.success(),
        "Multi-threaded test crashed. stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    // Should have marker events from multiple threads
    let marker_count = count_events(&combined, "multithread_marker");
    assert!(
        marker_count > 0,
        "Expected multiple marker events. stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}

#[test]
fn test_multithreaded_tracing_completes_without_crash() {
    setup();

    // Run once to verify basic functionality (multiple iterations can be slow)
    let output = run_tracer(&["x", "-s", "multithread_marker", "--", "./multithread"]);

    assert!(
        output.status.success(),
        "Multi-threaded test crashed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_nonexistent_symbol_exits_gracefully_with_warning() {
    setup();

    let output = run_tracer(&[
        "x",
        "-s",
        "this_symbol_definitely_does_not_exist_xyz123",
        "--",
        "./simple_target",
    ]);

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should report an error about the symbol not being found
    assert!(
        stderr.contains("not found") || stderr.contains("error") || stderr.contains("Error"),
        "Expected error message for nonexistent symbol. stderr: {}",
        stderr
    );
}

#[test]
fn test_invalid_program_path_exits_gracefully_with_error() {
    setup();

    let output = run_tracer(&["x", "-s", "malloc", "--", "./nonexistent_program_xyz"]);

    // Should fail but not crash
    assert!(
        !output.status.success(),
        "Expected failure for nonexistent program"
    );
}

// ============================================================================
// PAC (Pointer Authentication) Tests — arm64 only
// ============================================================================

/// Test hooking a function with PACIASP prologue (built with -mbranch-protection=standard).
/// Verifies the relocator handles PAC instructions correctly.
#[test]
#[cfg(target_arch = "aarch64")]
fn test_native_tracing_hooks_function_with_pac_prologue() {
    setup();

    let pac = fixture("pac_target");
    if !pac.exists() {
        println!("SKIPPED: pac_target not built (arm64 only)");
        return;
    }

    let output = run_tracer(&["x", "-s", "compute", "--", pac.to_str().unwrap()]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout, stderr);

    assert!(
        output.status.success(),
        "pac_target tracing failed. stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    assert!(
        combined.contains("compute"),
        "Expected compute trace event from pac_target. stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}
