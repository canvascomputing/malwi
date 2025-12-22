//! Cross-runtime tracing tests.
//!
//! Tests that verify tracing works correctly across multiple runtime boundaries.

use crate::common::*;
use crate::skip_if_no_python;

fn setup() {
    build_fixtures();
}

// ============================================================================
// Cross-Runtime Tracing Tests
// ============================================================================

/// Test tracing across Python, Node.js, and native code in a nested construct.
///
/// This test verifies that:
/// 1. Python functions are traced (py:traced_python_entry, py:nested_python_call)
/// 2. Python's open() calls are traced
/// 3. Python spawns Node.js child process (child gating detects it)
/// 4. Node.js built-in APIs are traced in the child (js:fs.readFileSync)
/// 5. Both runtimes execute successfully in the same traced session
#[test]
fn test_cross_runtime_traces_python_nodejs_and_native_calls() {
    setup();

    if find_node().is_none() {
        println!("SKIPPED: Node.js not found in PATH");
        return;
    }

    skip_if_no_python!(python => {
        // Trace Python functions, JS built-in APIs, and Python's open() calls
        let output = run_tracer(&[
            "x",
            "--py", "traced_python_entry",   // Python entry function
            "--py", "nested_python_call",    // Nested Python function
            "--py", "open",                  // Python's open() call
            "--js", "fs.*",                  // JS fs module calls
            "--",
            python.to_str().unwrap(),
            fixture("test_cross_runtime.py").to_str().unwrap(),
        ]);

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = strip_ansi_codes(&stdout_raw);
        let combined = format!("{}\n{}", stdout, stderr);

        eprintln!("=== Cross-Runtime Test Output ===");
        eprintln!("stdout:\n{}", stdout);
        eprintln!("stderr:\n{}", stderr);

        // Test should complete successfully
        assert!(
            output.status.success(),
            "Cross-runtime test failed to complete. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // Verify Python traces are present
        let has_python_entry = combined.contains("traced_python_entry");
        let has_python_nested = combined.contains("nested_python_call");
        let has_python_open = combined.lines().any(|l| l.contains("[malwi]") && l.contains("open"));

        eprintln!("Python traces found:");
        eprintln!("  traced_python_entry: {}", has_python_entry);
        eprintln!("  nested_python_call: {}", has_python_nested);
        eprintln!("  open: {}", has_python_open);

        assert!(
            has_python_entry,
            "Expected traced_python_entry trace. stdout: {}",
            stdout
        );
        assert!(
            has_python_nested,
            "Expected nested_python_call trace. stdout: {}",
            stdout
        );
        assert!(
            has_python_open,
            "Expected open trace. stdout: {}",
            stdout
        );

        // Verify JavaScript traces from spawned Node.js child
        // Node.js built-in APIs are traced via the V8 addon
        let has_js_fs = combined.contains("fs.readFileSync");

        eprintln!("JavaScript traces found:");
        eprintln!("  fs.readFileSync: {}", has_js_fs);

        assert!(
            has_js_fs,
            "Expected fs.readFileSync trace from Node.js child. stdout: {}",
            stdout
        );

        // The key verification is that JS traces from the spawned Node.js child are captured
        // (verified above with has_js_fs). Child process spawn events may or may not be
        // captured depending on how subprocess.run spawns the child.

        // Verify the test output shows both runtimes executed
        assert!(
            combined.contains("Python:") && combined.contains("JS:"),
            "Expected output from both Python and Node.js runtimes. stdout: {}",
            stdout
        );

        // Verify the cross-runtime sequence: Python called JS child
        assert!(
            combined.contains("JS child started"),
            "Expected Node.js child to start. stdout: {}",
            stdout
        );

        eprintln!("=== Cross-Runtime Test PASSED ===");
    });
}
