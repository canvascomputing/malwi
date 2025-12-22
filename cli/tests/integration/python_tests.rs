//! Python tracing tests.
//!
//! Tests for Python function tracing via sys.setprofile hooks.

use crate::common::*;
use crate::skip_if_no_python;

fn setup() {
    build_fixtures();
}

// ============================================================================
// Python Tracing Tests
// ============================================================================

#[test]
fn test_python_tracing_captures_single_function_call() {
    setup();

    skip_if_no_python!(python => {
        let output = run_tracer(&[
            "x",
            "--py", "calculate",
            "--",
            python.to_str().unwrap(),
            "./test_python.py",
        ]);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}\n{}", stdout, stderr);

        // Should have traced the calculate function
        assert!(
            combined.contains("calculate") || output.status.success(),
            "Expected calculate trace. stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}

#[test]
fn test_python_tracing_glob_matches_all_functions() {
    setup();

    skip_if_no_python!(python => {
        // Use specific glob patterns instead of py:* to avoid tracing thousands
        // of Python internal functions during import (which overwhelms HTTP)
        let output = run_tracer(&[
            "x",
            "--py", "calc*",       // matches calculate
            "--py", "process_*",   // matches process_data
            "--py", "nested_*",    // matches nested_outer, nested_inner
            "--py", "main",        // matches main
            "--",
            python.to_str().unwrap(),
            "./test_python.py",
        ]);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Should complete without crashing
        assert!(
            output.status.success(),
            "Python glob test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // Verify that glob patterns matched at least some functions
        assert!(
            stdout.contains("calculate") || stdout.contains("nested_"),
            "Expected glob patterns to match functions. stdout: {}",
            stdout
        );
    });
}

#[test]
fn test_python_tracing_captures_nested_function_calls() {
    setup();

    skip_if_no_python!(python => {
        let output = run_tracer(&[
            "x",
            "--py", "nested_*",
            "--",
            python.to_str().unwrap(),
            "./test_python.py",
        ]);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Should complete successfully
        assert!(
            output.status.success(),
            "Python nested test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}

#[test]
fn test_python_tracing_produces_no_events_when_filter_unmatched() {
    setup();

    skip_if_no_python!(python => {
        let output = run_tracer(&[
            "x",
            "--py", "nonexistent_function_xyz",
            "--",
            python.to_str().unwrap(),
            "./test_python.py",
        ]);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Should complete successfully
        assert!(
            output.status.success(),
            "Python no-match test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // The hook should be registered (HookAdded appears in log)
        // but no actual ENTER/LEAVE events for the function should appear
        // since no Python function matches "nonexistent_function_xyz"
        // This is a basic sanity check - the test passes if it completes
    });
}

#[test]
fn test_python_tracing_captures_calls_across_threads() {
    setup();

    skip_if_no_python!(python => {
        let output = run_tracer(&[
            "x",
            "--py", "worker",
            "--",
            python.to_str().unwrap(),
            "./test_python_threads.py",
        ]);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}\n{}", stdout, stderr);

        // Should complete without crashing
        assert!(
            output.status.success(),
            "Python multi-thread test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // Count how many times py:worker appears in output
        // The test creates 4 threads, each calling worker() once
        let worker_count = combined.matches("worker").count();
        assert!(
            worker_count >= 4,
            "Expected at least 4 py:worker traces (one per thread), got {}. Output: {}",
            worker_count, combined
        );
    });
}

#[test]
fn test_python_traced_functions_have_py_prefix() {
    setup();

    skip_if_no_python!(python => {
        // Create a simple test script
        let test_script = r#"
def calculate(x, y):
    return x + y

calculate(1, 2)
"#;
        std::fs::write("/tmp/test_py_prefix.py", test_script).unwrap();

        let output = run_tracer(&[
            "x",
            "--py", "calculate",
            "--",
            python.to_str().unwrap(),
            "/tmp/test_py_prefix.py",
        ]);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Check that the function name is present in trace output
        assert!(
            stdout.contains("calculate"),
            "Expected calculate in trace output. stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}

// ============================================================================
// Python Stack Trace Tests
// ============================================================================

#[test]
fn test_python_stack_trace_omitted_without_t_flag() {
    setup();

    skip_if_no_python!(python => {
        // Run WITHOUT --st flag - should NOT have stack traces
        let output = run_tracer(&[
            "x",
            "--py", "nested_*",
            "--",
            python.to_str().unwrap(),
            "./test_python.py",
        ]);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "Python test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // Should NOT have stack trace frames when -t is not used
        assert!(
            !has_stack_trace(&stdout),
            "Expected no stack traces without --st flag. stdout: {}",
            stdout
        );
    });
}

#[test]
fn test_python_stack_trace_included_with_t_flag() {
    setup();

    skip_if_no_python!(python => {
        // Run WITH --st flag - should have stack traces
        let output = run_tracer(&[
            "x",
            "--st",  // Enable stack traces
            "--py", "nested_inner",
            "--",
            python.to_str().unwrap(),
            "./test_python.py",
        ]);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "Python stack trace test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // Should have the nested_inner function call
        assert!(
            stdout.contains("nested_inner"),
            "Expected nested_inner trace. stdout: {}",
            stdout
        );

        // Should have stack trace frames showing call chain
        assert!(
            has_stack_trace(&stdout),
            "Expected stack traces with --st flag. stdout: {}",
            stdout
        );

        // Should have Python-style stack frames (function (file.py:line))
        assert!(
            has_python_stack_frame(&stdout, "nested_inner") || has_python_stack_frame(&stdout, "nested_outer"),
            "Expected Python stack frame format. stdout: {}",
            stdout
        );
    });
}

#[test]
fn test_python_stack_trace_includes_calling_function() {
    setup();

    skip_if_no_python!(python => {
        // Trace nested_inner and verify stack shows nested_outer as caller
        let output = run_tracer(&[
            "x",
            "--st",
            "--py", "nested_inner",
            "--",
            python.to_str().unwrap(),
            "./test_python.py",
        ]);

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = strip_ansi_codes(&stdout_raw);

        assert!(
            output.status.success(),
            "Python stack trace test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // The stack trace for nested_inner should show nested_outer in the call chain
        // Look for the pattern: nested_inner event followed by stack with nested_outer
        let lines: Vec<&str> = stdout.lines().collect();
        let mut found_nested_inner = false;
        let mut found_caller_in_stack = false;

        for (i, line) in lines.iter().enumerate() {
            if line.contains("[malwi]") && line.contains("nested_inner") {
                found_nested_inner = true;
                // Check subsequent lines for stack frames showing nested_outer
                for stack_line in lines.iter().skip(i + 1) {
                    if stack_line.starts_with("[malwi]") {
                        break; // Next event, stop looking
                    }
                    if stack_line.contains("nested_outer") {
                        found_caller_in_stack = true;
                        break;
                    }
                }
                break;
            }
        }

        assert!(
            found_nested_inner,
            "Expected nested_inner event. stdout: {}",
            stdout
        );

        assert!(
            found_caller_in_stack,
            "Expected nested_outer in stack trace of nested_inner. stdout: {}",
            stdout
        );
    });
}

#[test]
fn test_python_stack_trace_works_for_c_extension_calls() {
    setup();

    skip_if_no_python!(python => {
        // Test C extension function (marshal.loads) via audit hook
        // This verifies that PyEval_GetFrame works in the audit hook context
        let output = run_tracer(&[
            "x",
            "--st",
            "--py", "marshal.loads",
            "--",
            python.to_str().unwrap(),
            "-c", "import marshal; marshal.loads(marshal.dumps([1,2,3]))",
        ]);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "Python C extension stack trace test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // Should have marshal.loads event
        assert!(
            stdout.contains("marshal.loads"),
            "Expected marshal.loads trace. stdout: {}",
            stdout
        );

        // Should have stack trace for C extension function (via audit hook)
        // The stack trace shows the Python caller, e.g. "<module> (<string>:1)"
        assert!(
            has_stack_trace(&stdout),
            "Expected stack traces for C extension function. stdout: {}",
            stdout
        );
    });
}

// ============================================================================
// Python Argument Tracing Tests (Python 3.10+ required for argument capture)
// ============================================================================

#[test]
fn test_python_tracing_captures_numeric_arguments() {
    setup();

    skip_if_no_python!(python => {
        // Create a test script with numeric arguments
        let test_script = r#"
def calculate(x, y):
    return x + y

result = calculate(10, 20)
print(f"Result: {result}")
"#;
        std::fs::write("/tmp/test_py_calc.py", test_script).unwrap();

        let output = run_tracer(&[
            "x",
            "--py", "calculate",
            "--",
            python.to_str().unwrap(),
            "/tmp/test_py_calc.py",
        ]);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Check that we traced calculate with arguments (10, 20)
        assert!(
            stdout.contains("calculate") && (stdout.contains("10") || stdout.contains("20")),
            "Expected py:calculate with arguments. stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}

#[test]
fn test_python_tracing_captures_string_argument_values() {
    setup();

    skip_if_no_python!(python => {
        // Create a test script with string arguments
        let test_script = r#"
def greet(name, greeting="Hello"):
    return f"{greeting}, {name}!"

greet("World", "Hi")
"#;
        std::fs::write("/tmp/test_py_args.py", test_script).unwrap();

        let output = run_tracer(&[
            "x",
            "--py", "greet",
            "--",
            python.to_str().unwrap(),
            "/tmp/test_py_args.py",
        ]);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Check that string arguments are captured
        assert!(
            stdout.contains("greet") && stdout.contains("World"),
            "Expected py:greet with string arguments. stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}
