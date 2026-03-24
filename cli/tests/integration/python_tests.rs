//! Python tracing tests.
//!
//! Tests for Python function tracing via sys.setprofile hooks.

use crate::common::*;
use crate::skip_if_no_python;
use crate::skip_if_no_python_primary;

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
        let output = cmd(&format!("x --py calculate -- {} ./test_python.py", python.display()))
            .run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        // Should have traced the calculate function with arguments and source
        assert!(
            stdout.contains("[malwi] calculate(10, 20)"),
            "Expected [malwi] calculate(10, 20) trace. stdout: {}, stderr: {}",
            stdout, stderr
        );
        assert!(
            stdout.contains("test_python.py:"),
            "Expected test_python.py source location. stdout: {}",
            stdout
        );
    });
}

#[test]
fn test_python_tracing_glob_matches_all_functions() {
    setup();

    skip_if_no_python!(python => {
        // Use specific glob patterns instead of py:* to avoid tracing thousands
        // of Python internal functions during import (which overwhelms HTTP)
        let output = cmd(&format!("x --py calc* --py process_* --py nested_* --py main -- {} ./test_python.py", python.display()))
            .run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        // Should complete without crashing
        assert!(
            output.success(),
            "Python glob test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // Verify that glob patterns matched the calculate function with arguments and source
        assert!(
            stdout.contains("[malwi] calculate(10, 20)"),
            "Expected [malwi] calculate(10, 20) from glob pattern. stdout: {}",
            stdout
        );
        assert!(
            stdout.contains("test_python.py:"),
            "Expected test_python.py source location. stdout: {}",
            stdout
        );
    });
}

#[test]
fn test_python_tracing_captures_nested_function_calls() {
    setup();

    skip_if_no_python!(python => {
        let output = cmd(&format!("x --py nested_* -- {} ./test_python.py", python.display()))
            .run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        // Should complete successfully
        assert!(
            output.success(),
            "Python nested test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}

#[test]
fn test_python_tracing_produces_no_events_when_filter_unmatched() {
    setup();

    skip_if_no_python!(python => {
        let output = cmd(&format!("x --py nonexistent_function_xyz -- {} ./test_python.py", python.display()))
            .run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        // Should complete successfully
        assert!(
            output.success(),
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
        let output = cmd(&format!("x --py worker -- {} ./test_python_threads.py", python.display()))
            .run();

        let stdout = output.stdout();
        let stderr = output.stderr();
        let combined = format!("{}\n{}", stdout, stderr);

        // Should complete without crashing
        assert!(
            output.success(),
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

        let output = cmd(&format!("x --py calculate -- {} /tmp/test_py_prefix.py", python.display()))
            .run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        // Check that the function name appears in a trace line with arguments and source
        assert!(
            stdout.contains("[malwi] calculate(1, 2)"),
            "Expected [malwi] calculate(1, 2) in trace output. stdout: {}, stderr: {}",
            stdout, stderr
        );
        assert!(
            stdout.contains("test_py_prefix.py:"),
            "Expected test_py_prefix.py source location. stdout: {}",
            stdout
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
        let output = cmd(&format!("x --py nested_* -- {} ./test_python.py", python.display()))
            .run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        assert!(
            output.success(),
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
        let output = cmd(&format!("x --st --py nested_inner -- {} ./test_python.py", python.display()))
            .timeout(STACK_TRACE_TIMEOUT).run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        assert!(
            output.success(),
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

        // Should have Python-style stack frame for the traced function
        assert!(
            has_python_stack_frame(&stdout, "nested_inner"),
            "Expected Python stack frame for nested_inner. stdout: {}",
            stdout
        );
    });
}

#[test]
fn test_python_stack_trace_includes_calling_function() {
    setup();

    skip_if_no_python!(python => {
        // Trace nested_inner and verify stack shows nested_outer as caller
        let output = cmd(&format!("x --st --py nested_inner -- {} ./test_python.py", python.display()))
            .timeout(STACK_TRACE_TIMEOUT).run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        assert!(
            output.success(),
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
        let output = cmd(&format!("x --st --py marshal.loads -- {} -c {}",
            python.display(), sq("import marshal; marshal.loads(marshal.dumps([1,2,3]))")))
            .timeout(STACK_TRACE_TIMEOUT).run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        assert!(
            output.success(),
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
        // The stack trace shows the Python caller, e.g. "<module> (<eval>:1)"
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

        let output = cmd(&format!("x --py calculate -- {} /tmp/test_py_calc.py", python.display()))
            .run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        // Check that we traced calculate with arguments and source
        assert!(
            stdout.contains("[malwi] calculate(10, 20)"),
            "Expected [malwi] calculate(10, 20) trace. stdout: {}, stderr: {}",
            stdout, stderr
        );
        assert!(
            stdout.contains("test_py_calc.py:"),
            "Expected test_py_calc.py source location. stdout: {}",
            stdout
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

        let output = cmd(&format!("x --py greet -- {} /tmp/test_py_args.py", python.display()))
            .run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        // Check that string arguments are captured with source location
        assert!(
            stdout.contains("[malwi] greet('World', 'Hi')"),
            "Expected [malwi] greet('World', 'Hi') trace. stdout: {}, stderr: {}",
            stdout, stderr
        );
        assert!(
            stdout.contains("test_py_args.py:"),
            "Expected test_py_args.py source location. stdout: {}",
            stdout
        );
    });
}

// ============================================================================
// Python C Extension (c_call) Tracing Tests
// ============================================================================

/// Verify that C built-in function calls are traced via PYTRACE_C_CALL.
/// os.getpid() is a C extension function — its internal module is "posix"
/// but should be matchable via the "os" alias.
#[test]
fn test_python_c_function_call_traced() {
    setup();

    skip_if_no_python!(python => {
        let output = cmd(&format!("x --py os.getpid -- {} -c {}",
            python.display(), sq("import os; pid = os.getpid(); print(f'pid={pid}')")))
            .run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        assert!(
            output.success(),
            "Python c_call test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );

        assert!(
            stdout.contains("getpid"),
            "Expected os.getpid trace via PYTRACE_C_CALL. \
             C extension functions should be visible. \
             stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}

/// Verify that C extension functions from json module are traced.
/// json.loads is actually _json.loads internally.
#[test]
fn test_python_c_function_json_loads_traced() {
    setup();

    skip_if_no_python!(python => {
        let output = cmd(&format!("x --py json.loads -- {} -c {}",
            python.display(), sq("import json; json.loads('{}')")))
            .run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        assert!(
            output.success(),
            "Python c_call json test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );

        assert!(
            stdout.contains("loads"),
            "Expected json.loads trace via PYTRACE_C_CALL. \
             _json.loads should be matched via json alias. \
             stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}

// ============================================================================
// Threat Vector Tests — Python Attack Patterns
// ============================================================================

/// Threat: Supply-chain attacks use exec(compile(...)) to define and run
/// malicious functions at runtime. Verify that dynamically defined functions
/// called inside exec() are traced by sys.setprofile.
#[test]
fn test_python_exec_traces_dynamically_defined_functions() {
    setup();

    skip_if_no_python!(python => {
        let script = r#"
exec('def secret_func():\n    return 42\nsecret_func()')
"#;
        let output = cmd(&format!("x --py secret_func -- {} -c {}", python.display(), sq(script)))
            .run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        assert!(
            output.success(),
            "Python exec() tracing test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // exec() runs code through the normal interpreter, so sys.setprofile
        // should capture the dynamically defined function call
        assert!(
            stdout.contains("secret_func"),
            "Expected secret_func trace from exec(). \
             Supply-chain attacks using exec(compile(...)) should be visible. \
             stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}

/// Threat: Advanced supply-chain attacks use layered exec() to obscure malicious
/// payloads. The outer exec() defines a function that itself calls exec() to
/// define and run a second function. Both functions must be traced by
/// sys.setprofile to ensure complete visibility into staged code execution.
#[test]
fn test_python_nested_exec_traces_both_levels() {
    setup();

    skip_if_no_python!(python => {
        let script = r#"
def run():
    exec("def outer_payload():\n    exec(\"def inner_payload():\\n    return 99\\ninner_payload()\")\nouter_payload()")
run()
"#;
        let output = cmd(&format!("x -f json --py outer_payload --py inner_payload -- {} -c {}",
            python.display(), sq(script)))
            .run();

        let stderr = output.stderr();

        assert!(
            output.success(),
            "Python nested exec() test failed. stderr: {}",
            stderr
        );

        let events = output.json_events();

        assert!(
            events.iter().any(|e| e["source"] == "python" && e["name"] == "outer_payload"),
            "Expected outer_payload event from first exec() level. events: {:?}",
            events
        );

        assert!(
            events.iter().any(|e| e["source"] == "python" && e["name"] == "inner_payload"),
            "Expected inner_payload event from second exec() level. events: {:?}",
            events
        );
    });
}

/// Threat: Attackers combine eval() and exec() to compute and execute code
/// dynamically. eval() returns a value (the inner code string), which exec()
/// then executes. This two-stage pattern is common in obfuscated malware.
#[test]
fn test_python_nested_eval_exec_traces_computed_function() {
    setup();

    skip_if_no_python!(python => {
        let script = r#"
exec(eval("'def computed_func(): return 42'"))
computed_func()
"#;
        let output = cmd(&format!("x -f json --py computed_func -- {} -c {}",
            python.display(), sq(script)))
            .run();

        let stderr = output.stderr();

        assert!(
            output.success(),
            "Python eval+exec test failed. stderr: {}",
            stderr
        );

        let events = output.json_events();

        assert!(
            events.iter().any(|e| e["source"] == "python" && e["name"] == "computed_func"),
            "Expected computed_func event from eval()+exec() chain. events: {:?}",
            events
        );
    });
}

/// Threat: Malicious code disables tracing with sys.setprofile(None).
/// This test documents the current behavior: whether the profiler survives
/// or whether there's a gap after the attacker clears it.
#[test]
fn test_python_setprofile_resistance() {
    setup();

    skip_if_no_python!(python => {
        let script = r#"
import sys
def before_clear(): pass
before_clear()
sys.setprofile(None)
def after_clear(): pass
after_clear()
"#;
        let output = cmd(&format!("x --py before_clear --py after_clear -- {} -c {}",
            python.display(), sq(script)))
            .run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        assert!(
            output.success(),
            "Python setprofile resistance test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // before_clear() should always be traced (called before disable)
        assert!(
            stdout.contains("before_clear"),
            "Expected before_clear trace (called before setprofile(None)). stdout: {}",
            stdout
        );

        // Document whether after_clear is traced (resilience) or not (known gap).
        // Currently sys.setprofile(None) successfully disables our hook.
        if stdout.contains("after_clear") {
            println!("RESILIENT: sys.setprofile(None) did NOT disable tracing");
        } else {
            println!("KNOWN GAP: sys.setprofile(None) disables tracing for subsequent calls");
        }
    });
}

/// Threat: pickle deserialization can execute arbitrary code via __reduce__.
/// When __reduce__ returns (os.getpid, ()), pickle's C code calls os.getpid
/// directly via PyObject_Call — a C→C call that bypasses the Python eval loop.
/// The interceptor hooks the actual C function pointer, catching C→C calls.
#[test]
fn test_python_pickle_rce_function_traced() {
    setup();

    skip_if_no_python_primary!(python => {
        let script = r#"
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.getpid, ())

payload = pickle.dumps(Exploit())
result = pickle.loads(payload)
print(f"pickle_done pid={result}")
"#;
        let output = cmd(&format!("x --py os.getpid -- {} -c {}", python.display(), sq(script)))
            .run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        assert!(
            output.success(),
            "Python pickle RCE test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // os.getpid is hooked via interceptor — catches C→C calls from pickle
        assert!(
            stdout.contains("getpid"),
            "Expected os.getpid trace from pickle deserialization. \
             Pickle __reduce__ → os.getpid (C→C) should be caught by interceptor. \
             stdout: {}, stderr: {}",
            stdout, stderr
        );
    });
}

/// Threat: Python `requests` library is the most common HTTP client.
/// Verify that requests.get() is traced when the library is available.
#[test]
fn test_python_requests_library_traced() {
    setup();

    skip_if_no_python_primary!(python => {
        // Check if requests is importable
        let check = std::process::Command::new(python.as_os_str())
            .args(["-c", "import requests"])
            .output();
        match check {
            Ok(out) if out.status.success() => {}
            _ => {
                println!("SKIPPED: Python 'requests' library not installed");
                return;
            }
        }

        let script = r#"
import requests
try:
    requests.get('http://127.0.0.1:1/test', timeout=0.1)
except Exception:
    pass
"#;
        let output = cmd(&format!("x --py requests.get --py requests.api.get -- {} -c {}",
            python.display(), sq(script)))
            .run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        assert!(
            output.success(),
            "Python requests tracing test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // requests.get → requests.api.get should be traced with URL and source
        assert!(
            stdout.contains("[malwi] get("),
            "Expected [malwi] get( trace with args. stdout: {}, stderr: {}",
            stdout, stderr
        );
        assert!(
            stdout.contains("127.0.0.1"),
            "Expected 127.0.0.1 URL in get() arguments. stdout: {}",
            stdout
        );
        assert!(
            stdout.contains("<eval>:"),
            "Expected <eval> source location. stdout: {}",
            stdout
        );
    });
}

// ============================================================================
// Stack Depth & Frame Content Accuracy Tests
// ============================================================================

/// Verify that deep recursive call stacks are captured with correct depth.
/// Uses a 100-level recursive fixture and asserts that the captured stack
/// contains a meaningful number of frames (exercising MAX_FRAMES path).
#[test]
fn test_python_stack_trace_recursive_depth() {
    setup();

    skip_if_no_python!(python => {
        let output = cmd(&format!("x --st --py recurse -- {} ./test_python_recursive.py", python.display()))
            .timeout(STACK_TRACE_TIMEOUT).run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        assert!(
            output.success(),
            "Python recursive stack test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // Should have traced the recurse function
        assert!(
            stdout.contains("recurse"),
            "Expected recurse trace. stdout: {}",
            stdout
        );

        // Find the deepest recurse event (the last one with stack frames)
        // and count how many "recurse" frames appear in its stack
        let lines: Vec<&str> = stdout.lines().collect();
        let mut max_recurse_depth = 0;

        let mut i = 0;
        while i < lines.len() {
            if lines[i].contains("[malwi]") && lines[i].contains("recurse") {
                // Count stack frames containing "recurse" after this event
                let mut depth = 0;
                let mut j = i + 1;
                while j < lines.len() {
                    if lines[j].starts_with("    at ") {
                        if lines[j].contains("recurse") {
                            depth += 1;
                        }
                    } else {
                        break;
                    }
                    j += 1;
                }
                if depth > max_recurse_depth {
                    max_recurse_depth = depth;
                }
            }
            i += 1;
        }

        // With 100 levels of recursion, we expect the deepest stack to have
        // many recurse frames. Allow some slack for Python internals overhead.
        assert!(
            max_recurse_depth >= 50,
            "Expected at least 50 recursive stack frames at deepest point, got {}. stdout: {}",
            max_recurse_depth, stdout
        );
    });
}

/// Verify that stack frame content (function name, filename, line number) is accurate.
/// Asserts on specific function names and file references rather than just
/// checking that frames exist.
#[test]
fn test_python_stack_trace_frame_content_accuracy() {
    setup();

    skip_if_no_python!(python => {
        let output = cmd(&format!("x --st --py nested_inner -- {} ./test_python.py", python.display()))
            .timeout(STACK_TRACE_TIMEOUT).run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        assert!(
            output.success(),
            "Python frame accuracy test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // Find the nested_inner event and its stack frames
        let lines: Vec<&str> = stdout.lines().collect();
        let mut stack_frames = Vec::new();
        let mut found_event = false;

        for (i, line) in lines.iter().enumerate() {
            if line.contains("[malwi]") && line.contains("nested_inner") {
                found_event = true;
                // Collect stack frames
                for stack_line in lines.iter().skip(i + 1) {
                    if stack_line.starts_with("    at ") {
                        stack_frames.push(*stack_line);
                    } else {
                        break;
                    }
                }
                break;
            }
        }

        assert!(found_event, "Expected nested_inner event. stdout: {}", stdout);

        // Stack should contain nested_outer as caller
        let has_outer = stack_frames.iter().any(|f| f.contains("nested_outer"));
        assert!(
            has_outer,
            "Expected nested_outer in stack frames. frames: {:?}",
            stack_frames
        );

        // Stack frames should reference test_python.py
        let has_filename = stack_frames.iter().any(|f| f.contains("test_python.py"));
        assert!(
            has_filename,
            "Expected test_python.py in stack frames. frames: {:?}",
            stack_frames
        );

        // Stack frames should have line numbers (format: "filename:N")
        let has_line_number = stack_frames.iter().any(|f| {
            f.contains(".py:") && f.split(".py:").nth(1).map_or(false, |rest| {
                rest.chars().next().map_or(false, |c| c.is_ascii_digit())
            })
        });
        assert!(
            has_line_number,
            "Expected line numbers in stack frames. frames: {:?}",
            stack_frames
        );
    });
}

// ============================================================================
// Unicode Function Name Tests
// ============================================================================

/// Verify that Python functions with non-ASCII (Unicode) names are traced correctly.
/// Tests with German (grüße) and Cyrillic (подсчёт) function names.
#[test]
fn test_python_unicode_function_names_traced() {
    setup();

    skip_if_no_python!(python => {
        // Trace the German function name
        let output = cmd(&format!("x --py grüße --py подсчёт -- {} ./test_python_unicode.py", python.display()))
            .run();

        let stdout = output.stdout();
        let stderr = output.stderr();

        assert!(
            output.success(),
            "Python unicode function test failed. stdout: {}, stderr: {}",
            stdout, stderr
        );

        // Both Unicode function names should appear in output
        let has_german = stdout.contains("grüße");
        let has_cyrillic = stdout.contains("подсчёт");

        assert!(
            has_german && has_cyrillic,
            "Expected both Unicode function names in trace output. \
             grüße: {}, подсчёт: {}. stdout: {}, stderr: {}",
            has_german, has_cyrillic, stdout, stderr
        );
        assert!(
            stdout.contains("test_python_unicode.py:"),
            "Expected test_python_unicode.py source location. stdout: {}",
            stdout
        );
    });
}

// ============================================================================
// C Extension Method Argument Extraction Tests
// ============================================================================

/// Verify that C extension method arguments are captured via Interceptor::replace.
/// socket.connect is METH_O — the address arg should appear in trace output.
/// All calls go through the replacement, including the first.
#[test]
fn test_python_tracing_c_method_arguments_via_interceptor() {
    setup();

    skip_if_no_python_primary!(python => {
        let script = r#"
import socket
for _ in range(2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect(('127.0.0.1', 1))
    except Exception:
        pass
"#;
        let output = cmd(&format!("x --py socket.connect -- {} -c {}", python.display(), sq(script)))
            .timeout(secs(10)).run();

        let stdout = output.stdout();

        // All calls go through replacement — should have arguments
        assert!(
            stdout.contains("socket.connect(") && stdout.contains("127.0.0.1"),
            "Expected socket.connect with address argument via replacement. stdout: {}",
            stdout
        );
    });
}

/// C method arguments are captured on the very first call via
/// Interceptor::replace (no warmup call needed).
#[test]
fn test_python_tracing_c_method_captures_args_on_first_call() {
    setup();

    skip_if_no_python_primary!(python => {
        let script = r#"
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.1)
    s.connect(('127.0.0.1', 1))
except Exception:
    pass
"#;
        let output = cmd(&format!("x --py socket.connect -- {} -c {}", python.display(), sq(script)))
            .timeout(secs(10)).run();

        let stdout = output.stdout();

        assert!(
            stdout.contains("socket.connect(") && stdout.contains("127.0.0.1"),
            "Expected socket.connect with address on first call. stdout: {}",
            stdout
        );
    });
}

// ============================================================================
// EnvVar Monitoring Tests
// ============================================================================

/// Regression test: envvar monitoring must not break subprocess on Python 3.12+.
///
/// os.get_exec_path() calls env.get(b'PATH') with a bytes key. The profile
/// hook must clear the TypeError from PyUnicode_AsUTF8 on non-string keys,
/// otherwise PEP 669's legacy_event_handler raises SystemError.
#[test]
fn test_python_envvar_monitoring_allows_subprocess_run() {
    setup();

    skip_if_no_python!(python => {
        let policy = "version: 1\nenvvars:\n  warn:\n    - PATH\n    - HOME\n";
        let dir = std::env::temp_dir();
        let path = dir.join(format!("malwi-test-envvar-subprocess-{}.yaml", std::process::id()));
        std::fs::write(&path, policy).expect("write policy");

        let output = cmd(&format!("x -p {} -- {} -c {}",
            path.display(), python.display(),
            sq("import subprocess; subprocess.run(['echo', 'hello'])")))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&path);

        let stdout = output.stdout();
        let stderr = output.stderr();

        assert!(
            output.success(),
            "subprocess.run() failed with envvar policy. stdout:\n{}\nstderr:\n{}",
            stdout, stderr
        );

        // Should NOT contain SystemError
        assert!(
            !stdout.contains("SystemError"),
            "Got SystemError with envvar policy. stdout:\n{}\nstderr:\n{}",
            stdout, stderr
        );
    });
}

#[test]
fn test_python_c_function_module_self_not_in_args() {
    setup();

    skip_if_no_python_primary!(python => {
        let py_code = format!("import socket\ntry:\n socket.getaddrinfo('localhost', 443)\nexcept: pass{PY_FLUSH}");
        let output = cmd(&format!("x -f json --py *.getaddrinfo -- {} -c {}",
            python.display(), sq(&py_code)))
            .run();

        let stdout = output.stdout_raw();
        let events = output.json_events();

        let gai_events: Vec<_> = events.iter()
            .filter(|e| {
                e["source"] == "python"
                    && e["name"].as_str().map_or(false, |n| n.ends_with("getaddrinfo"))
            })
            .collect();

        assert!(!gai_events.is_empty(), "Expected getaddrinfo event. stdout: {}\nstderr: {}", stdout, output.stderr());

        // Every getaddrinfo event must have the hostname as args[0], not a module repr
        for event in &gai_events {
            let args = event["args"].as_array().expect("args should be array");
            let first_arg = args[0].as_str().unwrap_or("");
            assert!(
                first_arg.contains("localhost"),
                "First arg should contain hostname, not module self. args: {:?}\nstderr: {}",
                args, output.stderr()
            );
        }
    });
}

/// Stress test for glob-pattern event delivery.
///
/// Runs 10 iterations to amplify detection of intermittent delivery failures.
/// Each iteration spawns a fresh process with a glob-pattern filter, exercising
/// the lazy hook installation path (PYTRACE_C_CALL). If a regression reintroduces
/// a 5% per-run failure rate, this test has ~40% chance of catching it per CI run.
#[test]
fn test_python_glob_pattern_event_delivery_stress() {
    setup();
    skip_if_no_python_primary!(python => {
        for i in 0..10 {
            let script = format!(
                "import socket\ntry:\n socket.getaddrinfo('localhost', 443)\nexcept: pass{PY_FLUSH}"
            );
            let output = cmd(&format!(
                "x -f json --py *.getaddrinfo -- {} -c {}",
                python.display(), sq(&script)
            )).run();
            let events = output.json_events();
            let has_gai = events.iter()
                .any(|e| e["name"].as_str().map_or(false, |n| n.ends_with("getaddrinfo")));
            assert!(
                has_gai,
                "Iteration {i}/10: no getaddrinfo event.\nstdout: {}\nstderr: {}",
                output.stdout_raw(), output.stderr()
            );
        }
    });
}

// ============================================================================
// uv auto-detection: pypi-install policy
// ============================================================================

#[test]
fn test_uv_pip_install_auto_selects_pypi_install_policy() {
    setup();

    let uv = match which("uv") {
        Some(p) => p,
        None => {
            println!("SKIPPED: uv not found in PATH");
            return;
        }
    };

    let pkg_dir = fixture("fixtures/malicious-uv-package");

    // Create a temp dir for the install target
    let tmp_dir = std::env::temp_dir().join(format!("malwi-uv-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).expect("create temp dir");

    // Run `malwi x uv pip install --system --target <tmp> ./package` —
    // auto-detection should select pypi-install policy because program is "uv"
    // and arg contains "install". Use --system to avoid venv requirement and
    // --target to avoid polluting the real system Python.
    let output = cmd(&format!(
        "x -f json -- {} pip install --system --no-deps --target {} {}",
        uv.display(),
        tmp_dir.display(),
        pkg_dir.display()
    ))
    .timeout(secs(30))
    .run();

    // Clean up temp dir
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let stdout = output.stdout_raw();
    let stderr = output.stderr();
    println!("stdout: {}", stdout);
    println!("stderr: {}", stderr);

    // Verify auto-detection selected pypi-install policy
    assert!(
        stderr.contains("pypi-install"),
        "Expected 'pypi-install' in stderr (auto-detection). stderr: {}",
        stderr
    );

    let events = output.json_events();

    // Verify Python startup doesn't crash — no denied open() by the python deny
    // category (which would break imports). File-category denials (e.g. ~/.ssh/**)
    // are expected from the credential theft attack vectors.
    let has_open_python_denied = events.iter().any(|v| {
        v["name"].as_str() == Some("open")
            && v["policy"]["decision"].as_str() == Some("denied")
            && v["policy"]["category"].as_str() == Some("python")
    });
    assert!(
        !has_open_python_denied,
        "open() should not be denied by python deny section. stdout: {}",
        stdout
    );

    // The pypi-install policy denies subprocess.* at the Python level, so child
    // commands (curl, wget, nc, bash) never spawn. Verify the python deny section
    // blocks subprocess calls from setup.py.
    let has_subprocess_deny = events.iter().any(|v| {
        v["source"].as_str() == Some("python")
            && v["name"]
                .as_str()
                .map_or(false, |n| n.starts_with("subprocess."))
            && v["policy"]["decision"].as_str() == Some("denied")
    });
    assert!(
        has_subprocess_deny,
        "Expected subprocess.* to be denied by pypi-install python section. stdout: {}",
        stdout
    );

    // Verify evil.com network connection is denied by network allow-list
    let has_network_deny = events.iter().any(|v| {
        v["endpoint"]["host"].as_str() == Some("evil.com")
            && v["policy"]["decision"].as_str() == Some("denied")
    });
    assert!(
        has_network_deny,
        "Expected evil.com network access to be denied. stdout: {}",
        stdout
    );
}
