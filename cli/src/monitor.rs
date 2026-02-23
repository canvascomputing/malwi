//! Monitor server for receiving trace events over HTTP.
//!
//! The monitor runs in a separate terminal and displays trace events sent from
//! `malwi x --monitor` sessions, keeping the traced application's output clean.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use malwi_protocol::{EventType, HookType, RuntimeStack, TraceEvent};

use crate::{display_name, DIM, LIGHT_BLUE, RED, RESET, YELLOW};

/// Global flag for SIGINT handler to signal shutdown.
static MONITOR_SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigint(_sig: libc::c_int) {
    MONITOR_SHUTDOWN.store(true, Ordering::SeqCst);
    // Write message directly (write() is async-signal-safe)
    let msg = b"\n\x1b[93m[malwi monitor]\x1b[0m Shutting down...\n";
    unsafe {
        libc::write(
            libc::STDOUT_FILENO,
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
        )
    };
    // _exit is async-signal-safe
    unsafe { libc::_exit(0) };
}

// =============================================================================
// HTTP REQUEST BODIES
// =============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionStartRequest {
    pub session_id: String,
    pub command: Vec<String>,
    pub pid: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EventRequest {
    pub session_id: String,
    pub event: TraceEvent,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionEndRequest {
    pub session_id: String,
    pub exit_code: Option<i32>,
}

// =============================================================================
// MONITOR SERVER
// =============================================================================

/// Run the monitor HTTP server.
pub fn run_monitor(port: u16, show_stack: bool) -> Result<()> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr)
        .map_err(|e| anyhow::anyhow!("Failed to bind to {}: {}", addr, e))?;

    println!(
        "{}[malwi monitor]{} Listening on http://{}",
        YELLOW, RESET, addr
    );
    println!("Run 'malwi x --monitor <program>' in another terminal to trace.");
    println!("Press Ctrl+C to stop.\n");

    // Set up Ctrl+C handler via SIGINT
    unsafe {
        libc::signal(
            libc::SIGINT,
            handle_sigint as *const () as libc::sighandler_t,
        );
    }

    // Main request loop
    for stream in listener.incoming() {
        if MONITOR_SHUTDOWN.load(Ordering::SeqCst) {
            break;
        }

        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };

        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));

        if let Err(e) = handle_monitor_request(&mut stream, show_stack) {
            log::debug!("Monitor request error: {}", e);
        }
    }

    Ok(())
}

/// Parse a single HTTP request from a stream and handle it.
fn handle_monitor_request(stream: &mut TcpStream, show_stack: bool) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);

    // Read request line
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }
    let method = parts[0];
    let url = parts[1];

    // Read headers
    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.trim().is_empty() {
            break;
        }
        if line.to_ascii_lowercase().starts_with("content-length:") {
            if let Some(val) = line.split(':').nth(1) {
                content_length = val.trim().parse().unwrap_or(0);
            }
        }
    }

    // Read body
    let body = if content_length > 0 {
        let mut buf = vec![0u8; content_length];
        reader.read_exact(&mut buf)?;
        String::from_utf8_lossy(&buf).to_string()
    } else {
        String::new()
    };

    match (method, url) {
        ("GET", "/health") => {
            respond_ok(stream)?;
        }
        ("POST", "/session/start") => match serde_json::from_str::<SessionStartRequest>(&body) {
            Ok(req) => {
                println!(
                    "{}[session:{}]{} Started: {} (PID {})",
                    YELLOW,
                    &req.session_id[..8.min(req.session_id.len())],
                    RESET,
                    req.command.join(" "),
                    req.pid
                );
                respond_ok(stream)?;
            }
            Err(e) => {
                respond_error(stream, &format!("Invalid JSON: {}", e))?;
            }
        },
        ("POST", "/event") => match serde_json::from_str::<EventRequest>(&body) {
            Ok(req) => {
                print_trace_event(&req.event, show_stack, Some(req.session_id.as_str()));
                respond_ok(stream)?;
            }
            Err(e) => {
                respond_error(stream, &format!("Invalid JSON: {}", e))?;
            }
        },
        ("POST", "/session/end") => match serde_json::from_str::<SessionEndRequest>(&body) {
            Ok(req) => {
                println!(
                    "{}[session:{}]{} Ended (exit code: {:?})",
                    YELLOW,
                    &req.session_id[..8.min(req.session_id.len())],
                    RESET,
                    req.exit_code
                );
                respond_ok(stream)?;
            }
            Err(e) => {
                respond_error(stream, &format!("Invalid JSON: {}", e))?;
            }
        },
        _ => {
            let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
            stream.write_all(response.as_bytes())?;
        }
    }

    Ok(())
}

fn respond_ok(stream: &mut TcpStream) -> Result<()> {
    let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    stream.write_all(response.as_bytes())?;
    Ok(())
}

fn respond_error(stream: &mut TcpStream, msg: &str) -> Result<()> {
    let response = format!(
        "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n{}",
        msg.len(),
        msg
    );
    stream.write_all(response.as_bytes())?;
    Ok(())
}

/// Print a trace event to stdout.
fn print_trace_event(event: &TraceEvent, show_stack: bool, session_prefix: Option<&str>) {
    // Only print ENTER events
    if !matches!(event.event_type, EventType::Enter) {
        return;
    }

    let func = &event.function;
    let is_blocked = func.starts_with("BLOCKED ");
    let is_warn = func.starts_with("WARN ");
    let color = if is_blocked {
        RED
    } else if is_warn {
        YELLOW
    } else {
        LIGHT_BLUE
    };

    // For BLOCKED/WARN events sent from the CLI, parse and reformat
    let (display_func, policy_info) = if is_blocked {
        parse_prefixed_event(func, "BLOCKED ")
    } else if is_warn {
        parse_prefixed_event(func, "WARN ")
    } else {
        (display_name(func), None)
    };

    let tag = if let Some(session_id) = session_prefix {
        format!("[{}]", &session_id[..8.min(session_id.len())])
    } else {
        "[malwi]".to_string()
    };

    let src = crate::format_source_location(&event.source_file, event.source_line);

    if let Some((section, rule)) = policy_info {
        let action = if is_blocked { "denied" } else { "warning" };
        println!(
            "{}{}  {} {}:{} {} {}'{}'{}",
            color, tag, section, action, RESET, display_func, DIM, rule, RESET
        );
    } else if event.hook_type == HookType::Exec {
        // Exec: "cmd arg1 arg2" style (skip argv[0] which is the function name)
        let start = 1.min(event.arguments.len());
        let args: Vec<String> = event.arguments[start..]
            .iter()
            .filter_map(|a| a.display.clone())
            .collect();
        let args_str = crate::shell_format::format_shell_command(&args, 200);
        if args_str.is_empty() {
            println!("{}{}{}  {}{}", color, tag, RESET, display_func, src);
        } else {
            println!(
                "{}{}{}  {} {}{}{}{}",
                color, tag, RESET, display_func, DIM, args_str, RESET, src
            );
        }
    } else {
        // Function call: "func(arg1, arg2)" style
        let args: Vec<String> = event
            .arguments
            .iter()
            .map(|a| {
                a.display
                    .clone()
                    .unwrap_or_else(|| format!("{:#x}", a.raw_value))
            })
            .collect();
        let args_str = args.join(", ");

        if args_str.is_empty() {
            println!("{}{}{}  {}{}", color, tag, RESET, display_func, src);
        } else {
            println!(
                "{}{}{}  {}{}({}){}{}",
                color, tag, RESET, display_func, DIM, args_str, RESET, src
            );
        }
    }

    // Print stack traces if enabled
    if show_stack {
        // Native stack frames (raw addresses — not resolved in monitor)
        for &addr in &event.native_stack {
            println!("{}    at {:#x}{}", DIM, addr, RESET);
        }

        // Runtime stack frames
        match &event.runtime_stack {
            Some(RuntimeStack::Python(frames)) => {
                for frame in frames {
                    println!(
                        "{}    at {} ({}:{}){}",
                        DIM, frame.function, frame.filename, frame.line, RESET
                    );
                }
            }
            Some(RuntimeStack::Nodejs(frames)) => {
                for frame in frames {
                    println!(
                        "{}    at {} ({}:{}:{}){}",
                        DIM, frame.function, frame.script, frame.line, frame.column, RESET
                    );
                }
            }
            None => {}
        }
    }
}

/// Parse a "BLOCKED func (policy: section rule 'rule')" or "WARN func (...)" string.
/// Returns (display_name, Option<(section, rule)>).
fn parse_prefixed_event<'a>(func: &'a str, prefix: &str) -> (&'a str, Option<(&'a str, &'a str)>) {
    let rest = &func[prefix.len()..];
    // Try to parse "(policy: section rule 'rule')"
    if let Some(paren_pos) = rest.find(" (policy: ") {
        let name_part = &rest[..paren_pos];
        let policy_part = &rest[paren_pos + 10..]; // skip " (policy: "
                                                   // Parse "section rule 'rule')"
        if let Some(rule_pos) = policy_part.find(" rule '") {
            let section = &policy_part[..rule_pos];
            let rule_start = rule_pos + 7; // skip " rule '"
            if let Some(rule_end) = policy_part[rule_start..].find("')") {
                let rule = &policy_part[rule_start..rule_start + rule_end];
                return (display_name(name_part), Some((section, rule)));
            }
        }
        (display_name(name_part), None)
    } else {
        (display_name(rest), None)
    }
}
