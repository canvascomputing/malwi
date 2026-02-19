//! Monitor server for receiving trace events over HTTP.
//!
//! The monitor runs in a separate terminal and displays trace events sent from
//! `malwi x --monitor` sessions, keeping the traced application's output clean.

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tiny_http::{Response, Server};

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
    let server =
        Server::http(&addr).map_err(|e| anyhow::anyhow!("Failed to bind to {}: {}", addr, e))?;

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
    for request in server.incoming_requests() {
        if MONITOR_SHUTDOWN.load(Ordering::SeqCst) {
            break;
        }

        let url = request.url().to_string();
        let method = request.method().to_string();

        match (method.as_str(), url.as_str()) {
            ("GET", "/health") => {
                let response = Response::from_string("OK");
                let _ = request.respond(response);
            }
            ("POST", "/session/start") => match read_json_body::<SessionStartRequest>(request) {
                Ok((req, request)) => {
                    println!(
                        "{}[session:{}]{} Started: {} (PID {})",
                        YELLOW,
                        &req.session_id[..8.min(req.session_id.len())],
                        RESET,
                        req.command.join(" "),
                        req.pid
                    );
                    let _ = request.respond(Response::from_string("OK"));
                }
                Err((e, request)) => {
                    let _ = request.respond(
                        Response::from_string(format!("Error: {}", e)).with_status_code(400),
                    );
                }
            },
            ("POST", "/event") => match read_json_body::<EventRequest>(request) {
                Ok((req, request)) => {
                    print_trace_event(&req.event, show_stack, Some(req.session_id.as_str()));
                    let _ = request.respond(Response::from_string("OK"));
                }
                Err((e, request)) => {
                    let _ = request.respond(
                        Response::from_string(format!("Error: {}", e)).with_status_code(400),
                    );
                }
            },
            ("POST", "/session/end") => match read_json_body::<SessionEndRequest>(request) {
                Ok((req, request)) => {
                    println!(
                        "{}[session:{}]{} Ended (exit code: {:?})",
                        YELLOW,
                        &req.session_id[..8.min(req.session_id.len())],
                        RESET,
                        req.exit_code
                    );
                    let _ = request.respond(Response::from_string("OK"));
                }
                Err((e, request)) => {
                    let _ = request.respond(
                        Response::from_string(format!("Error: {}", e)).with_status_code(400),
                    );
                }
            },
            _ => {
                let _ = request.respond(Response::from_string("Not Found").with_status_code(404));
            }
        }
    }

    Ok(())
}

/// Read and parse JSON body from request.
#[allow(clippy::result_large_err)]
fn read_json_body<T: for<'de> Deserialize<'de>>(
    mut request: tiny_http::Request,
) -> std::result::Result<(T, tiny_http::Request), (String, tiny_http::Request)> {
    let mut body = String::new();
    if let Err(e) = request.as_reader().read_to_string(&mut body) {
        return Err((format!("Failed to read body: {}", e), request));
    }
    match serde_json::from_str(&body) {
        Ok(parsed) => Ok((parsed, request)),
        Err(e) => Err((format!("Invalid JSON: {}", e), request)),
    }
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
    } else if event.hook_type == HookType::DirectSyscall {
        RED
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
