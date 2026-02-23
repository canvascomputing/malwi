//! Python audit hook (PEP 578) registration.
//!
//! The audit hook serves two purposes:
//! 1. Triggers deferred profile hook registration when filters are present
//! 2. Logs Python runtime events that match registered filters

use std::ffi::c_void;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use log::{debug, error};

use crate::exec::SpawnHandler;
use crate::native;

use super::ffi::{init_python_api, PyAuditHookFunction, PySys_AddAuditHookFn, PYTHON_API};
use super::filters::{has_any_filters, matches_filter};
use super::helpers::{cstr_to_string, extract_tuple_arguments};
use super::profile::{do_register_profile_hook, set_thread_created, PROFILE_HOOK_REGISTERED};
use super::stack::capture_current_python_stack;

static AUDIT_HOOK_REGISTERED: AtomicBool = AtomicBool::new(false);
static AUDIT_REG_TASK_STARTED: AtomicBool = AtomicBool::new(false);

/// Best-effort background task to register the audit hook once Python is ready.
///
/// In some environments the agent is loaded very early (dyld constructor), and
/// Python's exported symbols may not be visible yet. Retrying avoids missing
/// subprocess audit events when exec filters are configured.
pub fn start_audit_registration_task() {
    if AUDIT_HOOK_REGISTERED.load(Ordering::SeqCst) {
        return;
    }
    if AUDIT_REG_TASK_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }

    std::thread::spawn(|| {
        // Bound the retry window to avoid an unkillable background loop.
        for _ in 0..100 {
            if AUDIT_HOOK_REGISTERED.load(Ordering::SeqCst) {
                break;
            }
            if register_audit_hook() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
}

/// Get the current Python frame, or null if PyEval_GetFrame is unavailable.
///
/// # Safety
/// Caller must ensure GIL is held.
unsafe fn get_current_frame() -> *mut c_void {
    match PYTHON_API.get().and_then(|api| api.eval_get_frame) {
        Some(eval_get_frame) => eval_get_frame(),
        None => std::ptr::null_mut(),
    }
}

#[allow(unreachable_code)]
fn capture_native_stack_for_exec(capture_stack: bool) -> Vec<usize> {
    if !capture_stack {
        return Vec::new();
    }

    #[cfg(target_arch = "aarch64")]
    unsafe {
        let fp: u64;
        let lr: u64;
        core::arch::asm!("mov {}, x29", out(reg) fp);
        core::arch::asm!("mov {}, x30", out(reg) lr);
        let ctx = malwi_intercept::types::Arm64CpuContext {
            pc: 0,
            sp: 0,
            nzcv: 0,
            x: [0u64; 29],
            fp,
            lr,
            v: [0u128; 32],
        };
        return malwi_intercept::backtrace::capture_backtrace(&ctx, 64);
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        let rbp: u64;
        core::arch::asm!("mov {}, rbp", out(reg) rbp);
        let ctx = malwi_intercept::types::X86_64CpuContext {
            rip: 0,
            rsp: 0,
            rflags: 0,
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
        };
        return malwi_intercept::backtrace::capture_backtrace(&ctx, 64);
    }

    Vec::new()
}

fn parse_python_list_repr(list_repr: &str) -> Option<Vec<String>> {
    let inner = list_repr.strip_prefix('[')?.strip_suffix(']')?;
    if inner.trim().is_empty() {
        return Some(Vec::new());
    }

    let mut parts: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut string_char = '"';
    let mut escape_next = false;

    for c in inner.chars() {
        if escape_next {
            current.push(c);
            escape_next = false;
            continue;
        }
        match c {
            '\\' if in_string => escape_next = true,
            '"' | '\'' if !in_string => {
                in_string = true;
                string_char = c;
                current.clear();
            }
            '"' | '\'' if in_string && c == string_char => {
                in_string = false;
                parts.push(current.clone());
                current.clear();
            }
            _ if in_string => current.push(c),
            _ => {}
        }
    }

    Some(parts)
}

/// Audit hook callback.
///
/// Wraps `audit_hook_inner` in `catch_unwind` so a panic in our code
/// never propagates into the Python interpreter (undefined behaviour).
///
/// SAFETY: This is called by Python with GIL held.
unsafe extern "C" fn audit_hook(
    event: *const c_char,
    args: *mut c_void,
    _user_data: *mut c_void,
) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        audit_hook_inner(event, args)
    })) {
        Ok(result) => result,
        Err(_) => 0,
    }
}

/// Inner audit hook logic, separated so `catch_unwind` covers the entire body.
///
/// SAFETY: Caller must ensure GIL is held.
unsafe fn audit_hook_inner(event: *const c_char, args: *mut c_void) -> i32 {
    // Try to register profile hook if we have filters and haven't registered yet
    if !PROFILE_HOOK_REGISTERED.load(Ordering::SeqCst) && has_any_filters() {
        do_register_profile_hook();
    }

    // Only log audit events that match registered filters
    if event.is_null() {
        return 0;
    }

    let Some(event_str) = cstr_to_string(event) else {
        return 0;
    };

    // The audit hook uses Python C-API helpers (repr(), tuple iteration).
    // Initialize the API cache opportunistically so exec-only runs can still
    // extract subprocess.Popen arguments.
    if !init_python_api() {
        debug!(
            "Python API not available in audit hook for event '{}'",
            event_str
        );
    }

    // Exec filter integration for Python: treat subprocess.Popen as an exec event.
    // This avoids relying on low-level fork/exec interception for Python runtimes.
    if crate::exec::filter::has_filters() && event_str == "subprocess.Popen" {
        let arguments = extract_tuple_arguments(args);
        if arguments.is_empty() {
            debug!("subprocess.Popen audit: no arguments extracted");
        }
        // Python audit args for subprocess.Popen look like:
        // ('executable', ['argv0', ...], cwd, env)
        // Prefer the argv list at index 1.
        let argv = arguments
            .get(1)
            .and_then(|a| a.display.as_deref())
            .and_then(parse_python_list_repr)
            .or_else(|| {
                arguments
                    .get(1)
                    .and_then(|a| a.display.as_deref())
                    .map(|s| s.split_whitespace().map(|p| p.to_string()).collect())
            })
            .or_else(|| {
                // Fallback to executable string at index 0.
                arguments
                    .first()
                    .and_then(|a| a.display.as_deref())
                    .map(|s| vec![s.to_string()])
            })
            .unwrap_or_default();

        let cmd = argv
            .first()
            .and_then(|s| std::path::Path::new(s).file_name().and_then(|p| p.to_str()))
            .or_else(|| argv.first().map(|s| s.as_str()));
        if cmd.is_none() {
            debug!("subprocess.Popen audit: could not extract command name");
        }
        if let Some(cmd) = cmd {
            let (matches, capture_stack) = crate::exec::filter::check_filter(cmd);
            if matches {
                if let Some(agent) = crate::Agent::get() {
                    let native_stack = capture_native_stack_for_exec(capture_stack);
                    let (source_file, source_line) = {
                        let frame = get_current_frame();
                        super::helpers::extract_frame_location(frame)
                    };
                    let runtime_stack = if capture_stack {
                        let frames = capture_current_python_stack();
                        if frames.is_empty() {
                            None
                        } else {
                            Some(malwi_protocol::RuntimeStack::Python(frames))
                        }
                    } else {
                        None
                    };
                    agent.on_spawn_created(crate::exec::SpawnInfo {
                        child_pid: 0,
                        path: None,
                        argv: Some(argv),
                        native_stack,
                        source_file,
                        source_line,
                        runtime_stack,
                    });
                }
            }
        }
    }

    // Detect thread creation via audit event - triggers profile propagation on next RETURN
    // Python 3.13+ renamed the audit event to start_joinable_thread
    if event_str == "_thread.start_new_thread" || event_str == "_thread.start_joinable_thread" {
        set_thread_created();
    }

    let (matches, capture_stack) = matches_filter(&event_str);
    if !matches {
        return 0;
    }

    // Extract arguments from the args tuple
    let mut arguments = extract_tuple_arguments(args);

    // Apply Python-specific formatting for networking functions
    super::format::format_python_arguments(&event_str, &mut arguments);

    // Capture Python stack if enabled (using PyEval_GetFrame)
    let runtime_stack = if capture_stack {
        let frames = capture_current_python_stack();
        if frames.is_empty() {
            None
        } else {
            Some(malwi_protocol::RuntimeStack::Python(frames))
        }
    } else {
        None
    };

    // Extract caller's source location from the current frame
    // For audit events, PyEval_GetFrame returns the caller's frame (borrowed ref — no decref)
    let (caller_file, caller_line) = {
        let frame = get_current_frame();
        super::helpers::extract_frame_location(frame)
    };

    let trace_event = crate::tracing::event::python_enter(&event_str)
        .arguments(arguments)
        .runtime_stack(runtime_stack)
        .source_location(caller_file, caller_line)
        .build();

    // Send to CLI (handles review mode internally)
    // Returning non-zero aborts the audited operation (PEP 578)
    if super::helpers::send_trace_event(trace_event).is_err() {
        return -1;
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_python_list_repr_basic() {
        assert_eq!(
            parse_python_list_repr("['curl', '--version']"),
            Some(vec!["curl".to_string(), "--version".to_string()])
        );
    }

    #[test]
    fn test_parse_python_list_repr_single_element() {
        assert_eq!(
            parse_python_list_repr("['single']"),
            Some(vec!["single".to_string()])
        );
    }

    #[test]
    fn test_parse_python_list_repr_empty_list() {
        assert_eq!(parse_python_list_repr("[]"), Some(vec![]));
    }

    #[test]
    fn test_parse_python_list_repr_empty_list_with_spaces() {
        assert_eq!(parse_python_list_repr("[  ]"), Some(vec![]));
    }

    #[test]
    fn test_parse_python_list_repr_mixed_quotes() {
        // Python repr can use either quote style
        assert_eq!(
            parse_python_list_repr(r#"['/bin/sh', '-c', "echo 'hello'"]"#),
            Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo 'hello'".to_string()
            ])
        );
    }

    #[test]
    fn test_parse_python_list_repr_double_quoted() {
        assert_eq!(
            parse_python_list_repr(r#"["curl", "--version"]"#),
            Some(vec!["curl".to_string(), "--version".to_string()])
        );
    }

    #[test]
    fn test_parse_python_list_repr_escaped_backslash() {
        assert_eq!(
            parse_python_list_repr(r"['path with\\backslash']"),
            Some(vec!["path with\\backslash".to_string()])
        );
    }

    #[test]
    fn test_parse_python_list_repr_escaped_quote() {
        assert_eq!(
            parse_python_list_repr(r"['it\'s']"),
            Some(vec!["it's".to_string()])
        );
    }

    #[test]
    fn test_parse_python_list_repr_no_brackets() {
        assert_eq!(parse_python_list_repr(""), None);
        assert_eq!(parse_python_list_repr("not a list"), None);
    }

    #[test]
    fn test_parse_python_list_repr_missing_closing_bracket() {
        assert_eq!(parse_python_list_repr("[open"), None);
    }

    #[test]
    fn test_parse_python_list_repr_missing_opening_bracket() {
        assert_eq!(parse_python_list_repr("closed]"), None);
    }

    #[test]
    fn test_parse_python_list_repr_path_arguments() {
        // Real-world subprocess.Popen argv
        assert_eq!(
            parse_python_list_repr("['python3', '-m', 'pip', 'install', 'requests']"),
            Some(vec![
                "python3".to_string(),
                "-m".to_string(),
                "pip".to_string(),
                "install".to_string(),
                "requests".to_string()
            ])
        );
    }

    #[test]
    fn test_parse_python_list_repr_empty_string_element() {
        assert_eq!(
            parse_python_list_repr("['', 'arg']"),
            Some(vec!["".to_string(), "arg".to_string()])
        );
    }

    #[test]
    fn test_parse_python_list_repr_spaces_in_values() {
        assert_eq!(
            parse_python_list_repr("['hello world', 'foo bar']"),
            Some(vec!["hello world".to_string(), "foo bar".to_string()])
        );
    }
}

/// Register audit hook (PEP 578) - for logging Python runtime events
/// and triggering deferred profile hook registration.
pub fn register_audit_hook() -> bool {
    if AUDIT_HOOK_REGISTERED.load(Ordering::SeqCst) {
        return true;
    }

    let addr = match native::find_export(None, "PySys_AddAuditHook") {
        Ok(a) => a,
        Err(e) => {
            // Can happen early during process startup; retry via start_audit_registration_task().
            debug!("Failed to find PySys_AddAuditHook: {}", e);
            return false;
        }
    };

    let add_hook: PySys_AddAuditHookFn = unsafe { std::mem::transmute(addr) };
    let result = unsafe { add_hook(audit_hook as PyAuditHookFunction, std::ptr::null_mut()) };

    if result == 0 {
        debug!("Python audit hook registered");
        AUDIT_HOOK_REGISTERED.store(true, Ordering::SeqCst);
        true
    } else {
        error!("PySys_AddAuditHook failed with code {}", result);
        false
    }
}
