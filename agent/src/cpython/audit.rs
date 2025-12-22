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
use malwi_protocol::RuntimeStack;

use crate::native;
use crate::spawn_monitor::SpawnHandler;

use super::ffi::{init_python_api, PyAuditHookFunction, PySys_AddAuditHookFn, PYTHON_API};
use super::filters::{has_any_filters, matches_filter};
use super::helpers::{cstr_to_string, extract_tuple_arguments, get_code_filename};
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

#[cfg(target_os = "macos")]
#[allow(unreachable_code)]
fn capture_native_stack_for_exec(cmd: &str) -> Vec<usize> {
    let (_matches, capture_stack) = crate::exec_filter::check_filter(cmd);
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
/// SAFETY: This is called by Python with GIL held.
unsafe extern "C" fn audit_hook(
    event: *const c_char,
    args: *mut c_void,
    _user_data: *mut c_void,
) -> i32 {
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
    let _ = init_python_api();

    // Exec filter integration for Python: treat subprocess.Popen as an exec event.
    // This avoids relying on low-level fork/exec interception for Python runtimes.
    if crate::exec_filter::has_filters() && event_str == "subprocess.Popen" {
        let arguments = extract_tuple_arguments(args);
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
                    .get(0)
                    .and_then(|a| a.display.as_deref())
                    .map(|s| vec![s.to_string()])
            })
            .unwrap_or_default();

        let cmd = argv
            .first()
            .and_then(|s| std::path::Path::new(s).file_name().and_then(|p| p.to_str()))
            .or_else(|| argv.first().map(|s| s.as_str()));
        if let Some(cmd) = cmd {
            let (matches, _capture_stack) = crate::exec_filter::check_filter(cmd);
            if matches {
                if let Some(agent) = crate::Agent::get() {
                    let native_stack = {
                        #[cfg(target_os = "macos")]
                        {
                            capture_native_stack_for_exec(cmd)
                        }
                        #[cfg(not(target_os = "macos"))]
                        {
                            Vec::new()
                        }
                    };
                    agent.on_spawn_created(crate::spawn_monitor::SpawnInfo {
                        child_pid: 0,
                        path: None,
                        argv: Some(argv),
                        native_stack,
                        source_file: None,
                        source_line: None,
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
            Some(RuntimeStack::Python(frames))
        }
    } else {
        None
    };

    // Extract caller's source location from the current frame
    // For audit events, PyEval_GetFrame returns the caller's frame (borrowed ref — no decref)
    let (caller_file, caller_line) = {
        let api = PYTHON_API.get();
        if let Some(api) = api {
            let frame = (api.eval_get_frame)();
            if !frame.is_null() {
                let code = (api.frame_get_code)(frame);
                let file = if !code.is_null() {
                    let f = get_code_filename(code);
                    (api.py_decref)(code);
                    f
                } else {
                    None
                };
                let line = (api.frame_get_line_number)(frame) as u32;
                // eval_get_frame returns borrowed ref — do NOT decref frame
                (file, if line > 0 { Some(line) } else { None })
            } else {
                (None, None)
            }
        } else {
            (None, None)
        }
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
