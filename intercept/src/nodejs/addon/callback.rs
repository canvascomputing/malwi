//! V8 Addon Trace Callback.
//!
//! This module contains the callback function invoked by the addon when trace events occur.
//! The addon calls this function with a direct struct pointer for efficient event processing.

use std::os::raw::c_char;

use crate::exec::envvar as envvar_filter;
use crate::nodejs::ffi::NodejsTraceEventData;

// Per-call flag: set after the addon handles a trace event, cleared by
// `take_addon_handled()` in the bytecode hook to avoid duplicate events.
std::thread_local! {
    static ADDON_HANDLED_CURRENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Mark that the addon has handled the current call (set by addon callback).
pub fn mark_addon_handled() {
    ADDON_HANDLED_CURRENT.with(|c| c.set(true));
}

/// Check and clear the addon-handled flag (consumed by bytecode dedup).
pub fn take_addon_handled() -> bool {
    ADDON_HANDLED_CURRENT.with(|c| c.replace(false))
}

/// Helper to extract a string from a C pointer with length.
/// Returns an empty string if the pointer is null or length is unreasonable.
#[inline]
unsafe fn extract_string(ptr: *const c_char, len: u32) -> String {
    // Safety bounds: reject null pointers, zero length, or unreasonably large lengths
    if ptr.is_null() || len == 0 || len > 1_000_000 {
        return String::new();
    }
    let slice = std::slice::from_raw_parts(ptr.cast::<u8>(), len as usize);
    String::from_utf8_lossy(slice).into_owned()
}

/// Callback function invoked by the addon when trace events occur.
/// This is passed to the addon via `malwi_addon_enable_tracing`.
/// Receives a direct struct pointer instead of JSON for better performance.
///
/// Returns 1 to allow execution, 0 to block (policy enforcement).
/// Uses i32 instead of bool for reliable C ABI compatibility.
/// Only ENTER events (event_type == 0) can be blocked - Leave events always return 1.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn malwi_nodejs_trace_callback(event_data: *const NodejsTraceEventData) -> i32 {
    if event_data.is_null() {
        return 1; // Allow if no data
    }

    let (event, is_enter) = unsafe {
        let e = &*event_data;

        // Extract function name
        let function = extract_string(e.function, e.function_len);

        // Skip events without a function name
        if function.is_empty() {
            return 1;
        }

        // Check if this is an Enter event
        let is_enter = e.event_type == 0;

        // Check filter for capture_stack flag
        let (_matches, capture_stack) = crate::nodejs::check_filter(&function);

        // Extract script path (module)
        let _script_path = extract_string(e.script_path, e.script_path_len);

        // Extract return value for Leave events
        let return_value = if e.return_value.is_null() {
            None
        } else {
            Some(extract_string(e.return_value, e.return_value_len))
        };

        // Extract arguments
        let arguments = if e.arguments.is_null() || e.arg_count == 0 {
            Vec::new()
        } else {
            let args_slice = std::slice::from_raw_parts(e.arguments, e.arg_count as usize);
            args_slice
                .iter()
                .map(|a| {
                    let display = extract_string(a.display, a.display_len);
                    crate::Argument {
                        raw_value: 0,
                        display: Some(display),
                    }
                })
                .collect()
        };

        // Capture caller source location (Enter events only).
        // Use get_top_source_location: in the addon callback path, the wrapped
        // function is native (no JS frame), so the top JS frame is already
        // the caller — no need to walk up a frame.
        let (caller_file, caller_line, caller_column) = if is_enter {
            crate::nodejs::stack::get_top_source_location(std::ptr::null_mut())
        } else {
            (None, None, None)
        };

        // Capture runtime stack trace if --st flag is set.
        // The addon callback runs from JS → N-API → Rust (no frida-gum trampoline),
        // so v8::StackTrace::CurrentStackTrace is safe here.
        let runtime_stack = if capture_stack {
            crate::nodejs::capture_stack()
        } else {
            Vec::new()
        };
        let runtime_stack = if runtime_stack.is_empty() {
            None
        } else {
            Some(crate::RuntimeStack::Nodejs(runtime_stack))
        };

        // Extract NetworkInfo from arguments for networking functions
        let network_info = if is_enter {
            crate::nodejs::format::format_nodejs_arguments(&function, &arguments)
        } else {
            None
        };

        // Build event using EventBuilder
        let builder = if is_enter {
            crate::tracing::event::js_enter(&function).arguments(arguments)
        } else {
            crate::tracing::event::js_leave(&function, return_value)
        };

        let event = builder
            .network_info(network_info)
            .runtime_stack(runtime_stack)
            .source_location(caller_file, caller_line, caller_column)
            .build();

        (event, is_enter)
    };

    let Some(agent) = crate::Agent::get() else {
        return 1; // Allow if no agent
    };

    // Agent-side policy: evaluate locally
    if let Some(decision) = agent.evaluate_policy(&event) {
        if is_enter {
            match decision {
                malwi_protocol::agent_policy::AgentDecision::Block { .. } => {
                    let _ = agent.send_event(event);
                    mark_addon_handled();
                    return 0; // Block
                }
                malwi_protocol::agent_policy::AgentDecision::Hide
                | malwi_protocol::agent_policy::AgentDecision::Suppress => {
                    mark_addon_handled();
                    return 1; // Suppress/Hide: don't send, allow
                }
                _ => {}
            }
        }
        let _ = agent.send_event(event);
        mark_addon_handled();
        return 1;
    }

    let _ = agent.send_event(event);
    mark_addon_handled();
    1 // Allow execution
}

/// FFI function called from the Node.js addon when process.env is accessed.
///
/// # Arguments
/// * `key_ptr` - Pointer to UTF-8 key string
/// * `key_len` - Length of key string
///
/// # Returns
/// * 1 = allow access
/// * 0 = block access (return undefined to JS)
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn malwi_nodejs_envvar_access(key_ptr: *const u8, key_len: usize) -> i32 {
    if key_ptr.is_null() || key_len == 0 {
        return 1;
    }

    // If envvar monitoring is not enabled, allow all without tracing
    if !crate::exec::is_envvar_monitoring_enabled() {
        return 1;
    }

    let key = unsafe {
        let slice = std::slice::from_raw_parts(key_ptr, key_len);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return 1,
        }
    };

    // Skip agent-internal variables
    if key.starts_with("MALWI_") {
        return 1;
    }

    // Check agent-side deny filter
    let blocked = envvar_filter::should_block(key);

    // Build and send EnvVar trace event
    let event = crate::tracing::event::envvar_enter(key).build();

    let Some(agent) = crate::Agent::get() else {
        return 1;
    };

    // Agent-side policy: evaluate locally
    if let Some(decision) = agent.evaluate_policy(&event) {
        match decision {
            malwi_protocol::agent_policy::AgentDecision::Block { .. } => {
                let _ = agent.send_event(event);
                return 0;
            }
            malwi_protocol::agent_policy::AgentDecision::Hide
            | malwi_protocol::agent_policy::AgentDecision::Suppress => {
                return 1; // Don't send, allow
            }
            _ => {
                let _ = agent.send_event(event);
                return 1;
            }
        }
    }

    let _ = agent.send_event(event);

    if blocked {
        0
    } else {
        1
    }
}
