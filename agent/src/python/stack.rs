//! Python stack capture.
//!
//! Captures Python call stack by walking the frame chain.

use std::ffi::c_void;

use malwi_protocol::PythonFrame;

use super::ffi::PYTHON_API;
use super::helpers::{get_code_filename, get_qualname, get_simple_name};

/// Capture Python call stack by walking frame chain.
///
/// Walks from the given frame up to the top of the call stack,
/// extracting function name, filename, and line number for each frame.
///
/// # Arguments
/// * `frame` - Starting frame (borrowed reference, not owned)
///
/// # Safety
/// Caller must ensure frame is a valid PyFrameObject pointer and GIL is held.
pub unsafe fn capture_python_stack(frame: *mut c_void) -> Vec<PythonFrame> {
    let api = match PYTHON_API.get() {
        Some(api) => api,
        None => return Vec::new(),
    };

    let mut frames = Vec::new();
    let mut current = frame;
    let initial = frame;

    while !current.is_null() {
        let code = (api.frame_get_code)(current);
        if !code.is_null() {
            let function = get_qualname(code)
                .or_else(|| get_simple_name(code))
                .unwrap_or_else(|| "<unknown>".to_string());
            let filename = get_code_filename(code).unwrap_or_else(|| "<unknown>".to_string());
            let line = (api.frame_get_line_number)(current) as u32;

            (api.py_decref)(code);

            frames.push(PythonFrame {
                function,
                filename,
                line,
                locals: None,
            });
        }

        // Get parent frame (returns new reference)
        let back = (api.frame_get_back)(current);

        // Decref current frame (except initial which we don't own)
        if current != initial {
            (api.py_decref)(current);
        }

        current = back;
    }

    frames
}

/// Capture current Python call stack using PyEval_GetFrame.
///
/// Used by the audit hook which doesn't receive a frame parameter.
/// Returns the current stack or empty vec if no frame available.
///
/// # Safety
/// Caller must ensure GIL is held.
pub unsafe fn capture_current_python_stack() -> Vec<PythonFrame> {
    let api = match PYTHON_API.get() {
        Some(api) => api,
        None => return Vec::new(),
    };

    // Get current frame (borrowed reference - do NOT decref)
    let frame = (api.eval_get_frame)();
    if frame.is_null() {
        return Vec::new();
    }

    capture_python_stack(frame)
}
