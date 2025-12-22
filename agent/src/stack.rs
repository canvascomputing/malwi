//! Unified stack capture interface for multiple language runtimes.
//!
//! Provides a common interface for capturing call stacks across different
//! language runtimes (native, Python, Node.js/JavaScript).

use std::ffi::c_void;

use malwi_protocol::{NativeFrame, NodejsFrame, PythonFrame};

/// Unified stack frame for display purposes.
/// Wraps language-specific frame types with a common display interface.
pub enum StackFrame {
    Native(NativeFrame),
    Python(PythonFrame),
    Nodejs(NodejsFrame),
}

impl StackFrame {
    /// Format frame for display: "symbol (location)"
    pub fn display(&self) -> String {
        match self {
            StackFrame::Native(f) => {
                let sym = f.symbol.as_deref().unwrap_or("<unknown>");
                format!("{} ({:#x})", sym, f.address)
            }
            StackFrame::Python(f) => {
                format!("{} ({}:{})", f.function, f.filename, f.line)
            }
            StackFrame::Nodejs(f) => {
                format!("{} ({}:{}:{})", f.function, f.script, f.line, f.column)
            }
        }
    }
}

/// Trait for capturing call stacks in different runtimes.
///
/// Each language runtime implements this to provide stack capture functionality.
pub trait StackCapturer: Send + Sync {
    /// Capture the call stack from the given context.
    ///
    /// The context is runtime-specific:
    /// - Native: `*mut InvocationContext`
    /// - Python: `*mut PyFrameObject`
    /// - V8: TBD
    fn capture(&self, context: *mut c_void) -> Vec<StackFrame>;
}
