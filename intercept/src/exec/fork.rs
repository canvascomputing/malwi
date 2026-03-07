//! Fork/vfork interception for child process gating (Unix only).
//!
//! Hooks fork() and vfork() to detect child process creation.

use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::OnceLock;

use crate::CallListener;
use crate::InvocationContext;
use core::ffi::c_void;
use log::{debug, info, warn};

// In forked children, threads don't survive. We need a reliable hook to
// reinitialize agent state (HTTP client / flush loop) in the child before exec.
// `pthread_atfork` works even when libc's fork implementation is hardened.
static ATFORK_REGISTERED: OnceLock<()> = OnceLock::new();

fn ensure_atfork_registered() {
    ATFORK_REGISTERED.get_or_init(|| unsafe {
        extern "C" fn child() {
            if let Some(agent) = crate::Agent::get() {
                agent.on_fork_in_child();
            }
        }
        // parent/prepare not needed; we only need child-side reinit.
        let _ = libc::pthread_atfork(None, None, Some(child));
    });
}

/// Static pointer to the fork address for replacement.
static ORIGINAL_FORK: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());
static ORIGINAL_VFORK: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());

/// Callback trait for fork events.
pub trait ForkHandler: Send + Sync {
    /// Called in the parent process after fork returns.
    /// `child_pid` is the PID of the newly created child.
    fn on_fork_in_parent(&self, child_pid: u32);

    /// Called in the child process after fork returns.
    fn on_fork_in_child(&self);
}

/// Monitor for fork/vfork system calls.
pub struct ForkMonitor {
    interceptor: &'static crate::Interceptor,
    listener: CallListener,
    vfork_addr: Option<usize>,
    #[allow(dead_code)]
    handler: *const dyn ForkHandler,
}

// Safety: ForkMonitor uses raw pointers but they're thread-safe
unsafe impl Send for ForkMonitor {}
unsafe impl Sync for ForkMonitor {}

impl ForkMonitor {
    /// Create a new fork monitor and install hooks.
    ///
    /// # Safety
    /// The handler must remain valid for the lifetime of this monitor.
    pub unsafe fn new<H: ForkHandler + 'static>(handler: &H) -> Option<Self> {
        ensure_atfork_registered();

        let interceptor = crate::Interceptor::obtain();

        // Find fork and vfork in libc
        let fork_addr = match crate::module::find_global_export_by_name("fork") {
            Ok(a) => a,
            Err(_) => {
                warn!("Could not find fork() in libc");
                return None;
            }
        };
        let vfork_addr = crate::module::find_global_export_by_name("vfork").ok();

        ORIGINAL_FORK.store(fork_addr as *mut (), Ordering::SeqCst);
        if let Some(vfork_addr) = vfork_addr {
            ORIGINAL_VFORK.store(vfork_addr as *mut (), Ordering::SeqCst);
        }

        // Create listener with callbacks
        let listener = CallListener {
            on_enter: Some(on_fork_enter),
            on_leave: Some(on_fork_leave),
            user_data: handler as *const _ as *mut c_void,
        };

        interceptor.begin_transaction();

        if let Err(e) = interceptor.attach(fork_addr as *mut c_void, listener) {
            warn!("Failed to attach to fork: {:?}", e);
        } else {
            info!("Attached fork monitor to fork() at {:#x}", fork_addr);
        }

        // Replace vfork with fork
        // vfork is problematic because parent is suspended until child execs
        let mut vfork_revert_addr: Option<usize> = None;
        if let Some(vfork_addr) = vfork_addr {
            let mut orig: *const c_void = core::ptr::null();
            if let Err(e) = interceptor.replace(
                vfork_addr as *mut c_void,
                fork_addr as *const c_void,
                ptr::null_mut(),
                &mut orig,
            ) {
                warn!("Failed to replace vfork with fork: {:?}", e);
            } else {
                info!("Replaced vfork() with fork() at {:#x}", vfork_addr);
                vfork_revert_addr = Some(vfork_addr);
            }
        }

        interceptor.end_transaction();

        Some(Self {
            interceptor,
            listener,
            vfork_addr: vfork_revert_addr,
            handler: handler as *const _,
        })
    }

    /// Check if the monitor is active.
    pub fn is_active(&self) -> bool {
        self.listener.on_enter.is_some() || self.listener.on_leave.is_some()
    }
}

impl Drop for ForkMonitor {
    fn drop(&mut self) {
        if let Some(vfork_addr) = self.vfork_addr {
            self.interceptor.revert(vfork_addr as *mut c_void);
        }
        self.interceptor.detach(&self.listener);
        debug!("Fork monitor detached");
    }
}

/// Callback when fork is about to be called.
unsafe extern "C" fn on_fork_enter(_context: *mut InvocationContext, _user_data: *mut c_void) {
    if crate::agent_debug_enabled() {
        eprintln!("[malwi-agent] fork enter");
    }
    debug!("fork() enter");
    // Nothing to do on enter - we just need to track the call
}

/// Callback when fork returns.
unsafe extern "C" fn on_fork_leave(context: *mut InvocationContext, user_data: *mut c_void) {
    let result = crate::invocation::get_return_value(context) as isize as i64;

    if crate::agent_debug_enabled() {
        eprintln!("[malwi-agent] fork leave, pid={}", result);
    }
    debug!("fork() leave, result = {}", result);

    if user_data.is_null() {
        return;
    }

    // Call the global agent's handler methods directly
    // The user_data is actually a pointer to the Agent which implements ForkHandler
    if let Some(agent) = crate::Agent::get() {
        if result > 0 {
            // We're in the parent process, result is child PID
            let child_pid = result as u32;
            debug!("Fork detected: parent, child_pid = {}", child_pid);
            agent.on_fork_in_parent(child_pid);
        }
        // result == 0 (child) is handled by pthread_atfork — no duplicate call needed.
        // result < 0 means fork failed, ignore.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_gum;
    use std::sync::atomic::AtomicU32;
    use std::sync::Arc;

    struct TestHandler {
        child_pid: AtomicU32,
        in_child: std::sync::atomic::AtomicBool,
    }

    impl ForkHandler for TestHandler {
        fn on_fork_in_parent(&self, child_pid: u32) {
            self.child_pid.store(child_pid, Ordering::SeqCst);
        }

        fn on_fork_in_child(&self) {
            self.in_child.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_fork_monitor_creation() {
        let _g = crate::lock_hook_tests();
        init_gum();

        let handler = Arc::new(TestHandler {
            child_pid: AtomicU32::new(0),
            in_child: std::sync::atomic::AtomicBool::new(false),
        });

        let monitor = unsafe { ForkMonitor::new(handler.as_ref()) };
        assert!(monitor.is_some(), "Should create fork monitor");
    }
}
