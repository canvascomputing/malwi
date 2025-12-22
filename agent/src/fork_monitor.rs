//! Fork/vfork interception for child process gating (Unix only).
//!
//! Hooks fork() and vfork() to detect child process creation.

use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::OnceLock;

use log::{debug, info, warn};
use malwi_intercept::CallListener;
use malwi_intercept::InvocationContext;
use core::ffi::c_void;

#[cfg(target_os = "macos")]
fn agent_debug_enabled() -> bool {
    std::env::var_os("MALWI_AGENT_DEBUG").is_some()
}

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

#[cfg(target_os = "macos")]
unsafe fn resolve_next(symbol: &str) -> *mut () {
    use std::ffi::CString;
    let c = match CString::new(symbol) {
        Ok(c) => c,
        Err(_) => return ptr::null_mut(),
    };
    libc::dlsym(libc::RTLD_NEXT, c.as_ptr()) as *mut ()
}

/// Static pointer to the fork address for replacement.
static FORK_IMPL: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());
static VFORK_IMPL: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());
#[cfg(target_os = "macos")]
static __FORK_IMPL: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());

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
    interceptor: &'static malwi_intercept::Interceptor,
    listener: CallListener,
    vfork_addr: Option<usize>,
    #[cfg(target_os = "macos")]
    fork_rebind: Option<Vec<(usize, usize)>>,
    #[cfg(target_os = "macos")]
    vfork_rebind: Option<Vec<(usize, usize)>>,
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

        let interceptor = malwi_intercept::Interceptor::obtain();

        // Find fork and vfork in libc
        let fork_addr = match malwi_intercept::module::find_global_export_by_name("fork") {
            Ok(a) => a,
            Err(_) => {
                warn!("Could not find fork() in libc");
                return None;
            }
        };
        let vfork_addr = malwi_intercept::module::find_global_export_by_name("vfork").ok();
        #[cfg(target_os = "macos")]
        let __fork_addr = malwi_intercept::module::find_global_export_by_name("__fork").ok();

        FORK_IMPL.store(fork_addr as *mut (), Ordering::SeqCst);
        if let Some(vfork_addr) = vfork_addr {
            VFORK_IMPL.store(vfork_addr as *mut (), Ordering::SeqCst);
        }
        #[cfg(target_os = "macos")]
        if let Some(addr) = __fork_addr {
            __FORK_IMPL.store(addr as *mut (), Ordering::SeqCst);
        }

        // Create listener with callbacks
        let listener = CallListener {
            on_enter: Some(on_fork_enter),
            on_leave: Some(on_fork_leave),
            user_data: handler as *const _ as *mut c_void,
        };

        interceptor.begin_transaction();

        #[cfg(target_os = "macos")]
        let mut fork_attached = false;
        if let Err(e) = interceptor.attach(fork_addr as *mut c_void, listener) {
            warn!("Failed to attach to fork: {:?}", e);
            #[cfg(target_os = "macos")]
            {
                warn!("Falling back to import rebinding for fork()");
            }
        } else {
            info!("Attached fork monitor to fork() at {:#x}", fork_addr);
            #[cfg(target_os = "macos")]
            { fork_attached = true; }
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
                #[cfg(target_os = "macos")]
                {
                    // If inline patching fails (system libs), rebind vfork() to call fork().
                    warn!("Falling back to import rebinding for vfork()");
                }
            } else {
                info!("Replaced vfork() with fork() at {:#x}", vfork_addr);
                vfork_revert_addr = Some(vfork_addr);
            }
        }

        interceptor.end_transaction();

        #[cfg(target_os = "macos")]
        let mut fork_rebind = None;
        #[cfg(target_os = "macos")]
        let mut vfork_rebind = None;

        #[cfg(target_os = "macos")]
        {
            // If attach failed, rebind fork().
            if !fork_attached {
                if let Ok(patched) = malwi_intercept::module::rebind_symbol("fork", fork_rebind_wrapper as usize) {
                    info!("Rebound fork in {} locations", patched.len());
                    fork_rebind = Some(patched);
                    if agent_debug_enabled() {
                        eprintln!("[malwi-agent] rebound fork");
                    }
                }
                if __FORK_IMPL.load(Ordering::SeqCst).is_null() == false {
                    if let Ok(patched) = malwi_intercept::module::rebind_symbol("__fork", __fork_rebind_wrapper as usize) {
                        info!("Rebound __fork in {} locations", patched.len());
                        fork_rebind = Some(patched);
                        if agent_debug_enabled() {
                            eprintln!("[malwi-agent] rebound __fork");
                        }
                    }
                }
            }

            // If replace failed, rebind vfork() to call fork().
            if vfork_revert_addr.is_none() {
                if let Ok(patched) = malwi_intercept::module::rebind_symbol("vfork", vfork_rebind_wrapper as usize) {
                    info!("Rebound vfork in {} locations", patched.len());
                    vfork_rebind = Some(patched);
                }
            }
        }

        Some(Self {
            interceptor,
            listener,
            vfork_addr: vfork_revert_addr,
            #[cfg(target_os = "macos")]
            fork_rebind,
            #[cfg(target_os = "macos")]
            vfork_rebind,
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
        #[cfg(target_os = "macos")]
        unsafe {
            if let Some(p) = &self.fork_rebind {
                restore_rebinds(p);
            }
            if let Some(p) = &self.vfork_rebind {
                restore_rebinds(p);
            }
        }
        debug!("Fork monitor detached");
    }
}

// ============================================================================
// macOS: import rebinding fallback (fishhook-style)
// ============================================================================

#[cfg(target_os = "macos")]
type ForkFn = unsafe extern "C" fn() -> libc::pid_t;

#[cfg(target_os = "macos")]
unsafe fn restore_rebinds(patched: &[(usize, usize)]) {
    let page_sz = libc::sysconf(libc::_SC_PAGESIZE) as usize;
    for (slot, original) in patched {
        let slot_ptr = *slot as *mut usize;
        let page = (slot_ptr as usize) & !(page_sz - 1);
        let page_ptr = page as *mut libc::c_void;
        let _ = libc::mprotect(page_ptr, page_sz, libc::PROT_READ | libc::PROT_WRITE);
        core::ptr::write_unaligned(slot_ptr, *original);
    }
}

#[cfg(target_os = "macos")]
pub(crate) unsafe extern "C" fn fork_rebind_wrapper() -> libc::pid_t {
    if agent_debug_enabled() {
        eprintln!("[malwi-agent] fork wrapper called");
    }
    let mut orig_ptr = FORK_IMPL.load(Ordering::SeqCst);
    if orig_ptr.is_null() {
        orig_ptr = resolve_next("fork");
        FORK_IMPL.store(orig_ptr, Ordering::SeqCst);
    }
    let orig: ForkFn = core::mem::transmute(orig_ptr);
    let result = orig();

    if let Some(agent) = crate::Agent::get() {
        if result > 0 {
            agent.on_fork_in_parent(result as u32);
        } else if result == 0 {
            agent.on_fork_in_child();
        }
    }

    result
}

#[cfg(target_os = "macos")]
pub(crate) unsafe extern "C" fn vfork_rebind_wrapper() -> libc::pid_t {
    if agent_debug_enabled() {
        eprintln!("[malwi-agent] vfork wrapper called");
    }
    // Avoid vfork semantics; delegate to fork().
    fork_rebind_wrapper()
}

#[cfg(target_os = "macos")]
pub(crate) unsafe extern "C" fn __fork_rebind_wrapper() -> libc::pid_t {
    if agent_debug_enabled() {
        eprintln!("[malwi-agent] __fork wrapper called");
    }
    let mut orig_ptr = __FORK_IMPL.load(Ordering::SeqCst);
    if orig_ptr.is_null() {
        orig_ptr = resolve_next("__fork");
        __FORK_IMPL.store(orig_ptr, Ordering::SeqCst);
    }
    let orig: ForkFn = core::mem::transmute(orig_ptr);
    let result = orig();

    if let Some(agent) = crate::Agent::get() {
        if result > 0 {
            agent.on_fork_in_parent(result as u32);
        } else if result == 0 {
            agent.on_fork_in_child();
        }
    }

    result
}

/// Callback when fork is about to be called.
unsafe extern "C" fn on_fork_enter(
    _context: *mut InvocationContext,
    _user_data: *mut c_void,
) {
    debug!("fork() enter");
    // Nothing to do on enter - we just need to track the call
}

/// Callback when fork returns.
unsafe extern "C" fn on_fork_leave(
    context: *mut InvocationContext,
    user_data: *mut c_void,
) {
    let result = malwi_intercept::invocation::get_return_value(context) as isize as i64;

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
        } else if result == 0 {
            // We're in the child process
            debug!("Fork detected: child process");
            agent.on_fork_in_child();
        }
        // result < 0 means fork failed, ignore
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
        init_gum();

        let handler = Arc::new(TestHandler {
            child_pid: AtomicU32::new(0),
            in_child: std::sync::atomic::AtomicBool::new(false),
        });

        let monitor = unsafe { ForkMonitor::new(handler.as_ref()) };
        assert!(monitor.is_some(), "Should create fork monitor");
    }
}
