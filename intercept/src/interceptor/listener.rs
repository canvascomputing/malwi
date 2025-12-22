use crate::types::InvocationContext;
use core::ffi::c_void;

pub type EnterCallback = unsafe extern "C" fn(*mut InvocationContext, *mut c_void);
pub type LeaveCallback = unsafe extern "C" fn(*mut InvocationContext, *mut c_void);

#[derive(Debug, Clone, Copy)]
pub struct CallListener {
    pub on_enter: Option<EnterCallback>,
    pub on_leave: Option<LeaveCallback>,
    pub user_data: *mut c_void,
}

impl CallListener {
    #[inline]
    pub fn matches(&self, other: &CallListener) -> bool {
        fn enter_eq(a: Option<EnterCallback>, b: Option<EnterCallback>) -> bool {
            match (a, b) {
                (None, None) => true,
                (Some(a), Some(b)) => core::ptr::fn_addr_eq(a, b),
                _ => false,
            }
        }

        fn leave_eq(a: Option<LeaveCallback>, b: Option<LeaveCallback>) -> bool {
            match (a, b) {
                (None, None) => true,
                (Some(a), Some(b)) => core::ptr::fn_addr_eq(a, b),
                _ => false,
            }
        }

        enter_eq(self.on_enter, other.on_enter)
            && leave_eq(self.on_leave, other.on_leave)
            && self.user_data == other.user_data
    }
}

// CallListener is an FFI-style tuple of function pointers + opaque user data.
// The interceptor stores listeners in a global singleton; treat this as thread-safe
// so long as the user upholds the usual FFI invariants for `user_data`.
unsafe impl Send for CallListener {}
unsafe impl Sync for CallListener {}
