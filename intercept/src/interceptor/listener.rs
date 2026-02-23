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

#[cfg(test)]
mod tests {
    use super::*;

    // Use inline(never) + black_box to prevent the compiler from merging
    // functions with identical bodies in release mode.
    #[inline(never)]
    unsafe extern "C" fn dummy_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
        std::hint::black_box(1u32);
    }
    #[inline(never)]
    unsafe extern "C" fn dummy_leave(_ctx: *mut InvocationContext, _ud: *mut c_void) {
        std::hint::black_box(2u32);
    }
    #[inline(never)]
    unsafe extern "C" fn other_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
        std::hint::black_box(3u32);
    }
    #[inline(never)]
    unsafe extern "C" fn other_leave(_ctx: *mut InvocationContext, _ud: *mut c_void) {
        std::hint::black_box(4u32);
    }

    #[test]
    fn matches_identical_listeners() {
        let a = CallListener {
            on_enter: Some(dummy_enter),
            on_leave: Some(dummy_leave),
            user_data: 0x42 as *mut c_void,
        };
        let b = CallListener {
            on_enter: Some(dummy_enter),
            on_leave: Some(dummy_leave),
            user_data: 0x42 as *mut c_void,
        };
        assert!(a.matches(&b));
    }

    #[test]
    fn matches_none_callbacks() {
        let a = CallListener {
            on_enter: None,
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        let b = CallListener {
            on_enter: None,
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        assert!(a.matches(&b));
    }

    #[test]
    fn does_not_match_different_enter() {
        let a = CallListener {
            on_enter: Some(dummy_enter),
            on_leave: Some(dummy_leave),
            user_data: core::ptr::null_mut(),
        };
        let b = CallListener {
            on_enter: Some(other_enter),
            on_leave: Some(dummy_leave),
            user_data: core::ptr::null_mut(),
        };
        assert!(!a.matches(&b));
    }

    #[test]
    fn does_not_match_different_leave() {
        let a = CallListener {
            on_enter: Some(dummy_enter),
            on_leave: Some(dummy_leave),
            user_data: core::ptr::null_mut(),
        };
        let b = CallListener {
            on_enter: Some(dummy_enter),
            on_leave: Some(other_leave),
            user_data: core::ptr::null_mut(),
        };
        assert!(!a.matches(&b));
    }

    #[test]
    fn does_not_match_different_user_data() {
        let a = CallListener {
            on_enter: Some(dummy_enter),
            on_leave: None,
            user_data: 0x1 as *mut c_void,
        };
        let b = CallListener {
            on_enter: Some(dummy_enter),
            on_leave: None,
            user_data: 0x2 as *mut c_void,
        };
        assert!(!a.matches(&b));
    }

    #[test]
    fn does_not_match_some_vs_none() {
        let a = CallListener {
            on_enter: Some(dummy_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        let b = CallListener {
            on_enter: None,
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        assert!(!a.matches(&b));
    }
}
