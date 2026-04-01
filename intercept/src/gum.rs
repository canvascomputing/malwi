//! Runtime initialization and platform helpers.

use crate::ffi as gum;

// ── Ptrauth support constants ──────────────────────────────────────

const GUM_PTRAUTH_SUPPORTED: gum::GumPtrauthSupport = 2;

// ── Pointer authentication ─────────────────────────────────────────

/// Query whether the current process uses pointer-authentication.
pub fn query_ptrauth_support() -> bool {
    unsafe { gum::gum_query_ptrauth_support() == GUM_PTRAUTH_SUPPORTED }
}

/// Strip pointer authentication code from a code pointer.
#[inline]
pub fn strip_code_ptr(ptr: usize) -> usize {
    unsafe { gum::gum_strip_code_pointer(ptr as gum::gpointer) as usize }
}

// ── Initialization ─────────────────────────────────────────────────

/// Initialize the interception runtime. Must be called before using any
/// intercept APIs. Safe to call multiple times (uses a Once guard internally).
pub(crate) fn init_runtime() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| unsafe {
        gum::init();
    });
}

// ── Test helpers ───────────────────────────────────────────────────

#[cfg(test)]
mod test_helpers {
    use super::*;
    use crate::types::HookError;

    const GUM_PAGE_READ: gum::GumPageProtection = 1;
    const GUM_PAGE_WRITE: gum::GumPageProtection = 2;
    const GUM_PAGE_EXECUTE: gum::GumPageProtection = 4;
    const GUM_PAGE_RW: gum::GumPageProtection = GUM_PAGE_READ | GUM_PAGE_WRITE;
    const GUM_PAGE_RX: gum::GumPageProtection = GUM_PAGE_READ | GUM_PAGE_EXECUTE;

    #[derive(Debug)]
    pub struct CodeSlice {
        pub data: *mut u8,
        pub pc: *const u8,
        pub size: usize,
    }

    unsafe impl Send for CodeSlice {}
    unsafe impl Sync for CodeSlice {}

    #[derive(Debug)]
    pub struct CodeAllocator {
        slab_size: usize,
    }

    impl Default for CodeAllocator {
        fn default() -> Self {
            Self { slab_size: 4096 }
        }
    }

    impl CodeAllocator {
        pub fn alloc_any(&mut self) -> Result<CodeSlice, HookError> {
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
            let n_pages = (self.slab_size + page_size - 1) / page_size;

            let ptr = unsafe { gum::gum_try_alloc_n_pages(n_pages as gum::guint, GUM_PAGE_RW) };

            if ptr.is_null() {
                return Err(HookError::AllocationFailed);
            }

            Ok(CodeSlice {
                data: ptr as *mut u8,
                pc: ptr as *const u8,
                size: n_pages * page_size,
            })
        }

        /// # Safety
        /// `slice` must have been allocated by this allocator.
        pub unsafe fn make_executable(&self, slice: &CodeSlice) -> Result<(), HookError> {
            gum::gum_mprotect(
                slice.data as gum::gpointer,
                slice.size as gum::gsize,
                GUM_PAGE_RX,
            );
            gum::gum_clear_cache(slice.data as gum::gpointer, slice.size as gum::gsize);
            Ok(())
        }
    }

    /// Probe whether SVC #0x80 can execute from a dynamically allocated code page.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn can_execute_svc_from_dynamic_page() -> bool {
        use std::sync::OnceLock;
        static RESULT: OnceLock<bool> = OnceLock::new();
        *RESULT.get_or_init(|| unsafe { probe_svc_from_dynamic_page() })
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    #[allow(dead_code)]
    pub(crate) fn can_execute_svc_from_dynamic_page() -> bool {
        false
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    unsafe fn probe_svc_from_dynamic_page() -> bool {
        use core::cell::UnsafeCell;
        use core::ffi::c_int;
        use core::mem::MaybeUninit;

        type SigJmpBuf = [c_int; 49];

        extern "C" {
            fn sigsetjmp(env: *mut SigJmpBuf, savesigs: c_int) -> c_int;
            fn siglongjmp(env: *mut SigJmpBuf, val: c_int) -> !;
        }

        thread_local! {
            static JUMP_BUF: UnsafeCell<SigJmpBuf> = UnsafeCell::new([0; 49]);
        }

        unsafe extern "C" fn sigsys_handler(
            _sig: c_int,
            _info: *mut libc::siginfo_t,
            _ctx: *mut libc::c_void,
        ) {
            JUMP_BUF.with(|buf| {
                siglongjmp((*buf).get(), 1);
            });
        }

        let mut alloc = CodeAllocator::default();
        let slice = match alloc.alloc_any() {
            Ok(s) => s,
            Err(_) => return false,
        };

        let code = slice.data as *mut u32;
        code.write(0x92800370); // MOVN X16, #0x1b
        code.add(1).write(0xD4001001); // SVC #0x80
        code.add(2).write(0xD65F03C0); // RET

        if alloc.make_executable(&slice).is_err() {
            return false;
        }

        let mut old_action: libc::sigaction = MaybeUninit::zeroed().assume_init();
        let mut new_action: libc::sigaction = MaybeUninit::zeroed().assume_init();
        new_action.sa_sigaction = sigsys_handler as *const () as usize;
        new_action.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut new_action.sa_mask as *mut libc::sigset_t);

        if libc::sigaction(libc::SIGSYS, &new_action, &mut old_action) != 0 {
            return false;
        }

        let ok = JUMP_BUF.with(|buf| {
            if sigsetjmp((*buf).get(), 1) != 0 {
                return false;
            }
            let f: extern "C" fn() -> u64 = core::mem::transmute(slice.pc);
            let _ret = f();
            true
        });

        libc::sigaction(libc::SIGSYS, &old_action, core::ptr::null_mut());

        ok
    }
}

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use test_helpers::{can_execute_svc_from_dynamic_page, CodeAllocator, CodeSlice};
