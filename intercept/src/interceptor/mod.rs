//! Function interception via inline code patching.

use crate::ffi as gum;
use crate::interceptor::listener::CallListener;
use crate::types::HookError;
use core::ffi::c_void;
use std::collections::HashMap;
use std::sync::Mutex;

pub mod invocation;
pub mod listener;

/// Entry tracking a single attached GumInvocationListener.
struct ListenerEntry {
    gum_listener: *mut gum::GumInvocationListener,
    call_listener: CallListener,
}

unsafe impl Send for ListenerEntry {}
unsafe impl Sync for ListenerEntry {}

/// Function interceptor.
///
/// Handles prologue patching, trampoline generation, instruction relocation,
/// and pointer authentication.
pub struct Interceptor {
    inner: *mut gum::GumInterceptor,
    /// function_address → list of attached listeners (for detach matching).
    listeners: Mutex<HashMap<usize, Vec<ListenerEntry>>>,
    /// function_address → replacement trampoline (for revert).
    replacements: Mutex<HashMap<usize, ()>>,
}

unsafe impl Send for Interceptor {}
unsafe impl Sync for Interceptor {}

impl Interceptor {
    pub fn obtain() -> &'static Interceptor {
        static INSTANCE: std::sync::OnceLock<Interceptor> = std::sync::OnceLock::new();
        INSTANCE.get_or_init(|| {
            crate::gum::init_runtime();
            let inner = unsafe { gum::gum_interceptor_obtain() };
            Interceptor {
                inner,
                listeners: Mutex::new(HashMap::new()),
                replacements: Mutex::new(HashMap::new()),
            }
        })
    }

    pub fn attach(
        &self,
        function_address: *mut c_void,
        listener: CallListener,
    ) -> Result<(), HookError> {
        let on_enter = listener.on_enter.map(|f| {
            // EnterCallback and GumInvocationCallback have compatible signatures:
            // unsafe extern "C" fn(*mut GumInvocationContext, *mut c_void)
            unsafe { core::mem::transmute::<_, gum::GumInvocationCallback>(Some(f)) }
        });
        let on_leave = listener
            .on_leave
            .map(|f| unsafe { core::mem::transmute::<_, gum::GumInvocationCallback>(Some(f)) });

        let gum_listener = unsafe {
            gum::gum_make_call_listener(
                on_enter.unwrap_or(None),
                on_leave.unwrap_or(None),
                listener.user_data as gum::gpointer,
                None, // no data_destroy — caller manages lifetime
            )
        };

        if gum_listener.is_null() {
            return Err(HookError::WrongSignature);
        }

        let ret = unsafe {
            gum::gum_interceptor_attach(
                self.inner,
                function_address as gum::gpointer,
                gum_listener,
                listener.user_data as gum::gpointer,
                gum::GumAttachFlags_GUM_ATTACH_FLAGS_NONE,
            )
        };

        match ret {
            gum::GumAttachReturn_GUM_ATTACH_OK => {
                let key = function_address as usize;
                let entry = ListenerEntry {
                    gum_listener,
                    call_listener: listener,
                };
                let mut map = self.listeners.lock().unwrap_or_else(|e| e.into_inner());
                map.entry(key).or_default().push(entry);
                Ok(())
            }
            gum::GumAttachReturn_GUM_ATTACH_ALREADY_ATTACHED => {
                // Release the listener we just created.
                unsafe { gum::g_object_unref(gum_listener as gum::gpointer) };
                Err(HookError::AlreadyAttached)
            }
            _ => {
                unsafe { gum::g_object_unref(gum_listener as gum::gpointer) };
                Err(HookError::WrongSignature)
            }
        }
    }

    pub fn detach(&self, listener: &CallListener) {
        let mut map = self.listeners.lock().unwrap_or_else(|e| e.into_inner());
        // Collect all matching entries across all functions.
        let mut to_detach = Vec::new();
        for entries in map.values_mut() {
            entries.retain(|entry| {
                if entry.call_listener.matches(listener) {
                    to_detach.push(entry.gum_listener);
                    false // remove from list
                } else {
                    true // keep
                }
            });
        }
        // Remove empty function entries.
        map.retain(|_, v| !v.is_empty());
        drop(map);

        // Detach and unref outside the lock.
        for gum_listener in to_detach {
            unsafe {
                gum::gum_interceptor_detach(self.inner, gum_listener);
                gum::g_object_unref(gum_listener as gum::gpointer);
            }
        }
    }

    pub fn replace(
        &self,
        function_address: *mut c_void,
        replacement: *const c_void,
        _replacement_data: *mut c_void,
        original: *mut *const c_void,
    ) -> Result<(), HookError> {
        let ret = unsafe {
            gum::gum_interceptor_replace(
                self.inner,
                function_address as gum::gpointer,
                replacement as gum::gpointer,
                _replacement_data as gum::gpointer,
                original as *mut gum::gpointer,
            )
        };
        match ret {
            gum::GumReplaceReturn_GUM_REPLACE_OK => {
                let key = function_address as usize;
                let mut map = self.replacements.lock().unwrap_or_else(|e| e.into_inner());
                map.insert(key, ());
                Ok(())
            }
            gum::GumReplaceReturn_GUM_REPLACE_ALREADY_REPLACED => Err(HookError::AlreadyAttached),
            _ => Err(HookError::WrongSignature),
        }
    }

    pub fn revert(&self, function_address: *mut c_void) {
        unsafe {
            gum::gum_interceptor_revert(self.inner, function_address as gum::gpointer);
        }
        let key = function_address as usize;
        let mut map = self.replacements.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(&key);
    }

    pub fn begin_transaction(&self) {
        unsafe { gum::gum_interceptor_begin_transaction(self.inner) };
    }

    pub fn end_transaction(&self) {
        unsafe { gum::gum_interceptor_end_transaction(self.inner) };
    }

    #[cfg(test)]
    pub fn reset(&self) {
        // Detach all listeners.
        let mut map = self.listeners.lock().unwrap_or_else(|e| e.into_inner());
        for entries in map.values() {
            for entry in entries {
                unsafe {
                    gum::gum_interceptor_detach(self.inner, entry.gum_listener);
                    gum::g_object_unref(entry.gum_listener as gum::gpointer);
                }
            }
        }
        map.clear();
        drop(map);

        // Revert all replacements.
        let mut rmap = self.replacements.lock().unwrap_or_else(|e| e.into_inner());
        for &key in rmap.keys() {
            unsafe {
                gum::gum_interceptor_revert(self.inner, key as gum::gpointer);
            }
        }
        rmap.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi as gum;
    use crate::gum::{CodeAllocator, CodeSlice};
    use crate::interceptor::invocation as inv;
    use crate::types::InvocationContext;
    use core::mem::MaybeUninit;
    use core::sync::atomic::{AtomicU32, Ordering};
    use std::sync::MutexGuard;

    fn lock_hook_tests() -> MutexGuard<'static, ()> {
        let guard = crate::lock_hook_tests();
        Interceptor::obtain().reset();
        guard
    }

    #[cfg(target_arch = "aarch64")]
    fn make_add_const(c: u32) -> (CodeSlice, extern "C" fn(i64) -> i64) {
        use gum::*;
        let mut alloc = CodeAllocator::default();
        let slice = alloc.alloc_any().expect("alloc");
        unsafe {
            let mut w = MaybeUninit::<GumArm64Writer>::uninit();
            gum_arm64_writer_init(w.as_mut_ptr(), slice.data as *mut c_void);
            let w = w.as_mut_ptr();
            gum_arm64_writer_put_add_reg_reg_imm(
                w,
                arm64_reg_ARM64_REG_X0,
                arm64_reg_ARM64_REG_X0,
                c as u64,
            );
            for _ in 0..4 {
                gum_arm64_writer_put_nop(w);
            }
            gum_arm64_writer_put_ret(w);
            for _ in 0..4 {
                gum_arm64_writer_put_nop(w);
            }
            gum_arm64_writer_flush(w);
            gum_arm64_writer_clear(w);
            alloc.make_executable(&slice).expect("rx");
        }
        let f: extern "C" fn(i64) -> i64 = unsafe { core::mem::transmute(slice.pc) };
        (slice, f)
    }

    #[cfg(target_arch = "x86_64")]
    fn make_add_const(c: u32) -> (CodeSlice, extern "C" fn(i64) -> i64) {
        use gum::*;
        // GumX86Reg enum values (from frida-gum's _GumX86Reg, not Capstone's x86_reg)
        const GUM_X86_RAX: GumX86Reg = 17;
        const GUM_X86_RDI: GumX86Reg = 24;
        let mut alloc = CodeAllocator::default();
        let slice = alloc.alloc_any().expect("alloc");
        unsafe {
            let mut w = MaybeUninit::<GumX86Writer>::uninit();
            gum_x86_writer_init(w.as_mut_ptr(), slice.data as *mut c_void);
            let w = w.as_mut_ptr();
            gum_x86_writer_put_mov_reg_reg(w, GUM_X86_RAX, GUM_X86_RDI);
            gum_x86_writer_put_add_reg_imm(w, GUM_X86_RAX, c as i64);
            for _ in 0..8 {
                gum_x86_writer_put_nop(w);
            }
            gum_x86_writer_put_ret(w);
            for _ in 0..4 {
                gum_x86_writer_put_nop(w);
            }
            gum_x86_writer_flush(w);
            gum_x86_writer_clear(w);
            alloc.make_executable(&slice).expect("rx");
        }
        let f: extern "C" fn(i64) -> i64 = unsafe { core::mem::transmute(slice.pc) };
        (slice, f)
    }

    // ── Replace tests ──────────────────────────────────────────────

    #[test]
    fn replace_and_revert_works() {
        let _g = lock_hook_tests();
        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);
        let (_r_mem, r) = make_add_const(100);
        assert_eq!(f(1), 2);

        let mut orig: *const c_void = core::ptr::null();
        i.replace(
            f as *mut c_void,
            r as *const c_void,
            core::ptr::null_mut(),
            &mut orig,
        )
        .unwrap();
        assert_eq!(f(1), 101);

        let orig_fn: extern "C" fn(i64) -> i64 = unsafe { core::mem::transmute(orig) };
        assert_eq!(orig_fn(1), 2);

        i.revert(f as *mut c_void);
        assert_eq!(f(1), 2);
    }

    // ── Attach tests ───────────────────────────────────────────────

    static ENTER_HITS: AtomicU32 = AtomicU32::new(0);
    static LEAVE_HITS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn on_enter(ctx: *mut InvocationContext, _ud: *mut c_void) {
        ENTER_HITS.fetch_add(1, Ordering::Relaxed);
        let a0 = inv::get_nth_argument(ctx, 0) as usize as u64;
        inv::replace_nth_argument(ctx, 0, (a0 + 10) as usize as *mut c_void);
    }

    unsafe extern "C" fn on_leave(ctx: *mut InvocationContext, _ud: *mut c_void) {
        LEAVE_HITS.fetch_add(1, Ordering::Relaxed);
        let rv = inv::get_return_value(ctx) as usize as u64;
        inv::replace_return_value(ctx, (rv * 2) as usize as *mut c_void);
    }

    #[test]
    fn attach_fires_callbacks_on_main_executable_function() {
        let _g = lock_hook_tests();
        ENTER_HITS.store(0, Ordering::Relaxed);
        LEAVE_HITS.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_mem, f) = make_add_const(1);

        let listener = CallListener {
            on_enter: Some(on_enter),
            on_leave: Some(on_leave),
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        // f(5) → on_enter rewrites arg to 15 → f computes 15+1=16 → on_leave doubles to 32
        let result = f(5);
        assert_eq!(result, 32);
        assert_eq!(ENTER_HITS.load(Ordering::Relaxed), 1);
        assert_eq!(LEAVE_HITS.load(Ordering::Relaxed), 1);

        i.detach(&listener);
        let result = f(5);
        assert_eq!(result, 6);
    }

    #[test]
    fn attach_fires_callbacks_on_libc_function() {
        let _g = lock_hook_tests();

        static ABS_ENTER: AtomicU32 = AtomicU32::new(0);
        unsafe extern "C" fn abs_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            ABS_ENTER.fetch_add(1, Ordering::Relaxed);
        }
        ABS_ENTER.store(0, Ordering::Relaxed);

        let abs_addr = crate::module::find_global_export_by_name("abs").expect("should find abs");

        let i = Interceptor::obtain();
        let listener = CallListener {
            on_enter: Some(abs_on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        i.attach(abs_addr as *mut c_void, listener).unwrap();

        // Call through the function pointer to avoid compiler builtin optimization.
        let abs_fn: extern "C" fn(libc::c_int) -> libc::c_int =
            unsafe { core::mem::transmute(abs_addr) };
        let result = abs_fn(std::hint::black_box(-42));
        assert_eq!(result, 42);
        assert!(ABS_ENTER.load(Ordering::Relaxed) >= 1);

        i.detach(&listener);
    }

    #[test]
    fn detach_restores_original_behavior() {
        let _g = lock_hook_tests();
        ENTER_HITS.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_mem, f) = make_add_const(1);

        let listener = CallListener {
            on_enter: Some(on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();
        assert_eq!(f(5), 16); // on_enter: 5+10=15, f: 15+1=16

        i.detach(&listener);
        assert_eq!(f(5), 6); // original: 5+1=6
    }

    #[test]
    fn replace_on_libc_abs_with_execution_verification() {
        let _g = lock_hook_tests();

        let abs_addr = crate::module::find_global_export_by_name("abs").expect("should find abs");

        extern "C" fn fake_abs(_x: libc::c_int) -> libc::c_int {
            999
        }

        let i = Interceptor::obtain();
        let mut orig: *const c_void = core::ptr::null();
        i.replace(
            abs_addr as *mut c_void,
            fake_abs as *const c_void,
            core::ptr::null_mut(),
            &mut orig,
        )
        .unwrap();

        // Call through the function pointer to avoid compiler builtin optimization.
        let abs_fn: extern "C" fn(libc::c_int) -> libc::c_int =
            unsafe { core::mem::transmute(abs_addr) };
        let result = abs_fn(std::hint::black_box(-42));
        assert_eq!(result, 999);

        i.revert(abs_addr as *mut c_void);
        let result = abs_fn(std::hint::black_box(-42));
        assert_eq!(result, 42);
    }

    #[test]
    fn attach_to_libc_socket_syscall_wrapper() {
        use core::sync::atomic::AtomicU32;

        let _g = lock_hook_tests();

        #[cfg(target_os = "macos")]
        if !crate::gum::can_execute_svc_from_dynamic_page() {
            eprintln!("skipping: SVC #0x80 blocked from dynamic pages on this system");
            return;
        }

        static SOCKET_ENTER: AtomicU32 = AtomicU32::new(0);
        unsafe extern "C" fn socket_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            SOCKET_ENTER.fetch_add(1, Ordering::Relaxed);
        }
        SOCKET_ENTER.store(0, Ordering::Relaxed);

        let socket_addr =
            crate::module::find_global_export_by_name("socket").expect("should find socket");

        let i = Interceptor::obtain();
        let listener = CallListener {
            on_enter: Some(socket_on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        i.attach(socket_addr as *mut c_void, listener).unwrap();

        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0, "socket() should succeed");
        unsafe { libc::close(fd) };

        assert!(SOCKET_ENTER.load(Ordering::Relaxed) >= 1);
        i.detach(&listener);
    }

    #[test]
    fn replace_and_revert_rapid_cycle_100_times() {
        let _g = lock_hook_tests();
        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);
        let (_r_mem, r) = make_add_const(100);

        for _ in 0..100 {
            let mut orig: *const c_void = core::ptr::null();
            i.replace(
                f as *mut c_void,
                r as *const c_void,
                core::ptr::null_mut(),
                &mut orig,
            )
            .unwrap();
            assert_eq!(f(1), 101);
            i.revert(f as *mut c_void);
            assert_eq!(f(1), 2);
        }
    }

    #[test]
    fn already_replaced_returns_error() {
        let _g = lock_hook_tests();
        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);
        let (_r_mem, r) = make_add_const(100);

        let mut orig: *const c_void = core::ptr::null();
        i.replace(
            f as *mut c_void,
            r as *const c_void,
            core::ptr::null_mut(),
            &mut orig,
        )
        .unwrap();

        let ret = i.replace(
            f as *mut c_void,
            r as *const c_void,
            core::ptr::null_mut(),
            &mut orig,
        );
        assert_eq!(ret, Err(HookError::AlreadyAttached));

        i.revert(f as *mut c_void);
    }

    #[test]
    fn replace_works_across_threads() {
        let _g = lock_hook_tests();
        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);
        let (_r_mem, r) = make_add_const(100);

        let mut orig: *const c_void = core::ptr::null();
        i.replace(
            f as *mut c_void,
            r as *const c_void,
            core::ptr::null_mut(),
            &mut orig,
        )
        .unwrap();

        let handles: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        assert_eq!(f(1), 101);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        i.revert(f as *mut c_void);
        assert_eq!(f(1), 2);
    }
}
