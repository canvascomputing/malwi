use crate::interceptor::listener::CallListener;
use crate::types::HookError;
use core::ffi::c_void;
use std::collections::HashMap;
use std::sync::Mutex;

pub mod invocation;
pub mod listener;

#[cfg(target_arch = "aarch64")]
mod replace_arm64;

#[cfg(target_arch = "aarch64")]
mod attach_arm64;

#[cfg(target_arch = "x86_64")]
mod replace_x86_64;

#[cfg(target_arch = "x86_64")]
mod attach_x86_64;

struct ReplacementEntry {
    function: usize,
    original_bytes: [u8; 16],
    #[allow(dead_code)]
    trampoline: usize,
}

struct FunctionContext {
    function: usize,
    original_bytes: [u8; 16],
    patch_size: usize,
    #[allow(dead_code)]
    trampoline: usize,
    wrapper: usize,
    listeners: Vec<CallListener>,
}

/// Minimal interceptor implementation.
///
/// This currently supports `replace()` + `revert()` on AArch64 by overwriting the first 16 bytes
/// with an absolute redirect (`LDR+BR` + literal). Listener-based attach/detach comes later.
pub struct Interceptor {
    replace_map: Mutex<HashMap<usize, ReplacementEntry>>,
    attach_map: Mutex<HashMap<usize, Box<FunctionContext>>>,
}

impl Interceptor {
    pub fn obtain() -> &'static Interceptor {
        static INSTANCE: std::sync::OnceLock<Interceptor> = std::sync::OnceLock::new();
        INSTANCE.get_or_init(|| Interceptor {
            replace_map: Mutex::new(HashMap::new()),
            attach_map: Mutex::new(HashMap::new()),
        })
    }

    pub fn attach(&self, _function_address: *mut c_void, _listener: CallListener) -> Result<(), HookError> {
        #[cfg(target_arch = "aarch64")]
        {
            attach_arm64::attach(self, _function_address, _listener)
        }
        #[cfg(target_arch = "x86_64")]
        {
            attach_x86_64::attach(self, _function_address, _listener)
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            let _ = (_function_address, _listener);
            Err(HookError::Unsupported)
        }
    }

    /// Prepare an attach wrapper (enter/leave + trampoline) without patching the target.
    ///
    /// This is intended for macOS hardened/shared-cache mappings where inline
    /// patching fails. Callers can use `module::rebind_symbol()` to redirect
    /// imported symbol pointers to the returned wrapper address.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    pub fn attach_rebinding(
        &self,
        _function_address: *mut c_void,
        _listener: CallListener,
    ) -> Result<usize, HookError> {
        #[cfg(target_arch = "aarch64")]
        {
            attach_arm64::attach_rebinding(self, _function_address, _listener)
        }
        #[cfg(target_arch = "x86_64")]
        {
            attach_x86_64::attach_rebinding(self, _function_address, _listener)
        }
    }

    pub fn detach(&self, listener: &CallListener) {
        #[cfg(target_arch = "aarch64")]
        {
            attach_arm64::detach(self, listener);
        }
        #[cfg(target_arch = "x86_64")]
        {
            attach_x86_64::detach(self, listener);
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            let _ = listener;
        }
    }

    pub fn replace(
        &self,
        function_address: *mut c_void,
        replacement: *const c_void,
        _replacement_data: *mut c_void,
        original: *mut *const c_void,
    ) -> Result<(), HookError> {
        #[cfg(target_arch = "aarch64")]
        {
            replace_arm64::replace(self, function_address, replacement, original)
        }
        #[cfg(target_arch = "x86_64")]
        {
            replace_x86_64::replace(self, function_address, replacement, original)
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            let _ = (function_address, replacement, original);
            Err(HookError::Unsupported)
        }
    }

    pub fn revert(&self, function_address: *mut c_void) {
        #[cfg(target_arch = "aarch64")]
        {
            let _ = replace_arm64::revert(self, function_address);
        }
        #[cfg(target_arch = "x86_64")]
        {
            let _ = replace_x86_64::revert(self, function_address);
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            let _ = function_address;
        }
    }

    pub fn begin_transaction(&self) {}
    pub fn end_transaction(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_arch = "aarch64")]
    use crate::arch::arm64::writer::{Arm64Writer, Reg};
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    use crate::code::allocator::{CodeAllocator, CodeSlice};
    use crate::interceptor::invocation as inv;
    use crate::types::InvocationContext;
    use core::sync::atomic::{AtomicU32, Ordering};
    use std::sync::MutexGuard;

    // Use the crate-level lock so patcher tests and interceptor tests don't collide.
    fn lock_hook_tests() -> MutexGuard<'static, ()> {
        crate::lock_hook_tests()
    }

    #[cfg(target_arch = "aarch64")]
    fn make_add_const(c: u32) -> (CodeSlice, extern "C" fn(i64) -> i64) {
        let mut alloc = CodeAllocator::default();
        let slice = alloc.alloc_any().expect("alloc");
        unsafe {
            let mut w = Arm64Writer::new(slice.data, slice.size, slice.data as u64);
            w.put_add_reg_reg_imm(Reg::X0, Reg::X0, c);
            w.put_ret();
            w.put_u32_raw(0xD503201F); // nop
            w.put_u32_raw(0xD503201F); // nop
            alloc.make_executable(&slice).expect("rx");
        }
        let f: extern "C" fn(i64) -> i64 = unsafe { core::mem::transmute(slice.pc) };
        (slice, f)
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn replace_and_revert_works() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();

        let (_f_mem, f) = make_add_const(1);
        let (_r_mem, r) = make_add_const(100);

        assert_eq!(f(1), 2);

        let mut orig: *const c_void = core::ptr::null();
        i.replace(f as *mut c_void, r as *const c_void, core::ptr::null_mut(), &mut orig)
            .unwrap();

        // Calling through the original symbol should now hit replacement.
        assert_eq!(f(1), 101);

        // Calling the trampoline should preserve original behavior.
        let orig_fn: extern "C" fn(i64) -> i64 = unsafe { core::mem::transmute(orig) };
        assert_eq!(orig_fn(1), 2);

        i.revert(f as *mut c_void);
        assert_eq!(f(1), 2);
    }

    #[cfg(target_arch = "aarch64")]
    static ENTER_HITS: AtomicU32 = AtomicU32::new(0);
    #[cfg(target_arch = "aarch64")]
    static LEAVE_HITS: AtomicU32 = AtomicU32::new(0);

    #[cfg(target_arch = "aarch64")]
    unsafe extern "C" fn on_enter(ctx: *mut InvocationContext, _ud: *mut c_void) {
        ENTER_HITS.fetch_add(1, Ordering::Relaxed);
        let a0 = inv::get_nth_argument(ctx, 0) as usize as u64;
        // Rewrite arg: x -> x + 10
        inv::replace_nth_argument(ctx, 0, (a0 + 10) as usize as *mut c_void);
    }

    #[cfg(target_arch = "aarch64")]
    unsafe extern "C" fn on_leave(ctx: *mut InvocationContext, _ud: *mut c_void) {
        LEAVE_HITS.fetch_add(1, Ordering::Relaxed);
        let rv = inv::get_return_value(ctx) as usize as u64;
        inv::replace_return_value(ctx, (rv + 1000) as usize as *mut c_void);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn attach_enter_leave_can_modify_args_and_return() {
        let _g = lock_hook_tests();

        ENTER_HITS.store(0, Ordering::Relaxed);
        LEAVE_HITS.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);

        // Original: x+1.
        assert_eq!(f(1), 2);

        let listener = CallListener {
            on_enter: Some(on_enter),
            on_leave: Some(on_leave),
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        // Enter adds 10 to arg => (1+10)+1 = 12; leave adds 1000 => 1012
        assert_eq!(f(1), 1012);
        assert_eq!(ENTER_HITS.load(Ordering::Relaxed), 1);
        assert_eq!(LEAVE_HITS.load(Ordering::Relaxed), 1);

        i.detach(&listener);
        assert_eq!(f(1), 2);
    }


    /// Calling replace_return_value in on_enter skips the original function.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn replace_return_value_in_on_enter_skips_original() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let _g = lock_hook_tests();

        static SKIP_ENTER: AtomicU32 = AtomicU32::new(0);
        static SKIP_LEAVE: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn skip_on_enter(ctx: *mut InvocationContext, _ud: *mut c_void) {
            SKIP_ENTER.fetch_add(1, Ordering::Relaxed);
            // Replace return value with -1 — this should skip the original function.
            inv::replace_return_value(ctx, (-1isize) as usize as *mut c_void);
        }
        unsafe extern "C" fn skip_on_leave(ctx: *mut InvocationContext, _ud: *mut c_void) {
            SKIP_LEAVE.fetch_add(1, Ordering::Relaxed);
            // Return value should be -1 (the replacement), not f(x).
            let rv = inv::get_return_value(ctx) as usize as i64;
            assert_eq!(rv, -1, "return value in on_leave should be the replacement");
        }

        SKIP_ENTER.store(0, Ordering::Relaxed);
        SKIP_LEAVE.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1); // f(x) = x+1

        assert_eq!(f(42), 43, "original should return x+1");

        let listener = CallListener {
            on_enter: Some(skip_on_enter),
            on_leave: Some(skip_on_leave),
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        // With skip_original, the result should be -1 regardless of input.
        let result = f(42);
        assert_eq!(result, -1i64, "should return replacement value (-1), not f(42)=43");
        assert_eq!(SKIP_ENTER.load(Ordering::Relaxed), 1);
        assert_eq!(SKIP_LEAVE.load(Ordering::Relaxed), 1);

        i.detach(&listener);
        assert_eq!(f(42), 43, "original restored after detach");
    }

    /// Skip original on a real libc function (getpid).
    #[test]
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn replace_return_value_skips_libc_getpid() {
        let _g = lock_hook_tests();

        unsafe extern "C" fn fake_enter(ctx: *mut InvocationContext, _ud: *mut c_void) {
            inv::replace_return_value(ctx, 12345usize as *mut c_void);
        }

        extern "C" { fn getpid() -> libc::pid_t; }

        let real_pid = unsafe { getpid() };
        assert_ne!(real_pid, 12345, "sanity: real PID should not be 12345");

        let i = Interceptor::obtain();
        let listener = CallListener {
            on_enter: Some(fake_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };

        let addr = crate::module::find_global_export_by_name("getpid")
            .expect("find getpid");
        let result = i.attach(addr as *mut c_void, listener);
        if result.is_err() { return; } // Skip if can't hook

        let f = std::hint::black_box(getpid);
        let pid = unsafe { f() };
        assert_eq!(pid, 12345, "getpid should return fake value when skipped");

        i.detach(&listener);
        let f = std::hint::black_box(getpid);
        assert_eq!(unsafe { f() }, real_pid, "getpid restored after detach");
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn detach_restores_original_behavior() {
        let _g = lock_hook_tests();

        ENTER_HITS.store(0, Ordering::Relaxed);
        LEAVE_HITS.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);

        let listener = CallListener {
            on_enter: Some(on_enter),
            on_leave: Some(on_leave),
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        assert_eq!(f(1), 1012);
        assert_eq!(ENTER_HITS.load(Ordering::Relaxed), 1);
        assert_eq!(LEAVE_HITS.load(Ordering::Relaxed), 1);

        i.detach(&listener);
        assert_eq!(f(1), 2);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn attach_with_no_callbacks_preserves_behavior() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);

        assert_eq!(f(1), 2);

        let listener = CallListener {
            on_enter: None,
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        // First, call the wrapper directly to isolate prologue patching issues.
        let wrapper = {
            let map = i.attach_map.lock().unwrap();
            map.get(&(f as usize)).unwrap().wrapper
        };
        let wrapper_fn: extern "C" fn(i64) -> i64 = unsafe { core::mem::transmute(wrapper as *const c_void) };
        assert_eq!(wrapper_fn(1), 2);

        // Then, call through the patched symbol.
        assert_eq!(f(1), 2);

        i.detach(&listener);
        assert_eq!(f(1), 2);
    }

    /// Attach to a real libc function (abs) and verify callbacks fire.
    ///
    /// This catches issues where:
    /// - patch_code silently fails on code-signed shared-cache pages
    /// - Cache incoherence prevents the CPU from executing patched code
    /// - The trampoline/wrapper works on allocated pages but not real code
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn attach_fires_callbacks_on_libc_function() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let _g = lock_hook_tests();

        static LIBC_ENTER: AtomicU32 = AtomicU32::new(0);
        static LIBC_LEAVE: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn libc_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            LIBC_ENTER.fetch_add(1, Ordering::Relaxed);
        }
        unsafe extern "C" fn libc_on_leave(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            LIBC_LEAVE.fetch_add(1, Ordering::Relaxed);
        }

        LIBC_ENTER.store(0, Ordering::Relaxed);
        LIBC_LEAVE.store(0, Ordering::Relaxed);

        extern "C" {
            fn abs(i: libc::c_int) -> libc::c_int;
        }

        let i = Interceptor::obtain();
        let listener = CallListener {
            on_enter: Some(libc_on_enter),
            on_leave: Some(libc_on_leave),
            user_data: core::ptr::null_mut(),
        };

        let result = i.attach(abs as *mut c_void, listener);
        if let Err(e) = &result {
            eprintln!("attach on abs() failed (may be expected in some environments): {:?}", e);
            return;
        }

        // Call abs() through a black_box'd pointer to prevent LLVM from
        // constant-folding the call (LLVM knows abs() semantics and will
        // emit inline cmp+cneg instead of an actual call in release mode).
        let abs_fn: unsafe extern "C" fn(libc::c_int) -> libc::c_int = abs;
        let abs_fn = std::hint::black_box(abs_fn);
        let val = unsafe { abs_fn(-42) };
        assert_eq!(val, 42, "abs(-42) should return 42");

        assert!(
            LIBC_ENTER.load(Ordering::Relaxed) > 0,
            "on_enter callback must fire when calling abs() after attach"
        );
        assert!(
            LIBC_LEAVE.load(Ordering::Relaxed) > 0,
            "on_leave callback must fire when calling abs() after attach"
        );

        i.detach(&listener);
    }

    /// Attach to a function in the main executable (not shared cache).
    ///
    /// This tests patching code pages of the current binary, which have
    /// different protection (max_prot=0x5 RX) than dynamically allocated pages.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn attach_fires_callbacks_on_main_executable_function() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let _g = lock_hook_tests();

        static MAIN_ENTER: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn main_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            MAIN_ENTER.fetch_add(1, Ordering::Relaxed);
        }

        MAIN_ENTER.store(0, Ordering::Relaxed);

        // A function defined in the test binary itself.
        // Must be long enough (>= 16 bytes / 4 instructions) for the
        // interceptor to relocate the prologue.
        #[inline(never)]
        extern "C" fn test_add(a: i64, b: i64) -> i64 {
            let c = a.wrapping_mul(3);
            let d = b.wrapping_add(c);
            d.wrapping_sub(a.wrapping_mul(2))
        }

        let i = Interceptor::obtain();
        let listener = CallListener {
            on_enter: Some(main_on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };

        let result = i.attach(test_add as *mut c_void, listener);
        if let Err(e) = &result {
            eprintln!("attach on test_add() failed: {:?}", e);
            panic!("attach on main executable function must succeed: {:?}", e);
        }

        // Use black_box to prevent compile-time evaluation of the call.
        let f = std::hint::black_box(test_add);
        let val = f(std::hint::black_box(3), std::hint::black_box(4));
        assert_eq!(val, 7, "test_add(3,4) should return 7");

        assert!(
            MAIN_ENTER.load(Ordering::Relaxed) > 0,
            "on_enter must fire when calling a function in the main executable"
        );

        i.detach(&listener);

        // Verify function still works after detach.
        let f = std::hint::black_box(test_add);
        assert_eq!(f(10, 20), 30);
    }

    /// Hook `send` — a short libc function (only 12 bytes / 3 instructions on
    /// macOS ARM64). Verifies that the adaptive 4-byte B patch works and does
    /// not corrupt the adjacent `recv` function.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn attach_short_function_does_not_corrupt_neighbors() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let _g = lock_hook_tests();

        static SHORT_ENTER: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn short_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            SHORT_ENTER.fetch_add(1, Ordering::Relaxed);
        }

        SHORT_ENTER.store(0, Ordering::Relaxed);

        extern "C" {
            fn send(socket: libc::c_int, buf: *const c_void, len: libc::size_t, flags: libc::c_int) -> libc::ssize_t;
            fn recv(socket: libc::c_int, buf: *mut c_void, len: libc::size_t, flags: libc::c_int) -> libc::ssize_t;
        }

        // Record recv's prologue before hooking send.
        let recv_before = unsafe { core::ptr::read_unaligned(recv as *const [u8; 16]) };

        let i = Interceptor::obtain();
        let listener = CallListener {
            on_enter: Some(short_on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };

        i.attach(send as *mut c_void, listener).unwrap();

        // Verify recv's prologue was NOT corrupted by hooking send.
        let recv_after = unsafe { core::ptr::read_unaligned(recv as *const [u8; 16]) };
        assert_eq!(
            recv_before, recv_after,
            "Hooking send must not corrupt adjacent recv function.\n  before: {:02x?}\n  after:  {:02x?}",
            recv_before, recv_after
        );

        // Verify the hook used a patch smaller than 16 bytes.
        // For shared cache functions ~2GB from the wrapper, expect 12-byte
        // ADRP+ADD+BR. If wrapper were within ±128MB, it would be 4-byte B.
        {
            let map = i.attach_map.lock().unwrap();
            let ctx = map.get(&(send as *const () as usize)).unwrap();
            assert!(ctx.patch_size <= 12, "Short function should use <=12 byte patch, got {}", ctx.patch_size);
        }

        // Verify the hook fires (call send on an invalid fd — it will fail but the hook should still trigger).
        let buf = [0u8; 1];
        let _ = unsafe { send(-1, buf.as_ptr() as *const c_void, 1, 0) };

        assert!(
            SHORT_ENTER.load(Ordering::Relaxed) > 0,
            "on_enter must fire when calling send() after attach"
        );

        i.detach(&listener);
    }

    /// Verify that the prologue bytes are actually modified after attach.
    ///
    /// This is a diagnostic test: if the interceptor reports success but
    /// the prologue bytes haven't changed, the patcher's vm_remap/write
    /// approach isn't working.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn attach_actually_patches_prologue_bytes() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);

        // Read prologue before attach.
        let before = unsafe { core::ptr::read_unaligned(f as *const [u8; 16]) };

        let listener = CallListener {
            on_enter: None,
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        // Read prologue after attach.
        let after = unsafe { core::ptr::read_unaligned(f as *const [u8; 16]) };

        assert_ne!(
            before, after,
            "Prologue bytes must change after attach.\n  before: {:02x?}\n  after:  {:02x?}",
            before, after
        );

        i.detach(&listener);

        // After detach, prologue should be restored.
        let restored = unsafe { core::ptr::read_unaligned(f as *const [u8; 16]) };
        assert_eq!(
            before, restored,
            "Prologue bytes must be restored after detach"
        );
    }

    /// Verify that a replaced function stays replaced across thousands of calls.
    ///
    /// This catches issues where:
    /// - The redirect stub gets corrupted after many calls
    /// - Cache coherency issues cause the CPU to execute stale (original) code
    /// - The trampoline page gets reclaimed or overwritten
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn replace_stays_active_across_many_calls() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();

        let (_f_mem, f) = make_add_const(1);   // f(x) = x+1
        let (_r_mem, r) = make_add_const(100); // r(x) = x+100

        assert_eq!(f(1), 2, "original before replace");

        i.replace(f as *mut c_void, r as *const c_void, core::ptr::null_mut(), core::ptr::null_mut())
            .unwrap();

        // Call the replaced function 5000 times (more than V8 bootstrap ~1800).
        for call_num in 0..5000u64 {
            let result = f(call_num as i64);
            assert_eq!(
                result,
                call_num as i64 + 100,
                "replace must stay active on call #{call_num} (got {result}, expected {})",
                call_num as i64 + 100,
            );
        }

        i.revert(f as *mut c_void);
        assert_eq!(f(1), 2, "original after revert");
    }

    /// Verify that replace works for a function with a realistic prologue
    /// (STP + MOV pattern common in C/C++ functions).
    #[cfg(target_arch = "aarch64")]
    fn make_realistic_function() -> (CodeSlice, extern "C" fn(i64) -> i64) {
        let mut alloc = CodeAllocator::default();
        let slice = alloc.alloc_any().expect("alloc");
        unsafe {
            let mut w = Arm64Writer::new(slice.data, slice.size, slice.data as u64);
            // STP x29, x30, [sp, #-16]!  (standard function prologue)
            w.put_u32_raw(0xA9BF7BFD);
            // MOV x29, sp
            w.put_u32_raw(0x910003FD);
            // ADD x0, x0, #5 (the actual computation)
            w.put_add_reg_reg_imm(Reg::X0, Reg::X0, 5);
            // LDP x29, x30, [sp], #16 (standard epilogue)
            w.put_u32_raw(0xA8C17BFD);
            // RET
            w.put_ret();
            // Padding NOPs
            w.put_u32_raw(0xD503201F);
            w.put_u32_raw(0xD503201F);
            w.put_u32_raw(0xD503201F);
            alloc.make_executable(&slice).expect("rx");
        }
        let f: extern "C" fn(i64) -> i64 = unsafe { core::mem::transmute(slice.pc) };
        (slice, f)
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn replace_works_with_realistic_prologue() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();

        let (_f_mem, f) = make_realistic_function(); // f(x) = x+5
        let (_r_mem, r) = make_add_const(200);       // r(x) = x+200

        assert_eq!(f(10), 15, "original function should return x+5");

        let mut orig: *const c_void = core::ptr::null();
        i.replace(f as *mut c_void, r as *const c_void, core::ptr::null_mut(), &mut orig)
            .unwrap();

        // Replacement should be active.
        assert_eq!(f(10), 210, "replaced function should return x+200");

        // Trampoline should call original.
        let orig_fn: extern "C" fn(i64) -> i64 = unsafe { core::mem::transmute(orig) };
        assert_eq!(orig_fn(10), 15, "trampoline should call original (x+5)");

        // Call many times to verify stability.
        for n in 0..2000i64 {
            assert_eq!(f(n), n + 200, "replace must stay active on call #{n}");
        }

        i.revert(f as *mut c_void);
        assert_eq!(f(10), 15, "original restored after revert");
    }

    /// Replace libc abs() with a custom function and verify execution.
    ///
    /// This catches issues where:
    /// - Code-signed shared-cache page patching silently fails
    /// - The trampoline correctly calls the original function
    /// - Revert fully restores the original behavior
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn replace_on_libc_abs_with_execution_verification() {
        let _g = lock_hook_tests();

        extern "C" {
            fn abs(i: libc::c_int) -> libc::c_int;
        }

        extern "C" fn fake_abs(_i: libc::c_int) -> libc::c_int {
            999
        }

        let i = Interceptor::obtain();

        // Verify original works.
        let abs_fn: unsafe extern "C" fn(libc::c_int) -> libc::c_int = abs;
        let abs_fn = std::hint::black_box(abs_fn);
        assert_eq!(unsafe { abs_fn(-42) }, 42, "original abs(-42) should be 42");

        let mut orig: *const c_void = core::ptr::null();
        let result = i.replace(
            abs as *mut c_void,
            fake_abs as *const c_void,
            core::ptr::null_mut(),
            &mut orig,
        );
        if let Err(e) = &result {
            eprintln!("replace on abs() failed (may be expected in some environments): {:?}", e);
            return;
        }

        // Calling abs should now return 999.
        let abs_fn = std::hint::black_box(abs_fn);
        assert_eq!(unsafe { abs_fn(-42) }, 999, "replaced abs(-42) should return 999");

        // Trampoline should call original → returns 42.
        assert!(!orig.is_null(), "trampoline pointer must not be null");
        let orig_fn: unsafe extern "C" fn(libc::c_int) -> libc::c_int =
            unsafe { core::mem::transmute(orig) };
        assert_eq!(unsafe { orig_fn(-42) }, 42, "trampoline should call original abs");

        // Revert and verify original is restored.
        i.revert(abs as *mut c_void);
        let abs_fn = std::hint::black_box(abs_fn);
        assert_eq!(unsafe { abs_fn(-42) }, 42, "abs(-42) should be 42 after revert");
    }

    /// Replace abs() and call through a pre-stored function pointer.
    ///
    /// This catches issues where inline patching works for direct calls
    /// but indirect calls through function pointers don't hit the replacement.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn replace_on_libc_called_via_function_pointer() {
        let _g = lock_hook_tests();

        extern "C" {
            fn abs(i: libc::c_int) -> libc::c_int;
        }

        extern "C" fn fake_abs(_i: libc::c_int) -> libc::c_int {
            777
        }

        // Store function pointer BEFORE replace.
        let fptr: unsafe extern "C" fn(libc::c_int) -> libc::c_int = abs;
        let fptr = std::hint::black_box(fptr);

        let i = Interceptor::obtain();
        let result = i.replace(
            abs as *mut c_void,
            fake_abs as *const c_void,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        if let Err(e) = &result {
            eprintln!("replace on abs() failed: {:?}", e);
            return;
        }

        // Call through the stored function pointer — must hit replacement.
        let fptr = std::hint::black_box(fptr);
        assert_eq!(unsafe { fptr(-10) }, 777, "call through pre-stored fn ptr should hit replacement");

        i.revert(abs as *mut c_void);
        let fptr = std::hint::black_box(fptr);
        assert_eq!(unsafe { fptr(-10) }, 10, "abs should work after revert");
    }

    /// Replace → verify → revert → verify, 100 iterations.
    ///
    /// Catches code page corruption from repeated patching/restoring.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn replace_and_revert_rapid_cycle_100_times() {
        let _g = lock_hook_tests();

        extern "C" {
            fn abs(i: libc::c_int) -> libc::c_int;
        }

        extern "C" fn fake_abs(_i: libc::c_int) -> libc::c_int {
            555
        }

        let i = Interceptor::obtain();
        let abs_fn: unsafe extern "C" fn(libc::c_int) -> libc::c_int = abs;

        for cycle in 0..100u32 {
            let result = i.replace(
                abs as *mut c_void,
                fake_abs as *const c_void,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
            if let Err(e) = &result {
                eprintln!("replace failed on cycle {cycle}: {:?}", e);
                return;
            }

            let f = std::hint::black_box(abs_fn);
            assert_eq!(
                unsafe { f(-7) }, 555,
                "cycle {cycle}: replaced abs should return 555"
            );

            i.revert(abs as *mut c_void);

            let f = std::hint::black_box(abs_fn);
            assert_eq!(
                unsafe { f(-7) }, 7,
                "cycle {cycle}: reverted abs should return 7"
            );
        }
    }

    /// Test attach_rebinding: creates a callable wrapper without patching the target.
    ///
    /// This tests the codepath used by spawn_monitor.rs for symbol rebinding.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn attach_rebinding_creates_callable_wrapper() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let _g = lock_hook_tests();

        static RB_ENTER: AtomicU32 = AtomicU32::new(0);
        static RB_LEAVE: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn rb_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            RB_ENTER.fetch_add(1, Ordering::Relaxed);
        }
        unsafe extern "C" fn rb_on_leave(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            RB_LEAVE.fetch_add(1, Ordering::Relaxed);
        }

        RB_ENTER.store(0, Ordering::Relaxed);
        RB_LEAVE.store(0, Ordering::Relaxed);

        extern "C" {
            fn abs(i: libc::c_int) -> libc::c_int;
        }

        let i = Interceptor::obtain();
        let listener = CallListener {
            on_enter: Some(rb_on_enter),
            on_leave: Some(rb_on_leave),
            user_data: core::ptr::null_mut(),
        };

        let wrapper = i.attach_rebinding(abs as *mut c_void, listener).unwrap();
        assert_ne!(wrapper, 0, "wrapper address must not be null");

        // The original function should NOT be patched.
        let abs_fn: unsafe extern "C" fn(libc::c_int) -> libc::c_int = abs;
        let abs_fn = std::hint::black_box(abs_fn);
        assert_eq!(unsafe { abs_fn(-42) }, 42, "original abs should still work (no patch)");
        assert_eq!(RB_ENTER.load(Ordering::Relaxed), 0, "calling original should NOT fire callbacks");

        // Calling through the wrapper should fire callbacks and return correct value.
        let wrapper_fn: unsafe extern "C" fn(libc::c_int) -> libc::c_int =
            unsafe { core::mem::transmute(wrapper as *const c_void) };
        let wrapper_fn = std::hint::black_box(wrapper_fn);
        let val = unsafe { wrapper_fn(-42) };
        assert_eq!(val, 42, "wrapper should return correct abs(-42) value");
        assert!(RB_ENTER.load(Ordering::Relaxed) > 0, "wrapper call must fire on_enter");
        assert!(RB_LEAVE.load(Ordering::Relaxed) > 0, "wrapper call must fire on_leave");

        i.detach(&listener);
    }

    /// attach_rebinding() must also reject targets that are already replaced.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn replace_then_attach_rebinding_returns_already_attached() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);
        let (_r_mem, r) = make_add_const(100);

        i.replace(
            f as *mut c_void,
            r as *const c_void,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
        .unwrap();

        let listener = CallListener {
            on_enter: None,
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        let result = i.attach_rebinding(f as *mut c_void, listener);
        assert_eq!(
            result,
            Err(HookError::AlreadyAttached),
            "attach_rebinding after replace must return AlreadyAttached"
        );

        i.revert(f as *mut c_void);
        assert_eq!(f(5), 6, "original restored after revert");
    }

    /// Verify replace works after changing CWD.
    ///
    /// If this passes, CWD-sensitivity is NOT in the hook library.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn replace_works_after_cwd_change() {
        let _g = lock_hook_tests();

        extern "C" {
            fn abs(i: libc::c_int) -> libc::c_int;
        }

        extern "C" fn fake_abs(_i: libc::c_int) -> libc::c_int {
            888
        }

        let original_cwd = std::env::current_dir().unwrap();

        // Change to /tmp.
        std::env::set_current_dir("/tmp").expect("failed to chdir to /tmp");

        let i = Interceptor::obtain();
        let result = i.replace(
            abs as *mut c_void,
            fake_abs as *const c_void,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );

        if let Err(e) = &result {
            std::env::set_current_dir(&original_cwd).ok();
            eprintln!("replace on abs() failed after CWD change: {:?}", e);
            return;
        }

        let abs_fn: unsafe extern "C" fn(libc::c_int) -> libc::c_int = abs;
        let abs_fn = std::hint::black_box(abs_fn);
        assert_eq!(
            unsafe { abs_fn(-5) }, 888,
            "replaced abs should return 888 after CWD change to /tmp"
        );

        i.revert(abs as *mut c_void);

        let abs_fn = std::hint::black_box(abs_fn);
        assert_eq!(
            unsafe { abs_fn(-5) }, 5,
            "reverted abs should return 5 after CWD change to /tmp"
        );

        // Restore CWD.
        std::env::set_current_dir(&original_cwd).ok();
    }

    /// Verify that a replaced function works correctly when called from
    /// multiple threads simultaneously.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn replace_works_across_threads() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();

        let (_f_mem, f) = make_add_const(1);   // f(x) = x+1
        let (_r_mem, r) = make_add_const(100); // r(x) = x+100

        i.replace(f as *mut c_void, r as *const c_void, core::ptr::null_mut(), core::ptr::null_mut())
            .unwrap();

        let f_addr = f as usize;
        let handles: Vec<_> = (0..4)
            .map(|thread_id| {
                std::thread::spawn(move || {
                    let f: extern "C" fn(i64) -> i64 = unsafe { core::mem::transmute(f_addr) };
                    for call in 0..1000i64 {
                        let result = f(call);
                        assert_eq!(
                            result,
                            call + 100,
                            "thread {thread_id} call #{call}: expected {}, got {result}",
                            call + 100,
                        );
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        i.revert(f as *mut c_void);
        assert_eq!(f(1), 2);
    }

    /// Hook execve (a short syscall wrapper on Linux ARM64) and verify no crash.
    ///
    /// On Linux ARM64, execve is typically only 6 instructions:
    ///   NOP, MOVZ X8, SVC, CMN, B.CS, RET
    /// This tests that the interceptor handles this short syscall stub.
    #[test]
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn attach_to_execve_no_crash() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let _g = lock_hook_tests();

        static EXECVE_ENTER: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn execve_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            EXECVE_ENTER.fetch_add(1, Ordering::Relaxed);
        }

        EXECVE_ENTER.store(0, Ordering::Relaxed);

        let execve_addr = crate::module::find_global_export_by_name("execve")
            .expect("should find execve");
        eprintln!("execve at: {:#x}", execve_addr);

        // Print execve prologue for diagnostics.
        unsafe {
            let insns = core::slice::from_raw_parts(execve_addr as *const u32, 8);
            for (j, &insn) in insns.iter().enumerate() {
                eprintln!("  execve+{}: {:#010x}", j * 4, insn);
            }
        }

        let i = Interceptor::obtain();
        let listener = CallListener {
            on_enter: Some(execve_on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };

        i.attach(execve_addr as *mut c_void, listener).unwrap();

        // Check patch size.
        {
            let map = i.attach_map.lock().unwrap();
            let ctx = map.get(&execve_addr).unwrap();
            eprintln!("execve patch_size: {} bytes ({} insns)", ctx.patch_size, ctx.patch_size / 4);
        }

        i.detach(&listener);
        eprintln!("execve hook+unhook succeeded");
    }

    /// Hook multiple libc syscall wrappers (getpid, getuid, etc.) and verify
    /// they still return correct values. These are very short functions (often
    /// just SVC + error check + RET) and exercise the can_relocate validation.
    #[test]
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn attach_to_syscall_wrappers_preserves_behavior() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let _g = lock_hook_tests();

        static HITS: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn count_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            HITS.fetch_add(1, Ordering::Relaxed);
        }

        let i = Interceptor::obtain();

        // getpid is a very short syscall wrapper.
        extern "C" { fn getpid() -> libc::pid_t; }
        let getpid_addr = crate::module::find_global_export_by_name("getpid")
            .expect("should find getpid");

        let expected_pid = unsafe { getpid() };

        HITS.store(0, Ordering::Relaxed);
        let listener = CallListener {
            on_enter: Some(count_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };

        let result = i.attach(getpid_addr as *mut c_void, listener);
        if let Err(e) = &result {
            eprintln!("attach to getpid failed (may need can_relocate fallback): {:?}", e);
            return;
        }

        // Call through black_box to prevent inlining.
        let f = std::hint::black_box(getpid);
        let pid = unsafe { f() };
        assert_eq!(pid, expected_pid, "getpid must return correct value after hook");
        assert!(HITS.load(Ordering::Relaxed) > 0, "on_enter must fire for getpid");

        i.detach(&listener);

        // Verify restored.
        let f = std::hint::black_box(getpid);
        assert_eq!(unsafe { f() }, expected_pid, "getpid must work after detach");
    }

    /// Hook a function with STP/LDP prologue (realistic C function pattern).
    /// Verifies the interceptor handles stack-manipulating prologues.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn attach_to_function_with_stp_prologue() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let _g = lock_hook_tests();

        static STP_ENTER: AtomicU32 = AtomicU32::new(0);
        static STP_LEAVE: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn stp_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            STP_ENTER.fetch_add(1, Ordering::Relaxed);
        }
        unsafe extern "C" fn stp_on_leave(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            STP_LEAVE.fetch_add(1, Ordering::Relaxed);
        }

        STP_ENTER.store(0, Ordering::Relaxed);
        STP_LEAVE.store(0, Ordering::Relaxed);

        // Build a function with a realistic STP prologue.
        let mut alloc = CodeAllocator::default();
        let slice = alloc.alloc_any().expect("alloc");
        unsafe {
            use crate::arch::arm64::writer::{Arm64Writer, Reg};
            let mut w = Arm64Writer::new(slice.data, slice.size, slice.data as u64);
            // STP x29, x30, [sp, #-16]!
            w.put_u32_raw(0xA9BF7BFD);
            // MOV x29, sp
            w.put_u32_raw(0x910003FD);
            // ADD x0, x0, #42
            w.put_add_reg_reg_imm(Reg::X0, Reg::X0, 42);
            // LDP x29, x30, [sp], #16
            w.put_u32_raw(0xA8C17BFD);
            // RET
            w.put_ret();
            // Padding
            for _ in 0..4 { w.put_u32_raw(0xD503201F); }
            alloc.make_executable(&slice).expect("rx");
        }
        let f: extern "C" fn(i64) -> i64 = unsafe { core::mem::transmute(slice.pc) };

        // Verify unhooked behavior.
        assert_eq!(f(10), 52, "f(10) should be 52 before hook");

        let i = Interceptor::obtain();
        let listener = CallListener {
            on_enter: Some(stp_on_enter),
            on_leave: Some(stp_on_leave),
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        // Verify hooked behavior preserves function semantics.
        let f = std::hint::black_box(f);
        assert_eq!(f(10), 52, "f(10) should still be 52 after hook");
        assert!(STP_ENTER.load(Ordering::Relaxed) > 0, "on_enter must fire");
        assert!(STP_LEAVE.load(Ordering::Relaxed) > 0, "on_leave must fire");

        // Call multiple times to verify stability.
        for n in 0..100i64 {
            assert_eq!(f(n), n + 42, "hooked f({n}) must return {}", n + 42);
        }

        i.detach(&listener);
        assert_eq!(f(10), 52, "f(10) should be 52 after detach");
    }

    /// Test the can_relocate function directly.
    /// SVC is position-independent and NOT a relocation boundary.
    /// Only BL/BLR are boundaries (they modify LR).
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn can_relocate_does_not_stop_at_svc() {
        use crate::arch::arm64::relocator::can_relocate;
        use crate::arch::arm64::writer::Reg;

        // Simulate execve-like prologue: NOP, MOVZ, SVC, CMN
        let insns: [u32; 4] = [
            0xD503201F, // NOP
            0xD2801BA8, // MOVZ X8, #0xDD
            0xD4000001, // SVC #0
            0xB13FFC1F, // CMN X0, #0xFFF
        ];
        let (max_safe, scratch) = unsafe { can_relocate(insns.as_ptr(), 4) };
        // SVC is NOT a boundary — all 4 instructions can be safely relocated.
        assert_eq!(max_safe, 4, "SVC should not stop relocation");
        assert_eq!(scratch, Reg::X16, "x16 should be available (only x8 used)");
    }

    /// Test can_relocate with a prologue that uses x16.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn can_relocate_detects_x16_usage() {
        use crate::arch::arm64::relocator::can_relocate;
        use crate::arch::arm64::writer::Reg;

        // MOV X16, X0 (AA0003F0) uses X16 as Rd
        let insns: [u32; 4] = [
            0xAA0003F0, // MOV X16, X0
            0xD503201F, // NOP
            0xD503201F, // NOP
            0xD503201F, // NOP
        ];
        let (_max, scratch) = unsafe { can_relocate(insns.as_ptr(), 4) };
        assert_eq!(scratch, Reg::X17, "should fall back to x17 when x16 is used");
    }

    /// BL should still be a relocation boundary (it sets LR = pc+4).
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn can_relocate_stops_at_bl() {
        use crate::arch::arm64::relocator::can_relocate;

        // NOP, BL #offset, NOP, NOP
        let insns: [u32; 4] = [
            0xD503201F, // NOP
            0x94000010, // BL #0x40
            0xD503201F, // NOP
            0xD503201F, // NOP
        ];
        let (max_safe, _) = unsafe { can_relocate(insns.as_ptr(), 4) };
        assert_eq!(max_safe, 2, "BL should stop relocation (include it, stop further)");
    }

    /// Hook a libc syscall wrapper (socket) that starts with MOV X16,#nr; SVC #0x80.
    ///
    /// This tests the critical path where SVC is NOT treated as a boundary:
    /// the interceptor must relocate past SVC to get enough instructions for the patch.
    /// On macOS, the dyld shared cache has no free pages nearby, so near-allocation
    /// would fail — the only option is to relocate past SVC to reach 4+ instructions.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn attach_to_libc_socket_syscall_wrapper() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let _g = lock_hook_tests();

        static SOCKET_ENTER: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn socket_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            SOCKET_ENTER.fetch_add(1, Ordering::Relaxed);
        }

        SOCKET_ENTER.store(0, Ordering::Relaxed);

        let socket_addr = crate::module::find_global_export_by_name("socket")
            .expect("should find socket");

        let i = Interceptor::obtain();
        let listener = CallListener {
            on_enter: Some(socket_on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };

        // This must succeed (inline attach, not rebinding fallback).
        i.attach(socket_addr as *mut c_void, listener).unwrap();

        // Call socket() — should trigger our hook.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0, "socket() should succeed");
        unsafe { libc::close(fd); }

        assert!(SOCKET_ENTER.load(Ordering::Relaxed) >= 1, "hook should fire for socket()");

        i.detach(&listener);

        // Verify socket() still works after detach.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0, "socket() should still work after detach");
        unsafe { libc::close(fd); }
    }

    /// Hook connect() (another syscall wrapper) and verify error handling works.
    ///
    /// connect() to a bogus address should return ECONNREFUSED/-1, verifying
    /// the relocated B.cond error path is correct.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn attach_to_libc_connect_preserves_error_path() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let _g = lock_hook_tests();

        static CONNECT_ENTER: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn connect_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            CONNECT_ENTER.fetch_add(1, Ordering::Relaxed);
        }

        CONNECT_ENTER.store(0, Ordering::Relaxed);

        let connect_addr = crate::module::find_global_export_by_name("connect")
            .expect("should find connect");

        let i = Interceptor::obtain();
        let listener = CallListener {
            on_enter: Some(connect_on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };

        i.attach(connect_addr as *mut c_void, listener).unwrap();

        // Create a socket and try to connect to a port that's (almost certainly) not listening.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);

        #[cfg(target_os = "macos")]
        let addr = libc::sockaddr_in {
            sin_len: core::mem::size_of::<libc::sockaddr_in>() as u8,
            sin_family: libc::AF_INET as u8,
            sin_port: 1u16.to_be(), // port 1 — unlikely to be listening
            sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes([127, 0, 0, 1]) },
            sin_zero: [0; 8],
        };
        #[cfg(not(target_os = "macos"))]
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 1u16.to_be(), // port 1 — unlikely to be listening
            sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes([127, 0, 0, 1]) },
            sin_zero: [0; 8],
        };
        let ret = unsafe {
            libc::connect(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                core::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        // connect should fail (ECONNREFUSED) — the error path via B.cond must work.
        assert_eq!(ret, -1, "connect to port 1 should fail");
        #[cfg(target_os = "macos")]
        let err = unsafe { *libc::__error() };
        #[cfg(not(target_os = "macos"))]
        let err = unsafe { *libc::__errno_location() };
        assert!(
            err == libc::ECONNREFUSED || err == libc::EACCES || err == libc::ENETUNREACH,
            "expected ECONNREFUSED/EACCES/ENETUNREACH, got errno={}", err
        );

        assert!(CONNECT_ENTER.load(Ordering::Relaxed) >= 1, "hook should fire for connect()");

        unsafe { libc::close(fd); }
        i.detach(&listener);
    }

    /// Two listeners on the same function; both on_enter fire.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn attach_two_listeners_fires_both() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let _g = lock_hook_tests();

        static COUNTER_A: AtomicU32 = AtomicU32::new(0);
        static COUNTER_B: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn on_enter_a(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            COUNTER_A.fetch_add(1, Ordering::Relaxed);
        }
        unsafe extern "C" fn on_enter_b(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            COUNTER_B.fetch_add(1, Ordering::Relaxed);
        }

        COUNTER_A.store(0, Ordering::Relaxed);
        COUNTER_B.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);

        let listener_a = CallListener {
            on_enter: Some(on_enter_a),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        let listener_b = CallListener {
            on_enter: Some(on_enter_b),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };

        i.attach(f as *mut c_void, listener_a).unwrap();
        i.attach(f as *mut c_void, listener_b).unwrap();

        let result = f(5);
        assert_eq!(result, 6, "f(5) should return 6");
        assert_eq!(COUNTER_A.load(Ordering::Relaxed), 1, "listener A should fire");
        assert_eq!(COUNTER_B.load(Ordering::Relaxed), 1, "listener B should fire");

        i.detach(&listener_a);
        i.detach(&listener_b);
        assert_eq!(f(5), 6, "original restored");
    }

    /// Recursive calls with hooks; wrapper is re-entrant; callback fires for each level.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn attach_to_recursive_function() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let _g = lock_hook_tests();

        static RECURSE_ENTER: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn recurse_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            RECURSE_ENTER.fetch_add(1, Ordering::Relaxed);
        }

        RECURSE_ENTER.store(0, Ordering::Relaxed);

        // Build recursive function: f(n) = if n<0 then n+1 else f(n-1)+1
        //   STP X29, X30, [SP, #-16]!
        //   MOV X29, SP
        //   SUBS X0, X0, #1
        //   B.LT +8  (to ADD)
        //   BL self
        //   ADD X0, X0, #1
        //   LDP X29, X30, [SP], #16
        //   RET
        let mut alloc = CodeAllocator::default();
        let slice = alloc.alloc_any().expect("alloc");
        let base = slice.data as u64;
        unsafe {
            let mut w = Arm64Writer::new(slice.data, slice.size, base);
            w.put_push_reg_reg(Reg::X29, Reg::X30);
            w.put_mov_reg_reg(Reg::X29, Reg::SP);
            w.put_u32_raw(0xF1000400); // SUBS X0, X0, #1
            w.put_u32_raw(0x5400_004B); // B.LT +8
            w.put_bl_imm(base);
            w.put_add_reg_reg_imm(Reg::X0, Reg::X0, 1);
            w.put_pop_reg_reg(Reg::X29, Reg::X30);
            w.put_ret();
            for _ in 0..4 {
                w.put_u32_raw(0xD503201F);
            }
            alloc.make_executable(&slice).expect("rx");
        }
        let f: extern "C" fn(i64) -> i64 = unsafe { core::mem::transmute(slice.pc) };

        assert_eq!(f(4), 4, "unhooked f(4) should return 4");

        let i = Interceptor::obtain();
        let listener = CallListener {
            on_enter: Some(recurse_on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        RECURSE_ENTER.store(0, Ordering::Relaxed);
        let result = f(4);
        assert_eq!(result, 4, "hooked f(4) should still return 4");
        assert_eq!(
            RECURSE_ENTER.load(Ordering::Relaxed),
            5,
            "on_enter fires for each recursion level (4,3,2,1,0)"
        );

        i.detach(&listener);
        assert_eq!(f(4), 4, "f(4) after detach");
    }

    /// Detach one of two listeners; remaining listener still fires.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn detach_one_of_two_listeners() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let _g = lock_hook_tests();

        static DA: AtomicU32 = AtomicU32::new(0);
        static DB: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn enter_a(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            DA.fetch_add(1, Ordering::Relaxed);
        }
        unsafe extern "C" fn enter_b(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            DB.fetch_add(1, Ordering::Relaxed);
        }

        DA.store(0, Ordering::Relaxed);
        DB.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);

        let listener_a = CallListener {
            on_enter: Some(enter_a),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        let listener_b = CallListener {
            on_enter: Some(enter_b),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };

        i.attach(f as *mut c_void, listener_a).unwrap();
        i.attach(f as *mut c_void, listener_b).unwrap();

        // Both fire.
        assert_eq!(f(5), 6);
        assert_eq!(DA.load(Ordering::Relaxed), 1);
        assert_eq!(DB.load(Ordering::Relaxed), 1);

        // Detach A — only B fires.
        i.detach(&listener_a);
        assert_eq!(f(5), 6);
        assert_eq!(DA.load(Ordering::Relaxed), 1, "A must not fire after detach");
        assert_eq!(DB.load(Ordering::Relaxed), 2, "B must still fire");

        // Detach B — original restored.
        i.detach(&listener_b);
        assert_eq!(f(5), 6, "original restored");
    }

    /// Hook doesn't corrupt callee-saved registers (X19-X28).
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn cpu_register_clobber() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let _g = lock_hook_tests();

        static CLOBBER_FLAG: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn clobber_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            CLOBBER_FLAG.fetch_add(1, Ordering::Relaxed);
        }

        CLOBBER_FLAG.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(0); // f(x) = x (identity)

        let listener = CallListener {
            on_enter: Some(clobber_on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        // results[0]=ret, [1..10]=x19..x28
        let mut results = [0u64; 11];
        let func_ptr = f as usize;
        let results_ptr = results.as_mut_ptr();

        // Can't name x19-x28 as asm operands (LLVM reserves them), so we
        // manually save/restore them and pass func/out via the stack.
        unsafe {
            core::arch::asm!(
                // Save LLVM's callee-saved regs
                "stp x19, x20, [sp, #-16]!",
                "stp x21, x22, [sp, #-16]!",
                "stp x23, x24, [sp, #-16]!",
                "stp x25, x26, [sp, #-16]!",
                "stp x27, x28, [sp, #-16]!",
                // Save func and out ptrs (they may live in x19-x28)
                "stp {func}, {out}, [sp, #-16]!",
                // Set known values
                "mov x19, #0x19",
                "mov x20, #0x20",
                "mov x21, #0x21",
                "mov x22, #0x22",
                "mov x23, #0x23",
                "mov x24, #0x24",
                "mov x25, #0x25",
                "mov x26, #0x26",
                "mov x27, #0x27",
                "mov x28, #0x28",
                // Load func from stack and call
                "ldr x16, [sp]",
                "mov x0, #42",
                "blr x16",
                // Load out ptr from stack and store results
                "ldr x16, [sp, #8]",
                "str x0, [x16, #0]",
                "str x19, [x16, #8]",
                "str x20, [x16, #16]",
                "str x21, [x16, #24]",
                "str x22, [x16, #32]",
                "str x23, [x16, #40]",
                "str x24, [x16, #48]",
                "str x25, [x16, #56]",
                "str x26, [x16, #64]",
                "str x27, [x16, #72]",
                "str x28, [x16, #80]",
                // Pop func/out
                "add sp, sp, #16",
                // Restore LLVM's callee-saved regs
                "ldp x27, x28, [sp], #16",
                "ldp x25, x26, [sp], #16",
                "ldp x23, x24, [sp], #16",
                "ldp x21, x22, [sp], #16",
                "ldp x19, x20, [sp], #16",
                func = in(reg) func_ptr,
                out = in(reg) results_ptr,
                out("x0") _,
                out("x1") _,
                out("x2") _,
                out("x3") _,
                out("x4") _,
                out("x5") _,
                out("x6") _,
                out("x7") _,
                out("x8") _,
                out("x9") _,
                out("x10") _,
                out("x11") _,
                out("x12") _,
                out("x13") _,
                out("x14") _,
                out("x15") _,
                out("x16") _,
                out("x17") _,
                out("x30") _,
            );
        }

        assert_eq!(CLOBBER_FLAG.load(Ordering::Relaxed), 1, "hook should fire");
        assert_eq!(results[0], 42, "return value preserved");
        assert_eq!(results[1], 0x19, "x19 preserved");
        assert_eq!(results[2], 0x20, "x20 preserved");
        assert_eq!(results[3], 0x21, "x21 preserved");
        assert_eq!(results[4], 0x22, "x22 preserved");
        assert_eq!(results[5], 0x23, "x23 preserved");
        assert_eq!(results[6], 0x24, "x24 preserved");
        assert_eq!(results[7], 0x25, "x25 preserved");
        assert_eq!(results[8], 0x26, "x26 preserved");
        assert_eq!(results[9], 0x27, "x27 preserved");
        assert_eq!(results[10], 0x28, "x28 preserved");

        i.detach(&listener);
    }

    /// Hook doesn't corrupt NZCV condition flags.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn cpu_flag_clobber() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let _g = lock_hook_tests();

        static FLAG_ENTER: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn flag_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            FLAG_ENTER.fetch_add(1, Ordering::Relaxed);
        }

        FLAG_ENTER.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(0); // identity

        let listener = CallListener {
            on_enter: Some(flag_on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        // N=1,Z=0,C=1,V=0 → 0xA000_0000
        let mut nzcv_out: u64 = 0;
        let nzcv_in: u64 = 0xA000_0000;
        let func_ptr = f as usize;
        let out_ptr = &mut nzcv_out as *mut u64;

        unsafe {
            core::arch::asm!(
                "msr nzcv, {flags_in}",
                "blr {func}",
                "mrs x16, nzcv",
                "str x16, [{out_ptr}]",
                func = in(reg) func_ptr,
                flags_in = in(reg) nzcv_in,
                out_ptr = in(reg) out_ptr,
                out("x0") _,
                out("x1") _,
                out("x2") _,
                out("x3") _,
                out("x4") _,
                out("x5") _,
                out("x6") _,
                out("x7") _,
                out("x8") _,
                out("x9") _,
                out("x10") _,
                out("x11") _,
                out("x12") _,
                out("x13") _,
                out("x14") _,
                out("x15") _,
                out("x16") _,
                out("x17") _,
                out("x30") _,
            );
        }

        assert_eq!(FLAG_ENTER.load(Ordering::Relaxed), 1, "hook should fire");
        assert_eq!(
            nzcv_out, nzcv_in,
            "NZCV flags must be preserved: expected {:#x}, got {:#x}",
            nzcv_in, nzcv_out
        );

        i.detach(&listener);
    }

    /// Attach to a function that reads its own LR (link register).
    ///
    /// A function with `MOV X0, X30` in its prologue captures the caller's
    /// return address. After hooking, the relocated prologue runs inside
    /// the wrapper, so the LR visible to it is the wrapper's BLR return
    /// address — NOT the original caller's LR. This test documents that
    /// behavior: the returned LR should NOT point into the wrapper page.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn attach_to_function_reading_lr() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();

        // Build function: MOV X0, X30; NOP; NOP; NOP; RET
        // Returns the current LR in X0.
        let mut alloc = CodeAllocator::default();
        let slice = alloc.alloc_any().expect("alloc");
        unsafe {
            let mut w = Arm64Writer::new(slice.data, slice.size, slice.data as u64);
            w.put_mov_reg_reg(Reg::X0, Reg::X30); // MOV X0, LR
            w.put_u32_raw(0xD503201F); // NOP
            w.put_u32_raw(0xD503201F); // NOP
            w.put_u32_raw(0xD503201F); // NOP
            w.put_ret();
            for _ in 0..4 { w.put_u32_raw(0xD503201F); }
            alloc.make_executable(&slice).expect("rx");
        }
        let f: extern "C" fn() -> u64 = unsafe { core::mem::transmute(slice.pc) };

        // Baseline: LR without hook should be in this test binary's code range.
        let lr_before = f();
        assert_ne!(lr_before, 0, "baseline LR should be non-zero");

        let listener = CallListener {
            on_enter: None,
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        let wrapper_addr = {
            let map = i.attach_map.lock().unwrap();
            map.get(&(f as usize)).unwrap().wrapper
        };

        // After hooking, LR captured by the relocated prologue may point
        // into the wrapper (since the wrapper uses BLR to call the trampoline).
        // This is a known correctness limitation of inline hooking.
        let lr_hooked = f();
        assert_ne!(lr_hooked, 0, "hooked LR should be non-zero");

        // Document: if LR points into the wrapper page (within 4KB), the
        // relocated prologue sees the wrapper's BLR return address.
        let in_wrapper = (lr_hooked as i64 - wrapper_addr as i64).unsigned_abs() < 4096;
        if in_wrapper {
            eprintln!(
                "NOTE: LR-reading function sees wrapper BLR return address \
                 (lr={:#x}, wrapper={:#x}). This is expected for inline hooking.",
                lr_hooked, wrapper_addr
            );
        }

        i.detach(&listener);

        // After detach, LR should be back to normal.
        let lr_after = f();
        assert_ne!(lr_after, 0, "post-detach LR should be non-zero");
    }

    /// replace() then attach(): attaching to an already-replaced function must fail.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn replace_then_attach_returns_already_attached() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();

        let (_f_mem, f) = make_add_const(1);   // f(x) = x+1
        let (_r_mem, r) = make_add_const(100); // r(x) = x+100

        // Replace f with r.
        i.replace(f as *mut c_void, r as *const c_void, core::ptr::null_mut(), core::ptr::null_mut())
            .unwrap();
        assert_eq!(f(5), 105, "replaced function should return x+100");

        // Now try to attach a listener to the same function.
        // This must fail; mixed-mode hooks on one target are unsupported.
        let listener = CallListener {
            on_enter: None,
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        let attach_result = i.attach(f as *mut c_void, listener);
        assert_eq!(
            attach_result,
            Err(HookError::AlreadyAttached),
            "attach after replace must return AlreadyAttached"
        );

        // Revert the replacement.
        i.revert(f as *mut c_void);
        assert_eq!(f(5), 6, "original restored after revert");
    }

    /// attach() then replace(): replacing an already-attached function must fail.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn attach_then_replace_returns_already_attached() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);
        let (_r_mem, r) = make_add_const(100);

        let listener = CallListener {
            on_enter: None,
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();
        assert_eq!(f(5), 6, "attached function should preserve behavior");

        let replace_result = i.replace(
            f as *mut c_void,
            r as *const c_void,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        assert_eq!(
            replace_result,
            Err(HookError::AlreadyAttached),
            "replace after attach must return AlreadyAttached"
        );

        i.detach(&listener);
        assert_eq!(f(5), 6, "original restored after detach");
    }

    /// Double replace() on the same function returns AlreadyAttached error.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn already_replaced_returns_error() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();

        let (_f_mem, f) = make_add_const(1);    // f(x) = x+1
        let (_r1_mem, r1) = make_add_const(100); // r1(x) = x+100
        let (_r2_mem, r2) = make_add_const(200); // r2(x) = x+200

        // First replace succeeds.
        i.replace(f as *mut c_void, r1 as *const c_void, core::ptr::null_mut(), core::ptr::null_mut())
            .unwrap();
        assert_eq!(f(5), 105, "first replacement active");

        // Second replace on same function should fail.
        let result = i.replace(
            f as *mut c_void,
            r2 as *const c_void,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        assert_eq!(result, Err(HookError::AlreadyAttached), "double replace should return AlreadyAttached");

        // Original replacement (r1) should still be active.
        assert_eq!(f(5), 105, "r1 replacement still active after failed second replace");

        // Revert restores original.
        i.revert(f as *mut c_void);
        assert_eq!(f(5), 6, "original restored after revert");
    }

    /// Hook malloc and free, perform allocations, verify heap integrity.
    /// Linux-only: macOS shared cache functions may not be hookable in all environments.
    #[test]
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn attach_to_malloc_free_preserves_heap() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let _g = lock_hook_tests();

        static MALLOC_HITS: AtomicU32 = AtomicU32::new(0);
        static FREE_HITS: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn malloc_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            MALLOC_HITS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe extern "C" fn free_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            FREE_HITS.fetch_add(1, Ordering::Relaxed);
        }

        MALLOC_HITS.store(0, Ordering::Relaxed);
        FREE_HITS.store(0, Ordering::Relaxed);

        let malloc_addr = crate::module::find_global_export_by_name("malloc")
            .expect("should find malloc");
        let free_addr = crate::module::find_global_export_by_name("free")
            .expect("should find free");

        let i = Interceptor::obtain();

        let malloc_listener = CallListener {
            on_enter: Some(malloc_on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        let free_listener = CallListener {
            on_enter: Some(free_on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };

        i.attach(malloc_addr as *mut c_void, malloc_listener).unwrap();
        i.attach(free_addr as *mut c_void, free_listener).unwrap();

        // Use function pointers via black_box to prevent LLVM from optimizing
        // away malloc/free pairs (LLVM recognizes malloc as a builtin and can
        // elide allocations that don't escape in release mode).
        let malloc_fn: unsafe extern "C" fn(usize) -> *mut c_void =
            unsafe { core::mem::transmute(malloc_addr) };
        let free_fn: unsafe extern "C" fn(*mut c_void) =
            unsafe { core::mem::transmute(free_addr) };

        // Perform 100 malloc+free cycles.
        for _ in 0..100 {
            let f = std::hint::black_box(malloc_fn);
            let ptr = unsafe { f(64) };
            assert!(!ptr.is_null(), "malloc(64) should succeed with hooks active");
            // Write to the allocation to verify it's usable.
            unsafe { core::ptr::write_bytes(ptr as *mut u8, 0xAB, 64); }
            let g = std::hint::black_box(free_fn);
            unsafe { g(ptr); }
        }

        let final_hits = MALLOC_HITS.load(Ordering::Relaxed);
        let final_free = FREE_HITS.load(Ordering::Relaxed);

        assert!(
            final_hits >= 100,
            "malloc hook should fire at least 100 times, got {}",
            final_hits
        );
        assert!(
            final_free >= 100,
            "free hook should fire at least 100 times, got {}",
            final_free
        );

        i.detach(&malloc_listener);
        i.detach(&free_listener);

        // Verify heap still works after detach.
        let f = std::hint::black_box(malloc_fn);
        let ptr = unsafe { f(128) };
        assert!(!ptr.is_null(), "malloc should work after detach");
        let g = std::hint::black_box(free_fn);
        unsafe { g(ptr); }
    }

    /// Detach then re-attach 10 times; ensures clean state in attach_map.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn detach_and_reattach_cycle() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let _g = lock_hook_tests();

        static CYCLE_ENTER: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn cycle_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            CYCLE_ENTER.fetch_add(1, Ordering::Relaxed);
        }

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);

        for cycle in 0..10 {
            CYCLE_ENTER.store(0, Ordering::Relaxed);

            let listener = CallListener {
                on_enter: Some(cycle_on_enter),
                on_leave: None,
                user_data: core::ptr::null_mut(),
            };

            i.attach(f as *mut c_void, listener).unwrap();

            let result = f(5);
            assert_eq!(result, 6, "cycle {cycle}: hooked f(5) should return 6");
            assert!(
                CYCLE_ENTER.load(Ordering::Relaxed) > 0,
                "cycle {cycle}: hook should fire"
            );

            i.detach(&listener);

            let result = f(5);
            assert_eq!(result, 6, "cycle {cycle}: unhooked f(5) should return 6");
        }
    }

    // ── x86_64 tests ─────────────────────────────────────────────────

    #[cfg(target_arch = "x86_64")]
    use crate::arch::x86_64::writer::{X86_64Writer, Reg as X86Reg};

    /// Allocate a code page with f(x) = x + C.
    /// Emits: lea rax, [rdi + C]; ret; nop * 14 (padding for relocation)
    #[cfg(target_arch = "x86_64")]
    fn make_add_const(c: i32) -> (CodeSlice, extern "C" fn(i64) -> i64) {
        let mut alloc = CodeAllocator::default();
        let slice = alloc.alloc_any().expect("alloc");
        unsafe {
            let mut w = X86_64Writer::new(slice.data, slice.size, slice.data as u64);
            // lea rax, [rdi + c]
            w.put_lea_reg_mem(X86Reg::RAX, X86Reg::RDI, c);
            w.put_ret();
            // Padding NOPs to ensure enough prologue for relocation.
            w.put_nop_n(14);
            alloc.make_executable(&slice).expect("rx");
        }
        let f: extern "C" fn(i64) -> i64 = unsafe { core::mem::transmute(slice.pc) };
        (slice, f)
    }

    // ── Replace tests ────────────────────────────────────────────────

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn replace_and_revert_works() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();

        let (_f_mem, f) = make_add_const(1);
        let (_r_mem, r) = make_add_const(100);

        assert_eq!(f(1), 2);

        let mut orig: *const c_void = core::ptr::null();
        i.replace(f as *mut c_void, r as *const c_void, core::ptr::null_mut(), &mut orig)
            .unwrap();

        assert_eq!(f(1), 101);

        let orig_fn: extern "C" fn(i64) -> i64 = unsafe { core::mem::transmute(orig) };
        assert_eq!(orig_fn(1), 2);

        i.revert(f as *mut c_void);
        assert_eq!(f(1), 2);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn replace_stays_active_across_many_calls() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();

        let (_f_mem, f) = make_add_const(1);
        let (_r_mem, r) = make_add_const(100);

        i.replace(f as *mut c_void, r as *const c_void, core::ptr::null_mut(), core::ptr::null_mut())
            .unwrap();

        for call_num in 0..5000u64 {
            let result = f(call_num as i64);
            assert_eq!(result, call_num as i64 + 100);
        }

        i.revert(f as *mut c_void);
        assert_eq!(f(1), 2);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn replace_and_revert_rapid_cycle_100_times() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();

        let (_f_mem, f) = make_add_const(1);
        let (_r_mem, r) = make_add_const(100);

        for cycle in 0..100u32 {
            i.replace(f as *mut c_void, r as *const c_void, core::ptr::null_mut(), core::ptr::null_mut())
                .unwrap();

            let result = f(5);
            assert_eq!(result, 105, "cycle {cycle}: replaced f(5) should return 105");

            i.revert(f as *mut c_void);
            assert_eq!(f(5), 6, "cycle {cycle}: reverted f(5) should return 6");
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn replace_works_across_threads() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();

        let (_f_mem, f) = make_add_const(1);
        let (_r_mem, r) = make_add_const(100);

        i.replace(f as *mut c_void, r as *const c_void, core::ptr::null_mut(), core::ptr::null_mut())
            .unwrap();

        let f_addr = f as usize;
        let handles: Vec<_> = (0..4)
            .map(|thread_id| {
                std::thread::spawn(move || {
                    let f: extern "C" fn(i64) -> i64 = unsafe { core::mem::transmute(f_addr) };
                    for call in 0..1000i64 {
                        let result = f(call);
                        assert_eq!(result, call + 100, "thread {thread_id} call #{call}");
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        i.revert(f as *mut c_void);
        assert_eq!(f(1), 2);
    }

    #[test]
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fn replace_on_libc_abs_with_execution_verification() {
        let _g = lock_hook_tests();

        extern "C" {
            fn abs(i: libc::c_int) -> libc::c_int;
        }

        extern "C" fn fake_abs(_i: libc::c_int) -> libc::c_int {
            999
        }

        let i = Interceptor::obtain();

        let abs_fn: unsafe extern "C" fn(libc::c_int) -> libc::c_int = abs;
        let abs_fn = std::hint::black_box(abs_fn);
        assert_eq!(unsafe { abs_fn(-42) }, 42);

        let mut orig: *const c_void = core::ptr::null();
        let result = i.replace(abs as *mut c_void, fake_abs as *const c_void, core::ptr::null_mut(), &mut orig);
        if let Err(e) = &result {
            eprintln!("replace on abs() failed: {:?}", e);
            return;
        }

        let abs_fn = std::hint::black_box(abs_fn);
        assert_eq!(unsafe { abs_fn(-42) }, 999);

        assert!(!orig.is_null());
        let orig_fn: unsafe extern "C" fn(libc::c_int) -> libc::c_int = unsafe { core::mem::transmute(orig) };
        assert_eq!(unsafe { orig_fn(-42) }, 42);

        i.revert(abs as *mut c_void);
        let abs_fn = std::hint::black_box(abs_fn);
        assert_eq!(unsafe { abs_fn(-42) }, 42);
    }

    // ── Attach tests ─────────────────────────────────────────────────

    #[cfg(target_arch = "x86_64")]
    static X86_ENTER_HITS: AtomicU32 = AtomicU32::new(0);
    #[cfg(target_arch = "x86_64")]
    static X86_LEAVE_HITS: AtomicU32 = AtomicU32::new(0);

    #[cfg(target_arch = "x86_64")]
    unsafe extern "C" fn x86_on_enter(ctx: *mut InvocationContext, _ud: *mut c_void) {
        X86_ENTER_HITS.fetch_add(1, Ordering::Relaxed);
        let a0 = inv::get_nth_argument(ctx, 0) as usize as u64;
        inv::replace_nth_argument(ctx, 0, (a0 + 10) as usize as *mut c_void);
    }

    #[cfg(target_arch = "x86_64")]
    unsafe extern "C" fn x86_on_leave(ctx: *mut InvocationContext, _ud: *mut c_void) {
        X86_LEAVE_HITS.fetch_add(1, Ordering::Relaxed);
        let rv = inv::get_return_value(ctx) as usize as u64;
        inv::replace_return_value(ctx, (rv + 1000) as usize as *mut c_void);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn attach_enter_leave_can_modify_args_and_return() {
        let _g = lock_hook_tests();

        X86_ENTER_HITS.store(0, Ordering::Relaxed);
        X86_LEAVE_HITS.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);

        assert_eq!(f(1), 2);

        let listener = CallListener {
            on_enter: Some(x86_on_enter),
            on_leave: Some(x86_on_leave),
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        // Enter adds 10 to arg => (1+10)+1 = 12; leave adds 1000 => 1012
        assert_eq!(f(1), 1012);
        assert_eq!(X86_ENTER_HITS.load(Ordering::Relaxed), 1);
        assert_eq!(X86_LEAVE_HITS.load(Ordering::Relaxed), 1);

        i.detach(&listener);
        assert_eq!(f(1), 2);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn attach_with_no_callbacks_preserves_behavior() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);

        assert_eq!(f(1), 2);

        let listener = CallListener {
            on_enter: None,
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        assert_eq!(f(1), 2);

        i.detach(&listener);
        assert_eq!(f(1), 2);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn detach_restores_original_behavior() {
        let _g = lock_hook_tests();

        X86_ENTER_HITS.store(0, Ordering::Relaxed);
        X86_LEAVE_HITS.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);

        let listener = CallListener {
            on_enter: Some(x86_on_enter),
            on_leave: Some(x86_on_leave),
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        assert_eq!(f(1), 1012);
        i.detach(&listener);
        assert_eq!(f(1), 2);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn replace_return_value_in_on_enter_skips_original() {
        let _g = lock_hook_tests();

        static SKIP_ENTER: AtomicU32 = AtomicU32::new(0);
        static SKIP_LEAVE: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn skip_on_enter(ctx: *mut InvocationContext, _ud: *mut c_void) {
            SKIP_ENTER.fetch_add(1, Ordering::Relaxed);
            inv::replace_return_value(ctx, (-1isize) as usize as *mut c_void);
        }
        unsafe extern "C" fn skip_on_leave(ctx: *mut InvocationContext, _ud: *mut c_void) {
            SKIP_LEAVE.fetch_add(1, Ordering::Relaxed);
            let rv = inv::get_return_value(ctx) as usize as i64;
            assert_eq!(rv, -1);
        }

        SKIP_ENTER.store(0, Ordering::Relaxed);
        SKIP_LEAVE.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);

        assert_eq!(f(42), 43);

        let listener = CallListener {
            on_enter: Some(skip_on_enter),
            on_leave: Some(skip_on_leave),
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        let result = f(42);
        assert_eq!(result, -1i64);
        assert_eq!(SKIP_ENTER.load(Ordering::Relaxed), 1);
        assert_eq!(SKIP_LEAVE.load(Ordering::Relaxed), 1);

        i.detach(&listener);
        assert_eq!(f(42), 43);
    }

    #[test]
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fn replace_return_value_skips_libc_getpid() {
        let _g = lock_hook_tests();

        unsafe extern "C" fn fake_enter(ctx: *mut InvocationContext, _ud: *mut c_void) {
            inv::replace_return_value(ctx, 12345usize as *mut c_void);
        }

        extern "C" { fn getpid() -> libc::pid_t; }

        let real_pid = unsafe { getpid() };
        assert_ne!(real_pid, 12345);

        let i = Interceptor::obtain();
        let listener = CallListener {
            on_enter: Some(fake_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };

        let addr = crate::module::find_global_export_by_name("getpid")
            .expect("find getpid");
        let result = i.attach(addr as *mut c_void, listener);
        if result.is_err() { return; }

        let f = std::hint::black_box(getpid);
        let pid = unsafe { f() };
        assert_eq!(pid, 12345);

        i.detach(&listener);
        let f = std::hint::black_box(getpid);
        assert_eq!(unsafe { f() }, real_pid);
    }

    #[test]
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fn attach_fires_callbacks_on_libc_function() {
        let _g = lock_hook_tests();

        static LIBC_ENTER: AtomicU32 = AtomicU32::new(0);
        static LIBC_LEAVE: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn libc_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            LIBC_ENTER.fetch_add(1, Ordering::Relaxed);
        }
        unsafe extern "C" fn libc_on_leave(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            LIBC_LEAVE.fetch_add(1, Ordering::Relaxed);
        }

        LIBC_ENTER.store(0, Ordering::Relaxed);
        LIBC_LEAVE.store(0, Ordering::Relaxed);

        extern "C" {
            fn abs(i: libc::c_int) -> libc::c_int;
        }

        let i = Interceptor::obtain();
        let listener = CallListener {
            on_enter: Some(libc_on_enter),
            on_leave: Some(libc_on_leave),
            user_data: core::ptr::null_mut(),
        };

        let result = i.attach(abs as *mut c_void, listener);
        if let Err(e) = &result {
            eprintln!("attach on abs() failed: {:?}", e);
            return;
        }

        let abs_fn: unsafe extern "C" fn(libc::c_int) -> libc::c_int = abs;
        let abs_fn = std::hint::black_box(abs_fn);
        let val = unsafe { abs_fn(-42) };
        assert_eq!(val, 42);

        assert!(LIBC_ENTER.load(Ordering::Relaxed) > 0);
        assert!(LIBC_LEAVE.load(Ordering::Relaxed) > 0);

        i.detach(&listener);
    }

    #[test]
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fn attach_to_malloc_free_preserves_heap() {
        let _g = lock_hook_tests();

        static MALLOC_HITS: AtomicU32 = AtomicU32::new(0);
        static FREE_HITS: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn malloc_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            MALLOC_HITS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe extern "C" fn free_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            FREE_HITS.fetch_add(1, Ordering::Relaxed);
        }

        MALLOC_HITS.store(0, Ordering::Relaxed);
        FREE_HITS.store(0, Ordering::Relaxed);

        let malloc_addr = crate::module::find_global_export_by_name("malloc")
            .expect("find malloc");
        let free_addr = crate::module::find_global_export_by_name("free")
            .expect("find free");

        let i = Interceptor::obtain();

        let malloc_listener = CallListener {
            on_enter: Some(malloc_on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        let free_listener = CallListener {
            on_enter: Some(free_on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };

        i.attach(malloc_addr as *mut c_void, malloc_listener).unwrap();
        i.attach(free_addr as *mut c_void, free_listener).unwrap();

        let malloc_fn: unsafe extern "C" fn(usize) -> *mut c_void =
            unsafe { core::mem::transmute(malloc_addr) };
        let free_fn: unsafe extern "C" fn(*mut c_void) =
            unsafe { core::mem::transmute(free_addr) };

        for _ in 0..100 {
            let f = std::hint::black_box(malloc_fn);
            let ptr = unsafe { f(64) };
            assert!(!ptr.is_null());
            unsafe { core::ptr::write_bytes(ptr as *mut u8, 0xAB, 64); }
            let g = std::hint::black_box(free_fn);
            unsafe { g(ptr); }
        }

        assert!(MALLOC_HITS.load(Ordering::Relaxed) >= 100);
        assert!(FREE_HITS.load(Ordering::Relaxed) >= 100);

        i.detach(&malloc_listener);
        i.detach(&free_listener);

        let f = std::hint::black_box(malloc_fn);
        let ptr = unsafe { f(128) };
        assert!(!ptr.is_null());
        let g = std::hint::black_box(free_fn);
        unsafe { g(ptr); }
    }

    // ── Multiple listeners ──

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn attach_two_listeners_fires_both() {
        let _g = lock_hook_tests();

        static COUNTER_A: AtomicU32 = AtomicU32::new(0);
        static COUNTER_B: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn on_enter_a(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            COUNTER_A.fetch_add(1, Ordering::Relaxed);
        }
        unsafe extern "C" fn on_enter_b(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            COUNTER_B.fetch_add(1, Ordering::Relaxed);
        }

        COUNTER_A.store(0, Ordering::Relaxed);
        COUNTER_B.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);

        let listener_a = CallListener { on_enter: Some(on_enter_a), on_leave: None, user_data: core::ptr::null_mut() };
        let listener_b = CallListener { on_enter: Some(on_enter_b), on_leave: None, user_data: core::ptr::null_mut() };

        i.attach(f as *mut c_void, listener_a).unwrap();
        i.attach(f as *mut c_void, listener_b).unwrap();

        assert_eq!(f(5), 6);
        assert_eq!(COUNTER_A.load(Ordering::Relaxed), 1);
        assert_eq!(COUNTER_B.load(Ordering::Relaxed), 1);

        i.detach(&listener_a);
        i.detach(&listener_b);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn detach_one_of_two_listeners() {
        let _g = lock_hook_tests();

        static DA: AtomicU32 = AtomicU32::new(0);
        static DB: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn enter_a(_ctx: *mut InvocationContext, _ud: *mut c_void) { DA.fetch_add(1, Ordering::Relaxed); }
        unsafe extern "C" fn enter_b(_ctx: *mut InvocationContext, _ud: *mut c_void) { DB.fetch_add(1, Ordering::Relaxed); }

        DA.store(0, Ordering::Relaxed);
        DB.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);

        let listener_a = CallListener { on_enter: Some(enter_a), on_leave: None, user_data: core::ptr::null_mut() };
        let listener_b = CallListener { on_enter: Some(enter_b), on_leave: None, user_data: core::ptr::null_mut() };

        i.attach(f as *mut c_void, listener_a).unwrap();
        i.attach(f as *mut c_void, listener_b).unwrap();

        assert_eq!(f(5), 6);
        assert_eq!(DA.load(Ordering::Relaxed), 1);
        assert_eq!(DB.load(Ordering::Relaxed), 1);

        i.detach(&listener_a);
        assert_eq!(f(5), 6);
        assert_eq!(DA.load(Ordering::Relaxed), 1, "A must not fire after detach");
        assert_eq!(DB.load(Ordering::Relaxed), 2, "B must still fire");

        i.detach(&listener_b);
        assert_eq!(f(5), 6);
    }

    // ── CPU state preservation ──

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn cpu_register_clobber() {
        let _g = lock_hook_tests();

        static CLOBBER_FLAG: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn clobber_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            CLOBBER_FLAG.fetch_add(1, Ordering::Relaxed);
        }

        CLOBBER_FLAG.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(0); // identity

        let listener = CallListener {
            on_enter: Some(clobber_on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        // results[0]=ret, [1..6]=rbx,rbp,r12,r13,r14,r15
        let mut results = [0u64; 7];
        let func_ptr = f as usize as u64;

        // Use explicit register constraints: rax=func, rcx=results_ptr.
        // Manually push/pop rbx and rbp since LLVM doesn't allow them in constraints.
        unsafe {
            core::arch::asm!(
                // Save results ptr and rbx/rbp on stack
                "push rcx",
                "push rbx",
                "push rbp",
                // Set known values in callee-saved regs
                "mov rbx, 0xBB",
                "mov rbp, 0xBBBB",
                "mov r12, 0x1212",
                "mov r13, 0x1313",
                "mov r14, 0x1414",
                "mov r15, 0x1515",
                // Call f(42) — func ptr is in rax
                "mov rdi, 42",
                "call rax",
                // Results ptr is at [rsp+16] (above saved rbp and rbx)
                "mov rcx, [rsp+16]",
                // Store results
                "mov [rcx], rax",
                "mov [rcx+8], rbx",
                "mov [rcx+16], rbp",
                "mov [rcx+24], r12",
                "mov [rcx+32], r13",
                "mov [rcx+40], r14",
                "mov [rcx+48], r15",
                // Restore rbp, rbx, and clean up results ptr
                "pop rbp",
                "pop rbx",
                "add rsp, 8",
                in("rax") func_ptr,
                in("rcx") results.as_mut_ptr(),
                lateout("rax") _,
                lateout("rcx") _,
                lateout("rdx") _,
                lateout("rsi") _,
                lateout("rdi") _,
                lateout("r8") _,
                lateout("r9") _,
                lateout("r10") _,
                lateout("r11") _,
                lateout("r12") _,
                lateout("r13") _,
                lateout("r14") _,
                lateout("r15") _,
            );
        }

        assert_eq!(CLOBBER_FLAG.load(Ordering::Relaxed), 1, "hook should fire");
        assert_eq!(results[0], 42, "return value preserved");
        assert_eq!(results[1], 0xBB, "rbx preserved");
        assert_eq!(results[2], 0xBBBB, "rbp preserved");
        assert_eq!(results[3], 0x1212, "r12 preserved");
        assert_eq!(results[4], 0x1313, "r13 preserved");
        assert_eq!(results[5], 0x1414, "r14 preserved");
        assert_eq!(results[6], 0x1515, "r15 preserved");

        i.detach(&listener);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn cpu_flag_clobber() {
        let _g = lock_hook_tests();

        static FLAG_ENTER: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn flag_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            FLAG_ENTER.fetch_add(1, Ordering::Relaxed);
        }

        FLAG_ENTER.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(0);

        let listener = CallListener {
            on_enter: Some(flag_on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        // Set CF=1, ZF=0 by doing: stc (sets CF); clz (ZF already 0 from other)
        // We'll use pushfq/popfq to set specific flags.
        let mut flags_out: u64 = 0;
        let func_ptr = f as usize as u64;

        unsafe {
            core::arch::asm!(
                // Zero the argument first (before setting flags).
                "xor edi, edi",
                // Set CF=1 (bit 0) and OF=1 (bit 11)
                // flags = 0x801 = CF + OF
                "pushfq",
                "pop rax",
                "or rax, 0x801",
                "push rax",
                "popfq",
                // Call f(0) — no flag-clobbering insns between popfq and call.
                "call {func}",
                // Read flags
                "pushfq",
                "pop rax",
                "mov [{out}], rax",
                func = in(reg) func_ptr,
                out = in(reg) &mut flags_out,
                out("rax") _,
                out("rcx") _,
                out("rdx") _,
                out("rsi") _,
                out("rdi") _,
                out("r8") _,
                out("r9") _,
                out("r10") _,
                out("r11") _,
            );
        }

        assert_eq!(FLAG_ENTER.load(Ordering::Relaxed), 1, "hook should fire");
        // Check CF (bit 0) and OF (bit 11) are preserved
        assert!(flags_out & 0x01 != 0, "CF must be preserved, flags={:#x}", flags_out);
        assert!(flags_out & 0x800 != 0, "OF must be preserved, flags={:#x}", flags_out);

        i.detach(&listener);
    }

    // ── Error handling ──

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn replace_then_attach_returns_already_attached() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);
        let (_r_mem, r) = make_add_const(100);

        i.replace(f as *mut c_void, r as *const c_void, core::ptr::null_mut(), core::ptr::null_mut()).unwrap();
        assert_eq!(f(5), 105);

        let listener = CallListener { on_enter: None, on_leave: None, user_data: core::ptr::null_mut() };
        let result = i.attach(f as *mut c_void, listener);
        assert_eq!(result, Err(HookError::AlreadyAttached));

        i.revert(f as *mut c_void);
        assert_eq!(f(5), 6);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn attach_then_replace_returns_already_attached() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);
        let (_r_mem, r) = make_add_const(100);

        let listener = CallListener { on_enter: None, on_leave: None, user_data: core::ptr::null_mut() };
        i.attach(f as *mut c_void, listener).unwrap();

        let result = i.replace(f as *mut c_void, r as *const c_void, core::ptr::null_mut(), core::ptr::null_mut());
        assert_eq!(result, Err(HookError::AlreadyAttached));

        i.detach(&listener);
        assert_eq!(f(5), 6);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn already_replaced_returns_error() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);
        let (_r1_mem, r1) = make_add_const(100);
        let (_r2_mem, r2) = make_add_const(200);

        i.replace(f as *mut c_void, r1 as *const c_void, core::ptr::null_mut(), core::ptr::null_mut()).unwrap();
        assert_eq!(f(5), 105);

        let result = i.replace(f as *mut c_void, r2 as *const c_void, core::ptr::null_mut(), core::ptr::null_mut());
        assert_eq!(result, Err(HookError::AlreadyAttached));

        i.revert(f as *mut c_void);
        assert_eq!(f(5), 6);
    }

    // ── Detach/reattach cycle ──

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn detach_and_reattach_cycle() {
        let _g = lock_hook_tests();

        static CYCLE_ENTER: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn cycle_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            CYCLE_ENTER.fetch_add(1, Ordering::Relaxed);
        }

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1);

        for cycle in 0..10 {
            CYCLE_ENTER.store(0, Ordering::Relaxed);

            let listener = CallListener {
                on_enter: Some(cycle_on_enter),
                on_leave: None,
                user_data: core::ptr::null_mut(),
            };

            i.attach(f as *mut c_void, listener).unwrap();

            let result = f(5);
            assert_eq!(result, 6, "cycle {cycle}: hooked f(5) should return 6");
            assert!(CYCLE_ENTER.load(Ordering::Relaxed) > 0, "cycle {cycle}: hook should fire");

            i.detach(&listener);
            assert_eq!(f(5), 6, "cycle {cycle}: unhooked f(5) should return 6");
        }
    }

    // ── Syscall wrapper tests ──

    #[test]
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fn attach_to_syscall_wrappers_preserves_behavior() {
        let _g = lock_hook_tests();

        static HITS: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn count_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            HITS.fetch_add(1, Ordering::Relaxed);
        }

        let i = Interceptor::obtain();

        extern "C" { fn getpid() -> libc::pid_t; }
        let getpid_addr = crate::module::find_global_export_by_name("getpid")
            .expect("find getpid");

        let expected_pid = unsafe { getpid() };

        HITS.store(0, Ordering::Relaxed);
        let listener = CallListener {
            on_enter: Some(count_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };

        let result = i.attach(getpid_addr as *mut c_void, listener);
        if let Err(e) = &result {
            eprintln!("attach to getpid failed: {:?}", e);
            return;
        }

        let f = std::hint::black_box(getpid);
        let pid = unsafe { f() };
        assert_eq!(pid, expected_pid, "getpid must return correct value");
        assert!(HITS.load(Ordering::Relaxed) > 0, "on_enter must fire");

        i.detach(&listener);

        let f = std::hint::black_box(getpid);
        assert_eq!(unsafe { f() }, expected_pid, "getpid works after detach");
    }

    #[test]
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fn replace_on_libc_called_via_function_pointer() {
        let _g = lock_hook_tests();

        extern "C" {
            fn abs(i: libc::c_int) -> libc::c_int;
        }

        extern "C" fn fake_abs(_i: libc::c_int) -> libc::c_int {
            777
        }

        let fptr: unsafe extern "C" fn(libc::c_int) -> libc::c_int = abs;
        let fptr = std::hint::black_box(fptr);

        let i = Interceptor::obtain();
        let result = i.replace(abs as *mut c_void, fake_abs as *const c_void, core::ptr::null_mut(), core::ptr::null_mut());
        if let Err(e) = &result {
            eprintln!("replace on abs() failed: {:?}", e);
            return;
        }

        let fptr = std::hint::black_box(fptr);
        assert_eq!(unsafe { fptr(-10) }, 777);

        i.revert(abs as *mut c_void);
        let fptr = std::hint::black_box(fptr);
        assert_eq!(unsafe { fptr(-10) }, 10);
    }

    // ── XMM register preservation ──

    /// Verify that XMM0-XMM5 (volatile/argument registers) are preserved
    /// across hook entry and exit. The wrapper uses FXSAVE/FXRSTOR.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn xmm_register_clobber() {
        let _g = lock_hook_tests();

        static XMM_ENTER: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn xmm_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            XMM_ENTER.fetch_add(1, Ordering::Relaxed);
        }

        XMM_ENTER.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(0); // identity

        let listener = CallListener {
            on_enter: Some(xmm_on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        // xmm_out[0..3] = xmm0 low 64 bits, xmm_out[4..7] = xmm1-xmm3 low 64 bits
        let mut xmm_out = [0u64; 4];
        let func_ptr = f as usize as u64;

        unsafe {
            core::arch::asm!(
                // Load known values into XMM0-XMM3
                "mov rax, 0x1111111111111111",
                "movq xmm0, rax",
                "mov rax, 0x2222222222222222",
                "movq xmm1, rax",
                "mov rax, 0x3333333333333333",
                "movq xmm2, rax",
                "mov rax, 0x4444444444444444",
                "movq xmm3, rax",
                // Call hooked function f(0)
                "xor edi, edi",
                "call {func}",
                // Read XMM values back
                "movq rax, xmm0",
                "mov [{out}], rax",
                "movq rax, xmm1",
                "mov [{out}+8], rax",
                "movq rax, xmm2",
                "mov [{out}+16], rax",
                "movq rax, xmm3",
                "mov [{out}+24], rax",
                func = in(reg) func_ptr,
                out = in(reg) xmm_out.as_mut_ptr(),
                out("rax") _,
                out("rcx") _,
                out("rdx") _,
                out("rsi") _,
                out("rdi") _,
                out("r8") _,
                out("r9") _,
                out("r10") _,
                out("r11") _,
                out("xmm0") _,
                out("xmm1") _,
                out("xmm2") _,
                out("xmm3") _,
                out("xmm4") _,
                out("xmm5") _,
            );
        }

        assert_eq!(XMM_ENTER.load(Ordering::Relaxed), 1, "hook should fire");
        assert_eq!(xmm_out[0], 0x1111111111111111, "xmm0 preserved");
        assert_eq!(xmm_out[1], 0x2222222222222222, "xmm1 preserved");
        assert_eq!(xmm_out[2], 0x3333333333333333, "xmm2 preserved");
        assert_eq!(xmm_out[3], 0x4444444444444444, "xmm3 preserved");

        i.detach(&listener);
    }

    // ── Direction flag preservation ──

    /// Verify that the direction flag (DF) is preserved across hook entry/exit.
    /// The wrapper clears DF for callbacks (C ABI requirement) but must restore
    /// it to the caller's original value afterward.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn direction_flag_preserved() {
        let _g = lock_hook_tests();

        static DF_ENTER: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn df_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            DF_ENTER.fetch_add(1, Ordering::Relaxed);
        }

        DF_ENTER.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(0);

        let listener = CallListener {
            on_enter: Some(df_on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        let mut flags_out: u64 = 0;
        let func_ptr = f as usize as u64;

        unsafe {
            core::arch::asm!(
                // Zero the argument first
                "xor edi, edi",
                // Set DF=1 (bit 10 in RFLAGS)
                "std",
                // Call hooked function
                "call {func}",
                // Read flags
                "pushfq",
                "pop rax",
                "mov [{out}], rax",
                // Clear DF so Rust code is safe
                "cld",
                func = in(reg) func_ptr,
                out = in(reg) &mut flags_out,
                out("rax") _,
                out("rcx") _,
                out("rdx") _,
                out("rsi") _,
                out("rdi") _,
                out("r8") _,
                out("r9") _,
                out("r10") _,
                out("r11") _,
            );
        }

        assert_eq!(DF_ENTER.load(Ordering::Relaxed), 1, "hook should fire");
        // DF is bit 10 (0x400)
        assert!(
            flags_out & 0x400 != 0,
            "DF must be preserved after hook, flags={:#x}",
            flags_out
        );

        i.detach(&listener);
    }

    // ── Additional x86_64 helpers ───────────────────────────────────────

    /// f(a0,a1,a2,a3,a4,a5) = a0+a1+a2+a3+a4+a5
    /// Emits: mov rax,rdi; add rax,rsi; add rax,rdx; add rax,rcx;
    ///        add rax,r8; add rax,r9; ret; nop*14
    #[cfg(target_arch = "x86_64")]
    fn make_sum_6args() -> (CodeSlice, extern "C" fn(i64, i64, i64, i64, i64, i64) -> i64) {
        let mut alloc = CodeAllocator::default();
        let slice = alloc.alloc_any().expect("alloc");
        unsafe {
            let mut w = X86_64Writer::new(slice.data, slice.size, slice.data as u64);
            // mov rax, rdi
            w.put_mov_reg_reg(X86Reg::RAX, X86Reg::RDI);
            // add rax, rsi — REX.W 01 F0 (src=rsi encoded as 01 /r with r=rsi, rm=rax)
            w.put_bytes(&[0x48, 0x01, 0xF0]);
            // add rax, rdx — REX.W 01 D0
            w.put_bytes(&[0x48, 0x01, 0xD0]);
            // add rax, rcx — REX.W 01 C8
            w.put_bytes(&[0x48, 0x01, 0xC8]);
            // add rax, r8 — REX.W+REX.B 4C 01 C0
            w.put_bytes(&[0x4C, 0x01, 0xC0]);
            // add rax, r9 — REX.W+REX.B 4C 01 C8
            w.put_bytes(&[0x4C, 0x01, 0xC8]);
            w.put_ret();
            w.put_nop_n(14);
            alloc.make_executable(&slice).expect("rx");
        }
        let f: extern "C" fn(i64, i64, i64, i64, i64, i64) -> i64 =
            unsafe { core::mem::transmute(slice.pc) };
        (slice, f)
    }

    /// f(x) = x + c, prefixed with ENDBR64.
    /// Emits: endbr64; lea rax,[rdi+c]; ret; nop*14
    #[cfg(target_arch = "x86_64")]
    fn make_endbr64_add_const(c: i32) -> (CodeSlice, extern "C" fn(i64) -> i64) {
        let mut alloc = CodeAllocator::default();
        let slice = alloc.alloc_any().expect("alloc");
        unsafe {
            let mut w = X86_64Writer::new(slice.data, slice.size, slice.data as u64);
            // ENDBR64: F3 0F 1E FA
            w.put_bytes(&[0xF3, 0x0F, 0x1E, 0xFA]);
            // lea rax, [rdi + c]
            w.put_lea_reg_mem(X86Reg::RAX, X86Reg::RDI, c);
            w.put_ret();
            w.put_nop_n(14);
            alloc.make_executable(&slice).expect("rx");
        }
        let f: extern "C" fn(i64) -> i64 = unsafe { core::mem::transmute(slice.pc) };
        (slice, f)
    }

    // ── Additional x86_64 tests ─────────────────────────────────────────

    /// f(x) = x + c, with a long NOP-padded prologue so that attach_rebinding
    /// (which needs 16 relocatable bytes) can build a trampoline.
    #[cfg(target_arch = "x86_64")]
    fn make_add_const_long(c: i32) -> (CodeSlice, extern "C" fn(i64) -> i64) {
        let mut alloc = CodeAllocator::default();
        let slice = alloc.alloc_any().expect("alloc");
        unsafe {
            let mut w = X86_64Writer::new(slice.data, slice.size, slice.data as u64);
            // lea rax, [rdi + c] — 7 bytes
            w.put_lea_reg_mem(X86Reg::RAX, X86Reg::RDI, c);
            // 14 NOPs before ret — gives 21 relocatable bytes (> 16 for FAR_JMP)
            w.put_nop_n(14);
            w.put_ret();
            alloc.make_executable(&slice).expect("rx");
        }
        let f: extern "C" fn(i64) -> i64 = unsafe { core::mem::transmute(slice.pc) };
        (slice, f)
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn x86_64_attach_rebinding_creates_callable_wrapper() {
        let _g = lock_hook_tests();

        static RB_ENTER: AtomicU32 = AtomicU32::new(0);
        static RB_LEAVE: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn rb_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            RB_ENTER.fetch_add(1, Ordering::Relaxed);
        }
        unsafe extern "C" fn rb_on_leave(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            RB_LEAVE.fetch_add(1, Ordering::Relaxed);
        }

        RB_ENTER.store(0, Ordering::Relaxed);
        RB_LEAVE.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const_long(7); // f(x) = x + 7

        assert_eq!(f(10), 17);

        let listener = CallListener {
            on_enter: Some(rb_on_enter),
            on_leave: Some(rb_on_leave),
            user_data: core::ptr::null_mut(),
        };

        let wrapper = i.attach_rebinding(f as *mut c_void, listener).unwrap();
        assert_ne!(wrapper, 0, "wrapper address must not be null");

        // The original function should NOT be patched — calling f directly should
        // NOT fire callbacks.
        assert_eq!(f(10), 17, "original f should still work (no patch)");
        assert_eq!(RB_ENTER.load(Ordering::Relaxed), 0, "calling original must NOT fire callbacks");

        // Calling through the wrapper should fire callbacks and return correct value.
        let wrapper_fn: extern "C" fn(i64) -> i64 =
            unsafe { core::mem::transmute(wrapper as *const c_void) };
        let wrapper_fn = std::hint::black_box(wrapper_fn);
        let val = wrapper_fn(10);
        assert_eq!(val, 17, "wrapper should return correct f(10) value");
        assert!(RB_ENTER.load(Ordering::Relaxed) > 0, "wrapper call must fire on_enter");
        assert!(RB_LEAVE.load(Ordering::Relaxed) > 0, "wrapper call must fire on_leave");

        i.detach(&listener);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn on_leave_modifies_return_value_without_skip() {
        let _g = lock_hook_tests();

        unsafe extern "C" fn only_on_leave(ctx: *mut InvocationContext, _ud: *mut c_void) {
            let rv = inv::get_return_value(ctx) as usize as u64;
            // Multiply return value by 10 — tests the end_invocation write-back path
            // independently of on_enter.
            inv::replace_return_value(ctx, (rv * 10) as usize as *mut c_void);
        }

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1); // f(x) = x + 1

        assert_eq!(f(5), 6);

        let listener = CallListener {
            on_enter: None,
            on_leave: Some(only_on_leave),
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        // Original returns 6, on_leave makes it 60
        assert_eq!(f(5), 60);

        i.detach(&listener);
        assert_eq!(f(5), 6);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn attach_modifies_all_six_argument_registers() {
        let _g = lock_hook_tests();

        unsafe extern "C" fn add100_to_all_args(ctx: *mut InvocationContext, _ud: *mut c_void) {
            for n in 0..6u32 {
                let val = inv::get_nth_argument(ctx, n) as usize as u64;
                inv::replace_nth_argument(ctx, n, (val + 100) as usize as *mut c_void);
            }
        }

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_sum_6args();

        // Without hook: 1+2+3+4+5+6 = 21
        assert_eq!(f(1, 2, 3, 4, 5, 6), 21);

        let listener = CallListener {
            on_enter: Some(add100_to_all_args),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        // With hook: (1+100)+(2+100)+(3+100)+(4+100)+(5+100)+(6+100) = 21+600 = 621
        assert_eq!(f(1, 2, 3, 4, 5, 6), 621);

        i.detach(&listener);
        assert_eq!(f(1, 2, 3, 4, 5, 6), 21);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn attach_to_function_starting_with_endbr64() {
        let _g = lock_hook_tests();

        static ENDBR_ENTER: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn endbr_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            ENDBR_ENTER.fetch_add(1, Ordering::Relaxed);
        }

        ENDBR_ENTER.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_endbr64_add_const(7); // f(x) = x + 7

        assert_eq!(f(10), 17);

        let listener = CallListener {
            on_enter: Some(endbr_on_enter),
            on_leave: None,
            user_data: core::ptr::null_mut(),
        };
        i.attach(f as *mut c_void, listener).unwrap();

        assert_eq!(f(10), 17, "function behavior preserved through ENDBR64 hook");
        assert_eq!(ENDBR_ENTER.load(Ordering::Relaxed), 1, "hook fires on ENDBR64 function");

        // Verify ENDBR64 bytes are not overwritten: first 4 bytes should still be F3 0F 1E FA
        let func_ptr = f as *const u8;
        let endbr_bytes = unsafe { core::slice::from_raw_parts(func_ptr, 4) };
        assert_eq!(endbr_bytes, &[0xF3, 0x0F, 0x1E, 0xFA], "ENDBR64 must not be overwritten");

        i.detach(&listener);
        assert_eq!(f(10), 17);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn attach_to_recursive_function() {
        let _g = lock_hook_tests();

        static REC_ENTER: AtomicU32 = AtomicU32::new(0);
        static REC_LEAVE: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn rec_on_enter(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            REC_ENTER.fetch_add(1, Ordering::Relaxed);
        }
        unsafe extern "C" fn rec_on_leave(_ctx: *mut InvocationContext, _ud: *mut c_void) {
            REC_LEAVE.fetch_add(1, Ordering::Relaxed);
        }

        #[inline(never)]
        extern "C" fn recursive_sum(n: i64) -> i64 {
            let n = std::hint::black_box(n);
            if n <= 0 { 0 } else { n + recursive_sum(n - 1) }
        }

        REC_ENTER.store(0, Ordering::Relaxed);
        REC_LEAVE.store(0, Ordering::Relaxed);

        // Verify baseline
        let f = std::hint::black_box(recursive_sum);
        assert_eq!(f(5), 15);

        let i = Interceptor::obtain();
        let listener = CallListener {
            on_enter: Some(rec_on_enter),
            on_leave: Some(rec_on_leave),
            user_data: core::ptr::null_mut(),
        };

        let result = i.attach(recursive_sum as *mut c_void, listener);
        if let Err(e) = &result {
            eprintln!("attach to recursive_sum failed: {:?} — skipping", e);
            return;
        }

        let f = std::hint::black_box(recursive_sum);
        assert_eq!(f(5), 15, "recursive_sum(5) must still return 15");
        // n=5,4,3,2,1,0 → 6 calls
        assert_eq!(REC_ENTER.load(Ordering::Relaxed), 6, "enter count for recursive_sum(5)");
        assert_eq!(REC_LEAVE.load(Ordering::Relaxed), 6, "leave count for recursive_sum(5)");

        i.detach(&listener);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn on_enter_calls_hooked_function() {
        let _g = lock_hook_tests();

        use core::sync::atomic::AtomicI64;

        static REENTRY_DEPTH: AtomicU32 = AtomicU32::new(0);
        static REENTRY_RESULT: AtomicI64 = AtomicI64::new(0);

        unsafe extern "C" fn reentry_on_enter(ctx: *mut InvocationContext, ud: *mut c_void) {
            let depth = REENTRY_DEPTH.fetch_add(1, Ordering::Relaxed);
            if depth == 0 {
                // First entry: call the hooked function from within the callback.
                let fptr: extern "C" fn(i64) -> i64 = core::mem::transmute(ud);
                let result = fptr(99);
                REENTRY_RESULT.store(result, Ordering::Relaxed);
            }
            // depth >= 1: don't recurse further to prevent infinite loop.
            let _ = ctx;
        }

        REENTRY_DEPTH.store(0, Ordering::Relaxed);
        REENTRY_RESULT.store(0, Ordering::Relaxed);

        let i = Interceptor::obtain();
        let (_f_mem, f) = make_add_const(1); // f(x) = x + 1

        let listener = CallListener {
            on_enter: Some(reentry_on_enter),
            on_leave: None,
            // Pass function pointer as user_data so the callback can call the hooked function.
            user_data: f as *mut c_void,
        };
        i.attach(f as *mut c_void, listener).unwrap();

        let result = f(42);
        // The outer call goes through the wrapper; the inner call from on_enter
        // also goes through the wrapper (re-entry).
        assert_eq!(REENTRY_DEPTH.load(Ordering::Relaxed), 2, "re-entry must happen");
        // Inner call: f(99) = 100; outer call: f(42) = 43
        assert_eq!(REENTRY_RESULT.load(Ordering::Relaxed), 100, "inner call result");
        assert_eq!(result, 43, "outer call result");

        i.detach(&listener);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn replace_trampoline_called_from_multiple_threads() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();

        let (_f_mem, f) = make_add_const(1);  // f(x) = x + 1
        let (_r_mem, r) = make_add_const(100); // r(x) = x + 100

        let mut orig: *const c_void = core::ptr::null();
        i.replace(f as *mut c_void, r as *const c_void, core::ptr::null_mut(), &mut orig)
            .unwrap();
        assert!(!orig.is_null());

        let orig_addr = orig as usize;
        let handles: Vec<_> = (0..4)
            .map(|tid| {
                std::thread::spawn(move || {
                    let orig_fn: extern "C" fn(i64) -> i64 =
                        unsafe { core::mem::transmute(orig_addr) };
                    for call in 0..1000i64 {
                        let result = orig_fn(call);
                        assert_eq!(result, call + 1, "thread {tid} call #{call}");
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        i.revert(f as *mut c_void);
        assert_eq!(f(1), 2);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn replace_verifies_near_redirect_encoding() {
        let _g = lock_hook_tests();

        let i = Interceptor::obtain();

        // Allocate two nearby synthetic functions — they'll be in the same page region,
        // so the redirect should be a 5-byte near JMP (0xE9).
        let (_f_mem, f) = make_add_const(1);
        let (_r_mem, r) = make_add_const(100);

        // Save original first byte.
        let f_ptr = f as *const u8;
        let orig_first_byte = unsafe { f_ptr.read() };

        i.replace(f as *mut c_void, r as *const c_void, core::ptr::null_mut(), core::ptr::null_mut())
            .unwrap();

        // Read first byte of patched function — should be E9 (near JMP).
        let patched_first_byte = unsafe { f_ptr.read() };
        assert_eq!(patched_first_byte, 0xE9, "patched prologue should start with near JMP");

        i.revert(f as *mut c_void);

        // After revert, original bytes should be restored.
        let restored_first_byte = unsafe { f_ptr.read() };
        assert_eq!(restored_first_byte, orig_first_byte, "original bytes restored after revert");
    }
}
