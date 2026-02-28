//! Backtrace capture.
//!
//! Uses a fuzzy backtracer that scans the stack for return addresses validated
//! by instruction pattern matching (BL/BLR on arm64, CALL on x86). Unlike
//! libunwind-based backtracers, it does not require `.eh_frame` unwind info,
//! so it works correctly when the saved CPU context has its PC in a
//! dynamically-generated interceptor trampoline.

use crate::ffi as gum;
use crate::types::CpuContext;
use std::sync::OnceLock;

/// Cached fuzzy backtracer instance (thread-safe, never freed).
fn backtracer() -> *mut gum::GumBacktracer {
    static BT: OnceLock<usize> = OnceLock::new();
    *BT.get_or_init(|| unsafe { gum::gum_backtracer_make_fuzzy() as usize })
        as *mut gum::GumBacktracer
}

/// Capture a backtrace from the given CPU context.
///
/// `max_depth` is clamped to 16 (the fixed capacity of `GumReturnAddressArray`).
/// Returns a vector of return addresses (PAC-stripped, trampoline-translated).
///
/// If `cpu_context` is `None`, gum captures from the current thread's context.
/// Pass `Some(ctx)` from interceptor callbacks — the fuzzy backtracer handles
/// trampoline contexts correctly (reads lr/sp, not pc).
pub fn capture_backtrace(cpu_context: Option<&CpuContext>, max_depth: usize) -> Vec<usize> {
    if max_depth == 0 {
        return Vec::new();
    }

    let bt = backtracer();
    if bt.is_null() {
        return Vec::new();
    }

    let ctx_ptr = match cpu_context {
        Some(ctx) => ctx as *const CpuContext,
        None => core::ptr::null(),
    };

    let limit = max_depth.min(16) as gum::guint;
    let mut array = gum::GumReturnAddressArray::default();

    unsafe {
        gum::gum_backtracer_generate_with_limit(bt, ctx_ptr, &mut array, limit);
    }

    let len = (array.len as usize).min(16);
    array.items[..len]
        .iter()
        .map(|&addr| addr as usize)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backtrace_returns_frames() {
        let _g = crate::lock_hook_tests();
        crate::gum::init_runtime();
        // A zeroed CpuContext has NULL fp/sp, which causes gum's frame-
        // pointer walker to SIGSEGV.  Use the *current* frame instead.
        #[cfg(target_arch = "aarch64")]
        let ctx = {
            let mut c = CpuContext::default();
            unsafe {
                core::arch::asm!("mov {}, x29", out(reg) c.fp);
                core::arch::asm!("mov {}, x30", out(reg) c.lr);
            }
            c
        };
        #[cfg(target_arch = "x86_64")]
        let ctx = {
            let mut c = CpuContext::default();
            unsafe {
                core::arch::asm!(
                    "lea {rip}, [rip]",
                    "mov {rbp}, rbp",
                    "mov {rsp_val}, rsp",
                    rip = out(reg) c.rip,
                    rbp = out(reg) c.rbp,
                    rsp_val = out(reg) c.rsp,
                );
            }
            c
        };
        let bt = capture_backtrace(Some(&ctx), 16);
        assert!(!bt.is_empty(), "expected at least one frame");
    }

    #[test]
    fn backtrace_respects_zero_depth() {
        let _g = crate::lock_hook_tests();
        crate::gum::init_runtime();
        let bt = capture_backtrace(None, 0);
        assert!(bt.is_empty());
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn backtrace_from_current_frame_arm64() {
        let _g = crate::lock_hook_tests();
        crate::gum::init_runtime();
        let fp: u64;
        let lr: u64;
        unsafe {
            core::arch::asm!("mov {}, x29", out(reg) fp);
            core::arch::asm!("mov {}, x30", out(reg) lr);
        }
        let mut ctx = CpuContext::default();
        ctx.fp = fp;
        ctx.lr = lr;
        let bt = capture_backtrace(Some(&ctx), 16);
        assert!(!bt.is_empty(), "expected at least one frame");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn backtrace_from_current_frame_x86_64() {
        let _g = crate::lock_hook_tests();
        crate::gum::init_runtime();
        let rbp: u64;
        let rip: u64;
        let rsp_val: u64;
        unsafe {
            core::arch::asm!(
                "lea {rip}, [rip]",
                "mov {rbp}, rbp",
                "mov {rsp_val}, rsp",
                rip = out(reg) rip,
                rbp = out(reg) rbp,
                rsp_val = out(reg) rsp_val,
            );
        }
        let mut ctx = CpuContext::default();
        ctx.rip = rip;
        ctx.rbp = rbp;
        ctx.rsp = rsp_val;
        let bt = capture_backtrace(Some(&ctx), 16);
        assert!(!bt.is_empty(), "expected at least one frame");
    }
}
