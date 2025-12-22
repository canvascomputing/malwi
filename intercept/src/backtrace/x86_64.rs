use crate::types::X86_64CpuContext;

/// Read a u64 from an arbitrary pointer without risking SIGSEGV.
///
/// Uses `process_vm_readv(pid=0)` to read from own address space —
/// returns `Err` for unmapped/unreadable addresses instead of faulting.
fn safe_read_u64(addr: *const u64) -> Option<u64> {
    // Reject obviously invalid addresses.
    if (addr as usize) < 0x1000 || (addr as usize) & 7 != 0 {
        return None;
    }
    let mut buf = 0u64;
    let local = libc::iovec {
        iov_base: &mut buf as *mut u64 as *mut libc::c_void,
        iov_len: 8,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: 8,
    };
    let ret = unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) };
    if ret == 8 {
        Some(buf)
    } else {
        None
    }
}

pub fn capture_backtrace(cpu_context: &X86_64CpuContext, max_depth: usize) -> Vec<usize> {
    let mut frames = Vec::with_capacity(max_depth.min(256));
    if max_depth == 0 {
        return frames;
    }

    // First frame: return address at RIP (best-effort).
    if cpu_context.rip != 0 {
        frames.push(cpu_context.rip as usize);
    }

    let mut rbp = cpu_context.rbp;
    for _ in 0..max_depth.saturating_sub(1) {
        if rbp == 0 || (rbp & 0x7) != 0 {
            break;
        }
        let prev_rbp = match safe_read_u64(rbp as *const u64) {
            Some(v) => v,
            None => break,
        };
        let ret_addr = match safe_read_u64((rbp as *const u64).wrapping_add(1)) {
            Some(v) => v,
            None => break,
        };
        if ret_addr == 0 {
            break;
        }
        frames.push(ret_addr as usize);
        if prev_rbp <= rbp {
            break;
        }
        rbp = prev_rbp;
    }

    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_read_u64_valid_address() {
        let val: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let result = safe_read_u64(&val as *const u64);
        assert_eq!(result, Some(0xDEAD_BEEF_CAFE_BABE));
    }

    #[test]
    fn test_safe_read_u64_null() {
        let result = safe_read_u64(core::ptr::null());
        assert_eq!(result, None);
    }

    #[test]
    fn test_safe_read_u64_low_address() {
        let result = safe_read_u64(0x800 as *const u64);
        assert_eq!(result, None);
    }

    #[test]
    fn test_safe_read_u64_unaligned() {
        let result = safe_read_u64(0x1001 as *const u64);
        assert_eq!(result, None);
    }

    #[test]
    fn test_capture_backtrace_with_zero_depth() {
        let ctx = X86_64CpuContext {
            rip: 0x1000,
            rsp: 0,
            rflags: 0,
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
        };
        let frames = capture_backtrace(&ctx, 0);
        assert!(frames.is_empty());
    }

    #[test]
    fn test_capture_backtrace_does_not_crash_with_bad_rbp() {
        let ctx = X86_64CpuContext {
            rip: 0x4000_0000,
            rsp: 0,
            rflags: 0,
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0xDEAD,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
        };
        // Should not crash — just return the RIP frame.
        let frames = capture_backtrace(&ctx, 16);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], 0x4000_0000);
    }
}
