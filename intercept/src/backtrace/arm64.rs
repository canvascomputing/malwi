use crate::types::Arm64CpuContext;

pub fn capture_backtrace(cpu_context: &Arm64CpuContext, max_depth: usize) -> Vec<usize> {
    let mut frames = Vec::with_capacity(max_depth.min(256));
    if max_depth == 0 {
        return frames;
    }

    let mut fp = cpu_context.fp;
    let mut lr = cpu_context.lr;

    if lr != 0 {
        frames.push(lr as usize);
    }

    for _ in 0..max_depth.saturating_sub(1) {
        if fp == 0 || fp % 16 != 0 {
            break;
        }

        // AArch64 frame layout: [0] previous FP, [1] return address (LR).
        let prev_fp = unsafe { *(fp as *const u64) };
        let ret_addr = unsafe { *((fp as *const u64).add(1)) };
        if ret_addr == 0 {
            break;
        }
        frames.push(ret_addr as usize);
        if prev_fp <= fp {
            break;
        }
        fp = prev_fp;
        lr = ret_addr;
    }

    // Silence unused warning for lr, and keep the variable for debugging ease.
    let _ = lr;

    frames
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::arch::asm;

    #[test]
    fn backtrace_from_current_frame() {
        let fp: u64;
        let lr: u64;
        unsafe {
            asm!("mov {}, x29", out(reg) fp);
            asm!("mov {}, x30", out(reg) lr);
        }
        let ctx = Arm64CpuContext {
            pc: 0,
            sp: 0,
            nzcv: 0,
            x: [0u64; 29],
            fp,
            lr,
            v: [0u128; 32],
        };
        let bt = capture_backtrace(&ctx, 16);
        assert!(bt.len() >= 1);
    }

    #[test]
    fn backtrace_stops_on_null_fp() {
        let ctx = Arm64CpuContext {
            pc: 0,
            sp: 0,
            nzcv: 0,
            x: [0u64; 29],
            fp: 0,
            lr: 0x1234,
            v: [0u128; 32],
        };
        let bt = capture_backtrace(&ctx, 16);
        assert_eq!(bt, vec![0x1234usize]);
    }

    #[test]
    fn backtrace_respects_max_depth() {
        let ctx = Arm64CpuContext {
            pc: 0,
            sp: 0,
            nzcv: 0,
            x: [0u64; 29],
            fp: 0,
            lr: 0x1234,
            v: [0u128; 32],
        };
        let bt = capture_backtrace(&ctx, 1);
        assert!(bt.len() <= 1);
    }
}

