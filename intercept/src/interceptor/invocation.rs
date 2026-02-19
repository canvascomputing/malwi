#[cfg(target_arch = "aarch64")]
use crate::types::{Arm64CpuContext, InvocationContext};

#[cfg(target_arch = "x86_64")]
use crate::types::{InvocationContext, X86_64CpuContext};

use core::ffi::c_void;

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn cpu<'a>(ctx: *mut InvocationContext) -> &'a mut Arm64CpuContext {
    &mut *(*ctx).cpu_context
}

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn cpu<'a>(ctx: *mut InvocationContext) -> &'a mut X86_64CpuContext {
    &mut *(*ctx).cpu_context
}

// ── AArch64 ──────────────────────────────────────────────────────────

/// # Safety
/// `ctx` must be a valid pointer to an active `InvocationContext`.
#[cfg(target_arch = "aarch64")]
pub unsafe fn get_nth_argument(ctx: *mut InvocationContext, n: u32) -> *mut c_void {
    let cpu = cpu(ctx);
    if n < 8 {
        cpu.x[n as usize] as usize as *mut c_void
    } else {
        core::ptr::null_mut()
    }
}

/// # Safety
/// `ctx` must be a valid pointer to an active `InvocationContext`.
#[cfg(target_arch = "aarch64")]
pub unsafe fn replace_nth_argument(ctx: *mut InvocationContext, n: u32, value: *mut c_void) {
    let cpu = cpu(ctx);
    if n < 8 {
        cpu.x[n as usize] = value as usize as u64;
    }
}

/// # Safety
/// `ctx` must be a valid pointer to an active `InvocationContext`.
#[cfg(target_arch = "aarch64")]
pub unsafe fn get_return_value(ctx: *mut InvocationContext) -> *mut c_void {
    let cpu = cpu(ctx);
    cpu.x[0] as usize as *mut c_void
}

/// # Safety
/// `ctx` must be a valid pointer to an active `InvocationContext`.
#[cfg(target_arch = "aarch64")]
pub unsafe fn replace_return_value(ctx: *mut InvocationContext, value: *mut c_void) {
    let cpu = cpu(ctx);
    cpu.x[0] = value as usize as u64;
    (*ctx).skip_original = true;
}

// ── x86_64 (System V AMD64 ABI) ─────────────────────────────────────
//
// Arg0=RDI, Arg1=RSI, Arg2=RDX, Arg3=RCX, Arg4=R8, Arg5=R9
// Return value=RAX

/// # Safety
/// `ctx` must be a valid pointer to an active `InvocationContext`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_nth_argument(ctx: *mut InvocationContext, n: u32) -> *mut c_void {
    let cpu = cpu(ctx);
    let val = match n {
        0 => cpu.rdi,
        1 => cpu.rsi,
        2 => cpu.rdx,
        3 => cpu.rcx,
        4 => cpu.r8,
        5 => cpu.r9,
        _ => return core::ptr::null_mut(),
    };
    val as usize as *mut c_void
}

/// # Safety
/// `ctx` must be a valid pointer to an active `InvocationContext`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn replace_nth_argument(ctx: *mut InvocationContext, n: u32, value: *mut c_void) {
    let cpu = cpu(ctx);
    let val = value as usize as u64;
    match n {
        0 => cpu.rdi = val,
        1 => cpu.rsi = val,
        2 => cpu.rdx = val,
        3 => cpu.rcx = val,
        4 => cpu.r8 = val,
        5 => cpu.r9 = val,
        _ => {}
    }
}

/// # Safety
/// `ctx` must be a valid pointer to an active `InvocationContext`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_return_value(ctx: *mut InvocationContext) -> *mut c_void {
    let cpu = cpu(ctx);
    cpu.rax as usize as *mut c_void
}

/// # Safety
/// `ctx` must be a valid pointer to an active `InvocationContext`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn replace_return_value(ctx: *mut InvocationContext, value: *mut c_void) {
    let cpu = cpu(ctx);
    cpu.rax = value as usize as u64;
    (*ctx).skip_original = true;
}
