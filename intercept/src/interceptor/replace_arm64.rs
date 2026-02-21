use super::{Interceptor, ReplacementEntry};
use crate::arch::arm64::relocator::Arm64Relocator;
use crate::arch::arm64::writer::{Arm64Writer, Reg};
use crate::code::allocator::CodeAllocator;
use crate::code::patcher::patch_code;
use crate::code::ptrauth::{sign_code_ptr, strip_code_ptr};
use crate::types::HookError;
use core::ffi::c_void;

fn read_16(addr: *const u8) -> [u8; 16] {
    unsafe { core::ptr::read_unaligned(addr as *const [u8; 16]) }
}

pub(crate) fn replace(
    interceptor: &Interceptor,
    function_address: *mut c_void,
    replacement: *const c_void,
    original_out: *mut *const c_void,
) -> Result<(), HookError> {
    let function_address = strip_code_ptr(function_address as usize) as *mut c_void;
    let key = function_address as usize;
    let ptrauth = interceptor.ptrauth;

    // Attach and replace are mutually exclusive for a given function address.
    {
        let attach_map = interceptor.attach_map.lock().unwrap();
        if attach_map.contains_key(&key) {
            return Err(HookError::AlreadyAttached);
        }
    }

    let mut map = interceptor.replace_map.lock().unwrap();
    if map.contains_key(&key) {
        return Err(HookError::AlreadyAttached);
    }

    // Build a trampoline that runs the overwritten prologue then jumps back to function+16.
    let mut alloc = CodeAllocator::default();
    let slice = alloc.alloc_any()?;

    let tramp_pc = slice.data as u64;
    unsafe {
        let mut w = Arm64Writer::new_with_ptrauth(slice.data, slice.size, tramp_pc, ptrauth);
        let mut r = Arm64Relocator::new(function_address as *const u32, function_address as u64);
        r.relocate_n(&mut w, 4)?;

        // Sign the resume address when ptrauth is active so that BRAAZ can
        // authenticate it before branching.
        let resume_raw = (function_address as u64) + 16;
        let resume = sign_code_ptr(resume_raw as usize, ptrauth) as u64;
        w.put_mov_reg_u64(Reg::X16, resume);
        w.put_br_reg(Reg::X16);
        alloc.make_executable(&slice)?;
    }

    // Emit the redirect stub to the replacement function.
    // Uses put_ldr_br_address which always uses plain BR (no auth) — the target
    // is a raw loaded constant, not a signed pointer.
    let mut stub = [0u8; 16];
    unsafe {
        let mut w = Arm64Writer::new(stub.as_mut_ptr(), stub.len(), function_address as u64);
        w.put_ldr_br_address(Reg::X16, replacement as u64);
    }

    let original_bytes = read_16(function_address as *const u8);
    unsafe {
        patch_code(function_address as *mut u8, stub.len(), |p| {
            core::ptr::copy_nonoverlapping(stub.as_ptr(), p, stub.len());
        })?;
    }

    // Sign the trampoline address so the replacement function can call
    // through it on arm64e.
    let tramp_raw = slice.pc as usize;
    let tramp_signed = sign_code_ptr(tramp_raw, ptrauth);
    let tramp_ptr = tramp_signed as *const c_void;
    if !original_out.is_null() {
        unsafe {
            *original_out = tramp_ptr;
        }
    }

    map.insert(
        key,
        ReplacementEntry {
            function: function_address as usize,
            original_bytes,
            trampoline: tramp_ptr as usize,
        },
    );

    Ok(())
}

pub(crate) fn revert(
    interceptor: &Interceptor,
    function_address: *mut c_void,
) -> Result<(), HookError> {
    let mut map = interceptor.replace_map.lock().unwrap();
    let function_address = strip_code_ptr(function_address as usize) as *mut c_void;
    let key = function_address as usize;
    let entry = match map.remove(&key) {
        Some(e) => e,
        None => return Ok(()),
    };

    unsafe {
        patch_code(entry.function as *mut u8, 16, |p| {
            core::ptr::copy_nonoverlapping(entry.original_bytes.as_ptr(), p, 16);
        })?;
    }

    Ok(())
}
