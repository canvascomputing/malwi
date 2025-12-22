use super::{Interceptor, ReplacementEntry};
use crate::arch::x86_64::relocator::{is_endbr64, X86_64Relocator};
use crate::arch::x86_64::writer::X86_64Writer;
use crate::code::allocator::CodeAllocator;
use crate::code::patcher::patch_code;
use crate::code::ptrauth::strip_code_ptr;
use crate::types::HookError;
use core::ffi::c_void;

/// Near JMP (E9 rel32): 5 bytes.
const NEAR_JMP_SIZE: usize = 5;

/// Far JMP (FF 25 02 00 00 00; 0F 0B; .quad addr): 16 bytes.
const FAR_JMP_SIZE: usize = 16;

/// Maximum relative distance for a near JMP rel32 (±2GB).
const NEAR_RANGE: usize = 0x7FFF_FFFF;

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

    // Attach and replace are mutually exclusive.
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

    // Detect ENDBR64 at function start.
    let mut patch_addr = function_address as *mut u8;
    let mut patch_pc = function_address as u64;
    if is_endbr64(patch_addr) {
        patch_addr = unsafe { patch_addr.add(4) };
        patch_pc += 4;
    }

    // Allocate code page, prefer near the function (enables 5-byte near JMP).
    let mut alloc = CodeAllocator::default();
    let slice = alloc
        .alloc_near(patch_addr, NEAR_RANGE)
        .or_else(|_| alloc.alloc_any())?;

    let page_is_near =
        ((slice.data as i64) - (patch_pc as i64)).unsigned_abs() as usize <= NEAR_RANGE;
    let repl_is_near = ((replacement as i64)
        - (patch_pc as i64 + NEAR_JMP_SIZE as i64))
        .unsigned_abs() as usize
        <= NEAR_RANGE;

    // If replacement or allocated page is near, use 5-byte redirect;
    // otherwise fall back to 16-byte far JMP.
    let redirect_size = if repl_is_near || page_is_near {
        NEAR_JMP_SIZE
    } else {
        FAR_JMP_SIZE
    };

    // Build trampoline: relocate prologue + JMP back to function+relocated_bytes.
    // If replacement is far but page is near, also emit a relay stub on the page.
    let tramp_pc = slice.data as u64;
    let relocated_bytes;
    let redirect_target;
    unsafe {
        let mut w = X86_64Writer::new(slice.data, slice.size, tramp_pc);
        let mut r = X86_64Relocator::new(patch_addr, patch_pc);
        relocated_bytes = r.relocate_bytes(&mut w, redirect_size)?;
        // Jump back to the instruction after the relocated prologue.
        let resume = patch_pc + relocated_bytes as u64;
        w.put_jmp_address(resume);

        // Determine redirect target.
        if repl_is_near {
            // Direct near JMP to replacement.
            redirect_target = replacement as u64;
        } else if page_is_near {
            // Replacement is far but page is near: add relay stub after trampoline.
            redirect_target = w.pc();
            w.put_jmp_far(replacement as u64);
        } else {
            // Both far: far JMP directly to replacement.
            redirect_target = replacement as u64;
        }

        alloc.make_executable(&slice)?;
    }

    // Build redirect stub.
    let mut stub = [0u8; 16];
    unsafe {
        let mut w = X86_64Writer::new(stub.as_mut_ptr(), stub.len(), patch_pc);
        if redirect_size == NEAR_JMP_SIZE {
            w.put_jmp_near(redirect_target);
        } else {
            w.put_jmp_far(redirect_target);
        }
        // NOP-pad any remaining bytes up to relocated_bytes.
        let written = w.offset();
        if written < relocated_bytes {
            w.put_nop_n(relocated_bytes - written);
        }
    }

    let original_bytes = read_16(function_address as *const u8);
    let patch_total = if patch_addr != function_address as *mut u8 {
        // ENDBR64 case: patch from function+4, but store original_bytes from function start
        relocated_bytes
    } else {
        relocated_bytes
    };

    unsafe {
        patch_code(patch_addr, patch_total, |p| {
            core::ptr::copy_nonoverlapping(stub.as_ptr(), p, patch_total);
        })?;
    }

    let tramp_ptr = slice.pc as *const c_void;
    if !original_out.is_null() {
        unsafe { *original_out = tramp_ptr; }
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

pub(crate) fn revert(interceptor: &Interceptor, function_address: *mut c_void) -> Result<(), HookError> {
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
