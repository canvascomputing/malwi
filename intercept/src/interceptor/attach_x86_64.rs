use super::{FunctionContext, Interceptor};
use crate::arch::x86_64::relocator::{can_relocate, is_endbr64, X86_64Relocator};
use crate::arch::x86_64::writer::{Reg, X86_64Writer};
use crate::code::allocator::{CodeAllocator, CodeSlice};
use crate::code::patcher::patch_code;
use crate::code::ptrauth::strip_code_ptr;
use crate::interceptor::listener::CallListener;
use crate::types::{HookError, InvocationContext, X86_64CpuContext};
use core::ffi::c_void;

// ── Saved area layout ────────────────────────────────────────────────
//
// The wrapper saves registers to a "saved area" on the stack so
// begin_invocation / end_invocation can populate X86_64CpuContext.
//
// Offset  Content         Size
// 0       RDI (arg0)      8
// 8       RSI (arg1)      8
// 16      RDX (arg2)      8
// 24      RCX (arg3)      8
// 32      R8  (arg4)      8
// 40      R9  (arg5)      8
// 48      RAX             8
// 56      return_addr     8
// 64      sp0 (orig RSP)  8
// 72      ret_value       8
// 80      RBP             8
// 88      RFLAGS          8
// 96      R10             8
// 104     R11             8
// 112     RBX             8
// 120     R12             8
// 128     R13             8
// 136     R14             8
// 144     R15             8
const SAVED_AREA_SIZE: usize = 152;

const RDI_OFF: usize = 0;
const RSI_OFF: usize = 8;
const RDX_OFF: usize = 16;
const RCX_OFF: usize = 24;
const R8_OFF: usize = 32;
const R9_OFF: usize = 40;
const RAX_OFF: usize = 48;
const RET_ADDR_OFF: usize = 56;
const SP0_OFF: usize = 64;
const RET_VALUE_OFF: usize = 72;
const RBP_OFF: usize = 80;
const RFLAGS_OFF: usize = 88;
const R10_OFF: usize = 96;
const R11_OFF: usize = 104;
const RBX_OFF: usize = 112;
const R12_OFF: usize = 120;
const R13_OFF: usize = 128;
const R14_OFF: usize = 136;
const R15_OFF: usize = 144;

/// Arguments passed between the wrapper and begin/end_invocation.
#[repr(C)]
struct BeginEndArgs {
    saved: *mut u8,
    frame_size: u64,
    function: u64,
}

/// Called by the wrapper before the original function.
/// Returns 1 if the original should be skipped (replace_return_value was called).
unsafe extern "C" fn begin_invocation(
    ctx: *mut FunctionContext,
    inv: *mut InvocationContext,
    args: *mut BeginEndArgs,
) -> u64 {
    let ctx = &mut *ctx;
    let args = &mut *args;

    let cpu_ptr = (args.saved as usize + SAVED_AREA_SIZE) as *mut X86_64CpuContext;
    let cpu = &mut *cpu_ptr;

    cpu.rip = args.function;
    cpu.rsp = *(args.saved.add(SP0_OFF) as *const u64);
    cpu.rflags = *(args.saved.add(RFLAGS_OFF) as *const u64);
    cpu.rdi = *(args.saved.add(RDI_OFF) as *const u64);
    cpu.rsi = *(args.saved.add(RSI_OFF) as *const u64);
    cpu.rdx = *(args.saved.add(RDX_OFF) as *const u64);
    cpu.rcx = *(args.saved.add(RCX_OFF) as *const u64);
    cpu.r8 = *(args.saved.add(R8_OFF) as *const u64);
    cpu.r9 = *(args.saved.add(R9_OFF) as *const u64);
    cpu.rax = *(args.saved.add(RAX_OFF) as *const u64);
    cpu.rbp = *(args.saved.add(RBP_OFF) as *const u64);
    cpu.r10 = *(args.saved.add(R10_OFF) as *const u64);
    cpu.r11 = *(args.saved.add(R11_OFF) as *const u64);
    cpu.rbx = *(args.saved.add(RBX_OFF) as *const u64);
    cpu.r12 = *(args.saved.add(R12_OFF) as *const u64);
    cpu.r13 = *(args.saved.add(R13_OFF) as *const u64);
    cpu.r14 = *(args.saved.add(R14_OFF) as *const u64);
    cpu.r15 = *(args.saved.add(R15_OFF) as *const u64);

    (*inv).function = ctx.function as *mut c_void;
    (*inv).cpu_context = cpu_ptr;
    (*inv).skip_original = false;

    for l in &ctx.listeners {
        if let Some(cb) = l.on_enter {
            cb(inv, l.user_data);
        }
    }

    let skip = (*inv).skip_original;

    if skip {
        // Listener called replace_return_value — store in ret_value slot.
        *(args.saved.add(RET_VALUE_OFF) as *mut u64) = cpu.rax;
    } else {
        // Write back possibly modified args.
        *(args.saved.add(RDI_OFF) as *mut u64) = cpu.rdi;
        *(args.saved.add(RSI_OFF) as *mut u64) = cpu.rsi;
        *(args.saved.add(RDX_OFF) as *mut u64) = cpu.rdx;
        *(args.saved.add(RCX_OFF) as *mut u64) = cpu.rcx;
        *(args.saved.add(R8_OFF) as *mut u64) = cpu.r8;
        *(args.saved.add(R9_OFF) as *mut u64) = cpu.r9;
        *(args.saved.add(RAX_OFF) as *mut u64) = cpu.rax;
        // Clear ret_value slot.
        *(args.saved.add(RET_VALUE_OFF) as *mut u64) = 0;
    }

    skip as u64
}

unsafe extern "C" fn end_invocation(
    ctx: *mut FunctionContext,
    inv: *mut InvocationContext,
    args: *mut BeginEndArgs,
) {
    let ctx = &mut *ctx;
    let args = &mut *args;

    let cpu_ptr = (args.saved as usize + SAVED_AREA_SIZE) as *mut X86_64CpuContext;
    let cpu = &mut *cpu_ptr;

    cpu.rax = *(args.saved.add(RET_VALUE_OFF) as *const u64);

    (*inv).function = ctx.function as *mut c_void;
    (*inv).cpu_context = cpu_ptr;

    for l in &ctx.listeners {
        if let Some(cb) = l.on_leave {
            cb(inv, l.user_data);
        }
    }

    // Write back possibly modified return value.
    *(args.saved.add(RET_VALUE_OFF) as *mut u64) = cpu.rax;
}

// ── Redirect sizes ───────────────────────────────────────────────────

/// Near JMP (E9 rel32): 5 bytes.
const NEAR_JMP_SIZE: usize = 5;

/// Far JMP (FF 25 02 00 00 00; 0F 0B; .quad addr): 16 bytes.
const FAR_JMP_SIZE: usize = 16;

/// Maximum relative distance for near JMP rel32 (±2GB).
const NEAR_RANGE: usize = 0x7FFF_FFFF;

/// Red zone size on System V AMD64.
const RED_ZONE: i32 = 128;

fn read_16(addr: *const u8) -> [u8; 16] {
    unsafe { core::ptr::read_unaligned(addr as *const [u8; 16]) }
}

/// Build a trampoline that executes `relocated_bytes` bytes of the original
/// prologue starting at `patch_addr` and then jumps back to `patch_addr + relocated_bytes`.
unsafe fn build_trampoline(
    patch_addr: *mut u8,
    patch_pc: u64,
    redirect_size: usize,
) -> Result<(usize, usize), HookError> {
    let mut alloc = CodeAllocator::default();
    let slice = alloc.alloc_any()?;

    let tramp_pc = slice.data as u64;
    let mut w = X86_64Writer::new(slice.data, slice.size, tramp_pc);
    let mut r = X86_64Relocator::new(patch_addr, patch_pc);
    let relocated_bytes = r.relocate_bytes(&mut w, redirect_size)?;
    let resume = patch_pc + relocated_bytes as u64;
    w.put_jmp_address(resume);
    alloc.make_executable(&slice)?;

    Ok((slice.pc as usize, relocated_bytes))
}

unsafe fn build_wrapper_in(
    ctx_ptr: *mut FunctionContext,
    trampoline: usize,
    slice: CodeSlice,
    alloc: &mut CodeAllocator,
) -> Result<usize, HookError> {
    let cpu_sz = core::mem::size_of::<X86_64CpuContext>();
    let inv_sz = core::mem::size_of::<InvocationContext>();
    let args_sz = core::mem::size_of::<BeginEndArgs>();

    let inv_off = SAVED_AREA_SIZE + cpu_sz;
    let args_off = SAVED_AREA_SIZE + cpu_sz + inv_sz;

    // FXSAVE requires a 16-byte-aligned 512-byte region.
    // We add 15 bytes of slack so we can 16-byte align the address at
    // runtime (RSP alignment at wrapper entry may vary).
    let fxsave_off = args_off + args_sz;
    let mut frame = fxsave_off + 15 + 512;
    frame = (frame + 15) & !15; // 16-byte align total

    let wrapper_pc = slice.data as u64;
    let mut w = X86_64Writer::new(slice.data, slice.size, wrapper_pc);

    // ── Preserve red zone (use LEA to avoid clobbering RFLAGS) ──
    w.put_lea_reg_mem(Reg::RSP, Reg::RSP, -RED_ZONE);

    // ── Save RFLAGS (before any arithmetic) ──
    w.put_pushfq();

    // ── Allocate frame ──
    w.put_sub_reg_imm32(Reg::RSP, frame as u32);

    // ── Save argument registers to saved area ──
    w.put_mov_mem_reg(Reg::RSP, RDI_OFF as i32, Reg::RDI);
    w.put_mov_mem_reg(Reg::RSP, RSI_OFF as i32, Reg::RSI);
    w.put_mov_mem_reg(Reg::RSP, RDX_OFF as i32, Reg::RDX);
    w.put_mov_mem_reg(Reg::RSP, RCX_OFF as i32, Reg::RCX);
    w.put_mov_mem_reg(Reg::RSP, R8_OFF as i32, Reg::R8);
    w.put_mov_mem_reg(Reg::RSP, R9_OFF as i32, Reg::R9);
    w.put_mov_mem_reg(Reg::RSP, RAX_OFF as i32, Reg::RAX);
    w.put_mov_mem_reg(Reg::RSP, R10_OFF as i32, Reg::R10);
    w.put_mov_mem_reg(Reg::RSP, R11_OFF as i32, Reg::R11);
    w.put_mov_mem_reg(Reg::RSP, RBP_OFF as i32, Reg::RBP);
    w.put_mov_mem_reg(Reg::RSP, RBX_OFF as i32, Reg::RBX);
    w.put_mov_mem_reg(Reg::RSP, R12_OFF as i32, Reg::R12);
    w.put_mov_mem_reg(Reg::RSP, R13_OFF as i32, Reg::R13);
    w.put_mov_mem_reg(Reg::RSP, R14_OFF as i32, Reg::R14);
    w.put_mov_mem_reg(Reg::RSP, R15_OFF as i32, Reg::R15);

    // ── Clear direction flag (C ABI mandates DF=0 for callbacks) ──
    w.put_cld();

    // ── Save FPU/XMM state (FXSAVE requires 16-byte alignment) ──
    w.put_lea_reg_mem(Reg::R11, Reg::RSP, (fxsave_off + 15) as i32);
    w.put_and_reg_imm32(Reg::R11, !15u32);
    w.put_fxsave_reg_indirect(Reg::R11);

    // ── Capture return address from [RSP + frame + 8(pushfq) + RED_ZONE] ──
    // Stack at entry to wrapper:
    //   [RSP_entry]        = return address (pushed by CALL)
    //   RSP_entry - 128    = after LEA (red zone)
    //   RSP_entry - 128 - 8 = after pushfq
    //   RSP_entry - 128 - 8 - frame = current RSP
    // So return address is at RSP + frame + 8 + RED_ZONE
    let ret_addr_stack_off = (frame as i32) + 8 + RED_ZONE;
    w.put_mov_reg_mem(Reg::R11, Reg::RSP, ret_addr_stack_off);
    w.put_mov_mem_reg(Reg::RSP, RET_ADDR_OFF as i32, Reg::R11);

    // ── Compute original RSP (before the CALL that reached us) ──
    // Original RSP = RSP + frame + 8(pushfq) + RED_ZONE + 8(return addr)
    let orig_rsp_off = (frame as i32) + 8 + RED_ZONE + 8;
    w.put_lea_reg_mem(Reg::R11, Reg::RSP, orig_rsp_off);
    w.put_mov_mem_reg(Reg::RSP, SP0_OFF as i32, Reg::R11);

    // ── Save RFLAGS from the pushfq result ──
    // RFLAGS is at [RSP + frame] (from pushfq earlier)
    w.put_mov_reg_mem(Reg::R11, Reg::RSP, frame as i32);
    w.put_mov_mem_reg(Reg::RSP, RFLAGS_OFF as i32, Reg::R11);

    // ── Prepare BeginEndArgs on stack ──
    // saved = RSP (start of saved area)
    w.put_mov_reg_reg(Reg::R11, Reg::RSP);
    w.put_mov_mem_reg(Reg::RSP, args_off as i32, Reg::R11);
    // frame_size
    w.put_mov_reg_imm64(Reg::R11, frame as u64);
    w.put_mov_mem_reg(Reg::RSP, (args_off + 8) as i32, Reg::R11);
    // function address
    w.put_mov_reg_imm64(Reg::R11, (*ctx_ptr).function as u64);
    w.put_mov_mem_reg(Reg::RSP, (args_off + 16) as i32, Reg::R11);

    // ── Call begin_invocation(ctx, &inv, &args) → RAX = skip flag ──
    w.put_mov_reg_imm64(Reg::RDI, ctx_ptr as u64);
    w.put_lea_reg_mem(Reg::RSI, Reg::RSP, inv_off as i32);
    w.put_lea_reg_mem(Reg::RDX, Reg::RSP, args_off as i32);
    w.put_mov_reg_imm64(Reg::R11, begin_invocation as *const () as usize as u64);
    w.put_call_reg(Reg::R11);

    // ── Check skip flag ──
    w.put_test_reg_reg(Reg::RAX, Reg::RAX);
    // JNZ to skip_label — we'll fix up the offset after emitting the trampoline call block.
    let jnz_patch = w.code_ptr();
    let jnz_pc = w.pc();
    // Emit placeholder JNZ rel32 (6 bytes: 0F 85 xx xx xx xx)
    w.put_bytes(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);

    // ── Restore args from saved area ──
    w.put_mov_reg_mem(Reg::RDI, Reg::RSP, RDI_OFF as i32);
    w.put_mov_reg_mem(Reg::RSI, Reg::RSP, RSI_OFF as i32);
    w.put_mov_reg_mem(Reg::RDX, Reg::RSP, RDX_OFF as i32);
    w.put_mov_reg_mem(Reg::RCX, Reg::RSP, RCX_OFF as i32);
    w.put_mov_reg_mem(Reg::R8, Reg::RSP, R8_OFF as i32);
    w.put_mov_reg_mem(Reg::R9, Reg::RSP, R9_OFF as i32);
    w.put_mov_reg_mem(Reg::RAX, Reg::RSP, RAX_OFF as i32);

    // ── Restore RFLAGS before calling trampoline ──
    w.put_push_mem(Reg::RSP, RFLAGS_OFF as i32);
    w.put_popfq();

    // ── Call trampoline (original prologue + resume) ──
    w.put_mov_reg_imm64(Reg::R11, trampoline as u64);
    w.put_call_reg(Reg::R11);

    // ── Save return value ──
    w.put_mov_mem_reg(Reg::RSP, RET_VALUE_OFF as i32, Reg::RAX);

    // ── Fix up JNZ to skip here ──
    {
        let skip_pc = w.pc();
        let rel = (skip_pc as i64) - (jnz_pc as i64 + 6);
        let jnz_disp_ptr = jnz_patch.add(2) as *mut i32;
        jnz_disp_ptr.write_unaligned(rel as i32);
    }

    // ── Call end_invocation(ctx, &inv, &args) ──
    w.put_mov_reg_imm64(Reg::RDI, ctx_ptr as u64);
    w.put_lea_reg_mem(Reg::RSI, Reg::RSP, inv_off as i32);
    w.put_lea_reg_mem(Reg::RDX, Reg::RSP, args_off as i32);
    w.put_mov_reg_imm64(Reg::R11, end_invocation as *const () as usize as u64);
    w.put_call_reg(Reg::R11);

    // ── Load return value ──
    w.put_mov_reg_mem(Reg::RAX, Reg::RSP, RET_VALUE_OFF as i32);

    // ── Restore FPU/XMM state ──
    w.put_lea_reg_mem(Reg::R11, Reg::RSP, (fxsave_off + 15) as i32);
    w.put_and_reg_imm32(Reg::R11, !15u32);
    w.put_fxrstor_reg_indirect(Reg::R11);

    // ── Restore callee-saved registers ──
    w.put_mov_reg_mem(Reg::RBX, Reg::RSP, RBX_OFF as i32);
    w.put_mov_reg_mem(Reg::R12, Reg::RSP, R12_OFF as i32);
    w.put_mov_reg_mem(Reg::R13, Reg::RSP, R13_OFF as i32);
    w.put_mov_reg_mem(Reg::R14, Reg::RSP, R14_OFF as i32);
    w.put_mov_reg_mem(Reg::R15, Reg::RSP, R15_OFF as i32);
    w.put_mov_reg_mem(Reg::RBP, Reg::RSP, RBP_OFF as i32);

    // ── Restore RFLAGS ──
    w.put_push_mem(Reg::RSP, RFLAGS_OFF as i32);
    w.put_popfq();

    // ── Restore return address ──
    w.put_mov_reg_mem(Reg::R11, Reg::RSP, RET_ADDR_OFF as i32);

    // ── Teardown frame + pushfq + red zone (LEA to preserve RFLAGS) ──
    w.put_lea_reg_mem(Reg::RSP, Reg::RSP, (frame as i32) + 8 + RED_ZONE);

    // ── Put return address back on stack and RET ──
    w.put_mov_mem_reg(Reg::RSP, 0, Reg::R11);
    w.put_ret();

    alloc.make_executable(&slice)?;
    Ok(slice.pc as usize)
}

pub(crate) fn attach(
    interceptor: &Interceptor,
    function_address: *mut c_void,
    listener: CallListener,
) -> Result<(), HookError> {
    let function_address = strip_code_ptr(function_address as usize) as *mut c_void;
    let key = function_address as usize;

    // Mutual exclusion with replace.
    {
        let replace_map = interceptor.replace_map.lock().unwrap();
        if replace_map.contains_key(&key) {
            return Err(HookError::AlreadyAttached);
        }
    }

    // If already attached, just add listener.
    {
        let mut map = interceptor.attach_map.lock().unwrap();
        if let Some(ctx) = map.get_mut(&key) {
            ctx.listeners.push(listener);
            return Ok(());
        }
    }

    let original_bytes = read_16(function_address as *const u8);

    // Detect ENDBR64.
    let mut patch_addr = function_address as *mut u8;
    let mut patch_pc = function_address as u64;
    if is_endbr64(patch_addr) {
        patch_addr = unsafe { patch_addr.add(4) };
        patch_pc += 4;
    }

    // Allocate wrapper near the function for smallest redirect.
    let mut alloc = CodeAllocator::default();
    let wrapper_slice = alloc
        .alloc_near(patch_addr, NEAR_RANGE)
        .or_else(|_| alloc.alloc_any())?;
    let wrapper_addr_estimate = wrapper_slice.data as u64;

    let dist = (wrapper_addr_estimate as i64 - patch_pc as i64).unsigned_abs() as usize;
    let redirect_size = if dist < NEAR_RANGE { NEAR_JMP_SIZE } else { FAR_JMP_SIZE };

    // Validate relocation.
    let max_safe = can_relocate(patch_addr, redirect_size);
    if max_safe < redirect_size {
        // Can't relocate enough bytes.
        return Err(HookError::RelocationFailed);
    }

    let (trampoline, relocated_bytes) = unsafe { build_trampoline(patch_addr, patch_pc, redirect_size)? };

    let patch_size = relocated_bytes;

    let mut ctx = Box::new(FunctionContext {
        function: key,
        original_bytes,
        patch_size,
        trampoline,
        wrapper: 0,
        listeners: vec![listener],
    });
    let ctx_ptr: *mut FunctionContext = &mut *ctx;

    let wrapper = unsafe { build_wrapper_in(ctx_ptr, trampoline, wrapper_slice, &mut alloc)? };
    ctx.wrapper = wrapper;

    // Emit the prologue patch.
    let mut stub = [0u8; 16];
    unsafe {
        let mut w = X86_64Writer::new(stub.as_mut_ptr(), stub.len(), patch_pc);
        if redirect_size == NEAR_JMP_SIZE {
            w.put_jmp_near(wrapper as u64);
        } else {
            w.put_jmp_far(wrapper as u64);
        }
        // NOP-pad remaining bytes.
        let written = w.offset();
        if written < relocated_bytes {
            w.put_nop_n(relocated_bytes - written);
        }
    }
    unsafe {
        patch_code(patch_addr, patch_size, |p| {
            core::ptr::copy_nonoverlapping(stub.as_ptr(), p, patch_size);
        })?;
    }

    let mut map = interceptor.attach_map.lock().unwrap();
    map.insert(key, ctx);
    Ok(())
}

pub(crate) fn attach_rebinding(
    interceptor: &Interceptor,
    function_address: *mut c_void,
    listener: CallListener,
) -> Result<usize, HookError> {
    let function_address = strip_code_ptr(function_address as usize) as *mut c_void;
    let key = function_address as usize;

    {
        let replace_map = interceptor.replace_map.lock().unwrap();
        if replace_map.contains_key(&key) {
            return Err(HookError::AlreadyAttached);
        }
    }

    {
        let mut map = interceptor.attach_map.lock().unwrap();
        if let Some(ctx) = map.get_mut(&key) {
            ctx.listeners.push(listener);
            return Ok(ctx.wrapper);
        }
    }

    let original_bytes = read_16(function_address as *const u8);
    let patch_addr = function_address as *mut u8;
    let patch_pc = function_address as u64;

    let (trampoline, _) = unsafe { build_trampoline(patch_addr, patch_pc, FAR_JMP_SIZE)? };

    let mut alloc = CodeAllocator::default();
    let slice = alloc.alloc_any()?;

    let mut ctx = Box::new(FunctionContext {
        function: key,
        original_bytes,
        patch_size: 0, // no prologue patch for rebinding
        trampoline,
        wrapper: 0,
        listeners: vec![listener],
    });
    let ctx_ptr: *mut FunctionContext = &mut *ctx;

    let wrapper = unsafe { build_wrapper_in(ctx_ptr, trampoline, slice, &mut alloc)? };
    ctx.wrapper = wrapper;

    let mut map = interceptor.attach_map.lock().unwrap();
    map.insert(key, ctx);

    Ok(wrapper)
}

pub(crate) fn detach(interceptor: &Interceptor, listener: &CallListener) {
    let mut map = interceptor.attach_map.lock().unwrap();

    let mut to_remove: Vec<usize> = Vec::new();
    for (key, ctx) in map.iter_mut() {
        let before = ctx.listeners.len();
        ctx.listeners.retain(|l| !l.matches(listener));
        if before != ctx.listeners.len() && ctx.listeners.is_empty() {
            to_remove.push(*key);
        }
    }

    for key in to_remove {
        if let Some(ctx) = map.remove(&key) {
            if ctx.patch_size > 0 {
                // Determine where the patch was applied (may be after ENDBR64).
                let func_ptr = key as *const u8;
                let patch_start = if is_endbr64(func_ptr) {
                    unsafe { func_ptr.add(4) as *mut c_void }
                } else {
                    key as *mut c_void
                };
                unsafe {
                    // Restore original bytes at the patch location.
                    let offset = (patch_start as usize) - key;
                    let _ = patch_code(patch_start as *mut u8, ctx.patch_size, |p| {
                        core::ptr::copy_nonoverlapping(
                            ctx.original_bytes.as_ptr().add(offset),
                            p,
                            ctx.patch_size,
                        );
                    });
                }
            }
        }
    }
}
