use super::{FunctionContext, Interceptor};
use crate::arch::arm64::relocator::{Arm64Relocator, can_relocate};
use crate::arch::arm64::writer::{Arm64Writer, Reg};
use crate::code::allocator::{CodeAllocator, CodeSlice};
use crate::code::patcher::patch_code;
use crate::code::ptrauth::strip_code_ptr;
use crate::interceptor::listener::CallListener;
use crate::types::{Arm64CpuContext, HookError, InvocationContext};
use core::ffi::c_void;

#[repr(C)]
struct BeginEndArgs {
    saved: *mut u8,
    frame_size: u64,
    function: u64,
}

/// Returns 1 if the original function should be skipped (replace_return_value was called).
unsafe extern "C" fn begin_invocation(ctx: *mut FunctionContext, inv: *mut InvocationContext, args: *mut BeginEndArgs) -> u64 {
    let ctx = &mut *ctx;
    let args = &mut *args;

    // Layout created by wrapper:
    // saved[0..): x0..x7, lr, sp0, ret
    const X0_OFF: usize = 0;
    const LR_OFF: usize = 64;
    const SP0_OFF: usize = 72;
    const RET_OFF: usize = 80;
    const FP_OFF: usize = 88;

    let cpu_ptr = (args.saved as usize + SAVED_AREA_SIZE) as *mut Arm64CpuContext;
    let cpu = &mut *cpu_ptr;

    cpu.pc = args.function;
    cpu.sp = *(args.saved.add(SP0_OFF) as *const u64);
    cpu.lr = *(args.saved.add(LR_OFF) as *const u64);
    cpu.fp = *(args.saved.add(FP_OFF) as *const u64);
    for i in 0..8 {
        cpu.x[i] = *(args.saved.add(X0_OFF + i * 8) as *const u64);
    }

    (*inv).function = ctx.function as *mut c_void;
    (*inv).cpu_context = cpu_ptr;
    (*inv).skip_original = false;

    // Dispatch on_enter.
    for l in &ctx.listeners {
        if let Some(cb) = l.on_enter {
            cb(inv, l.user_data);
        }
    }

    let skip = (*inv).skip_original;

    if skip {
        // Listener called replace_return_value — store the replacement in the ret slot
        // and do NOT write back modified args (they would corrupt the original call).
        *(args.saved.add(RET_OFF) as *mut u64) = cpu.x[0];
    } else {
        // Write back possibly modified args to the saved area (x0-x7).
        for i in 0..8 {
            *(args.saved.add(X0_OFF + i * 8) as *mut u64) = cpu.x[i];
        }
        // Clear ret slot.
        *(args.saved.add(RET_OFF) as *mut u64) = 0;
    }

    skip as u64
}

unsafe extern "C" fn end_invocation(ctx: *mut FunctionContext, inv: *mut InvocationContext, args: *mut BeginEndArgs) {
    let ctx = &mut *ctx;
    let args = &mut *args;

    const RET_OFF: usize = 80;
    let cpu_ptr = (args.saved as usize + SAVED_AREA_SIZE) as *mut Arm64CpuContext;
    let cpu = &mut *cpu_ptr;

    // Populate return value into cpu.x0 before callbacks.
    cpu.x[0] = *(args.saved.add(RET_OFF) as *const u64);

    (*inv).function = ctx.function as *mut c_void;
    (*inv).cpu_context = cpu_ptr;

    for l in &ctx.listeners {
        if let Some(cb) = l.on_leave {
            cb(inv, l.user_data);
        }
    }

    // Write back possibly modified return value.
    *(args.saved.add(RET_OFF) as *mut u64) = cpu.x[0];
}

const SAVED_AREA_SIZE: usize = 112; // x0-x7 (64) + lr (8) + sp0 (8) + ret (8) + fp (8) + nzcv (8) + pad (8)

fn read_16(addr: *const u8) -> [u8; 16] {
    unsafe { core::ptr::read_unaligned(addr as *const [u8; 16]) }
}

unsafe fn restore_prologue(function: *mut c_void, original_bytes: &[u8; 16], size: usize) -> Result<(), HookError> {
    patch_code(function as *mut u8, size, |p| {
        core::ptr::copy_nonoverlapping(original_bytes.as_ptr(), p, size);
    })
}

/// Build a trampoline that executes `n_insns` relocated instructions from
/// the function prologue and then branches back to `function + n_insns * 4`.
unsafe fn build_trampoline_n(function: *mut c_void, n_insns: usize) -> Result<usize, HookError> {
    let mut alloc = CodeAllocator::default();
    let slice = alloc.alloc_any()?;

    let tramp_pc = slice.data as u64;
    let mut w = Arm64Writer::new(slice.data, slice.size, tramp_pc);
    let mut r = Arm64Relocator::new(function as *const u32, function as u64);
    r.relocate_n(&mut w, n_insns)?;
    let resume = (function as u64) + (n_insns as u64) * 4;
    w.put_mov_reg_u64(Reg::X16, resume);
    w.put_br_reg(Reg::X16);
    alloc.make_executable(&slice)?;

    Ok(slice.pc as usize)
}

unsafe fn build_wrapper_in(
    ctx_ptr: *mut FunctionContext,
    trampoline: usize,
    slice: CodeSlice,
    alloc: &mut CodeAllocator,
) -> Result<usize, HookError> {
    // Stack frame layout:
    //   [sp + 0..96)                   saved: x0-x7 (64), lr (8), sp0 (8), ret (8), pad
    //   [sp + 96..96+CPU_SZ)           Arm64CpuContext (for listeners)
    //   [sp + INV_OFF..INV_OFF+INV_SZ) InvocationContext
    //   [sp + ARGS_OFF..ARGS_OFF+24)   BeginEndArgs
    let cpu_sz = core::mem::size_of::<Arm64CpuContext>();
    let inv_sz = core::mem::size_of::<InvocationContext>();
    let args_sz = core::mem::size_of::<BeginEndArgs>();

    let mut frame = SAVED_AREA_SIZE + cpu_sz + inv_sz + args_sz;
    frame = (frame + 15) & !15;

    let wrapper_pc = slice.data as u64;
    let mut w = Arm64Writer::new(slice.data, slice.size, wrapper_pc);

    // sub sp, sp, #frame
    w.put_sub_reg_reg_imm(Reg::SP, Reg::SP, frame as u32);

    // Save x0-x7.
    for i in 0..8 {
        w.put_str_reg_reg_offset(core::mem::transmute::<u8, Reg>(i as u8), Reg::SP, (i * 8) as i64);
    }
    // Save LR.
    w.put_str_reg_reg_offset(Reg::X30, Reg::SP, 64);
    // Save sp0 (original sp) into slot.
    w.put_add_reg_reg_imm(Reg::X16, Reg::SP, frame as u32);
    w.put_str_reg_reg_offset(Reg::X16, Reg::SP, 72);
    // Save FP (x29) for backtracing.
    w.put_str_reg_reg_offset(Reg::X29, Reg::SP, 88);
    // Save NZCV flags so the hook wrapper doesn't corrupt condition codes.
    w.put_u32_raw(0xD53B4210); // MRS X16, NZCV
    w.put_str_reg_reg_offset(Reg::X16, Reg::SP, 96);

    let inv_off = SAVED_AREA_SIZE + cpu_sz;
    let args_off = SAVED_AREA_SIZE + cpu_sz + inv_sz;

    // Prepare BeginEndArgs on stack (points at saved area).
    // saved ptr
    w.put_mov_reg_reg(Reg::X16, Reg::SP);
    w.put_str_reg_reg_offset(Reg::X16, Reg::SP, args_off as i64);
    // frame_size
    w.put_mov_reg_u64(Reg::X16, frame as u64);
    w.put_str_reg_reg_offset(Reg::X16, Reg::SP, (args_off + 8) as i64);
    // function address
    w.put_mov_reg_u64(Reg::X16, (*ctx_ptr).function as u64);
    w.put_str_reg_reg_offset(Reg::X16, Reg::SP, (args_off + 16) as i64);

    // Call begin_invocation(ctx, &inv, &args) → returns skip flag in x0.
    w.put_mov_reg_u64(Reg::X0, ctx_ptr as u64);
    w.put_add_reg_reg_imm(Reg::X1, Reg::SP, inv_off as u32);
    w.put_add_reg_reg_imm(Reg::X2, Reg::SP, args_off as u32);
    w.put_mov_reg_u64(Reg::X16, begin_invocation as *const () as usize as u64);
    w.put_blr_reg(Reg::X16);

    // If begin_invocation returned non-zero (skip_original), jump over trampoline.
    // Emit a placeholder CBNZ that we'll fix up after emitting the trampoline block.
    let cbnz_slot = w.code_ptr();
    w.put_u32_raw(0xD503201F); // placeholder NOP (will become CBNZ X0, #offset)

    // Restore (possibly modified) args x0-x7 from saved area.
    for i in 0..8 {
        w.put_ldr_reg_reg_offset(core::mem::transmute::<u8, Reg>(i as u8), Reg::SP, (i * 8) as i64);
    }

    // Call trampoline (original prologue + resume).
    w.put_mov_reg_u64(Reg::X16, trampoline as u64);
    w.put_blr_reg(Reg::X16);

    // Save return value into ret slot.
    w.put_str_reg_reg_offset(Reg::X0, Reg::SP, 80);

    // Fix up the CBNZ to jump here (after the trampoline block).
    // When skip_original is true, the ret slot already contains the replacement value
    // (set by begin_invocation), so we skip straight to end_invocation.
    {
        let skip_target = w.code_ptr();
        let offset_insns = (skip_target as isize - cbnz_slot as isize) / 4;
        // CBNZ X0, #offset: 0b00110101_imm19_00000 (Rt=X0=0, sf=1 for 64-bit)
        let cbnz = 0xB5000000u32 | (((offset_insns as u32) & 0x7FFFF) << 5);
        cbnz_slot.write(cbnz);
    }

    // Call end_invocation(ctx, &inv, &args)
    w.put_mov_reg_u64(Reg::X0, ctx_ptr as u64);
    w.put_add_reg_reg_imm(Reg::X1, Reg::SP, inv_off as u32);
    w.put_add_reg_reg_imm(Reg::X2, Reg::SP, args_off as u32);
    w.put_mov_reg_u64(Reg::X16, end_invocation as *const () as usize as u64);
    w.put_blr_reg(Reg::X16);

    // Restore NZCV flags.
    w.put_ldr_reg_reg_offset(Reg::X16, Reg::SP, 96);
    w.put_u32_raw(0xD51B4210); // MSR NZCV, X16

    // Load return value from ret slot.
    w.put_ldr_reg_reg_offset(Reg::X0, Reg::SP, 80);

    // Restore LR for the final RET.
    w.put_ldr_reg_reg_offset(Reg::X30, Reg::SP, 64);

    // add sp, sp, #frame; ret
    w.put_add_reg_reg_imm(Reg::SP, Reg::SP, frame as u32);
    w.put_ret();

    alloc.make_executable(&slice)?;
    Ok(slice.pc as usize)
}

/// Maximum range for ARM64 B (branch) instruction: ±128 MB.
const B_RANGE: usize = 128 * 1024 * 1024;

/// Maximum range for ADRP (page-relative addressing): ±4 GB.
const ADRP_RANGE: usize = 4 * 1024 * 1024 * 1024;

/// Determine the smallest prologue patch size based on the distance from
/// the function to the wrapper.
///
/// Returns (patch_bytes, relocated_instruction_count):
///   -  4 bytes / 1 insn:  B imm26        (±128 MB)
///   - 12 bytes / 3 insns: ADRP+ADD+BR    (±4 GB)
///   - 16 bytes / 4 insns: LDR+BR+literal (any distance)
fn choose_patch_strategy(function: u64, wrapper: u64) -> (usize, usize) {
    let dist = (wrapper as i64 - function as i64).unsigned_abs() as usize;
    if dist < B_RANGE {
        (4, 1)
    } else if dist < ADRP_RANGE {
        (12, 3)
    } else {
        (16, 4)
    }
}

pub(crate) fn attach(interceptor: &Interceptor, function_address: *mut c_void, listener: CallListener) -> Result<(), HookError> {
    let function_address = strip_code_ptr(function_address as usize) as *mut c_void;
    let key = function_address as usize;

    // Attach and replace are mutually exclusive for a given function address.
    // Mixing modes would build trampolines from already-patched prologues.
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
    let func_addr = function_address as u64;

    // Allocate the wrapper near the target for the smallest possible prologue patch.
    let mut alloc = CodeAllocator::default();
    let wrapper_slice = alloc
        .alloc_near(function_address as *const u8, B_RANGE)
        .or_else(|_| alloc.alloc_any())?;
    let wrapper_addr_estimate = wrapper_slice.data as u64;

    let (mut patch_size, mut n_insns) = choose_patch_strategy(func_addr, wrapper_addr_estimate);

    // Validate that the required number of instructions can be safely relocated.
    // can_relocate stops after BL/BLR boundaries (which modify LR). SVC is NOT
    // a boundary — it is position-independent (the relocator copies it verbatim).
    let (max_safe, _scratch) = unsafe { can_relocate(
        function_address as *const u32,
        n_insns,
    ) };
    if max_safe < n_insns {
        // Reduce patch size to fit within the safe relocation boundary.
        let dist = (wrapper_addr_estimate as i64 - func_addr as i64).unsigned_abs() as usize;
        if max_safe >= 3 && dist < ADRP_RANGE {
            patch_size = 12;
            n_insns = 3;
        } else if max_safe >= 1 && dist < B_RANGE {
            patch_size = 4;
            n_insns = 1;
        } else {
            return Err(HookError::AllocationFailed);
        }
    }

    let trampoline = unsafe { build_trampoline_n(function_address, n_insns)? };

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
        let mut w = Arm64Writer::new(stub.as_mut_ptr(), stub.len(), func_addr);
        match patch_size {
            4 => w.put_b_imm(wrapper as u64),
            12 => w.put_adrp_add_br(Reg::X16, wrapper as u64),
            _ => w.put_ldr_br_address(Reg::X16, wrapper as u64),
        }
    }
    unsafe {
        patch_code(function_address as *mut u8, patch_size, |p| {
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

    // Rebinding attach and replace are mutually exclusive for a given symbol.
    {
        let replace_map = interceptor.replace_map.lock().unwrap();
        if replace_map.contains_key(&key) {
            return Err(HookError::AlreadyAttached);
        }
    }

    // If already attached, just add listener and return existing wrapper.
    {
        let mut map = interceptor.attach_map.lock().unwrap();
        if let Some(ctx) = map.get_mut(&key) {
            ctx.listeners.push(listener);
            return Ok(ctx.wrapper);
        }
    }

    // Create context + wrapper, but do NOT patch the function prologue.
    let original_bytes = read_16(function_address as *const u8);
    let trampoline = unsafe { build_trampoline_n(function_address, 4)? };

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

    // Remove the listener from all attached functions; if a function has no listeners left,
    // restore its original prologue and drop its context.
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
                unsafe {
                    let _ = restore_prologue(key as *mut c_void, &ctx.original_bytes, ctx.patch_size);
                }
            }
        }
    }
}
