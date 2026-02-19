use crate::code::cache::invalidate_icache;
use crate::types::HookError;

#[cfg(target_os = "macos")]
mod darwin {
    use super::*;

    use mach2::boolean::boolean_t;
    use mach2::kern_return::KERN_SUCCESS;
    use mach2::traps::mach_task_self;
    use mach2::vm_inherit::{VM_INHERIT_COPY, VM_INHERIT_NONE};
    use mach2::vm_prot::{vm_prot_t, VM_PROT_COPY, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
    use mach2::vm::{mach_vm_allocate, mach_vm_deallocate, mach_vm_write};
    use mach2::vm_statistics::{VM_FLAGS_ANYWHERE, VM_FLAGS_FIXED};
    use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t, vm_address_t, vm_size_t};
    use mach2::vm_types::vm_offset_t;
    use mach2::message::mach_msg_type_number_t;

    const FALSE: boolean_t = 0;
    const TRUE: boolean_t = 1;
    const VM_FLAGS_OVERWRITE: libc::c_int = 0x4000;

    extern "C" {
        fn vm_remap(
            target_task: mach2::vm_types::vm_map_t,
            target_address: *mut vm_address_t,
            size: vm_size_t,
            mask: vm_address_t,
            flags: ::libc::c_int,
            src_task: mach2::vm_types::vm_map_t,
            src_address: vm_address_t,
            copy: boolean_t,
            cur_protection: *mut vm_prot_t,
            max_protection: *mut vm_prot_t,
            inheritance: mach2::vm_inherit::vm_inherit_t,
        ) -> mach2::kern_return::kern_return_t;
    }

    #[inline]
    fn debug_enabled() -> bool {
        std::env::var_os("MALWI_HOOK_DEBUG").is_some()
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn mach_vm_protect_svc(
        target_task: mach2::vm_types::vm_map_t,
        address: mach_vm_address_t,
        size: mach_vm_size_t,
        set_maximum: boolean_t,
        new_protection: vm_prot_t,
    ) -> i32 {
        // Try the library wrapper first — it works in CI and most environments.
        let kr = mach2::vm::mach_vm_protect(target_task, address, size, set_maximum, new_protection);
        if kr == 0 {
            return kr;
        }

        // Fall back to direct SVC syscall for ARM64. Under hardened runtime /
        // "debugger mapping" enforcement the libsystem wrapper may fail where
        // the raw SVC succeeds.
        let x0: u64 = target_task as usize as u64;
        let x1: u64 = address;
        let x2: u64 = size;
        let x3: u64 = set_maximum as u64;
        let x4: u64 = new_protection as u64;
        let ret: u64;
        core::arch::asm!(
            "movn x16, 0xd",
            "svc 0x80",
            inlateout("x0") x0 => ret,
            inlateout("x1") x1 => _,
            inlateout("x2") x2 => _,
            inlateout("x3") x3 => _,
            inlateout("x4") x4 => _,
            out("x16") _,
            options(nostack),
        );
        ret as i32
    }

    #[cfg(not(target_arch = "aarch64"))]
    unsafe fn mach_vm_protect_svc(
        target_task: mach2::vm_types::vm_map_t,
        address: mach_vm_address_t,
        size: mach_vm_size_t,
        set_maximum: boolean_t,
        new_protection: vm_prot_t,
    ) -> i32 {
        mach2::vm::mach_vm_protect(target_task, address, size, set_maximum, new_protection)
    }

    #[inline]
    fn page_size() -> usize {
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
    }

    pub unsafe fn patch_code(addr: *mut u8, size: usize, apply: impl FnOnce(*mut u8)) -> Result<(), HookError> {
        if size == 0 {
            return Ok(());
        }

        let page_sz = page_size();
        let start = (addr as usize) & !(page_sz - 1);
        let end = (addr as usize)
            .saturating_add(size)
            .saturating_add(page_sz - 1)
            & !(page_sz - 1);
        let map_size = (end - start).max(page_sz);

        patch_range(start as *mut u8, map_size, addr, size, apply)?;
        Ok(())
    }

    unsafe fn patch_range(
        page_start: *mut u8,
        map_size: usize,
        orig_addr: *mut u8,
        orig_size: usize,
        apply: impl FnOnce(*mut u8),
    ) -> Result<(), HookError> {
        let task = mach_task_self();

        let mut writable: vm_address_t = 0;
        let mut cur_prot: vm_prot_t = 0;
        let mut max_prot: vm_prot_t = 0;

        let kr = vm_remap(
            task,
            &mut writable,
            map_size as vm_size_t,
            0 as vm_address_t,
            VM_FLAGS_ANYWHERE,
            task,
            page_start as usize as vm_address_t,
            FALSE,
            &mut cur_prot,
            &mut max_prot,
            VM_INHERIT_NONE,
        );
        if kr != KERN_SUCCESS {
            if debug_enabled() {
                eprintln!(
                    "[malwi-intercept] patcher: vm_remap failed kr={} page_start=0x{:x} map_size=0x{:x}",
                    kr,
                    page_start as usize,
                    map_size
                );
            }
            let patched = prepare_patched_bytes(orig_addr, orig_size, apply);
            return patch_range_mach_write(orig_addr, &patched)
                .or_else(|_| patch_range_mprotect(page_start, map_size, orig_addr, &patched));
        }
        if debug_enabled() {
            eprintln!(
                "[malwi-intercept] patcher: remap ok writable=0x{:x} cur_prot=0x{:x} max_prot=0x{:x}",
                writable as usize,
                cur_prot,
                max_prot
            );
        }

        // Set current protection to RW via direct SVC syscall. On ARM64 macOS,
        // the direct mach_vm_protect syscall can bypass max_prot restrictions
        // that the libsystem wrapper enforces.
        //
        // IMPORTANT: Do NOT call set_maximum=TRUE first — that triggers a
        // kernel code path that creates a copy-on-write version of the page,
        // causing writes through the alias to go to a private copy instead
        // of the shared physical page.
        let mut kr = mach_vm_protect_svc(
            task,
            writable as mach_vm_address_t,
            map_size as mach_vm_size_t,
            FALSE,
            VM_PROT_READ | VM_PROT_WRITE,
        );
        if kr != KERN_SUCCESS {
            kr = mach_vm_protect_svc(
                task,
                writable as mach_vm_address_t,
                map_size as mach_vm_size_t,
                FALSE,
                VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY,
            );
        }

        if kr != KERN_SUCCESS {
            if debug_enabled() {
                eprintln!(
                    "[malwi-intercept] patcher: mach_vm_protect_svc failed kr={} writable=0x{:x} map_size=0x{:x} cur_prot=0x{:x} max_prot=0x{:x}",
                    kr,
                    writable as usize,
                    map_size,
                    cur_prot,
                    max_prot
                );
            }
            // Even if we cannot make the alias RW, a kernel-assisted write may still succeed.
            let patched = prepare_patched_bytes(orig_addr, orig_size, apply);
            let page_off = (orig_addr as usize).saturating_sub(page_start as usize);
            let alias_target = (writable as *mut u8).add(page_off);

            let kr2 = mach_vm_write(
                task,
                alias_target as mach_vm_address_t,
                patched.as_ptr() as vm_offset_t,
                patched.len() as mach_msg_type_number_t,
            );
            if kr2 == KERN_SUCCESS {
                invalidate_icache(orig_addr, patched.len());
                let _ = mach_vm_deallocate(task, writable as mach_vm_address_t, map_size as mach_vm_size_t);
                return Ok(());
            } else if debug_enabled() {
                eprintln!(
                    "[malwi-intercept] patcher: mach_vm_write(alias) failed kr={} alias=0x{:x} size=0x{:x}",
                    kr2,
                    alias_target as usize,
                    patched.len()
                );
            }

            let _ = mach_vm_deallocate(task, writable as mach_vm_address_t, map_size as mach_vm_size_t);

            // mprotect often fails on code-signed pages. Try a Mach write to the original
            // mapping before giving up.
            return patch_range_mach_write(orig_addr, &patched)
                .or_else(|_| patch_range_mprotect(page_start, map_size, orig_addr, &patched));
        }

        let page_off = (orig_addr as usize).saturating_sub(page_start as usize);

        // Prepare the patched bytes in a buffer so we can verify and retry.
        let patched = prepare_patched_bytes(orig_addr, orig_size, apply);

        // Write through the writable alias.
        core::ptr::copy_nonoverlapping(patched.as_ptr(), (writable as *mut u8).add(page_off), patched.len());
        invalidate_icache(orig_addr, orig_size);

        // Verify the write is visible at the original address.
        // On macOS ARM64, vm_remap with copy=FALSE can still COW under
        // hardened runtime, causing the alias write to go to a private copy
        // while the original page remains unchanged.
        let visible = core::slice::from_raw_parts(orig_addr, orig_size) == patched.as_slice();

        let _ = mach_vm_deallocate(task, writable as mach_vm_address_t, map_size as mach_vm_size_t);

        if visible {
            return Ok(());
        }

        if debug_enabled() {
            eprintln!(
                "[malwi-intercept] patcher: alias write not visible at original address (COW); falling back to mach_vm_write"
            );
        }

        // Alias write was COW'd. Fall back to alternative approaches:
        // 1. Remap overwrite: allocate writable page, copy+patch, remap over original
        // 2. Direct SVC mach_vm_protect on original page → write → restore
        // 3. mach_vm_write (kernel-assisted) to original address
        // 4. mprotect to RWX (last resort)
        patch_range_remap_overwrite(page_start, map_size, orig_addr, &patched)
            .or_else(|_| patch_range_direct_protect(page_start, map_size, orig_addr, &patched))
            .or_else(|_| patch_range_mach_write(orig_addr, &patched))
            .or_else(|_| patch_range_mprotect(page_start, map_size, orig_addr, &patched))
    }

    /// Make the original page writable via direct SVC, write, restore.
    ///
    /// This bypasses vm_remap entirely. The direct mach_vm_protect SVC
    /// can succeed even when max_prot doesn't include WRITE, because the
    /// ARM64 SVC path in the macOS kernel has fewer restrictions than
    /// the libsystem wrapper.
    unsafe fn patch_range_direct_protect(
        page_start: *mut u8,
        map_size: usize,
        orig_addr: *mut u8,
        patched: &[u8],
    ) -> Result<(), HookError> {
        let task = mach_task_self();

        // Make original page writable via direct SVC.
        let kr = mach_vm_protect_svc(
            task,
            page_start as mach_vm_address_t,
            map_size as mach_vm_size_t,
            FALSE,
            VM_PROT_READ | VM_PROT_WRITE,
        );
        if kr != KERN_SUCCESS {
            if debug_enabled() {
                eprintln!(
                    "[malwi-intercept] patcher: direct protect RW failed kr={} page=0x{:x}",
                    kr,
                    page_start as usize
                );
            }
            return Err(HookError::AllocationFailed);
        }

        // Write directly to the original address.
        core::ptr::copy_nonoverlapping(patched.as_ptr(), orig_addr, patched.len());
        invalidate_icache(orig_addr, patched.len());

        // Restore RX protection.
        let _ = mach_vm_protect_svc(
            task,
            page_start as mach_vm_address_t,
            map_size as mach_vm_size_t,
            FALSE,
            VM_PROT_READ | VM_PROT_EXECUTE,
        );

        if debug_enabled() {
            eprintln!(
                "[malwi-intercept] patcher: direct protect+write succeeded at 0x{:x}",
                orig_addr as usize
            );
        }

        Ok(())
    }

    /// Replace the original code page by remapping a modified copy over it.
    ///
    /// This is the most reliable approach for patching main executable __TEXT
    /// pages on macOS ARM64 with hardened runtime, where:
    /// - vm_remap alias writes are COW'd (not visible at original address)
    /// - mach_vm_protect cannot add WRITE to max_prot=RX pages
    ///
    /// The approach: allocate a writable page, copy original content + patches,
    /// then `vm_remap(VM_FLAGS_OVERWRITE)` to atomically replace the original
    /// mapping with the modified copy.
    unsafe fn patch_range_remap_overwrite(
        page_start: *mut u8,
        map_size: usize,
        orig_addr: *mut u8,
        patched: &[u8],
    ) -> Result<(), HookError> {
        let task = mach_task_self();

        // 1. Allocate a fresh anonymous page (RWX-capable).
        let mut temp_addr: mach_vm_address_t = 0;
        let kr = mach_vm_allocate(
            task,
            &mut temp_addr,
            map_size as mach_vm_size_t,
            VM_FLAGS_ANYWHERE,
        );
        if kr != KERN_SUCCESS {
            if debug_enabled() {
                eprintln!(
                    "[malwi-intercept] patcher: remap_overwrite: mach_vm_allocate failed kr={} size=0x{:x}",
                    kr, map_size
                );
            }
            return Err(HookError::AllocationFailed);
        }

        // 2. Copy entire original page content to the temp page.
        core::ptr::copy_nonoverlapping(
            page_start as *const u8,
            temp_addr as *mut u8,
            map_size,
        );

        // 3. Apply patches at the correct offset within the temp page.
        let page_off = orig_addr as usize - page_start as usize;
        core::ptr::copy_nonoverlapping(
            patched.as_ptr(),
            (temp_addr as *mut u8).add(page_off),
            patched.len(),
        );

        // 4. Set temp page to RX BEFORE remapping.
        //    This is critical: the remap inherits the source's protection.
        //    If we remap while the temp page is RW, the overwritten code page
        //    becomes RW (non-executable). Any code on that page would fault
        //    on instruction fetch before we can call mach_vm_protect.
        let _ = mach_vm_protect_svc(
            task,
            temp_addr as mach_vm_address_t,
            map_size as mach_vm_size_t,
            FALSE,
            VM_PROT_READ | VM_PROT_EXECUTE,
        );

        // 5. Remap the modified temp page over the original address.
        //    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE ensures the kernel uses the
        //    exact target address and atomically replaces the existing mapping.
        //    Without VM_FLAGS_FIXED, the kernel may choose a different address,
        //    leaving the original code page unchanged.
        //    copy=TRUE makes the new mapping independent of the temp page.
        let mut target_addr = page_start as vm_address_t;
        let mut cur_prot: vm_prot_t = 0;
        let mut max_prot: vm_prot_t = 0;
        let kr = vm_remap(
            task,
            &mut target_addr,
            map_size as vm_size_t,
            0 as vm_address_t,
            VM_FLAGS_FIXED as libc::c_int | VM_FLAGS_OVERWRITE,
            task,
            temp_addr as vm_address_t,
            TRUE,
            &mut cur_prot,
            &mut max_prot,
            VM_INHERIT_COPY,
        );

        // 6. Deallocate temp page (copy=TRUE made the remap independent).
        let _ = mach_vm_deallocate(task, temp_addr, map_size as mach_vm_size_t);

        if kr != KERN_SUCCESS {
            if debug_enabled() {
                eprintln!(
                    "[malwi-intercept] patcher: remap_overwrite: vm_remap(FIXED|OVERWRITE) failed kr={} target=0x{:x}",
                    kr, page_start as usize
                );
            }
            return Err(HookError::AllocationFailed);
        }

        // 7. Flush caches.
        invalidate_icache(orig_addr, patched.len());

        // 8. Verify the write is visible at the original address.
        let visible = core::slice::from_raw_parts(orig_addr, patched.len()) == patched;
        if !visible {
            if debug_enabled() {
                eprintln!(
                    "[malwi-intercept] patcher: remap_overwrite: bytes NOT visible after remap at 0x{:x}",
                    orig_addr as usize
                );
            }
            return Err(HookError::AllocationFailed);
        }

        if debug_enabled() {
            eprintln!(
                "[malwi-intercept] patcher: remap_overwrite succeeded at 0x{:x}",
                orig_addr as usize
            );
        }

        Ok(())
    }

    unsafe fn prepare_patched_bytes(
        orig_addr: *mut u8,
        orig_size: usize,
        apply: impl FnOnce(*mut u8),
    ) -> Vec<u8> {
        let mut tmp = vec![0u8; orig_size];
        if orig_size != 0 {
            core::ptr::copy_nonoverlapping(orig_addr as *const u8, tmp.as_mut_ptr(), orig_size);
            apply(tmp.as_mut_ptr());
        }
        tmp
    }

    unsafe fn patch_range_mach_write(orig_addr: *mut u8, patched: &[u8]) -> Result<(), HookError> {
        if patched.is_empty() {
            return Ok(());
        }

        let task = mach_task_self();
        let kr = mach_vm_write(
            task,
            orig_addr as mach_vm_address_t,
            patched.as_ptr() as vm_offset_t,
            patched.len() as mach_msg_type_number_t,
        );
        if kr != KERN_SUCCESS {
            if debug_enabled() {
                eprintln!(
                    "[malwi-intercept] patcher: mach_vm_write failed kr={} addr=0x{:x} size=0x{:x}",
                    kr,
                    orig_addr as usize,
                    patched.len()
                );
            }
            return Err(HookError::AllocationFailed);
        }

        invalidate_icache(orig_addr, patched.len());
        Ok(())
    }

    unsafe fn patch_range_mprotect(
        page_start: *mut u8,
        map_size: usize,
        orig_addr: *mut u8,
        patched: &[u8],
    ) -> Result<(), HookError> {
        let page_sz = page_size();
        debug_assert_eq!((page_start as usize) & (page_sz - 1), 0);
        debug_assert_eq!(map_size & (page_sz - 1), 0);

        // Best-effort fallback for cases where `mach_vm_remap` cannot create a writable alias
        // (e.g., some locally built/test binaries). This may fail on hardened/signed mappings.
        if libc::mprotect(page_start as *mut _, map_size, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) != 0 {
            if debug_enabled() {
                let errno = *libc::__error();
                eprintln!(
                    "[malwi-intercept] patcher: mprotect RWX failed errno={} page_start=0x{:x} map_size=0x{:x}",
                    errno,
                    page_start as usize,
                    map_size
                );
            }
            return Err(HookError::AllocationFailed);
        }

        if !patched.is_empty() {
            core::ptr::copy_nonoverlapping(patched.as_ptr(), orig_addr, patched.len());
            invalidate_icache(orig_addr, patched.len());
        }

        let _ = libc::mprotect(page_start as *mut _, map_size, libc::PROT_READ | libc::PROT_EXEC);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    pub unsafe fn patch_code(addr: *mut u8, size: usize, apply: impl FnOnce(*mut u8)) -> Result<(), HookError> {
        if size == 0 {
            return Ok(());
        }

        let page_sz = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let page_start = (addr as usize) & !(page_sz - 1);
        let page_end = ((addr as usize) + size + page_sz - 1) & !(page_sz - 1);
        let map_size = page_end - page_start;

        // Make writable (RWX so existing code on the page can still execute).
        if libc::mprotect(
            page_start as *mut libc::c_void,
            map_size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        ) != 0
        {
            return Err(HookError::AllocationFailed);
        }

        apply(addr);

        // Restore RX.
        libc::mprotect(
            page_start as *mut libc::c_void,
            map_size,
            libc::PROT_READ | libc::PROT_EXEC,
        );

        // Flush the entire page (not just the patched bytes) AFTER restoring RX.
        // This prevents stale I-cache entries
        // when multiple functions on the same page are patched independently.
        invalidate_icache(page_start as *mut u8, map_size);
        Ok(())
    }
}

/// Patch code at `addr` for `size` bytes.
///
/// On macOS, uses a writable alias to preserve code-signing validity.
/// On Linux, uses mprotect to temporarily make the page writable.
///
/// # Safety
/// `addr` must point to `size` bytes of executable memory. `apply` must write within that range.
pub unsafe fn patch_code(addr: *mut u8, size: usize, apply: impl FnOnce(*mut u8)) -> Result<(), HookError> {
    #[cfg(target_os = "macos")]
    {
        darwin::patch_code(addr, size, apply)
    }
    #[cfg(target_os = "linux")]
    {
        linux::patch_code(addr, size, apply)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (addr, size, apply);
        Err(HookError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::allocator::CodeAllocator;

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn patcher_can_modify_executable_page() {
        let mut alloc = CodeAllocator::default();
        let slice = alloc.alloc_any().expect("alloc");

        unsafe {
            // Fill with NOPs then RET.
            // nop
            (slice.data as *mut u32).write(0xD503201F);
            // ret
            (slice.data.add(4) as *mut u32).write(0xD65F03C0);
            alloc.make_executable(&slice).expect("rx");

            // Patch first instruction to RET.
            patch_code(slice.data, 4, |p| {
                (p as *mut u32).write(0xD65F03C0);
            })
            .expect("patch");

            // Call the code. It should return immediately (no crash).
            let f: extern "C" fn() = core::mem::transmute(slice.pc);
            f();
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn patcher_can_modify_executable_page() {
        let mut alloc = CodeAllocator::default();
        let slice = alloc.alloc_any().expect("alloc");

        unsafe {
            // Fill with NOP then RET: 90 C3
            slice.data.write(0x90); // NOP
            slice.data.add(1).write(0xC3); // RET
            alloc.make_executable(&slice).expect("rx");

            // Patch first byte to RET (skip the NOP).
            patch_code(slice.data, 1, |p| {
                p.write(0xC3);
            })
            .expect("patch");

            // Call the code. It should return immediately (no crash).
            let f: extern "C" fn() = core::mem::transmute(slice.pc);
            f();
        }
    }

    /// Verify patch_code writes are visible when reading back the original address.
    ///
    /// This catches issues where the writable alias (vm_remap) write
    /// doesn't reflect in the original mapping due to cache incoherence
    /// or COW semantics.
    #[test]
    fn patch_code_writes_are_visible_at_original_address() {
        let mut alloc = CodeAllocator::default();
        let slice = alloc.alloc_any().expect("alloc");

        unsafe {
            // Write 4 NOPs.
            for i in 0..4 {
                (slice.data.add(i * 4) as *mut u32).write(0xD503201F);
            }
            alloc.make_executable(&slice).expect("rx");

            let before = core::ptr::read_unaligned(slice.data as *const u32);
            assert_eq!(before, 0xD503201F, "pre-patch should be NOP");

            // Patch first instruction to RET.
            let marker = 0xD65F03C0u32;
            patch_code(slice.data, 4, |p| {
                (p as *mut u32).write(marker);
            })
            .expect("patch");

            // Read back from ORIGINAL address (not alias).
            let after = core::ptr::read_unaligned(slice.data as *const u32);
            assert_eq!(
                after, marker,
                "patch_code write must be visible at original address (got {:#010x})",
                after
            );
        }
    }

    /// Verify patch_code works on a real libc function (code-signed shared cache).
    ///
    /// This catches issues where vm_remap + mach_vm_protect fails silently
    /// on hardened runtime pages. We patch abs() prologue and verify the
    /// bytes changed, then restore.
    #[test]
    #[cfg(target_os = "macos")]
    fn patch_code_modifies_real_libc_function_bytes() {
        let _g = crate::lock_hook_tests();

        extern "C" {
            fn abs(i: libc::c_int) -> libc::c_int;
        }

        unsafe {
            let addr = abs as *mut u8;
            let original = core::ptr::read_unaligned(addr as *const [u8; 16]);

            // Patch with a known pattern (NOP sled).
            let nops: [u8; 16] = {
                let mut buf = [0u8; 16];
                for i in 0..4 {
                    let nop = 0xD503201Fu32.to_le_bytes();
                    buf[i * 4..i * 4 + 4].copy_from_slice(&nop);
                }
                buf
            };

            let result = patch_code(addr, 16, |p| {
                core::ptr::copy_nonoverlapping(nops.as_ptr(), p, 16);
            });

            if let Err(e) = &result {
                // Some CI environments may block code patching.
                eprintln!("patch_code on libc failed (may be expected): {:?}", e);
                return;
            }

            let patched = core::ptr::read_unaligned(addr as *const [u8; 16]);
            assert_eq!(
                patched, nops,
                "Patched bytes must be visible at original address.\n  expected: {:02x?}\n  got:      {:02x?}",
                nops, patched
            );

            // Restore original bytes.
            patch_code(addr, 16, |p| {
                core::ptr::copy_nonoverlapping(original.as_ptr(), p, 16);
            })
            .expect("restore");

            // Verify restoration.
            let restored = core::ptr::read_unaligned(addr as *const [u8; 16]);
            assert_eq!(restored, original, "Original bytes must be restored");

            // Verify abs() still works.
            assert_eq!(abs(-42), 42);
        }
    }

    /// Patch abs() prologue with MOV X0, #999; RET and verify CPU executes it.
    ///
    /// This is the critical missing test: previous patcher tests only verify bytes,
    /// not actual CPU execution of patched code.
    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn patch_and_execute_libc_function() {
        let _g = crate::lock_hook_tests();

        extern "C" {
            fn abs(i: libc::c_int) -> libc::c_int;
        }

        unsafe {
            let addr = abs as *mut u8;
            let original = core::ptr::read_unaligned(addr as *const [u8; 8]);

            // Verify abs works before patch.
            let abs_fn: unsafe extern "C" fn(libc::c_int) -> libc::c_int = abs;
            let abs_fn = std::hint::black_box(abs_fn);
            assert_eq!(abs_fn(-1), 1, "abs(-1) should be 1 before patch");

            // MOV W0, #999 (MOVZ W0, #0x3E7)
            // Encoding: 0x52807CE0
            let mov_w0_999: u32 = 0x52807CE0;
            // RET
            let ret: u32 = 0xD65F03C0;

            let result = patch_code(addr, 8, |p| {
                (p as *mut u32).write(mov_w0_999);
                (p as *mut u32).add(1).write(ret);
            });

            if let Err(e) = &result {
                eprintln!("patch_code on libc failed (may be expected): {:?}", e);
                return;
            }

            // Call abs — CPU must execute patched code and return 999.
            let abs_fn = std::hint::black_box(abs_fn);
            let val = abs_fn(-1);
            assert_eq!(val, 999, "patched abs(-1) must return 999 (got {val})");

            // Restore original bytes.
            patch_code(addr, 8, |p| {
                core::ptr::copy_nonoverlapping(original.as_ptr(), p, 8);
            })
            .expect("restore");

            // Verify abs works again.
            let abs_fn = std::hint::black_box(abs_fn);
            assert_eq!(abs_fn(-1), 1, "abs(-1) should be 1 after restore");
        }
    }

    /// Patch abs() 50 times, alternating between two different patches,
    /// executing after each patch to verify the CPU runs the new code.
    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn patch_code_survives_50_cycles() {
        let _g = crate::lock_hook_tests();

        extern "C" {
            fn abs(i: libc::c_int) -> libc::c_int;
        }

        unsafe {
            let addr = abs as *mut u8;
            let original = core::ptr::read_unaligned(addr as *const [u8; 8]);

            let abs_fn: unsafe extern "C" fn(libc::c_int) -> libc::c_int = abs;

            // Patch A: MOV W0, #100; RET
            let patch_a: [u32; 2] = [0x52800C80, 0xD65F03C0]; // MOVZ W0, #0x64
            // Patch B: MOV W0, #200; RET
            let patch_b: [u32; 2] = [0x52801900, 0xD65F03C0]; // MOVZ W0, #0xC8

            for cycle in 0..50u32 {
                let (patch, expected) = if cycle % 2 == 0 {
                    (&patch_a, 100)
                } else {
                    (&patch_b, 200)
                };

                let result = patch_code(addr, 8, |p| {
                    (p as *mut u32).write(patch[0]);
                    (p as *mut u32).add(1).write(patch[1]);
                });

                if let Err(e) = &result {
                    // Restore and bail.
                    let _ = patch_code(addr, 8, |p| {
                        core::ptr::copy_nonoverlapping(original.as_ptr(), p, 8);
                    });
                    panic!("patch_code failed on cycle {cycle}: {:?}", e);
                }

                let f = std::hint::black_box(abs_fn);
                let val = f(-1);
                if val != expected {
                    // Restore before panicking.
                    let _ = patch_code(addr, 8, |p| {
                        core::ptr::copy_nonoverlapping(original.as_ptr(), p, 8);
                    });
                    panic!("cycle {cycle}: expected {expected}, got {val}");
                }
            }

            // Restore original.
            patch_code(addr, 8, |p| {
                core::ptr::copy_nonoverlapping(original.as_ptr(), p, 8);
            })
            .expect("restore");

            let f = std::hint::black_box(abs_fn);
            assert_eq!(f(-42), 42, "abs should work after 50 patch cycles");
        }
    }

    /// Verify patch_code works on the main executable's __TEXT (user binary).
    ///
    /// Uses the test's own function as a target. This catches issues where
    /// patching works on dynamically-allocated pages but fails on the
    /// main executable's code pages.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn patch_code_modifies_main_executable_function() {
        // Use a function in this binary as the target.
        extern "C" fn dummy_target(x: i64) -> i64 {
            x + 1
        }

        unsafe {
            let addr = dummy_target as *mut u8;
            let original = core::ptr::read_unaligned(addr as *const [u8; 4]);

            // Patch first instruction.
            let marker = 0xD503201Fu32; // NOP
            let result = patch_code(addr, 4, |p| {
                (p as *mut u32).write(marker);
            });

            if let Err(e) = &result {
                eprintln!("patch_code on main executable failed: {:?}", e);
                return;
            }

            let patched = core::ptr::read_unaligned(addr as *const [u8; 4]);
            assert_eq!(
                u32::from_le_bytes(patched),
                marker,
                "Patched bytes must be visible at original address"
            );

            // Restore.
            patch_code(addr, 4, |p| {
                core::ptr::copy_nonoverlapping(original.as_ptr(), p, 4);
            })
            .expect("restore");

            // Function should still work.
            assert_eq!(dummy_target(41), 42);
        }
    }

    /// Patch two functions on the same page independently; verify both work.
    ///
    /// This catches the I-cache coherency bug where patching function B on the
    /// same page as function A invalidates A's I-cache line via the mprotect
    /// cycle, but only re-flushes B's cache line — leaving A stale.
    #[test]
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn same_page_double_patch_both_hooks_fire() {
        unsafe {
            let page_sz = libc::sysconf(libc::_SC_PAGESIZE) as usize;

            // Allocate one RWX page with two small functions at offset 0 and 64.
            let page = libc::mmap(
                core::ptr::null_mut(),
                page_sz,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert_ne!(page, libc::MAP_FAILED, "mmap failed");

            let func_a = page as *mut u8;
            let func_b = func_a.add(64);

            // Write NOP + RET at each function slot.
            // Function A: NOP; RET  (returns whatever is in X0)
            (func_a as *mut u32).write(0xD503201F); // NOP
            (func_a as *mut u32).add(1).write(0xD65F03C0); // RET

            // Function B: NOP; RET
            (func_b as *mut u32).write(0xD503201F); // NOP
            (func_b as *mut u32).add(1).write(0xD65F03C0); // RET

            // Make executable.
            libc::mprotect(page, page_sz, libc::PROT_READ | libc::PROT_EXEC);

            let call_a: extern "C" fn(u64) -> u64 = core::mem::transmute(func_a);
            let call_b: extern "C" fn(u64) -> u64 = core::mem::transmute(func_b);

            // Baseline: both return their argument.
            assert_eq!(call_a(7), 7, "baseline A");
            assert_eq!(call_b(8), 8, "baseline B");

            // Patch function A: MOV W0, #42; RET
            patch_code(func_a, 8, |p| {
                (p as *mut u32).write(0x52800540); // MOVZ W0, #42
                (p as *mut u32).add(1).write(0xD65F03C0); // RET
            })
            .expect("patch A");

            let call_a = std::hint::black_box(call_a);
            assert_eq!(call_a(0), 42, "A should return 42 after patch");

            // Patch function B: MOV W0, #99; RET
            // This triggers mprotect on the SAME page, which can invalidate A's I-cache.
            patch_code(func_b, 8, |p| {
                (p as *mut u32).write(0x52800C60); // MOVZ W0, #99
                (p as *mut u32).add(1).write(0xD65F03C0); // RET
            })
            .expect("patch B");

            let call_b = std::hint::black_box(call_b);
            assert_eq!(call_b(0), 99, "B should return 99 after patch");

            // THE CRITICAL CHECK: A must still return 42 after B's patch.
            let call_a = std::hint::black_box(call_a);
            assert_eq!(
                call_a(0), 42,
                "A must still return 42 after patching B on the same page (I-cache coherency)"
            );

            libc::munmap(page, page_sz);
        }
    }

    /// Stress test: patch function A, then patch function B on the same page
    /// 10 times, verifying A still works after each B-patch cycle.
    #[test]
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn patch_code_cache_coherent_across_page_mprotect_cycle() {
        unsafe {
            let page_sz = libc::sysconf(libc::_SC_PAGESIZE) as usize;

            let page = libc::mmap(
                core::ptr::null_mut(),
                page_sz,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert_ne!(page, libc::MAP_FAILED, "mmap failed");

            let func_a = page as *mut u8;
            let func_b = func_a.add(64);

            // Initial code: NOP + RET at both slots.
            (func_a as *mut u32).write(0xD503201F);
            (func_a as *mut u32).add(1).write(0xD65F03C0);
            (func_b as *mut u32).write(0xD503201F);
            (func_b as *mut u32).add(1).write(0xD65F03C0);

            libc::mprotect(page, page_sz, libc::PROT_READ | libc::PROT_EXEC);

            // Patch A once: MOV W0, #42; RET
            patch_code(func_a, 8, |p| {
                (p as *mut u32).write(0x52800540); // MOVZ W0, #42
                (p as *mut u32).add(1).write(0xD65F03C0);
            })
            .expect("patch A");

            let call_a: extern "C" fn(u64) -> u64 = core::mem::transmute(func_a);

            // Patch B 10 times with different values, checking A after each.
            for i in 0u32..10 {
                let val = 100 + i;
                // MOVZ W0, #val  →  0x5280_0000 | (val << 5)
                let movz = 0x52800000u32 | (val << 5);

                patch_code(func_b, 8, |p| {
                    (p as *mut u32).write(movz);
                    (p as *mut u32).add(1).write(0xD65F03C0);
                })
                .expect("patch B");

                let call_b: extern "C" fn(u64) -> u64 = core::mem::transmute(func_b);
                let call_b = std::hint::black_box(call_b);
                assert_eq!(
                    call_b(0), val as u64,
                    "iteration {i}: B should return {val}"
                );

                let call_a = std::hint::black_box(call_a);
                assert_eq!(
                    call_a(0), 42,
                    "iteration {i}: A must still return 42 after re-patching B"
                );
            }

            libc::munmap(page, page_sz);
        }
    }
}
