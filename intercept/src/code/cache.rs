#[cfg(target_os = "macos")]
extern "C" {
    fn sys_icache_invalidate(addr: *mut core::ffi::c_void, size: usize);
    fn sys_dcache_flush(addr: *mut core::ffi::c_void, size: usize);
}

/// Flush data cache and invalidate instruction cache for a code region.
///
/// On ARM64, the data and instruction caches are not coherent. After
/// writing new instructions through the data cache, we must:
/// 1. Flush the data cache to ensure writes reach main memory
/// 2. Invalidate the instruction cache to discard stale entries
///
/// Calls both `sys_dcache_flush()` and `sys_icache_invalidate()`.
///
/// # Safety
/// `addr` must point to at least `size` bytes of memory.
#[inline]
pub unsafe fn invalidate_icache(addr: *mut u8, size: usize) {
    #[cfg(target_os = "macos")]
    {
        sys_dcache_flush(addr as *mut core::ffi::c_void, size);
        sys_icache_invalidate(addr as *mut core::ffi::c_void, size);
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        extern "C" {
            fn __clear_cache(beg: *mut libc::c_void, end: *mut libc::c_void);
        }
        __clear_cache(addr as *mut libc::c_void, addr.add(size) as *mut libc::c_void);
    }

    // x86_64 has coherent I-cache, no flush needed.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let _ = (addr, size);
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (addr, size);
    }
}

