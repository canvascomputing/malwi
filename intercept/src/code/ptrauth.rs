#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
#[inline]
pub(crate) fn strip_code_ptr(ptr: usize) -> usize {
    // On arm64e, function pointers may be signed. Strip PAC bits so we can treat it as an address.
    let mut x = ptr as u64;
    unsafe {
        core::arch::asm!("xpaci {0}", inout(reg) x, options(nostack, preserves_flags));
    }
    x as usize
}

#[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
#[inline]
pub(crate) fn strip_code_ptr(ptr: usize) -> usize {
    ptr
}

