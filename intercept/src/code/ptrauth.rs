/// Query whether the current process uses pointer authentication.
///
/// On macOS ARM64, checks dyld's `notification` pointer for PAC bits.
/// The result is cached for the lifetime of the process.
pub fn query_ptrauth_support() -> bool {
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        use std::sync::OnceLock;
        static CACHED: OnceLock<bool> = OnceLock::new();
        *CACHED.get_or_init(detect_ptrauth_macos)
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
    {
        false
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
fn detect_ptrauth_macos() -> bool {
    // _dyld_get_all_image_infos is a private symbol; look it up via dlsym
    // to avoid link-time dependency on a deprecated/unexported function.
    // Its `notification` field (offset 16) is a function pointer that carries
    // PAC bits when the process runs under arm64e.
    unsafe {
        let handle = libc::dlsym(
            libc::RTLD_DEFAULT,
            b"_dyld_get_all_image_infos\0".as_ptr().cast(),
        );
        if handle.is_null() {
            return false;
        }

        let func: unsafe extern "C" fn() -> *const u8 = core::mem::transmute(handle);
        let infos = func();
        if infos.is_null() {
            return false;
        }

        // notification is at offset 16 in dyld_all_image_infos
        // (after version u32 + infoArrayCount u32 + infoArray ptr).
        let notification_ptr = infos.add(16) as *const usize;
        let raw = notification_ptr.read();

        if raw == 0 {
            return false;
        }

        let stripped = strip_code_ptr(raw);
        raw != stripped
    }
}

/// Strip pointer authentication code from a code pointer.
///
/// On arm64 macOS, uses XPACI to remove PAC bits. No-op on other platforms.
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
#[inline]
pub(crate) fn strip_code_ptr(ptr: usize) -> usize {
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

/// Sign a code pointer with the IA key (instruction address, discriminator=0).
///
/// On arm64e, indirect branches via BRAAZ/BLRAAZ authenticate with key A and
/// zero discriminator. Pointers stored in trampolines and contexts must be
/// signed to pass authentication.
///
/// No-op when ptrauth is false or on non-arm64 platforms.
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
#[inline]
pub(crate) fn sign_code_ptr(ptr: usize, ptrauth: bool) -> usize {
    if !ptrauth {
        return ptr;
    }
    let mut x = ptr as u64;
    unsafe {
        // PACIZA X16 — sign with IA key, zero discriminator.
        // Encoded as raw .inst (0xDAC123F0) because the assembler may not
        // accept PAC mnemonics on non-arm64e targets.
        // PACIZA encoding: 0xDAC123E0 | Rd; Rd=16 → 0xDAC123F0.
        core::arch::asm!(
            ".inst 0xDAC123F0",
            inout("x16") x,
            options(nostack, preserves_flags)
        );
    }
    x as usize
}

#[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
#[inline]
pub(crate) fn sign_code_ptr(ptr: usize, _ptrauth: bool) -> usize {
    ptr
}
