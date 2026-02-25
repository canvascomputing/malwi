/// Query whether the current process uses pointer-authentication for
/// **indirect branches** (BRAAZ/BLRAAZ). This controls whether the
/// Interceptor emits PAC-aware trampolines.
///
/// On macOS ARM64, checks dyld's `notification` pointer for PAC bits
/// (arm64e ABI). On Linux, indirect branches are never authenticated —
/// only return addresses are signed — so this always returns false.
///
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
///
/// Note: on Linux arm64, function pointers are NOT PAC-signed (only return
/// addresses on the stack are). Use [`strip_return_address_pac`] for
/// backtrace return addresses.
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

/// Strip PAC from a **return address** captured during stack unwinding.
///
/// On arm64 Linux with FEAT_PAuth (HWCAP_PACA), the kernel enables PAC and
/// function prologues sign LR with PACIASP. Return addresses read from the
/// stack carry PAC bits that must be stripped before symbol resolution.
///
/// On arm64 macOS (arm64e), delegates to [`strip_code_ptr`] (XPACI).
/// No-op on all other platforms and when PAC is not available.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[inline]
pub(crate) fn strip_return_address_pac(addr: usize) -> usize {
    if !has_pac_return_addresses() {
        return addr;
    }
    let mut x = addr as u64;
    unsafe {
        // XPACI X16 — strip PAC from instruction pointer.
        // Encoded as raw .inst because the assembler may not accept PAC
        // mnemonics on the default aarch64-unknown-linux-gnu target.
        // XPACI encoding: 0xDAC143E0 | Rd; Rd=16 → 0xDAC143F0.
        core::arch::asm!(
            ".inst 0xDAC143F0",
            inout("x16") x,
            options(nostack, preserves_flags)
        );
    }
    x as usize
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
#[inline]
pub(crate) fn strip_return_address_pac(addr: usize) -> usize {
    strip_code_ptr(addr)
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub(crate) fn strip_return_address_pac(addr: usize) -> usize {
    addr
}

/// Check if return addresses on the stack carry PAC signature bits.
///
/// On Linux arm64, queries HWCAP_PACA. On macOS, defers to
/// [`query_ptrauth_support`] (arm64e detection). The result is cached.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn has_pac_return_addresses() -> bool {
    use std::sync::OnceLock;
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| {
        // HWCAP_PACA (bit 30) indicates the CPU supports pointer
        // authentication with the A key. When set, the kernel enables PAC
        // for userspace and return addresses carry PAC signature bits.
        const HWCAP_PACA: u64 = 1 << 30;
        let hwcap = unsafe { libc::getauxval(libc::AT_HWCAP) };
        hwcap & HWCAP_PACA != 0
    })
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
