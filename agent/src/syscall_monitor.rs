//! Direct syscall detection (stub).
//!
//! Syscall detection is not yet implemented in malwi-hook.
//! This module provides a no-op stub so that policies with `syscalls:`
//! sections don't crash the agent. The monitor will be re-implemented
//! as a separate feature.

use log::warn;

/// Manages direct syscall detection (currently a no-op stub).
pub struct SyscallMonitor {
    _private: (),
}

unsafe impl Send for SyscallMonitor {}
unsafe impl Sync for SyscallMonitor {}

impl SyscallMonitor {
    /// Create a new SyscallMonitor.
    ///
    /// Currently returns immediately without scanning or patching.
    /// Logs a warning that syscall detection is not yet implemented.
    ///
    /// # Safety
    /// Must be called after malwi_intercept::init().
    pub unsafe fn new() -> Option<Self> {
        warn!("Direct syscall detection is not yet implemented; syscalls: policy section will have no effect");
        Some(SyscallMonitor { _private: () })
    }
}

// =============================================================================
// Module classification (kept for future re-implementation)
// =============================================================================

/// Check if a module path belongs to a system library.
#[cfg(test)]
fn is_system_library(path: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        path.starts_with("/usr/lib/")
            || path.starts_with("/System/")
            || path.contains("/dyld")
    }
    #[cfg(target_os = "linux")]
    {
        path.starts_with("/lib/")
            || path.starts_with("/lib64/")
            || path.starts_with("/usr/lib/")
            || path.starts_with("/usr/lib64/")
            || path.contains("linux-vdso")
            || path.contains("ld-linux")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = path;
        false
    }
}

// =============================================================================
// Sensitive syscall tables (kept for future re-implementation)
// =============================================================================

#[cfg(test)]
#[allow(dead_code)] // Used by platform-specific tests; kept for future re-implementation
fn sensitive_syscall_name(nr: u64) -> Option<&'static str> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        match nr {
            97 => Some("socket"),
            98 => Some("connect"),
            104 => Some("bind"),
            106 => Some("listen"),
            30 => Some("accept"),
            133 => Some("sendto"),
            29 => Some("recvfrom"),
            28 => Some("sendmsg"),
            27 => Some("recvmsg"),
            59 => Some("execve"),
            2 => Some("fork"),
            66 => Some("vfork"),
            5 => Some("open"),
            463 => Some("openat"),
            _ => None,
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        match nr {
            97 => Some("socket"),
            98 => Some("connect"),
            104 => Some("bind"),
            106 => Some("listen"),
            30 => Some("accept"),
            133 => Some("sendto"),
            29 => Some("recvfrom"),
            28 => Some("sendmsg"),
            27 => Some("recvmsg"),
            59 => Some("execve"),
            2 => Some("fork"),
            66 => Some("vfork"),
            5 => Some("open"),
            463 => Some("openat"),
            _ => None,
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        match nr {
            41 => Some("socket"),
            42 => Some("connect"),
            49 => Some("bind"),
            50 => Some("listen"),
            43 => Some("accept"),
            44 => Some("sendto"),
            45 => Some("recvfrom"),
            46 => Some("sendmsg"),
            47 => Some("recvmsg"),
            59 => Some("execve"),
            57 => Some("fork"),
            58 => Some("vfork"),
            56 => Some("clone"),
            2 => Some("open"),
            257 => Some("openat"),
            _ => None,
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        match nr {
            198 => Some("socket"),
            203 => Some("connect"),
            200 => Some("bind"),
            201 => Some("listen"),
            202 => Some("accept"),
            206 => Some("sendto"),
            207 => Some("recvfrom"),
            211 => Some("sendmsg"),
            212 => Some("recvmsg"),
            221 => Some("execve"),
            220 => Some("clone"),
            56 => Some("openat"),
            _ => None,
        }
    }

    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
    )))]
    {
        let _ = nr;
        None
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn test_is_system_library_macos() {
        assert!(is_system_library("/usr/lib/libSystem.B.dylib"));
        assert!(is_system_library(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
        ));
        assert!(is_system_library("/usr/lib/dyld"));
        assert!(!is_system_library("/Users/me/malware"));
        assert!(!is_system_library("/tmp/payload.dylib"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_is_system_library_linux() {
        assert!(is_system_library("/usr/lib/libc.so.6"));
        assert!(is_system_library("/lib/aarch64-linux-gnu/libpthread.so.0"));
        assert!(is_system_library("/usr/lib64/libstdc++.so.6"));
        assert!(is_system_library("linux-vdso.so.1"));
        assert!(is_system_library("/lib/ld-linux-aarch64.so.1"));
        assert!(!is_system_library("/home/user/malware"));
        assert!(!is_system_library("/tmp/payload.so"));
    }

    #[test]
    fn test_sensitive_syscall_name_returns_known() {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            assert_eq!(sensitive_syscall_name(97), Some("socket"));
            assert_eq!(sensitive_syscall_name(59), Some("execve"));
            assert_eq!(sensitive_syscall_name(999), None);
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            assert_eq!(sensitive_syscall_name(41), Some("socket"));
            assert_eq!(sensitive_syscall_name(59), Some("execve"));
            assert_eq!(sensitive_syscall_name(999), None);
        }
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        {
            assert_eq!(sensitive_syscall_name(198), Some("socket"));
            assert_eq!(sensitive_syscall_name(221), Some("execve"));
            assert_eq!(sensitive_syscall_name(999), None);
        }
    }
}
