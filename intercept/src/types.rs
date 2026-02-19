use core::ffi::c_void;

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Arm64CpuContext {
    pub pc: u64,
    pub sp: u64,
    pub nzcv: u64,
    pub x: [u64; 29],  // x0-x28
    pub fp: u64,       // x29
    pub lr: u64,       // x30
    pub v: [u128; 32], // q0-q31
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct X86_64CpuContext {
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

/// Invocation context passed to listeners.
///
/// This is intentionally minimal today; more accessors are added during the interceptor phases.
#[repr(C)]
#[derive(Debug)]
pub struct InvocationContext {
    pub function: *mut c_void,
    #[cfg(target_arch = "aarch64")]
    pub cpu_context: *mut Arm64CpuContext,
    #[cfg(target_arch = "x86_64")]
    pub cpu_context: *mut X86_64CpuContext,
    /// When set to true in on_enter, the original function is skipped and
    /// the value from replace_return_value is returned directly.
    pub skip_original: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointCut {
    Enter,
    Leave,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookError {
    WrongSignature,
    AlreadyAttached,
    PolicyViolation,
    WrongType,
    AllocationFailed,
    RelocationFailed,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleInfo {
    pub name: String,
    pub path: String,
    pub base_address: usize,
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportInfo {
    pub name: String,
    pub address: usize,
}
