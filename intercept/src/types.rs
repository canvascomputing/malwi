use crate::ffi as gum;

// ── CPU context types ────────────────────────────────────────────
// Direct aliases to FFI-generated types.

#[cfg(target_arch = "aarch64")]
pub type Arm64CpuContext = gum::GumArm64CpuContext;

#[cfg(target_arch = "x86_64")]
pub type X86_64CpuContext = gum::GumX64CpuContext;

pub type CpuContext = gum::GumCpuContext;

// ── Invocation context ───────────────────────────────────────────
// Alias to FFI-generated invocation context type.

pub type InvocationContext = gum::GumInvocationContext;

// ── Error types ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookError {
    WrongSignature,
    AlreadyAttached,
    AllocationFailed,
    PolicyViolation,
    WrongType,
    Unsupported,
}

// ── Module types ─────────────────────────────────────────────────

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
