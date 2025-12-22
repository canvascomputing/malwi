#[cfg(target_arch = "aarch64")]
mod arm64;

#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
pub use arm64::capture_backtrace;

#[cfg(target_arch = "x86_64")]
pub use x86_64::capture_backtrace;

