//! Malwi-trace agent — thin cdylib wrapper.
//!
//! All agent logic lives in malwi-intercept; this crate exists only to
//! produce the `libmalwi_agent` shared library with platform-specific
//! constructor attributes that call `malwi_agent_init()` on load.

pub use malwi_intercept::*;

/// Constructor attribute for automatic initialization on library load (Linux).
#[cfg(all(target_os = "linux", not(test)))]
#[unsafe(link_section = ".init_array")]
#[used]
static INIT: extern "C" fn() = {
    extern "C" fn init() {
        malwi_agent_init();
    }
    init
};

/// Constructor attribute for automatic initialization on library load (macOS).
#[cfg(all(target_os = "macos", not(test)))]
#[unsafe(link_section = "__DATA,__mod_init_func")]
#[used]
static INIT: extern "C" fn() = {
    extern "C" fn init() {
        malwi_agent_init();
    }
    init
};
