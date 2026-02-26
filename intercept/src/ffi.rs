#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(clippy::all)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// GLib functions that bindgen may not generate on all platforms.
// On Linux with embedded devkit, GLib symbols are prefixed with _frida_
#[cfg(target_os = "linux")]
extern "C" {
    #[link_name = "_frida_g_object_unref"]
    pub fn g_object_unref(object: gpointer);
    #[link_name = "_frida_g_object_ref"]
    pub fn g_object_ref(object: gpointer) -> gpointer;
}

/// Initialize the embedded interception runtime.
///
/// # Safety
/// Must be called before any other FFI functions.
/// Should only be called once.
pub unsafe fn init() {
    gum_init_embedded();
}

/// Deinitialize the embedded interception runtime.
///
/// # Safety
/// Must be called after all usage is complete.
/// Should only be called once.
pub unsafe fn deinit() {
    gum_deinit_embedded();
}
