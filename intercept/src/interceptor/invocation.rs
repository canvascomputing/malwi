//! Invocation context accessors for intercepted function calls.

use crate::ffi as gum;
use crate::types::InvocationContext;
use core::ffi::c_void;

/// # Safety
/// `ctx` must be a valid pointer to an active `InvocationContext`.
pub unsafe fn get_nth_argument(ctx: *mut InvocationContext, n: u32) -> *mut c_void {
    gum::gum_invocation_context_get_nth_argument(ctx, n) as *mut c_void
}

/// # Safety
/// `ctx` must be a valid pointer to an active `InvocationContext`.
pub unsafe fn replace_nth_argument(ctx: *mut InvocationContext, n: u32, value: *mut c_void) {
    gum::gum_invocation_context_replace_nth_argument(ctx, n, value as gum::gpointer);
}

/// # Safety
/// `ctx` must be a valid pointer to an active `InvocationContext`.
pub unsafe fn get_return_value(ctx: *mut InvocationContext) -> *mut c_void {
    gum::gum_invocation_context_get_return_value(ctx) as *mut c_void
}

/// # Safety
/// `ctx` must be a valid pointer to an active `InvocationContext`.
pub unsafe fn replace_return_value(ctx: *mut InvocationContext, value: *mut c_void) {
    gum::gum_invocation_context_replace_return_value(ctx, value as gum::gpointer);
}
