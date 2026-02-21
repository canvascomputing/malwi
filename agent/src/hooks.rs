//! Hook management using malwi-hook Interceptor.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{anyhow, Result};
use core::ffi::c_void;
use log::{debug, info, warn};
use malwi_intercept::CallListener;
use malwi_intercept::InvocationContext;
use malwi_protocol::{Argument, HookConfig};

// Thread-local re-entrancy guard. Prevents infinite recursion when
// hooked functions (like `malloc`) are called from within the hook
// callback itself (e.g., by JSON serialization or HTTP operations).
thread_local! {
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

/// Suppress all hook callbacks on the current thread.
/// Call from agent-internal threads (flush, poll) to prevent amplification
/// loops when hooked functions like malloc are called during event delivery.
pub fn suppress_hooks_on_current_thread() {
    IN_HOOK.with(|h| h.set(true));
}

/// Set the re-entrancy guard on the current thread.
/// Used by the syscall monitor to prevent malloc hook recursion during arg formatting.
pub fn set_in_hook(val: bool) {
    IN_HOOK.with(|h| h.set(val));
}

/// Check if we are currently inside a hook callback on this thread.
/// Used by the syscall monitor to avoid re-entrancy.
pub fn is_in_hook() -> bool {
    IN_HOOK.with(|h| h.get())
}

/// RAII guard that suppresses hook callbacks for its lifetime.
/// Saves the current IN_HOOK state and sets it to true; restores on drop.
/// Nesting-safe: inner guards restore the previous (already-true) state.
pub struct HookSuppressGuard(bool);

impl HookSuppressGuard {
    pub fn new() -> Self {
        let was = is_in_hook();
        set_in_hook(true);
        Self(was)
    }
}

impl Drop for HookSuppressGuard {
    fn drop(&mut self) {
        set_in_hook(self.0);
    }
}

use crate::native;
use crate::native::format_native_arguments;

/// Check if a syscall number corresponds to a network-related syscall.
/// Used to filter the libc `syscall()` hook — only report/block network syscalls.
fn is_network_syscall(nr: usize) -> bool {
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        matches!(
            nr,
            198  // socket
            | 200 // bind
            | 201 // listen
            | 202 // accept
            | 203 // connect
            | 206 // sendto
            | 207 // recvfrom
            | 208 // sendmsg_x / setsockopt on some
            | 211 // sendmsg
            | 212 // recvmsg
            | 214 // getsockname
            | 215 // getpeername
            | 205 // getsockopt
            | 204 // setsockopt
        )
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        matches!(
            nr,
            41  // socket
            | 42  // connect
            | 43  // accept
            | 44  // sendto
            | 45  // recvfrom
            | 46  // sendmsg
            | 47  // recvmsg
            | 49  // bind
            | 50  // listen
            | 51  // getsockname
            | 52  // getpeername
            | 53  // socketpair — skip, needed for pipe-like IPC
            | 54  // setsockopt
            | 55 // getsockopt
        )
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        matches!(
            nr,
            97  // socket
            | 98  // connect
            | 104 // bind
            | 106 // listen
            | 30  // accept
            | 133 // sendto
            | 29  // recvfrom
            | 28  // sendmsg
            | 27 // recvmsg
        )
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "aarch64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
    )))]
    {
        let _ = nr;
        true // conservative: report all
    }
}

/// Result of adding hooks (may be multiple for glob patterns).
pub struct AddHookResult {
    /// List of (symbol_name, address) pairs that were hooked.
    pub symbols: Vec<(String, usize)>,
}

/// Manages function hooks using malwi-hook's Interceptor.
pub struct HookManager {
    interceptor: &'static malwi_intercept::Interceptor,
    hooks: Mutex<HashMap<String, HookEntry>>,
}

struct HookEntry {
    #[allow(dead_code)] // Kept for future attach mode
    address: usize,
    listener: CallListener,
    #[allow(dead_code)] // Kept for removing hooks by pattern
    config: HookConfig,
    callback_data: *mut HookCallbackData,
    // Fishhook-style rebinding fallback on macOS when inline patching fails
    // (e.g., hardened shared-cache mappings like libSystem).
    #[cfg(target_os = "macos")]
    #[allow(dead_code)] // Used by restore_rebinds on unhook
    rebind_patches: Option<Vec<(usize, usize)>>,
}

/// Data passed to hook callbacks via user_data pointer.
///
/// Heap-allocated to ensure pointer stability across callback invocations.
/// Contains pre-resolved function/module names to avoid calling
/// symbol resolution APIs during hook callbacks.
#[repr(C)]
struct HookCallbackData {
    function_name: String,
    module_name: String,
    capture_stack: bool,
}

// Safety: HookManager uses interior mutability with Mutex
unsafe impl Send for HookManager {}
unsafe impl Sync for HookManager {}

impl HookManager {
    /// Create a new hook manager.
    pub fn new() -> Result<Self> {
        Ok(Self {
            interceptor: malwi_intercept::Interceptor::obtain(),
            hooks: Mutex::new(HashMap::new()),
        })
    }

    /// Add hook(s) for the specified symbol pattern.
    /// Supports glob patterns like `do_*` or `*connect*`.
    pub fn add_hook(&self, config: &HookConfig) -> Result<AddHookResult> {
        // Find all matching symbols (exports + non-exported/local).
        // Some fixtures (and bash internals) are not exported, but
        // malwi-intercept's enumerate_symbols finds them. Keep compatibility.
        let exports = native::find_symbols_matching(None, &config.symbol);

        if exports.is_empty() {
            return Err(anyhow!("Symbol not found: {}", config.symbol));
        }

        let mut result = AddHookResult {
            symbols: Vec::new(),
        };

        for export in exports {
            if self.hooks.lock().unwrap().contains_key(&export.name) {
                debug!("Skipping duplicate hook for {}", export.name);
                continue;
            }

            match self.try_attach_hook(&export, config) {
                Ok(()) => {
                    info!("Hooked {} at {:#x}", export.name, export.address);
                    result.symbols.push((export.name, export.address));
                }
                Err(e) => {
                    warn!("Failed to hook {}: {}", export.name, e);
                }
            }
        }

        if result.symbols.is_empty() {
            return Err(anyhow!(
                "Failed to hook any symbols matching: {}",
                config.symbol
            ));
        }

        Ok(result)
    }

    /// Attempt to attach a hook to a single export.
    fn try_attach_hook(&self, export: &native::ExportInfo, config: &HookConfig) -> Result<()> {
        let callback_data = Box::into_raw(Box::new(HookCallbackData {
            function_name: export.name.clone(),
            module_name: export.module.clone(),
            capture_stack: config.capture_stack,
        }));

        let listener = self
            .create_listener(callback_data)
            .inspect_err(|_e| unsafe {
                drop(Box::from_raw(callback_data));
            })?;

        // Primary path: inline interceptor attach.
        self.interceptor.begin_transaction();
        let attach_res = self
            .interceptor
            .attach(export.address as *mut c_void, listener);
        self.interceptor.end_transaction();

        // Fallback (macOS): rebind imported symbol pointers to an interceptor wrapper.
        #[cfg(target_os = "macos")]
        let (attach_ok, rebind_patches) = match attach_res {
            Ok(()) => (true, None),
            Err(e) => {
                warn!(
                    "Inline attach failed for {} ({:?}); trying import rebinding",
                    export.name, e
                );
                // Build wrapper/trampoline but don't patch the target.
                let wrapper = self
                    .interceptor
                    .attach_rebinding(export.address as *mut c_void, listener)
                    .map_err(|e| anyhow!("Attach rebinding failed: {:?}", e))?;
                let patched = unsafe {
                    malwi_intercept::module::rebind_symbol(&export.name, wrapper)
                        .map_err(|e| anyhow!("Rebind failed: {:?}", e))?
                };
                (true, Some(patched))
            }
        };

        #[cfg(not(target_os = "macos"))]
        let attach_ok = match attach_res {
            Ok(()) => true,
            Err(e) => {
                unsafe {
                    drop(Box::from_raw(callback_data));
                }
                return Err(anyhow!("Attach failed: {:?}", e));
            }
        };

        if !attach_ok {
            unsafe {
                drop(Box::from_raw(callback_data));
            }
            return Err(anyhow!("Attach failed"));
        }

        self.hooks.lock().unwrap().insert(
            export.name.clone(),
            HookEntry {
                address: export.address,
                listener,
                config: config.clone(),
                callback_data,
                #[cfg(target_os = "macos")]
                rebind_patches,
            },
        );

        Ok(())
    }

    /// Remove a hook by symbol name.
    pub fn remove_hook(&self, symbol: &str) -> Result<()> {
        let mut hooks = self.hooks.lock().unwrap();

        if let Some(entry) = hooks.remove(symbol) {
            self.interceptor.detach(&entry.listener);
            // Free the callback data
            if !entry.callback_data.is_null() {
                unsafe {
                    drop(Box::from_raw(entry.callback_data));
                }
            }
            debug!("Hook removed for {}", symbol);
            Ok(())
        } else {
            Err(anyhow!("No hook found for symbol: {}", symbol))
        }
    }

    /// Create a CallListener for the hook.
    fn create_listener(&self, callback_data: *mut HookCallbackData) -> Result<CallListener> {
        Ok(CallListener {
            on_enter: Some(on_enter),
            on_leave: Some(on_leave),
            user_data: callback_data as *mut c_void,
        })
    }

    /// List all installed hook symbols.
    pub fn list_hooks(&self) -> Vec<String> {
        let hooks = self.hooks.lock().unwrap();
        hooks.keys().cloned().collect()
    }
}

impl Drop for HookManager {
    fn drop(&mut self) {
        // Detach all hooks and free callback data
        let hooks = self.hooks.lock().unwrap();
        for (_, entry) in hooks.iter() {
            self.interceptor.detach(&entry.listener);
            if !entry.callback_data.is_null() {
                unsafe {
                    drop(Box::from_raw(entry.callback_data));
                }
            }
        }
    }
}

/// Extract function name and capture_stack flag from callback data.
/// Falls back to address string if no callback data is available.
unsafe fn get_hook_data(user_data: *mut c_void, func_addr: usize) -> (String, bool) {
    if !user_data.is_null() {
        let data = &*(user_data as *const HookCallbackData);
        (data.function_name.clone(), data.capture_stack)
    } else {
        (format!("{:#x}", func_addr), false)
    }
}

/// Callback when a hooked function is entered.
unsafe extern "C" fn on_enter(context: *mut InvocationContext, user_data: *mut c_void) {
    // Re-entrancy guard: skip if we're already inside a hook callback on this thread.
    // This prevents infinite recursion when hooked functions (e.g., malloc) are called
    // internally by the hook processing (JSON serialization, HTTP, allocations).
    if IN_HOOK.with(|h| h.get()) {
        return;
    }
    IN_HOOK.with(|h| h.set(true));

    on_enter_inner(context, user_data);

    IN_HOOK.with(|h| h.set(false));
}

unsafe fn on_enter_inner(context: *mut InvocationContext, user_data: *mut c_void) {
    let func_addr = (*context).function as usize;

    // Capture arguments (up to 6 for now)
    let mut arguments = Vec::new();
    for i in 0..6 {
        let arg = malwi_intercept::invocation::get_nth_argument(context, i);
        arguments.push(Argument {
            raw_value: arg as usize,
            display: None,
        });
    }

    let (function, capture_stack) = get_hook_data(user_data, func_addr);

    // When the hooked function is libc `syscall()`, the first argument is the
    // syscall number. Only report/block network-related syscalls; skip all
    // others (pipe, epoll, etc.) to avoid breaking normal process operations.
    if function == "syscall" {
        let syscall_nr = arguments[0].raw_value;
        if !is_network_syscall(syscall_nr) {
            return;
        }
        // Rewrite the function name to include the actual syscall for clarity.
        // The arguments shift by 1 (arg[0] was syscall number).
    }

    // Format display values for known functions (e.g., show paths instead of pointers)
    format_native_arguments(&function, &mut arguments);

    // Only capture backtrace if enabled for this hook
    let native_stack = if capture_stack {
        capture_backtrace(context)
    } else {
        Vec::new()
    };

    // Build trace event
    let event = crate::tracing::event::EventBuilder::enter(&function)
        .hook_type(malwi_protocol::HookType::Native)
        .arguments(arguments)
        .native_stack(native_stack)
        .build();

    // Send to CLI
    if let Some(agent) = crate::Agent::get() {
        if agent.is_review_mode() {
            // Review mode: send event and wait for user decision
            // Event is already shown to user via AwaitingDecision, no need to send again
            let decision = agent.await_review_decision(event.clone());
            if !decision.is_allowed() {
                // User denied - skip function by returning -1 and setting errno.
                // Returning 0/NULL would be misinterpreted by syscall wrappers
                // (e.g. socket() treats 0 as valid fd), causing infinite retry loops.
                malwi_intercept::invocation::replace_return_value(
                    context,
                    (-1isize) as usize as *mut c_void,
                );
                // Set errno = EACCES (Permission denied) so callers see a proper error
                #[cfg(target_os = "macos")]
                {
                    *libc::__error() = libc::EACCES;
                }
                #[cfg(target_os = "linux")]
                {
                    *libc::__errno_location() = libc::EACCES;
                }
                info!("BLOCKED: {}", event.function);
            }
        } else {
            // Normal mode: send event
            let _ = agent.send_event(event);
        }
    }
}

/// Callback when a hooked function returns.
unsafe extern "C" fn on_leave(context: *mut InvocationContext, user_data: *mut c_void) {
    if IN_HOOK.with(|h| h.get()) {
        return;
    }
    IN_HOOK.with(|h| h.set(true));

    on_leave_inner(context, user_data);

    IN_HOOK.with(|h| h.set(false));
}

unsafe fn on_leave_inner(context: *mut InvocationContext, user_data: *mut c_void) {
    let func_addr = (*context).function as usize;
    let return_value = malwi_intercept::invocation::get_return_value(context);

    let (function, _capture_stack) = get_hook_data(user_data, func_addr);

    let event = crate::tracing::event::EventBuilder::leave(
        &function,
        Some(format!("{:#x}", return_value as usize)),
    )
    .hook_type(malwi_protocol::HookType::Native)
    .build();

    if let Some(agent) = crate::Agent::get() {
        let _ = agent.send_event(event);
    }
}

/// Capture a native backtrace using malwi-hook's backtracer.
///
/// This is public so it can be called from spawn_monitor to capture
/// the call stack leading to exec/spawn syscalls.
///
/// # Safety
/// The caller must ensure `context` is a valid InvocationContext pointer.
pub unsafe fn capture_backtrace(context: *mut InvocationContext) -> Vec<usize> {
    unsafe {
        let cpu = &*(*context).cpu_context;
        malwi_intercept::backtrace::capture_backtrace(cpu, 64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_suppress_guard_basic() {
        // Start with hooks not suppressed
        set_in_hook(false);
        assert!(!is_in_hook());

        {
            let _guard = HookSuppressGuard::new();
            assert!(is_in_hook());
        }
        // Restored to false after drop
        assert!(!is_in_hook());
    }

    #[test]
    fn test_hook_suppress_guard_nested() {
        // Start already inside a hook
        set_in_hook(true);
        assert!(is_in_hook());

        {
            let _guard = HookSuppressGuard::new();
            assert!(is_in_hook());
        }
        // Restored to true (was already true)
        assert!(is_in_hook());

        // Clean up
        set_in_hook(false);
    }

    #[test]
    fn test_hook_suppress_guard_double_nested() {
        set_in_hook(false);

        {
            let _outer = HookSuppressGuard::new();
            assert!(is_in_hook());

            {
                let _inner = HookSuppressGuard::new();
                assert!(is_in_hook());
            }
            // Inner dropped — still true (outer saved true)
            assert!(is_in_hook());
        }
        // Outer dropped — restored to false
        assert!(!is_in_hook());
    }
}
