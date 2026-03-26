//! Hook management using malwi-hook Interceptor.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::CallListener;
use crate::InvocationContext;
use crate::{Argument, HookConfig};
use anyhow::{anyhow, Result};
use core::ffi::c_void;
use log::{debug, info, warn};

// Thread-local re-entrancy guard. Prevents infinite recursion when
// hooked functions (like `malloc`) are called from within the hook
// callback itself (e.g., by JSON serialization or HTTP operations).
thread_local! {
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

// Thread-local stash for DNS resolution context.
// Saved on getaddrinfo/gethostbyname enter, consumed on leave to
// record resolved IPs in the DnsTracker.
thread_local! {
    static PENDING_DNS: Cell<Option<PendingDns>> = const { Cell::new(None) };
}

/// Context stashed during DNS function entry, consumed on leave.
struct PendingDns {
    /// Hostname being resolved (from format.rs network_info)
    hostname: String,
    /// Pointer to the result pointer (getaddrinfo's `**res` arg)
    /// or the function's return value pointer (gethostbyname)
    res_ptr_ptr: usize,
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
    interceptor: &'static crate::Interceptor,
    hooks: Mutex<HashMap<String, HookEntry>>,
}

struct HookEntry {
    #[allow(dead_code)] // Kept for future attach mode
    address: usize,
    listener: CallListener,
    #[allow(dead_code)] // Kept for removing hooks by pattern
    config: HookConfig,
    callback_data: *mut HookCallbackData,
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
            interceptor: crate::Interceptor::obtain(),
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
            if self
                .hooks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&export.name)
            {
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

        // Inline interceptor attach.
        self.interceptor.begin_transaction();
        let attach_res = self
            .interceptor
            .attach(export.address as *mut c_void, listener);
        self.interceptor.end_transaction();

        if let Err(e) = attach_res {
            unsafe {
                drop(Box::from_raw(callback_data));
            }
            return Err(anyhow!("Attach failed: {:?}", e));
        }

        self.hooks.lock().unwrap_or_else(|e| e.into_inner()).insert(
            export.name.clone(),
            HookEntry {
                address: export.address,
                listener,
                config: config.clone(),
                callback_data,
            },
        );

        Ok(())
    }

    /// Remove a hook by symbol name.
    pub fn remove_hook(&self, symbol: &str) -> Result<()> {
        let mut hooks = self.hooks.lock().unwrap_or_else(|e| e.into_inner());

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
        let hooks = self.hooks.lock().unwrap_or_else(|e| e.into_inner());
        hooks.keys().cloned().collect()
    }
}

impl Drop for HookManager {
    fn drop(&mut self) {
        // Detach all hooks and free callback data
        let hooks = self.hooks.lock().unwrap_or_else(|e| e.into_inner());
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
        let arg = crate::invocation::get_nth_argument(context, i);
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
    let mut network_info = format_native_arguments(&function, &mut arguments);

    // DNS resolution: stash context so on_leave can parse the result.
    match function.as_str() {
        "getaddrinfo" | "_getaddrinfo" => {
            if let Some(ref ni) = network_info {
                // Domain is in ni.domain (hostname) or ni.ip (IP literal passed to getaddrinfo)
                let hostname = ni.domain.as_ref().or(ni.ip.as_ref());
                if let Some(host) = hostname {
                    // arg3 is the **addrinfo result pointer
                    let res_ptr_ptr = if arguments.len() >= 4 {
                        arguments[3].raw_value
                    } else {
                        0
                    };
                    PENDING_DNS.with(|p| {
                        p.set(Some(PendingDns {
                            hostname: host.clone(),
                            res_ptr_ptr,
                        }));
                    });
                }
            }
        }
        "gethostbyname" | "_gethostbyname" | "gethostbyname2" | "_gethostbyname2" => {
            if let Some(ref ni) = network_info {
                if let Some(ref host) = ni.domain {
                    PENDING_DNS.with(|p| {
                        p.set(Some(PendingDns {
                            hostname: host.clone(),
                            res_ptr_ptr: 0, // return value used instead
                        }));
                    });
                }
            }
        }
        // Enrich connect() with resolved domain from DNS cache
        "connect" | "_connect" => {
            if let Some(ref mut ni) = network_info {
                if let Some(ref ip) = ni.ip {
                    if let Some(domain) = crate::tracing::dns_tracker().lookup(ip) {
                        ni.domain = Some(domain);
                    }
                }
            }
        }
        _ => {}
    }

    // Only capture backtrace if enabled for this hook
    let native_stack = if capture_stack {
        capture_backtrace(context)
    } else {
        Vec::new()
    };

    // Build trace event
    let event = crate::tracing::event::EventBuilder::enter(&function)
        .hook_type(crate::HookType::Native)
        .arguments(arguments)
        .native_stack(native_stack)
        .network_info(network_info)
        .build();

    // Send to CLI
    if let Some(agent) = crate::Agent::get() {
        if let Some(decision) = agent.evaluate_policy(&event) {
            // Agent-side policy: evaluate locally, enforce immediately
            match decision {
                malwi_protocol::agent_policy::AgentDecision::Block { .. } => {
                    crate::invocation::replace_return_value(
                        context,
                        (-1isize) as usize as *mut c_void,
                    );
                    set_errno(libc::EACCES);
                    info!("BLOCKED: {}", event.function);
                }
                malwi_protocol::agent_policy::AgentDecision::Hide => {
                    match function.as_str() {
                        "getenv" | "secure_getenv" => {
                            crate::invocation::replace_return_value(context, std::ptr::null_mut());
                        }
                        _ => {
                            crate::invocation::replace_return_value(
                                context,
                                (-1isize) as usize as *mut c_void,
                            );
                            set_errno(libc::ENOENT);
                        }
                    }
                    info!("HIDDEN: {}", event.function);
                    return; // Hidden events are not sent to CLI
                }
                malwi_protocol::agent_policy::AgentDecision::Suppress => {
                    return; // Suppressed events are not sent to CLI
                }
                _ => {
                    // Trace, Warn — proceed to send_event (which attaches disposition)
                }
            }
            let _ = agent.send_event(event);
        } else {
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
    let return_value = crate::invocation::get_return_value(context);

    let (function, _capture_stack) = get_hook_data(user_data, func_addr);

    // DNS result capture: parse resolved IPs and record in DnsTracker.
    match function.as_str() {
        "getaddrinfo" | "_getaddrinfo" => {
            let ret = return_value as usize;
            if ret == 0 {
                // Success — parse result chain
                let pending = PENDING_DNS.with(|p| p.take());
                if let Some(dns) = pending {
                    if dns.res_ptr_ptr != 0 {
                        record_getaddrinfo_results(&dns.hostname, dns.res_ptr_ptr);
                    }
                }
            } else {
                // Failed — discard stash
                PENDING_DNS.with(|p| p.take());
            }
        }
        "gethostbyname" | "_gethostbyname" | "gethostbyname2" | "_gethostbyname2" => {
            let ret = return_value as usize;
            if ret != 0 {
                // Success — parse hostent
                let pending = PENDING_DNS.with(|p| p.take());
                if let Some(dns) = pending {
                    record_hostent_results(&dns.hostname, ret);
                }
            } else {
                // Failed — discard stash
                PENDING_DNS.with(|p| p.take());
            }
        }
        _ => {}
    }

    let event = crate::tracing::event::EventBuilder::leave(
        &function,
        Some(format!("{:#x}", return_value as usize)),
    )
    .hook_type(crate::HookType::Native)
    .build();

    if let Some(agent) = crate::Agent::get() {
        let _ = agent.send_event(event);
    }
}

/// Parse getaddrinfo result chain and record IP→domain associations.
///
/// # Safety
/// `res_ptr_ptr` must be the address of the `**addrinfo` output parameter
/// from getaddrinfo. Only called when getaddrinfo returned 0 (success).
unsafe fn record_getaddrinfo_results(hostname: &str, res_ptr_ptr: usize) {
    let res_ptr = *(res_ptr_ptr as *const *const libc::addrinfo);
    if res_ptr.is_null() {
        return;
    }

    let tracker = crate::tracing::dns_tracker();
    let mut current = res_ptr;
    let mut count = 0u32;
    const MAX_ADDRS: u32 = 64;

    while !current.is_null() && count < MAX_ADDRS {
        let ai = &*current;
        if !ai.ai_addr.is_null() {
            if let Some(ip) = extract_ip_from_sockaddr(ai.ai_addr as usize) {
                tracker.record(hostname, &ip);
            }
        }
        current = ai.ai_next;
        count += 1;
    }
}

/// Parse hostent result and record IP→domain associations.
///
/// # Safety
/// `hostent_ptr` must point to a valid `libc::hostent` struct.
/// Only called when gethostbyname returned non-NULL.
unsafe fn record_hostent_results(hostname: &str, hostent_ptr: usize) {
    let he = &*(hostent_ptr as *const libc::hostent);
    if he.h_addr_list.is_null() {
        return;
    }

    let tracker = crate::tracing::dns_tracker();
    let mut i = 0usize;
    const MAX_ADDRS: usize = 64;

    while i < MAX_ADDRS {
        let addr_ptr = *he.h_addr_list.add(i);
        if addr_ptr.is_null() {
            break;
        }

        let ip = if he.h_addrtype == libc::AF_INET as i32 {
            let bytes = std::slice::from_raw_parts(addr_ptr as *const u8, 4);
            Some(format!(
                "{}.{}.{}.{}",
                bytes[0], bytes[1], bytes[2], bytes[3]
            ))
        } else if he.h_addrtype == libc::AF_INET6 as i32 {
            let bytes = std::slice::from_raw_parts(addr_ptr as *const u8, 16);
            Some(crate::native::format::format_ipv6(bytes))
        } else {
            None
        };

        if let Some(ip) = ip {
            tracker.record(hostname, &ip);
        }
        i += 1;
    }
}

/// Extract an IP address string from a sockaddr pointer.
///
/// Handles AF_INET and AF_INET6. Returns None for other families.
unsafe fn extract_ip_from_sockaddr(addr_ptr: usize) -> Option<String> {
    if addr_ptr == 0 {
        return None;
    }

    let family_ptr = addr_ptr as *const u16;
    let family = {
        #[cfg(target_os = "macos")]
        {
            (*family_ptr >> 8) as i32
        }
        #[cfg(not(target_os = "macos"))]
        {
            *family_ptr as i32
        }
    };

    match family {
        libc::AF_INET => {
            let ip_bytes = std::slice::from_raw_parts((addr_ptr + 4) as *const u8, 4);
            Some(format!(
                "{}.{}.{}.{}",
                ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
            ))
        }
        libc::AF_INET6 => {
            let ip6_bytes = std::slice::from_raw_parts((addr_ptr + 8) as *const u8, 16);
            Some(crate::native::format::format_ipv6(ip6_bytes))
        }
        _ => None,
    }
}

/// Set errno portably.
unsafe fn set_errno(value: i32) {
    #[cfg(target_os = "macos")]
    {
        *libc::__error() = value;
    }
    #[cfg(target_os = "linux")]
    {
        *libc::__errno_location() = value;
    }
}

/// Capture a native backtrace using gum's fuzzy backtracer.
///
/// Passes the saved CPU context from the interceptor callback directly
/// to `gum_backtracer_generate_with_limit`. The fuzzy backtracer reads
/// lr/sp (arm64) or scans the stack (x86_64) for return addresses —
/// it does not rely on .eh_frame, so trampoline contexts are safe.
///
/// This is public so it can be called from spawn_monitor to capture
/// the call stack leading to exec/spawn syscalls.
///
/// # Safety
/// The caller must ensure `context` is a valid InvocationContext pointer.
pub unsafe fn capture_backtrace(context: *mut InvocationContext) -> Vec<usize> {
    let cpu_ctx = (*context).cpu_context;
    if cpu_ctx.is_null() {
        return crate::backtrace::capture_backtrace(None, 64);
    }
    crate::backtrace::capture_backtrace(Some(&*cpu_ctx), 64)
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
