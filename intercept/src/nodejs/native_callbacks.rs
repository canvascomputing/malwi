//! Hook Node.js native module C++ callbacks via frida-gum.
//!
//! Node.js built-in module functions (fs.readFileSync, dns.lookup, etc.) are
//! C++ callbacks registered via `v8::FunctionTemplate::New`. They have a
//! uniform signature:
//!
//!   void Func(const v8::FunctionCallbackInfo<v8::Value>& args)
//!
//! FunctionCallbackInfo layout (v8-function-callback.h:154-156):
//!   [0x00] implicit_args_: Address*  (internal slots; isolate at index 1)
//!   [0x08] values_:        Address*  (JS argument values — tagged V8 pointers)
//!   [0x10] length_:        i32       (number of JS arguments)
//!
//! We hook these C++ functions directly with frida-gum's interceptor,
//! extract arguments from FunctionCallbackInfo, and emit trace events.
//! No NODE_OPTIONS, no JS wrapper, no N-API needed.

use core::ffi::c_void;
use std::sync::OnceLock;

use log::{debug, info};

use crate::interceptor::Interceptor;
use crate::{Argument, CallListener, InvocationContext};

/// JS API name → C++ demangled callback name.
/// Derived from node/src/node_file.cc SetMethod calls, cares_wrap.cc, etc.
static JS_TO_CPP: &[(&str, &str)] = &[
    // fs module (node_file.cc)
    ("fs.access", "node::fs::Access"),
    ("fs.close", "node::fs::Close"),
    ("fs.open", "node::fs::Open"),
    ("fs.read", "node::fs::Read"),
    ("fs.stat", "node::fs::Stat"),
    ("fs.lstat", "node::fs::LStat"),
    ("fs.fstat", "node::fs::FStat"),
    ("fs.readFileSync", "node::fs::ReadFileUtf8"),
    ("fs.writeFileSync", "node::fs::WriteFileUtf8"),
    ("fs.existsSync", "node::fs::ExistsSync"),
    ("fs.mkdir", "node::fs::MKDir"),
    ("fs.rmdir", "node::fs::RMDir"),
    ("fs.unlink", "node::fs::Unlink"),
    ("fs.rename", "node::fs::Rename"),
    ("fs.link", "node::fs::Link"),
    ("fs.symlink", "node::fs::Symlink"),
    ("fs.readlink", "node::fs::ReadLink"),
    ("fs.chmod", "node::fs::Chmod"),
    ("fs.chown", "node::fs::Chown"),
    ("fs.fsync", "node::fs::Fsync"),
    ("fs.realpath", "node::fs::RealPath"),
    // os module (node_os.cc)
    ("os.hostname", "node::os::GetHostname"),
    ("os.homedir", "node::os::GetHomeDirectory"),
    ("os.userInfo", "node::os::GetUserInfo"),
    ("os.cpus", "node::os::GetCPUInfo"),
    // child_process module (process_wrap.cc, spawn_sync.cc)
    ("child_process.spawn", "node::{anon}::ProcessWrap::Spawn"),
    ("child_process.spawnSync", "node::SyncProcessRunner::Spawn"),
    ("child_process.kill", "node::{anon}::ProcessWrap::Kill"),
    // crypto module (crypto_cipher.cc)
    ("crypto.createCipher", "node::crypto::CipherBase::Init"),
    ("crypto.createCipheriv", "node::crypto::CipherBase::InitIv"),
    ("crypto.cipherUpdate", "node::crypto::CipherBase::Update"),
    ("crypto.cipherFinal", "node::crypto::CipherBase::Final"),
    // net module (tcp_wrap.cc)
    ("net.createConnection", "node::TCPWrap::New"),
    // tls module (crypto_context.cc)
    (
        "tls.createSecureContext",
        "node::crypto::SecureContext::New",
    ),
    // vm module (node_contextify.cc)
    ("vm.Script", "node::contextify::ContextifyScript::New"),
    (
        "vm.runInContext",
        "node::contextify::ContextifyScript::RunInContext",
    ),
    (
        "vm.createContext",
        "node::contextify::ContextifyContext::MakeContext",
    ),
    // dns module (cares_wrap.cc)
    ("dns.lookup", "node::cares_wrap::{anon}::GetAddrInfo"),
    ("dns.lookupService", "node::cares_wrap::{anon}::GetNameInfo"),
];

/// Suffix that all V8 FunctionCallback mangled symbols contain.
const FCI_SUFFIX: &str = "FunctionCallbackInfoI";

/// Data attached to each hook via user_data pointer.
struct HookData {
    js_name: String,
    capture_stack: bool,
}

/// State for an installed native callback hook.
struct HookEntry {
    _listener: CallListener,
}

/// All installed hooks.
static HOOKS: OnceLock<Vec<HookEntry>> = OnceLock::new();

/// Set of JS function names that have native C++ callback hooks installed.
/// Used by the bytecode hook to suppress duplicate events.
static HOOKED_NAMES: OnceLock<std::collections::HashSet<String>> = OnceLock::new();

/// Check if a function name has a native callback hook installed.
/// The bytecode hook calls this to suppress duplicates.
pub fn has_native_hook(name: &str) -> bool {
    HOOKED_NAMES
        .get()
        .map(|set| set.contains(name))
        .unwrap_or(false)
}

/// Install frida-gum hooks on Node.js C++ callbacks matching the given filters.
pub fn install_hooks(filters: &[crate::tracing::Filter]) {
    if HOOKS.get().is_some() {
        return; // Already installed
    }

    let interceptor = Interceptor::obtain();
    let mut entries = Vec::new();
    let mut hooked_names = std::collections::HashSet::new();

    // Enumerate ALL symbols from the node binary
    let node_module = super::find_node_module();
    let node_module = match node_module {
        Some(name) => name,
        None => {
            debug!("Node module not found for native callback hooking");
            return;
        }
    };

    let symbols = match crate::module::enumerate_symbols(&node_module) {
        Ok(s) => s,
        Err(e) => {
            debug!("Failed to enumerate node symbols: {:?}", e);
            return;
        }
    };

    // Build a map of demangled name → address for FunctionCallbackInfo symbols
    let mut callback_map: Vec<(String, usize)> = Vec::new();
    for sym in &symbols {
        if !sym.name.contains(FCI_SUFFIX) {
            continue;
        }
        // Demangle: extract the function name portion
        if let Some(demangled) = demangle_node_callback(&sym.name) {
            callback_map.push((demangled, sym.address));
        }
    }

    debug!(
        "Found {} hookable Node.js callbacks in '{}'",
        callback_map.len(),
        node_module
    );

    // For each filter, find matching C++ callbacks and hook them
    interceptor.begin_transaction();

    for filter in filters {
        let matching_js_names = find_matching_js_names(&filter.pattern);
        for js_name in matching_js_names {
            // Look up the C++ callback name
            let cpp_name = match js_to_cpp_name(js_name) {
                Some(n) => n,
                None => continue,
            };

            // Find the symbol address
            let addr = match find_callback_addr(&callback_map, cpp_name) {
                Some(a) => a,
                None => {
                    debug!("Symbol not found for {}: {}", js_name, cpp_name);
                    continue;
                }
            };

            // Create hook data with name and capture_stack flag
            let hook_data = Box::new(HookData {
                js_name: js_name.to_string(),
                capture_stack: filter.capture_stack,
            });
            let user_data = Box::into_raw(hook_data) as *mut c_void;

            let listener = CallListener {
                on_enter: Some(on_native_callback_enter),
                on_leave: None,
                user_data,
            };

            if interceptor.attach(addr as *mut c_void, listener).is_ok() {
                info!("Hooked {} at {:#x} ({})", js_name, addr, cpp_name);
                hooked_names.insert(js_name.to_string());
                entries.push(HookEntry {
                    _listener: listener,
                });
            } else {
                debug!("Failed to hook {} at {:#x}", js_name, addr);
                unsafe {
                    let _ = Box::from_raw(user_data as *mut HookData);
                }
            }
        }
    }

    interceptor.end_transaction();

    if !entries.is_empty() {
        info!("Installed {} native Node.js callback hooks", entries.len());
    }

    let _ = HOOKED_NAMES.set(hooked_names);
    let _ = HOOKS.set(entries);
}

/// on_enter callback for native Node.js C++ callbacks.
unsafe extern "C" fn on_native_callback_enter(
    context: *mut InvocationContext,
    user_data: *mut c_void,
) {
    // Reentrancy guard
    if crate::native::hooks::is_in_hook() {
        return;
    }

    let data = &*(user_data as *const HookData);

    // arg0 is &FunctionCallbackInfo — pointer to the 24-byte struct
    let fci_ptr = crate::invocation::get_nth_argument(context, 0) as *const u8;
    if fci_ptr.is_null() {
        return;
    }

    // Read FunctionCallbackInfo fields
    let values_ptr = *(fci_ptr.add(8) as *const *const usize); // offset 0x08: values_
    let length = *(fci_ptr.add(16) as *const i32); // offset 0x10: length_

    // Parse arguments as V8 tagged values
    let mut arguments = Vec::new();
    if !values_ptr.is_null() && length > 0 {
        let max_args = length.min(6) as usize;
        for i in 0..max_args {
            let tagged = *values_ptr.add(i);
            let display = super::stack::format_tagged_value(tagged);
            arguments.push(Argument {
                raw_value: 0,
                display: Some(display),
            });
        }
    }

    // Capture JS stack trace when --st is enabled.
    // Extract isolate from FunctionCallbackInfo.implicit_args_[1].
    let runtime_stack = if data.capture_stack {
        let implicit_args = *(fci_ptr as *const *const usize);
        if !implicit_args.is_null() {
            let isolate = *implicit_args.add(1) as *mut c_void;
            super::capture_stack_from_isolate(isolate)
        } else {
            None
        }
    } else {
        None
    };

    emit_trace_event(&data.js_name, arguments, runtime_stack);
}

/// Emit a JS trace event for a native callback.
fn emit_trace_event(
    js_name: &str,
    mut arguments: Vec<Argument>,
    runtime_stack: Option<crate::RuntimeStack>,
) {
    let network_info = super::format::format_nodejs_arguments(js_name, &mut arguments);

    let event = crate::tracing::event::js_enter(js_name)
        .arguments(arguments)
        .network_info(network_info)
        .runtime_stack(runtime_stack)
        .build();

    if let Some(agent) = crate::Agent::get() {
        let _ = agent.send_event(event);
    }
}

// ── Symbol resolution helpers ──────────────────────────────────

/// Demangle a node C++ FunctionCallbackInfo symbol to "namespace::Function" form.
/// Input: mangled symbol like `_ZN4node2fsL12ReadFileUtf8ERKN2v8...`
/// Output: "node::fs::ReadFileUtf8"
fn demangle_node_callback(mangled: &str) -> Option<String> {
    // Quick check: must contain FunctionCallbackInfo
    if !mangled.contains(FCI_SUFFIX) {
        return None;
    }

    // Use a simple Itanium demangling approach for node:: symbols.
    // Pattern: [_]ZN4node{len}{ns}[L]{len}{name}E...
    // The leading underscore is stripped by enumerate_symbols on macOS.
    let s = mangled
        .strip_prefix("_ZN")
        .or_else(|| mangled.strip_prefix("ZN"))?;

    let mut result = Vec::new();
    let mut pos = 0;
    let bytes = s.as_bytes();

    while pos < bytes.len() {
        // Skip 'L' prefix (static linkage)
        if bytes[pos] == b'L' {
            pos += 1;
            continue;
        }

        // Read length prefix
        if !bytes[pos].is_ascii_digit() {
            break;
        }
        let mut len = 0usize;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            len = len * 10 + (bytes[pos] - b'0') as usize;
            pos += 1;
        }
        if len == 0 || pos + len > bytes.len() {
            break;
        }

        let component = &s[pos..pos + len];
        pos += len;

        // Stop at the function signature (starts with 'E' or 'R')
        if component.starts_with("v2") || component.contains("FunctionCallback") {
            break;
        }

        // Skip anonymous namespace markers
        if component == "_GLOBAL__N_1" {
            result.push("{anon}".to_string());
            continue;
        }

        result.push(component.to_string());
    }

    if result.len() >= 2 {
        Some(result.join("::"))
    } else {
        None
    }
}

/// Find JS names matching a filter pattern (exact or glob).
fn find_matching_js_names(pattern: &str) -> Vec<&'static str> {
    let mut matches = Vec::new();

    // Check for glob prefix match (e.g., "fs.*")
    if let Some(dot) = pattern.find('.') {
        let prefix = &pattern[..dot];
        let func_part = &pattern[dot + 1..];

        for &(js_name, _) in JS_TO_CPP {
            if let Some(js_dot) = js_name.find('.') {
                let js_prefix = &js_name[..js_dot];
                let js_func = &js_name[js_dot + 1..];

                if js_prefix == prefix {
                    if func_part == "*" || crate::glob::matches_glob(func_part, js_func) {
                        matches.push(js_name);
                    }
                }
            }
        }
    } else {
        // Bare name — match function part only
        for &(js_name, _) in JS_TO_CPP {
            if let Some(dot) = js_name.find('.') {
                let js_func = &js_name[dot + 1..];
                if js_func == pattern {
                    matches.push(js_name);
                }
            }
        }
    }

    matches
}

/// Look up the C++ callback name for a JS API name.
fn js_to_cpp_name(js_name: &str) -> Option<&'static str> {
    JS_TO_CPP
        .iter()
        .find(|&&(js, _)| js == js_name)
        .map(|&(_, cpp)| cpp)
}

/// Find a callback address by matching demangled names.
fn find_callback_addr(callback_map: &[(String, usize)], cpp_name: &str) -> Option<usize> {
    callback_map
        .iter()
        .find(|(demangled, _)| demangled == cpp_name)
        .map(|(_, addr)| *addr)
}
