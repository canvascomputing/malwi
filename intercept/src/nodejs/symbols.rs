//! Platform-specific mangled symbol names for V8 API.
//!
//! These differ between GCC/Clang (Unix) and MSVC (Windows).

// V8/Node.js detection symbols
pub const NODE_MODULE_REGISTER: &str = "node_module_register";
pub const UV_VERSION: &str = "uv_version";

/// Node.js per_process::metadata - contains version strings.
/// Memory layout (std::string with SSO):
/// 0x00: node version (e.g., "22.19.0")
/// 0x18: v8 version
/// 0x30: uv version
pub const PER_PROCESS_METADATA: &str = "_ZN4node11per_process8metadataE";

// libuv symbols (C ABI)
// On macOS, C symbols have underscore prefix in nm output but malwi-intercept uses the name without it
#[cfg(target_os = "macos")]
pub const UV_RUN: &str = "uv_run";
#[cfg(not(target_os = "macos"))]
pub const UV_RUN: &str = "uv_run";

// V8 API symbols - GCC/Clang (Unix)
#[cfg(unix)]
pub mod v8 {
    /// v8::Isolate::GetCurrent() -> Isolate*
    pub const ISOLATE_GET_CURRENT: &str = "_ZN2v87Isolate10GetCurrentEv";

    /// v8::Isolate::GetCurrentContext() -> Local<Context>
    pub const ISOLATE_GET_CURRENT_CONTEXT: &str = "_ZN2v87Isolate17GetCurrentContextEv";

    /// v8::Context::Global() -> Local<Object>
    pub const CONTEXT_GLOBAL: &str = "_ZN2v87Context6GlobalEv";

    /// v8::String::NewFromUtf8(Isolate*, const char*, NewStringType, int) -> MaybeLocal<String>
    pub const STRING_NEW_FROM_UTF8: &str =
        "_ZN2v86String11NewFromUtf8EPNS_7IsolateEPKcNS_13NewStringTypeEi";

    /// v8::String::Utf8Length(Isolate*) const -> int
    pub const STRING_UTF8_LENGTH: &str = "_ZNK2v86String10Utf8LengthEPNS_7IsolateE";

    /// v8::String::WriteUtf8(Isolate*, char*, int, int*, int) const -> int
    pub const STRING_WRITE_UTF8: &str = "_ZNK2v86String9WriteUtf8EPNS_7IsolateEPciPii";

    /// v8::Script::Compile(Local<Context>, Local<String>, ScriptOrigin*) -> MaybeLocal<Script>
    pub const SCRIPT_COMPILE: &str =
        "_ZN2v86Script7CompileENS_5LocalINS_7ContextEEENS1_INS_6StringEEEPNS_12ScriptOriginE";

    /// v8::Script::Run(Local<Context>) -> MaybeLocal<Value>
    pub const SCRIPT_RUN: &str = "_ZN2v86Script3RunENS_5LocalINS_7ContextEEE";

    /// v8::Object::Get(Local<Context>, Local<Value>) -> MaybeLocal<Value>
    pub const OBJECT_GET: &str = "_ZN2v86Object3GetENS_5LocalINS_7ContextEEENS1_INS_5ValueEEE";

    /// v8::Object::Set(Local<Context>, Local<Value>, Local<Value>) -> Maybe<bool>
    pub const OBJECT_SET: &str = "_ZN2v86Object3SetENS_5LocalINS_7ContextEEENS1_INS_5ValueEEES5_";

    /// v8::Function::Call(Local<Context>, Local<Value>, int, Local<Value>*) -> MaybeLocal<Value>
    pub const FUNCTION_CALL: &str =
        "_ZN2v88Function4CallENS_5LocalINS_7ContextEEENS1_INS_5ValueEEEiPS5_";

    /// v8::Object::New(Isolate*) -> Local<Object>
    pub const OBJECT_NEW: &str = "_ZN2v86Object3NewEPNS_7IsolateE";

    /// v8::Script::Run(Local<Context>) -> MaybeLocal<Value>
    /// Note: This is a method, so it takes (Script* this, Local<Context>)
    pub const SCRIPT_RUN_WITH_CONTEXT: &str = "_ZN2v86Script3RunENS_5LocalINS_7ContextEEE";
}

// N-API symbols - GCC/Clang (Unix)
#[cfg(unix)]
pub mod napi {
    /// napi_module_register_by_symbol(Local<Object>, Local<Value>, Local<Context>, napi_addon_register_func, int)
    pub const MODULE_REGISTER_BY_SYMBOL: &str =
        "_Z30napi_module_register_by_symbolN2v85LocalINS_6ObjectEEENS0_INS_5ValueEEENS0_INS_7ContextEEEPFP12napi_value__P10napi_env__S8_Ei";
}

// V8 API symbols - MSVC (Windows) - placeholder, needs verification
#[cfg(windows)]
#[allow(dead_code)]
pub mod v8 {
    pub const ISOLATE_GET_CURRENT: &str = "?GetCurrent@Isolate@v8@@SAPEAV12@XZ";
    pub const ISOLATE_GET_CURRENT_CONTEXT: &str = "";
    pub const CONTEXT_GLOBAL: &str = "";
    pub const STRING_NEW_FROM_UTF8: &str = "";
    pub const STRING_UTF8_LENGTH: &str = "";
    pub const STRING_WRITE_UTF8: &str = "";
    pub const SCRIPT_COMPILE: &str = "";
    pub const SCRIPT_RUN: &str = "";
    pub const OBJECT_GET: &str = "";
    pub const OBJECT_SET: &str = "";
    pub const FUNCTION_CALL: &str = "";
    pub const OBJECT_NEW: &str = "";
}

// N-API symbols - MSVC (Windows) - placeholder, needs verification
#[cfg(windows)]
#[allow(dead_code)]
pub mod napi {
    pub const MODULE_REGISTER_BY_SYMBOL: &str = "";
}
