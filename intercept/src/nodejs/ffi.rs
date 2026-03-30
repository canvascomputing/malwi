//! Node.js and N-API FFI Type Definitions.
//!
//! This module provides consolidated type definitions for V8 and N-API
//! foreign function interface (FFI) calls. All Node.js-related modules should
//! use these types for consistency.

#![allow(non_camel_case_types)]
#![allow(dead_code)]

use std::ffi::{c_int, c_void};
use std::os::raw::c_char;

// =============================================================================
// NODEJS/V8 OPAQUE POINTER TYPES
// =============================================================================

/// Opaque pointer to V8 Isolate.
/// The Isolate represents an isolated instance of the V8 engine.
pub type V8Isolate = *mut c_void;

/// Opaque pointer to V8 Context.
/// A Context is an execution environment that allows separate, unrelated
/// JavaScript applications to run in a single instance of V8.
pub type V8Context = *mut c_void;

/// Opaque pointer to V8 Object.
pub type V8Object = *mut c_void;

/// Opaque pointer to V8 Value (base class for all JavaScript values).
pub type V8Value = *mut c_void;

/// Opaque pointer to V8 String.
pub type V8String = *mut c_void;

/// Opaque pointer to V8 Script.
pub type V8Script = *mut c_void;

/// Opaque pointer to V8 ScriptOrigin.
pub type V8ScriptOrigin = *const c_void;

// =============================================================================
// N-API TYPES
// =============================================================================

/// N-API environment pointer.
pub type NapiEnv = *mut c_void;

/// N-API value pointer.
pub type NapiValue = *mut c_void;

/// N-API addon register function signature.
/// Signature: (napi_env env, napi_value exports) -> napi_value
pub type NapiAddonRegisterFunc = unsafe extern "C" fn(NapiEnv, NapiValue) -> NapiValue;

// =============================================================================
// V8 FUNCTION POINTER TYPES
// =============================================================================

/// Function type for v8::Isolate::GetCurrent()
/// Returns the current isolate for the calling thread.
pub type IsolateGetCurrentFn = unsafe extern "C" fn() -> V8Isolate;

/// Function type for v8::Isolate::GetCurrentContext()
/// Returns the context that is on the top of the stack for the given isolate.
pub type IsolateGetCurrentContextFn = unsafe extern "C" fn(V8Isolate) -> V8Context;

/// Function type for v8::Context::Global()
/// Returns the global object of the context.
pub type ContextGlobalFn = unsafe extern "C" fn(V8Context) -> V8Value;

/// Function type for v8::Object::New(Isolate*)
/// Creates a new empty object.
pub type ObjectNewFn = unsafe extern "C" fn(V8Isolate) -> V8Object;

/// Function type for v8::Object::Get(Context, Value)
/// Gets a property from an object.
pub type ObjectGetFn = unsafe extern "C" fn(V8Value, V8Context, V8Value) -> V8Value;

/// Function type for v8::Object::Set(Context, Value, Value)
/// Sets a property on an object.
pub type ObjectSetFn = unsafe extern "C" fn(V8Value, V8Context, V8Value, V8Value) -> bool;

/// Function type for v8::String::NewFromUtf8
/// Creates a new string from UTF-8 encoded data.
pub type StringNewFromUtf8Fn =
    unsafe extern "C" fn(V8Isolate, *const c_char, c_int, c_int) -> V8String;

/// Function type for v8::String::Utf8Length
/// Returns the UTF-8 encoded length of the string.
pub type StringUtf8LengthFn = unsafe extern "C" fn(V8String, V8Isolate) -> c_int;

/// Function type for v8::String::WriteUtf8
/// Writes the UTF-8 encoded string to a buffer.
pub type StringWriteUtf8Fn =
    unsafe extern "C" fn(V8String, V8Isolate, *mut c_char, c_int, *mut c_int, c_int) -> c_int;

/// Function type for v8::Script::Compile
/// Compiles a script from source.
pub type ScriptCompileFn = unsafe extern "C" fn(V8Context, V8String, V8ScriptOrigin) -> V8Script;

/// Function type for v8::Script::Run(Context)
/// Runs the compiled script and returns the result.
pub type ScriptRunFn = unsafe extern "C" fn(V8Script, V8Context) -> V8Value;

/// Function type for v8::Script::Run used by hooks (method form)
/// This is the method signature: Script::Run(this, context) -> MaybeLocal<Value>
pub type ScriptRunMethodFn = unsafe extern "C" fn(*mut c_void, V8Context) -> V8Value;

/// Function type for v8::Function::Call
/// Calls the function with the given receiver and arguments.
pub type FunctionCallFn =
    unsafe extern "C" fn(V8Value, V8Context, V8Value, c_int, *const V8Value) -> V8Value;

// =============================================================================
// N-API FUNCTION POINTER TYPES
// =============================================================================

/// Function type for napi_module_register_by_symbol
/// Registers an N-API module with the given exports.
/// Signature: (Local<Object> exports, Local<Value> module, Local<Context> context,
///             napi_addon_register_func init, int32_t module_api_version)
pub type NapiModuleRegisterBySymbolFn = unsafe extern "C" fn(
    V8Object,              // exports
    V8Value,               // module
    V8Context,             // context
    NapiAddonRegisterFunc, // init
    c_int,                 // module_api_version
);

// =============================================================================
// LIBUV TYPES
// =============================================================================

/// Function type for uv_run(uv_loop_t*, uv_run_mode)
/// Runs the event loop.
pub type UvRunFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;

// =============================================================================
// TYPE ALIASES FOR BACKWARDS COMPATIBILITY
// =============================================================================

// script.rs uses snake_case naming convention
pub type v8_Isolate = V8Isolate;
pub type v8_Context = V8Context;
pub type v8_Value = V8Value;
pub type v8_String = V8String;
pub type v8_Script = V8Script;
pub type v8_ScriptOrigin = V8ScriptOrigin;
