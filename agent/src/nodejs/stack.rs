//! V8 Stack Parser FFI Bindings.
//!
//! This module provides Rust bindings for the C stack parser API that
//! reads JavaScript function parameter types directly from V8 stack frames.

#![allow(dead_code)]

use std::ffi::{c_char, c_int, c_void, CStr};
use std::fmt;

// =============================================================================
// VALUE TYPE ENUM
// =============================================================================

/// Detected JavaScript value types.
/// These match the C enum MalwiValueType from stack_parser.h.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueType {
    Smi = 0,
    HeapNumber = 1,
    String = 2,
    Symbol = 3,
    BigInt = 4,
    Undefined = 5,
    Null = 6,
    True = 7,
    False = 8,
    Array = 9,
    Function = 10,
    Object = 11,
    Promise = 12,
    Date = 13,
    RegExp = 14,
    ArrayBuffer = 15,
    TypedArray = 16,
    Map = 17,
    Set = 18,
    Error = 19,
    Unknown = 20,
}

impl ValueType {
    /// Convert from raw u8 value.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => ValueType::Smi,
            1 => ValueType::HeapNumber,
            2 => ValueType::String,
            3 => ValueType::Symbol,
            4 => ValueType::BigInt,
            5 => ValueType::Undefined,
            6 => ValueType::Null,
            7 => ValueType::True,
            8 => ValueType::False,
            9 => ValueType::Array,
            10 => ValueType::Function,
            11 => ValueType::Object,
            12 => ValueType::Promise,
            13 => ValueType::Date,
            14 => ValueType::RegExp,
            15 => ValueType::ArrayBuffer,
            16 => ValueType::TypedArray,
            17 => ValueType::Map,
            18 => ValueType::Set,
            19 => ValueType::Error,
            _ => ValueType::Unknown,
        }
    }

    /// Get the type name as a static string.
    pub fn name(&self) -> &'static str {
        match self {
            ValueType::Smi => "Smi",
            ValueType::HeapNumber => "HeapNumber",
            ValueType::String => "String",
            ValueType::Symbol => "Symbol",
            ValueType::BigInt => "BigInt",
            ValueType::Undefined => "undefined",
            ValueType::Null => "null",
            ValueType::True => "true",
            ValueType::False => "false",
            ValueType::Array => "Array",
            ValueType::Function => "Function",
            ValueType::Object => "Object",
            ValueType::Promise => "Promise",
            ValueType::Date => "Date",
            ValueType::RegExp => "RegExp",
            ValueType::ArrayBuffer => "ArrayBuffer",
            ValueType::TypedArray => "TypedArray",
            ValueType::Map => "Map",
            ValueType::Set => "Set",
            ValueType::Error => "Error",
            ValueType::Unknown => "unknown",
        }
    }

    /// Check if this is a primitive type.
    pub fn is_primitive(&self) -> bool {
        matches!(
            self,
            ValueType::Smi
                | ValueType::HeapNumber
                | ValueType::String
                | ValueType::Symbol
                | ValueType::BigInt
                | ValueType::Undefined
                | ValueType::Null
                | ValueType::True
                | ValueType::False
        )
    }

    /// Check if this is a boolean-like type.
    pub fn is_boolean(&self) -> bool {
        matches!(self, ValueType::True | ValueType::False)
    }

    /// Check if this is a nullish type (null or undefined).
    pub fn is_nullish(&self) -> bool {
        matches!(self, ValueType::Null | ValueType::Undefined)
    }
}

impl fmt::Display for ValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// =============================================================================
// FFI STRUCTURES
// =============================================================================

/// FFI structure for parameter info.
/// Matches MalwiParameterInfo from stack_parser.h.
#[repr(C)]
pub struct MalwiParameterInfo {
    /// MalwiValueType enum (C int)
    pub value_type: c_int,
    pub smi_value: i64,
    pub type_name: *const c_char,
    // Value extraction fields (new)
    pub heap_number_value: f64,
    pub string_value: *mut c_char,
    pub array_length: i32,
    pub function_name: *mut c_char,
}

/// FFI structure for parse result.
/// Matches MalwiFrameParseResult from stack_parser.h.
#[repr(C)]
pub struct MalwiFrameParseResult {
    pub success: bool,
    pub parameter_count: i32,
    pub parameters: *mut MalwiParameterInfo,
    pub error: *const c_char,
}

// =============================================================================
// FFI FUNCTION TYPES (for dynamic loading)
// =============================================================================

type ParseFrameParametersFn = unsafe extern "C" fn(usize) -> *mut MalwiFrameParseResult;
type ParseFrameParametersWithIsolateFn = unsafe extern "C" fn(usize, *mut c_void) -> *mut MalwiFrameParseResult;
type FreeFrameResultFn = unsafe extern "C" fn(*mut MalwiFrameParseResult);
type WalkToJsFrameFn = unsafe extern "C" fn(usize) -> usize;
type GetJsFrameFromIsolateFn = unsafe extern "C" fn(*mut c_void) -> usize;
type GetPlatformInfoFn = unsafe extern "C" fn() -> *const c_char;
type GetTypeNameFn = unsafe extern "C" fn(c_int) -> *const c_char;
type GetCurrentFunctionNameFn = unsafe extern "C" fn(*mut c_void) -> *mut c_char;
type CaptureStackTraceFn = unsafe extern "C" fn(*mut c_void, c_int) -> *mut c_char;

// =============================================================================
// DYNAMIC FFI LOADING
// =============================================================================

use std::sync::OnceLock;
use log::{debug, warn};

/// Cached FFI function pointers (resolved from addon via dlsym)
struct StackParserFfi {
    parse_frame_parameters: ParseFrameParametersFn,
    parse_frame_parameters_with_isolate: ParseFrameParametersWithIsolateFn,
    free_frame_result: FreeFrameResultFn,
    walk_to_js_frame: WalkToJsFrameFn,
    get_js_frame_from_isolate: GetJsFrameFromIsolateFn,
    get_platform_info: GetPlatformInfoFn,
    get_type_name: GetTypeNameFn,
    get_current_function_name: GetCurrentFunctionNameFn,
    capture_stack_trace: CaptureStackTraceFn,
}

/// Global FFI - resolved once when addon is loaded
static STACK_PARSER_FFI: OnceLock<StackParserFfi> = OnceLock::new();

/// Resolve stack parser FFI functions from the addon.
#[cfg(unix)]
pub fn resolve_stack_parser_ffi(addon_path: &std::path::Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    if STACK_PARSER_FFI.get().is_some() {
        return true; // Already resolved
    }

    debug!("Resolving stack parser FFI from {:?}", addon_path);

    unsafe {
        let path_cstr = match CString::new(addon_path.as_os_str().as_bytes()) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let handle = libc::dlopen(path_cstr.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        if handle.is_null() {
            let err = CStr::from_ptr(libc::dlerror());
            warn!("Failed to dlopen addon for stack parser: {:?}", err);
            return false;
        }

        macro_rules! resolve_sym {
            ($name:expr, $ty:ty) => {{
                let sym_name = CString::new($name).unwrap();
                let sym = libc::dlsym(handle, sym_name.as_ptr());
                if sym.is_null() {
                    warn!("Failed to resolve stack parser symbol: {}", $name);
                    return false;
                }
                std::mem::transmute::<*mut libc::c_void, $ty>(sym)
            }};
        }

        let ffi = StackParserFfi {
            parse_frame_parameters: resolve_sym!("malwi_parse_frame_parameters", ParseFrameParametersFn),
            parse_frame_parameters_with_isolate: resolve_sym!("malwi_parse_frame_parameters_with_isolate", ParseFrameParametersWithIsolateFn),
            free_frame_result: resolve_sym!("malwi_free_frame_result", FreeFrameResultFn),
            walk_to_js_frame: resolve_sym!("malwi_walk_to_js_frame", WalkToJsFrameFn),
            get_js_frame_from_isolate: resolve_sym!("malwi_get_js_frame_from_isolate", GetJsFrameFromIsolateFn),
            get_platform_info: resolve_sym!("malwi_get_platform_info", GetPlatformInfoFn),
            get_type_name: resolve_sym!("malwi_get_type_name", GetTypeNameFn),
            get_current_function_name: resolve_sym!("malwi_get_current_function_name", GetCurrentFunctionNameFn),
            capture_stack_trace: resolve_sym!("malwi_capture_stack_trace", CaptureStackTraceFn),
        };

        let _ = STACK_PARSER_FFI.set(ffi);
        debug!("Stack parser FFI resolved successfully");
        true
    }
}

#[cfg(not(unix))]
pub fn resolve_stack_parser_ffi(_addon_path: &std::path::Path) -> bool {
    warn!("Stack parser FFI not implemented for this platform");
    false
}

/// Check if stack parser FFI is available.
pub fn is_stack_parser_available() -> bool {
    STACK_PARSER_FFI.get().is_some()
}

// =============================================================================
// SAFE RUST WRAPPERS
// =============================================================================

/// Information about a single parameter.
#[derive(Debug, Clone)]
pub struct ParameterInfo {
    /// The detected type of this parameter.
    pub value_type: ValueType,
    /// If value_type is Smi, this contains the integer value.
    pub smi_value: Option<i64>,
    /// Human-readable type name.
    pub type_name: String,
    /// If value_type is HeapNumber, this contains the double value.
    pub heap_number_value: Option<f64>,
    /// If value_type is String, this contains the string content.
    pub string_value: Option<String>,
    /// If value_type is Array, this contains the array length.
    pub array_length: Option<i32>,
    /// If value_type is Function, this may contain the function name.
    pub function_name: Option<String>,
}

impl ParameterInfo {
    /// Create from FFI struct.
    unsafe fn from_ffi(ffi: &MalwiParameterInfo) -> Self {
        let value_type = ValueType::from_u8(ffi.value_type as u8);

        let smi_value = if value_type == ValueType::Smi {
            Some(ffi.smi_value)
        } else {
            None
        };

        let heap_number_value = if value_type == ValueType::HeapNumber {
            Some(ffi.heap_number_value)
        } else {
            None
        };

        let string_value = if !ffi.string_value.is_null() {
            Some(CStr::from_ptr(ffi.string_value).to_string_lossy().into_owned())
        } else {
            None
        };

        let array_length = if value_type == ValueType::Array && ffi.array_length >= 0 {
            Some(ffi.array_length)
        } else {
            None
        };

        let function_name = if !ffi.function_name.is_null() {
            Some(CStr::from_ptr(ffi.function_name).to_string_lossy().into_owned())
        } else {
            None
        };

        let type_name = if ffi.type_name.is_null() {
            value_type.name().to_string()
        } else {
            CStr::from_ptr(ffi.type_name)
                .to_string_lossy()
                .into_owned()
        };

        Self {
            value_type,
            smi_value,
            type_name,
            heap_number_value,
            string_value,
            array_length,
            function_name,
        }
    }
}

impl fmt::Display for ParameterInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.value_type {
            ValueType::Smi => {
                if let Some(val) = self.smi_value {
                    write!(f, "{}", val)
                } else {
                    write!(f, "Smi")
                }
            }
            ValueType::HeapNumber => {
                if let Some(val) = self.heap_number_value {
                    write!(f, "{}", val)
                } else {
                    write!(f, "Number")
                }
            }
            ValueType::String => {
                if let Some(ref s) = self.string_value {
                    // Show quoted string, truncate if too long
                    if s.len() > 64 {
                        write!(f, "\"{}...\"", &s[..61])
                    } else {
                        write!(f, "\"{}\"", s)
                    }
                } else {
                    write!(f, "String")
                }
            }
            ValueType::Array => {
                if let Some(len) = self.array_length {
                    write!(f, "[Array({})]", len)
                } else {
                    write!(f, "[Array]")
                }
            }
            ValueType::Function => {
                if let Some(ref name) = self.function_name {
                    if name.is_empty() {
                        write!(f, "[Function]")
                    } else {
                        write!(f, "[Function: {}]", name)
                    }
                } else {
                    write!(f, "[Function]")
                }
            }
            ValueType::Object => write!(f, "[Object]"),
            ValueType::Undefined => write!(f, "undefined"),
            ValueType::Null => write!(f, "null"),
            ValueType::True => write!(f, "true"),
            ValueType::False => write!(f, "false"),
            ValueType::Promise => write!(f, "[Promise]"),
            ValueType::Date => write!(f, "[Date]"),
            ValueType::RegExp => write!(f, "[RegExp]"),
            ValueType::Map => write!(f, "[Map]"),
            ValueType::Set => write!(f, "[Set]"),
            ValueType::ArrayBuffer => write!(f, "[ArrayBuffer]"),
            ValueType::TypedArray => write!(f, "[TypedArray]"),
            ValueType::Error => write!(f, "[Error]"),
            _ => write!(f, "{}", self.type_name),
        }
    }
}

/// Result of parsing frame parameters.
pub struct FrameParameters {
    params: Vec<ParameterInfo>,
}

impl FrameParameters {
    /// Get the number of parameters.
    pub fn len(&self) -> usize {
        self.params.len()
    }

    /// Check if there are no parameters.
    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }

    /// Get parameter at index.
    pub fn get(&self, index: usize) -> Option<&ParameterInfo> {
        self.params.get(index)
    }

    /// Iterate over parameters.
    pub fn iter(&self) -> impl Iterator<Item = &ParameterInfo> {
        self.params.iter()
    }

    /// Get parameter types as a string (e.g., "String, Smi(42), Object")
    pub fn types_string(&self) -> String {
        self.params
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Get parameter types as a simple list (e.g., "String, Smi, Object")
    pub fn type_names(&self) -> Vec<&str> {
        self.params.iter().map(|p| p.type_name.as_str()).collect()
    }
}

impl std::ops::Index<usize> for FrameParameters {
    type Output = ParameterInfo;

    fn index(&self, index: usize) -> &Self::Output {
        &self.params[index]
    }
}

impl IntoIterator for FrameParameters {
    type Item = ParameterInfo;
    type IntoIter = std::vec::IntoIter<ParameterInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.params.into_iter()
    }
}

impl<'a> IntoIterator for &'a FrameParameters {
    type Item = &'a ParameterInfo;
    type IntoIter = std::slice::Iter<'a, ParameterInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.params.iter()
    }
}

/// Parse parameters from a JavaScript stack frame.
///
/// # Arguments
/// * `frame_pointer` - The frame pointer (rbp on x64, x29 on arm64).
///   Must point to a valid V8 JavaScript frame.
///
/// # Returns
/// * `Some(FrameParameters)` - Successfully parsed parameters.
/// * `None` - Failed to parse (invalid frame pointer, FFI not loaded, etc.).
pub fn parse_frame_parameters(frame_pointer: usize) -> Option<FrameParameters> {
    if frame_pointer == 0 {
        return None;
    }

    let ffi = STACK_PARSER_FFI.get()?;

    unsafe {
        let result = (ffi.parse_frame_parameters)(frame_pointer);
        if result.is_null() {
            return None;
        }

        // Check if parsing succeeded
        if !(*result).success {
            (ffi.free_frame_result)(result);
            return None;
        }

        // Extract parameters
        let count = (*result).parameter_count as usize;
        let mut params = Vec::with_capacity(count);

        if count > 0 && !(*result).parameters.is_null() {
            let param_slice = std::slice::from_raw_parts((*result).parameters, count);
            for ffi_param in param_slice {
                params.push(ParameterInfo::from_ffi(ffi_param));
            }
        }

        // Free the C result
        (ffi.free_frame_result)(result);

        Some(FrameParameters { params })
    }
}

/// Walk from an entry/stub frame to the JavaScript frame.
///
/// When hooking Runtime_TraceEnter, the initial frame pointer is often
/// an exit frame or stub frame. This function walks the frame chain
/// to find the actual JavaScript frame.
///
/// # Arguments
/// * `entry_fp` - Frame pointer from C++ entry (e.g., from InvocationContext).
///
/// # Returns
/// * `Some(usize)` - Frame pointer of the JavaScript frame.
/// * `None` - Could not find a JavaScript frame or FFI not loaded.
pub fn walk_to_js_frame(entry_fp: usize) -> Option<usize> {
    if entry_fp == 0 {
        return None;
    }

    let ffi = STACK_PARSER_FFI.get()?;
    let js_fp = unsafe { (ffi.walk_to_js_frame)(entry_fp) };

    if js_fp == 0 {
        None
    } else {
        Some(js_fp)
    }
}

/// Get JavaScript frame pointer from V8 Isolate.
///
/// # Arguments
/// * `isolate` - Pointer to v8::Isolate.
///
/// # Returns
/// * `Some(usize)` - Frame pointer of the top JavaScript frame.
/// * `None` - No JavaScript frame found or FFI not loaded.
///
/// # Safety
/// The caller must ensure `isolate` is a valid v8::Isolate pointer.
pub unsafe fn get_js_frame_from_isolate(isolate: *mut c_void) -> Option<usize> {
    if isolate.is_null() {
        return None;
    }

    let ffi = STACK_PARSER_FFI.get()?;
    let fp = (ffi.get_js_frame_from_isolate)(isolate);

    if fp == 0 {
        None
    } else {
        Some(fp)
    }
}

/// Get platform information string.
///
/// Returns a string like "rbp, ptr_size=8" describing the current platform.
pub fn get_platform_info() -> String {
    let ffi = match STACK_PARSER_FFI.get() {
        Some(f) => f,
        None => return "unknown (FFI not loaded)".to_string(),
    };

    unsafe {
        let ptr = (ffi.get_platform_info)();
        if ptr.is_null() {
            return "unknown".to_string();
        }
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

/// Get the type name for a value type enum value.
pub fn get_type_name(value_type: ValueType) -> String {
    let ffi = match STACK_PARSER_FFI.get() {
        Some(f) => f,
        None => return value_type.name().to_string(),
    };

    unsafe {
        let ptr = (ffi.get_type_name)(value_type as c_int);
        if ptr.is_null() {
            return "unknown".to_string();
        }
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

// =============================================================================
// V8 ISOLATE INTEGRATION
// =============================================================================

/// Parse JavaScript function parameters using V8 Isolate.
///
/// This is the primary API for parameter type detection. It:
/// 1. Reads `c_entry_fp` from V8 Isolate's ThreadLocalTop
/// 2. Walks from the C++ entry frame to the JavaScript frame
/// 3. Parses parameter types from the JavaScript frame
///
/// # Arguments
/// * `isolate` - Pointer to v8::Isolate (can be obtained from N-API env or V8 API).
///
/// # Returns
/// * `Some(FrameParameters)` - Successfully parsed parameters.
/// * `None` - Failed to parse (no JS frame, invalid isolate, etc.).
///
/// # Safety
/// The caller must ensure `isolate` is a valid v8::Isolate pointer.
pub unsafe fn parse_parameters_from_isolate(isolate: *mut c_void) -> Option<FrameParameters> {
    // Get JS frame pointer from isolate's ThreadLocalTop
    let js_fp = get_js_frame_from_isolate(isolate)?;

    // Parse parameters using the with_isolate variant for better string extraction
    let ffi = STACK_PARSER_FFI.get()?;
    unsafe {
        let result = (ffi.parse_frame_parameters_with_isolate)(js_fp, isolate);
        if result.is_null() {
            return None;
        }

        // Check success
        if !(*result).success {
            (ffi.free_frame_result)(result);
            return None;
        }

        // Extract parameters
        let count = (*result).parameter_count as usize;
        let mut params = Vec::with_capacity(count);

        if count > 0 && !(*result).parameters.is_null() {
            let param_slice = std::slice::from_raw_parts((*result).parameters, count);
            for ffi_param in param_slice {
                params.push(ParameterInfo::from_ffi(ffi_param));
            }
        }

        // Free the C result
        (ffi.free_frame_result)(result);

        Some(FrameParameters { params })
    }
}

/// Format parameter types as a string for logging.
///
/// # Arguments
/// * `params` - Optional frame parameters.
///
/// # Returns
/// A string like "String, Smi(42), Object" or "(no parameters)" if None.
pub fn format_parameters(params: Option<&FrameParameters>) -> String {
    match params {
        Some(p) if !p.is_empty() => p.types_string(),
        Some(_) => "(no parameters)".to_string(),
        None => "(parse failed)".to_string(),
    }
}

// =============================================================================
// FUNCTION NAME AND STACK TRACE
// =============================================================================

/// Get the script path for the current JavaScript function.
///
/// Returns the script/file path of the function at the top of the stack.
/// Returns None if the function is from eval/inline code or FFI is not loaded.
///
/// # Arguments
/// * `isolate` - Pointer to v8::Isolate.
///
/// # Returns
/// * `Some(String)` - The script path (may be empty for eval/inline code).
/// * `None` - FFI not loaded or error capturing stack.
///
/// # Safety
/// The caller must ensure `isolate` is a valid v8::Isolate pointer.
pub unsafe fn get_current_script_path(isolate: *mut c_void) -> Option<String> {
    let frames = unsafe { capture_stack_trace(isolate, 1) }?;
    if frames.is_empty() {
        return None;
    }
    Some(frames[0].script.clone())
}

/// Get the current function name from V8's StackTrace API.
///
/// Uses V8's public StackTrace API to get the name of the function
/// at the top of the JavaScript call stack.
///
/// # Arguments
/// * `isolate` - Pointer to v8::Isolate. Can be null to use current isolate.
///
/// # Returns
/// * `Some(String)` - The function name.
/// * `None` - No JavaScript frame available or FFI not loaded.
///
/// # Safety
/// The caller should ensure the isolate pointer is valid if provided.
pub unsafe fn get_current_function_name(isolate: *mut c_void) -> Option<String> {
    let ffi = STACK_PARSER_FFI.get()?;

    unsafe {
        let name_ptr = (ffi.get_current_function_name)(isolate);
        if name_ptr.is_null() {
            return None;
        }

        // Convert to Rust String and free the C string
        let name = CStr::from_ptr(name_ptr).to_string_lossy().into_owned();
        libc::free(name_ptr as *mut c_void);
        Some(name)
    }
}

/// V8 stack frame information.
#[derive(Debug, Clone)]
pub struct V8StackFrame {
    pub function: String,
    pub script: String,
    pub line: i32,
    pub column: i32,
}

/// Capture the current V8 stack trace.
///
/// # Arguments
/// * `isolate` - Pointer to v8::Isolate. Can be null to use current isolate.
/// * `max_frames` - Maximum number of frames to capture. 0 for default (10).
///
/// # Returns
/// * `Some(Vec<V8StackFrame>)` - The stack frames.
/// * `None` - Failed to capture or FFI not loaded.
///
/// # Safety
/// The caller must ensure `isolate` is a valid v8::Isolate pointer, or null.
pub unsafe fn capture_stack_trace(isolate: *mut c_void, max_frames: i32) -> Option<Vec<V8StackFrame>> {
    let ffi = STACK_PARSER_FFI.get()?;

    unsafe {
        let json_ptr = (ffi.capture_stack_trace)(isolate, max_frames);
        if json_ptr.is_null() {
            return None;
        }

        // Parse JSON
        let json_str = CStr::from_ptr(json_ptr).to_string_lossy();
        let result = parse_stack_trace_json(&json_str);

        // Free the C string
        libc::free(json_ptr as *mut c_void);
        result
    }
}

/// Parse stack trace JSON into V8StackFrame structs.
fn parse_stack_trace_json(json: &str) -> Option<Vec<V8StackFrame>> {
    // Simple JSON parsing for our specific format:
    // [{"function":"name","script":"file.js","line":1,"column":2}, ...]

    if !json.starts_with('[') || !json.ends_with(']') {
        return None;
    }

    let inner = &json[1..json.len() - 1];
    if inner.is_empty() {
        return Some(Vec::new());
    }

    let mut frames = Vec::new();
    let mut depth = 0;
    let mut start = 0;

    // Split by top-level commas (depth 0)
    for (i, c) in inner.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => depth -= 1,
            ',' if depth == 0 => {
                if let Some(frame) = parse_single_frame(&inner[start..i]) {
                    frames.push(frame);
                }
                start = i + 1;
            }
            _ => {}
        }
    }

    // Parse last frame
    if start < inner.len() {
        if let Some(frame) = parse_single_frame(&inner[start..]) {
            frames.push(frame);
        }
    }

    Some(frames)
}

/// Parse a single JSON object into V8StackFrame.
fn parse_single_frame(json: &str) -> Option<V8StackFrame> {
    let json = json.trim();
    if !json.starts_with('{') || !json.ends_with('}') {
        return None;
    }

    let mut function = String::new();
    let mut script = String::new();
    let mut line = 0i32;
    let mut column = 0i32;

    // Extract fields using simple string matching
    for field in ["function", "script", "line", "column"] {
        let key = format!("\"{}\":", field);
        if let Some(pos) = json.find(&key) {
            let value_start = pos + key.len();
            let value_end = json[value_start..]
                .find([',', '}'])
                .map(|i| value_start + i)
                .unwrap_or(json.len());
            let value = json[value_start..value_end].trim();

            match field {
                "function" | "script" => {
                    // String value - remove quotes
                    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
                        let unquoted = &value[1..value.len() - 1];
                        // Unescape basic JSON escapes
                        let unescaped = unquoted
                            .replace("\\\"", "\"")
                            .replace("\\\\", "\\")
                            .replace("\\n", "\n")
                            .replace("\\r", "\r")
                            .replace("\\t", "\t");
                        if field == "function" {
                            function = unescaped;
                        } else {
                            script = unescaped;
                        }
                    }
                }
                "line" => {
                    line = value.parse().unwrap_or(0);
                }
                "column" => {
                    column = value.parse().unwrap_or(0);
                }
                _ => {}
            }
        }
    }

    Some(V8StackFrame {
        function,
        script,
        line,
        column,
    })
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_type_parses_all_known_types() {
        assert_eq!(ValueType::from_u8(0), ValueType::Smi);
        assert_eq!(ValueType::from_u8(2), ValueType::String);
        assert_eq!(ValueType::from_u8(11), ValueType::Object);
        assert_eq!(ValueType::from_u8(255), ValueType::Unknown);
    }

    #[test]
    fn test_value_type_displays_readable_name() {
        assert_eq!(ValueType::Smi.to_string(), "Smi");
        assert_eq!(ValueType::Undefined.to_string(), "undefined");
        assert_eq!(ValueType::Function.to_string(), "Function");
    }

    #[test]
    fn test_value_type_classifies_primitives_correctly() {
        assert!(ValueType::Smi.is_primitive());
        assert!(ValueType::String.is_primitive());
        assert!(ValueType::Undefined.is_primitive());
        assert!(!ValueType::Array.is_primitive());
        assert!(!ValueType::Object.is_primitive());
    }

    #[test]
    fn test_value_type_classifies_nullish_correctly() {
        assert!(ValueType::Null.is_nullish());
        assert!(ValueType::Undefined.is_nullish());
        assert!(!ValueType::Smi.is_nullish());
        assert!(!ValueType::False.is_nullish());
    }

    #[test]
    fn test_parameter_info_formats_name_and_value() {
        // Test Smi with value
        let param = ParameterInfo {
            value_type: ValueType::Smi,
            smi_value: Some(42),
            type_name: "Smi".to_string(),
            heap_number_value: None,
            string_value: None,
            array_length: None,
            function_name: None,
        };
        assert_eq!(param.to_string(), "42");

        // Test String with value
        let param2 = ParameterInfo {
            value_type: ValueType::String,
            smi_value: None,
            type_name: "String".to_string(),
            heap_number_value: None,
            string_value: Some("hello".to_string()),
            array_length: None,
            function_name: None,
        };
        assert_eq!(param2.to_string(), "\"hello\"");

        // Test Array with length
        let param3 = ParameterInfo {
            value_type: ValueType::Array,
            smi_value: None,
            type_name: "Array".to_string(),
            heap_number_value: None,
            string_value: None,
            array_length: Some(5),
            function_name: None,
        };
        assert_eq!(param3.to_string(), "[Array(5)]");

        // Test HeapNumber
        let param4 = ParameterInfo {
            value_type: ValueType::HeapNumber,
            smi_value: None,
            type_name: "HeapNumber".to_string(),
            heap_number_value: Some(1.5),
            string_value: None,
            array_length: None,
            function_name: None,
        };
        assert_eq!(param4.to_string(), "1.5");

        // Test Object
        let param5 = ParameterInfo {
            value_type: ValueType::Object,
            smi_value: None,
            type_name: "Object".to_string(),
            heap_number_value: None,
            string_value: None,
            array_length: None,
            function_name: None,
        };
        assert_eq!(param5.to_string(), "[Object]");
    }
}
