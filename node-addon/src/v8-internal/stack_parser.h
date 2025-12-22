// V8 Stack Parser - Public C API
//
// This header defines the public FFI interface for parsing V8 JavaScript
// stack frames to extract parameter type information.
//
// Usage:
// ======
//
// 1. Get frame pointer from V8 Isolate
// 2. Call malwi_parse_frame_parameters(fp)
// 3. Iterate through result->parameters for type info
// 4. Call malwi_free_frame_result() when done
//
// Example:
// --------
//
//   MalwiFrameParseResult* result = malwi_parse_frame_parameters(fp);
//   if (result && result->success) {
//       for (int i = 0; i < result->parameter_count; i++) {
//           printf("param[%d]: %s\n", i, result->parameters[i].type_name);
//       }
//   }
//   malwi_free_frame_result(result);

#ifndef MALWI_STACK_PARSER_H
#define MALWI_STACK_PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Value Type Enumeration
// =============================================================================

// Detected JavaScript value types
// These map to V8's instance types but are simplified for tracing purposes
typedef enum {
    MALWI_TYPE_SMI = 0,           // Small integer (value directly available)
    MALWI_TYPE_HEAP_NUMBER,       // Double-precision float
    MALWI_TYPE_STRING,            // Any string type
    MALWI_TYPE_SYMBOL,            // ES6 Symbol
    MALWI_TYPE_BIGINT,            // BigInt
    MALWI_TYPE_UNDEFINED,         // undefined
    MALWI_TYPE_NULL,              // null
    MALWI_TYPE_TRUE,              // true
    MALWI_TYPE_FALSE,             // false
    MALWI_TYPE_ARRAY,             // Array
    MALWI_TYPE_FUNCTION,          // Function
    MALWI_TYPE_OBJECT,            // Generic object
    MALWI_TYPE_PROMISE,           // Promise
    MALWI_TYPE_DATE,              // Date
    MALWI_TYPE_REGEXP,            // RegExp
    MALWI_TYPE_ARRAYBUFFER,       // ArrayBuffer
    MALWI_TYPE_TYPEDARRAY,        // TypedArray (Int8Array, etc.)
    MALWI_TYPE_MAP,               // Map
    MALWI_TYPE_SET,               // Set
    MALWI_TYPE_ERROR,             // Error (any subtype)
    MALWI_TYPE_UNKNOWN            // Unrecognized type
} MalwiValueType;

// =============================================================================
// Result Structures
// =============================================================================

// Maximum string length to extract (prevents huge allocations)
#define MALWI_MAX_STRING_LENGTH 64

// Information about a single parameter
typedef struct {
    MalwiValueType type;          // Detected type
    int64_t smi_value;            // Value if type == MALWI_TYPE_SMI
    const char* type_name;        // Human-readable type name (static string)

    // Value extraction fields (new)
    double heap_number_value;     // Value if type == MALWI_TYPE_HEAP_NUMBER
    char* string_value;           // Heap-allocated string content (caller must free)
    int32_t array_length;         // Array length if type == MALWI_TYPE_ARRAY (-1 if unknown)
    char* function_name;          // Heap-allocated function name (caller must free)
} MalwiParameterInfo;

// Result of parsing frame parameters
typedef struct {
    bool success;                 // True if parsing succeeded
    int32_t parameter_count;      // Number of parameters (excluding receiver)
    MalwiParameterInfo* parameters; // Array of parameter info
    const char* error;            // Error message if !success
} MalwiFrameParseResult;

// =============================================================================
// Public API
// =============================================================================

// Parse parameters from a JavaScript stack frame
//
// Parameters:
//   frame_pointer: The frame pointer (rbp on x64, x29 on arm64)
//                  Must point to a valid V8 JavaScript frame
//
// Returns:
//   Heap-allocated result structure. Caller must free with malwi_free_frame_result().
//   Returns NULL on allocation failure.
//
// Notes:
//   - The frame_pointer should be the fp of the JavaScript frame, not an
//     intermediate stub or exit frame.
//   - Use malwi_walk_to_js_frame() if you have a C++ entry frame pointer.
//
__attribute__((visibility("default")))
MalwiFrameParseResult* malwi_parse_frame_parameters(uintptr_t frame_pointer);

// Parse parameters from a JavaScript stack frame with isolate for V8 API access
//
// Same as malwi_parse_frame_parameters but also uses V8's public API for
// more robust value extraction (especially strings).
//
// Parameters:
//   frame_pointer: The frame pointer (rbp on x64, x29 on arm64)
//   isolate: Pointer to v8::Isolate (required for V8 API string extraction)
//
// Returns:
//   Heap-allocated result structure. Caller must free with malwi_free_frame_result().
//
__attribute__((visibility("default")))
MalwiFrameParseResult* malwi_parse_frame_parameters_with_isolate(
    uintptr_t frame_pointer, void* isolate);

// Free a parse result
//
// Parameters:
//   result: Result returned by malwi_parse_frame_parameters(). May be NULL.
//
__attribute__((visibility("default")))
void malwi_free_frame_result(MalwiFrameParseResult* result);

// Walk from an entry/stub frame to the JavaScript frame
//
// When hooking Runtime_TraceEnter, the initial frame pointer is often
// an exit frame or stub frame. This function walks the frame chain
// to find the actual JavaScript frame.
//
// Parameters:
//   entry_fp: Frame pointer from C++ entry (e.g., from InvocationContext)
//
// Returns:
//   Frame pointer of the JavaScript frame, or 0 if not found.
//
// Notes:
//   Walks: entry_fp -> exit_frame -> stub_frame -> js_frame
//
__attribute__((visibility("default")))
uintptr_t malwi_walk_to_js_frame(uintptr_t entry_fp);

// Get JavaScript frame pointer from V8 Isolate
//
// Reads the top JavaScript frame pointer from the Isolate's ThreadLocalTop.
//
// Parameters:
//   isolate: Pointer to v8::Isolate
//
// Returns:
//   Frame pointer of the top JavaScript frame, or 0 if none.
//
// Notes:
//   This relies on V8 internals and may break with V8 version changes.
//   Use malwi_walk_to_js_frame() with InvocationContext when possible.
//
__attribute__((visibility("default")))
uintptr_t malwi_get_js_frame_from_isolate(void* isolate);

// Get platform information string
//
// Returns a static string describing the current platform configuration.
// Useful for debugging.
//
// Returns:
//   Static string like "x64, ptr_size=8"
//
__attribute__((visibility("default")))
const char* malwi_get_platform_info(void);

// Get type name for a value type
//
// Parameters:
//   type: Value type enum
//
// Returns:
//   Static string name for the type
//
__attribute__((visibility("default")))
const char* malwi_get_type_name(MalwiValueType type);

// Get raw instance type from a tagged value (for debugging)
// Returns the raw instance type, or 0xFFFF if not a valid heap object
__attribute__((visibility("default")))
uint16_t malwi_get_raw_instance_type(uintptr_t tagged_value);

// Get the current function name from V8's StackTrace API
//
// Uses V8's public StackTrace API to get the name of the function
// at the top of the JavaScript call stack.
//
// Parameters:
//   isolate: Pointer to v8::Isolate (can be NULL to use current)
//
// Returns:
//   Heap-allocated C string with function name. Caller must free().
//   Returns NULL if no JavaScript frame is available.
//
// Notes:
//   This is the preferred method for getting function names as it uses
//   V8's public API and handles all the complexity of name resolution
//   (debug names, inferred names, etc.)
//
__attribute__((visibility("default")))
char* malwi_get_current_function_name(void* isolate);

// Get full stack trace as JSON
//
// Captures the current V8 stack trace and returns it as a JSON array.
//
// Parameters:
//   isolate: Pointer to v8::Isolate (can be NULL to use current)
//   max_frames: Maximum number of frames to capture (0 = default 10)
//
// Returns:
//   Heap-allocated JSON string. Caller must free().
//   Returns NULL on failure.
//
// Example output:
//   [{"function":"readFile","script":"fs.js","line":123,"column":45}, ...]
//
__attribute__((visibility("default")))
char* malwi_capture_stack_trace(void* isolate, int max_frames);

#ifdef __cplusplus
}
#endif

#endif // MALWI_STACK_PARSER_H
