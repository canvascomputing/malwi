// V8 Stack Parser Implementation
//
// This file implements the stack parser for extracting JavaScript function
// parameter types from V8 stack frames.

#include "stack_parser.h"
#include "frame_constants.h"
#include "tagged_value.h"
#include "instance_types.h"

// V8 public API for StackTrace
#include <v8.h>

// V8 version macros (V8_MAJOR_VERSION, etc.)
#include <v8-version.h>

// Node.js version macros (NODE_MAJOR_VERSION, etc.)
#include <node_version.h>

// V8 internal header for Isolate layout constants
#include <v8-internal.h>

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sstream>

namespace malwi {
namespace v8_internal {

// =============================================================================
// Type Name Table
// =============================================================================

// Static type name strings (must match MalwiValueType enum order)
static const char* const kTypeNames[] = {
    "Smi",           // MALWI_TYPE_SMI
    "HeapNumber",    // MALWI_TYPE_HEAP_NUMBER
    "String",        // MALWI_TYPE_STRING
    "Symbol",        // MALWI_TYPE_SYMBOL
    "BigInt",        // MALWI_TYPE_BIGINT
    "undefined",     // MALWI_TYPE_UNDEFINED
    "null",          // MALWI_TYPE_NULL
    "true",          // MALWI_TYPE_TRUE
    "false",         // MALWI_TYPE_FALSE
    "Array",         // MALWI_TYPE_ARRAY
    "Function",      // MALWI_TYPE_FUNCTION
    "Object",        // MALWI_TYPE_OBJECT
    "Promise",       // MALWI_TYPE_PROMISE
    "Date",          // MALWI_TYPE_DATE
    "RegExp",        // MALWI_TYPE_REGEXP
    "ArrayBuffer",   // MALWI_TYPE_ARRAYBUFFER
    "TypedArray",    // MALWI_TYPE_TYPEDARRAY
    "Map",           // MALWI_TYPE_MAP
    "Set",           // MALWI_TYPE_SET
    "Error",         // MALWI_TYPE_ERROR
    "unknown"        // MALWI_TYPE_UNKNOWN
};

static_assert(sizeof(kTypeNames) / sizeof(kTypeNames[0]) == MALWI_TYPE_UNKNOWN + 1,
              "kTypeNames must match MalwiValueType enum");

// =============================================================================
// Type Classification
// =============================================================================

// Classify a tagged value and extract its value into MalwiParameterInfo
static MalwiValueType ClassifyValue(Tagged tagged_value, MalwiParameterInfo* info) {
    // Initialize all output fields
    info->smi_value = 0;
    info->heap_number_value = 0.0;
    info->string_value = nullptr;
    info->array_length = -1;
    info->function_name = nullptr;

    // Check Smi first (most common case for integer arguments)
    if (IsSmi(tagged_value)) {
        info->smi_value = SmiValue(tagged_value);
        return MALWI_TYPE_SMI;
    }

    // Must be a HeapObject - get instance type
    uint16_t instance_type;
    if (!SafeGetInstanceType(tagged_value, &instance_type)) {
        return MALWI_TYPE_UNKNOWN;
    }

    // Check for strings (all types below kFirstNonstringType)
    if (IsStringInstanceType(instance_type)) {
        // Extract string value (capped at MALWI_MAX_STRING_LENGTH)
        info->string_value = SafeReadStringValue(tagged_value, MALWI_MAX_STRING_LENGTH);
        return MALWI_TYPE_STRING;
    }

    // Check primitive-like heap types
    if (IsSymbolInstanceType(instance_type)) {
        return MALWI_TYPE_SYMBOL;
    }

    if (IsBigIntInstanceType(instance_type)) {
        return MALWI_TYPE_BIGINT;
    }

    if (IsHeapNumberInstanceType(instance_type)) {
        // Extract double value
        SafeReadHeapNumberValue(tagged_value, &info->heap_number_value);
        return MALWI_TYPE_HEAP_NUMBER;
    }

    // Check for Oddball (undefined, null, true, false)
    if (IsOddballInstanceType(instance_type)) {
        int kind = GetOddballKind(tagged_value);
        switch (kind) {
            case kOddballKindFalse:
                return MALWI_TYPE_FALSE;
            case kOddballKindTrue:
                return MALWI_TYPE_TRUE;
            case kOddballKindNull:
                return MALWI_TYPE_NULL;
            case kOddballKindUndefined:
                return MALWI_TYPE_UNDEFINED;
            default:
                // Other oddballs (hole, uninitialized) - treat as unknown
                return MALWI_TYPE_UNKNOWN;
        }
    }

    // Check for JSFunction
    if (IsJSFunctionInstanceType(instance_type)) {
        // Note: function name extraction is complex, skip for now
        return MALWI_TYPE_FUNCTION;
    }

    // Check for JSArray
    if (IsJSArrayInstanceType(instance_type)) {
        // Extract array length
        int32_t len;
        if (SafeReadArrayLength(tagged_value, &len)) {
            info->array_length = len;
        }
        return MALWI_TYPE_ARRAY;
    }

    // Check for specific object types
    if (IsJSPromiseInstanceType(instance_type)) {
        return MALWI_TYPE_PROMISE;
    }

    if (IsJSDateInstanceType(instance_type)) {
        return MALWI_TYPE_DATE;
    }

    if (IsJSRegExpInstanceType(instance_type)) {
        return MALWI_TYPE_REGEXP;
    }

    if (IsJSMapInstanceType(instance_type)) {
        return MALWI_TYPE_MAP;
    }

    if (IsJSSetInstanceType(instance_type)) {
        return MALWI_TYPE_SET;
    }

    if (IsJSArrayBufferInstanceType(instance_type)) {
        return MALWI_TYPE_ARRAYBUFFER;
    }

    if (IsJSTypedArrayInstanceType(instance_type)) {
        return MALWI_TYPE_TYPEDARRAY;
    }

    if (IsJSErrorInstanceType(instance_type)) {
        return MALWI_TYPE_ERROR;
    }

    // Generic JS object
    if (IsJSObjectInstanceType(instance_type)) {
        return MALWI_TYPE_OBJECT;
    }

    // Unknown type
    return MALWI_TYPE_UNKNOWN;
}

// =============================================================================
// Frame Parsing
// =============================================================================

// Create an error result
static MalwiFrameParseResult* CreateErrorResult(const char* error) {
    MalwiFrameParseResult* result = static_cast<MalwiFrameParseResult*>(
        malloc(sizeof(MalwiFrameParseResult)));
    if (!result) return nullptr;

    result->success = false;
    result->parameter_count = 0;
    result->parameters = nullptr;
    result->error = error;
    return result;
}

// Create a success result with allocated parameters array
static MalwiFrameParseResult* CreateSuccessResult(int32_t count) {
    MalwiFrameParseResult* result = static_cast<MalwiFrameParseResult*>(
        malloc(sizeof(MalwiFrameParseResult)));
    if (!result) return nullptr;

    result->success = true;
    result->parameter_count = count;
    result->error = nullptr;

    if (count > 0) {
        result->parameters = static_cast<MalwiParameterInfo*>(
            malloc(count * sizeof(MalwiParameterInfo)));
        if (!result->parameters) {
            free(result);
            return nullptr;
        }
    } else {
        result->parameters = nullptr;
    }

    return result;
}

} // namespace v8_internal
} // namespace malwi

// =============================================================================
// Forward Declarations
// =============================================================================

// Extract string value using V8's public API (defined below)
static char* ExtractStringValueV8(v8::Isolate* isolate, malwi::v8_internal::Tagged tagged_value, size_t max_len);

// =============================================================================
// Public API Implementation
// =============================================================================

using namespace malwi::v8_internal;

extern "C" {

// Get parameter count for the JS function at fp.
// V8 12.x: reads argc from frame (fp + kArgCOffset).
// V8 11.x: reads Function.length via V8 API (formal parameter count).
// Returns parameter count (excluding receiver), or -1 on failure.
static int32_t GetParameterCount(Address fp, v8::Isolate* isolate) {
#if V8_MAJOR_VERSION >= 12
    (void)isolate;
    Address argc_addr = fp + kArgCOffset;
    if (!IsValidPointer(argc_addr)) return -1;
    intptr_t raw_argc = *reinterpret_cast<intptr_t*>(argc_addr);
    if (raw_argc < 1 || raw_argc > 256) return -1;
    return static_cast<int32_t>(raw_argc - 1);
#else
    if (!isolate) return -1;
    v8::HandleScope scope(isolate);

    Address func_addr = fp + kFunctionOffset;
    if (!IsValidPointer(func_addr)) return -1;

    Tagged func_tagged = *reinterpret_cast<Tagged*>(func_addr);
    if (!IsHeapObject(func_tagged)) return -1;

    // Create a v8::Local pointing to the frame's function slot
    Tagged* func_slot = reinterpret_cast<Tagged*>(func_addr);
    v8::Local<v8::Value> local;
    memcpy(static_cast<void*>(&local), &func_slot, sizeof(func_slot));
    if (!local->IsFunction()) return -1;

    // Get .length property (formal parameter count) via property accessor
    v8::Local<v8::Function> func = local.As<v8::Function>();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    v8::Local<v8::String> length_key = v8::String::NewFromUtf8Literal(isolate, "length");
    v8::MaybeLocal<v8::Value> length_val = func->Get(context, length_key);
    if (length_val.IsEmpty()) return -1;
    v8::Maybe<int32_t> length_int = length_val.ToLocalChecked()->Int32Value(context);
    if (length_int.IsNothing()) return -1;
    return length_int.FromJust();
#endif
}

// Core: classify each parameter and optionally enhance strings using V8 API.
// When isolate is non-null, strings that weren't extracted by the basic method
// are re-extracted via V8's public API in the same pass (no second loop).
static MalwiFrameParseResult* ParseFrameParameters(
    Address fp, int32_t param_count, v8::Isolate* isolate) {

    Address caller_sp = GetCallerSP(fp);
    if (!IsValidPointer(caller_sp)) {
        return CreateErrorResult("invalid caller_sp");
    }

    MalwiFrameParseResult* result = CreateSuccessResult(param_count);
    if (!result) {
        return CreateErrorResult("allocation failed");
    }

    for (int32_t i = 0; i < param_count; i++) {
        Address param_slot = GetParameterSlot(caller_sp, i);
        Tagged tagged_value = 0;
        if (IsValidPointer(param_slot)) {
            tagged_value = *reinterpret_cast<Tagged*>(param_slot);
        }
        MalwiValueType type = ClassifyValue(tagged_value, &result->parameters[i]);
        result->parameters[i].type = type;
        result->parameters[i].type_name = kTypeNames[type];

        // V8 API string enhancement in the same pass (no re-read of frame slots)
        if (isolate && type == MALWI_TYPE_STRING &&
            result->parameters[i].string_value == nullptr && tagged_value != 0) {
            char* str = ExtractStringValueV8(isolate, tagged_value, MALWI_MAX_STRING_LENGTH);
            if (str) result->parameters[i].string_value = str;
        }
    }

    return result;
}

MalwiFrameParseResult* malwi_parse_frame_parameters(uintptr_t frame_pointer) {
    Address fp = static_cast<Address>(frame_pointer);
    if (fp == 0 || !IsValidPointer(fp)) {
        return CreateErrorResult("invalid frame pointer");
    }

    Address argc_addr = fp + kArgCOffset;
    if (!IsValidPointer(argc_addr)) {
        return CreateErrorResult("invalid argc address");
    }

    intptr_t raw_argc = *reinterpret_cast<intptr_t*>(argc_addr);
    if (raw_argc < 1 || raw_argc > 256) {
        return CreateErrorResult("argc out of range");
    }

    return ParseFrameParameters(fp, static_cast<int32_t>(raw_argc - 1), nullptr);
}

MalwiFrameParseResult* malwi_parse_frame_parameters_with_isolate(
    uintptr_t frame_pointer, void* isolate_ptr) {

    v8::Isolate* isolate = isolate_ptr
        ? static_cast<v8::Isolate*>(isolate_ptr)
        : v8::Isolate::GetCurrent();

    Address fp = static_cast<Address>(frame_pointer);
    if (fp == 0 || !IsValidPointer(fp)) {
        return CreateErrorResult("invalid frame pointer");
    }

    int32_t count = GetParameterCount(fp, isolate);
    if (count < 0) return CreateErrorResult("could not determine parameter count");
    if (count == 0) return CreateSuccessResult(0);

    v8::HandleScope handle_scope(isolate);
    return ParseFrameParameters(fp, count, isolate);
}

void malwi_free_frame_result(MalwiFrameParseResult* result) {
    if (result) {
        if (result->parameters) {
            // Free heap-allocated strings in each parameter
            for (int32_t i = 0; i < result->parameter_count; i++) {
                if (result->parameters[i].string_value) {
                    free(result->parameters[i].string_value);
                }
                if (result->parameters[i].function_name) {
                    free(result->parameters[i].function_name);
                }
            }
            free(result->parameters);
        }
        free(result);
    }
}

uintptr_t malwi_walk_to_js_frame(uintptr_t entry_fp) {
    // When hooking Runtime_TraceEnter, the frame chain is typically:
    //   entry_fp -> exit_frame -> stub_frame -> js_frame
    //
    // We walk the chain by following saved frame pointers.
    // Each frame's saved fp is at offset 0 from the current fp.

    if (entry_fp == 0 || !IsValidPointer(entry_fp)) {
        return 0;
    }

    Address fp = entry_fp;

    // Walk up to 5 frames to find the JS frame
    // (V8 11.x may have more intermediate frames than V8 12.x)
    for (int i = 0; i < 5; i++) {
        // Read the saved fp (previous frame pointer)
        Address saved_fp;
        if (!SafeReadPointer(fp, &saved_fp)) {
            return 0;
        }

        if (saved_fp == 0 || !IsValidPointer(saved_fp)) {
            return 0;
        }

        // Check if this looks like a JS frame:
        // 1. argc at fp-24 should be in reasonable range (1-256)
        // 2. JSFunction at fp-16 should be a HeapObject
        // argc is at fp-24 on all V8 versions (confirmed V8 11.8 and 12.x).
        Address argc_addr = saved_fp + kArgCOffset;
        if (IsValidPointer(argc_addr)) {
            intptr_t argc = *reinterpret_cast<intptr_t*>(argc_addr);
            if (argc >= 1 && argc <= 256) {
                Address func_addr = saved_fp + kFunctionOffset;
                if (IsValidPointer(func_addr)) {
                    Tagged func = *reinterpret_cast<Tagged*>(func_addr);
                    if (IsHeapObject(func)) {
                        return saved_fp;
                    }
                }
            }
        }

        fp = saved_fp;
    }

    // Didn't find a JS frame
    return 0;
}

// Cached c_entry_fp_ offset within ThreadLocalTop (resolved once)
static int g_c_entry_fp_offset = -1;

// Resolve the c_entry_fp_ offset within ThreadLocalTop.
// V8 12.x (Node 22+): c_entry_fp_ is at offset 0 (first field).
// V8 11.x (Node 21):  c_entry_fp_ is after ~15 fields, around offset 120.
// We probe candidate offsets and validate by trying to walk to a JS frame.
static int ResolveCEntryFpOffset(uintptr_t thread_local_top_addr) {
#if V8_MAJOR_VERSION >= 12
    return 0;  // V8 12.x: c_entry_fp_ is the first field
#else
    // V8 11.x: c_entry_fp_ is deep into ThreadLocalTop.
    // Probe candidate offsets based on the V8 11.8 struct layout.
    static const int candidates[] = {120, 128, 112, 104, 136};
    for (int off : candidates) {
        uintptr_t addr = thread_local_top_addr + off;
        if (!IsValidPointer(addr)) continue;
        uintptr_t value = *reinterpret_cast<uintptr_t*>(addr);
        if (value == 0 || !IsValidPointer(value)) continue;
        // Validate: try walking from this fp to find a JS frame
        uintptr_t js_fp = malwi_walk_to_js_frame(value);
        if (js_fp != 0) return off;
    }
    return 0;  // Fallback to offset 0
#endif
}

uintptr_t malwi_get_js_frame_from_isolate(void* isolate) {
    // This function reads the top JS frame from V8 Isolate's ThreadLocalTop.
    //
    // Layout (from v8-internal.h):
    //   Isolate + kIsolateThreadLocalTopOffset -> ThreadLocalTop
    //   ThreadLocalTop + c_entry_fp_offset -> c_entry_fp_
    //
    // The c_entry_fp_ offset varies by V8 version:
    //   V8 12.x (Node 22+): offset 0 (moved to front for cache locality)
    //   V8 11.x (Node 21):  offset ~120 (after 15+ fields)

    if (!isolate) {
        return 0;
    }

    // Get the offset to ThreadLocalTop within Isolate
    // This comes from v8::internal::Internals in v8-internal.h
    constexpr int kThreadLocalTopOffset =
        v8::internal::Internals::kIsolateThreadLocalTopOffset;

    // Calculate address of ThreadLocalTop
    uintptr_t isolate_addr = reinterpret_cast<uintptr_t>(isolate);
    uintptr_t thread_local_top = isolate_addr + kThreadLocalTopOffset;

    // Determine c_entry_fp offset (version-dependent, resolved once)
    if (g_c_entry_fp_offset < 0) {
        g_c_entry_fp_offset = ResolveCEntryFpOffset(thread_local_top);
    }

    uintptr_t c_entry_fp_addr = thread_local_top + g_c_entry_fp_offset;

    // Validate the address before reading
    if (!IsValidPointer(c_entry_fp_addr)) {
        return 0;
    }

    // Read c_entry_fp
    uintptr_t c_entry_fp = *reinterpret_cast<uintptr_t*>(c_entry_fp_addr);

    if (c_entry_fp == 0 || !IsValidPointer(c_entry_fp)) {
        return 0;
    }

    // Walk from c_entry_fp to find the JavaScript frame
    return malwi_walk_to_js_frame(c_entry_fp);
}

const char* malwi_get_platform_info(void) {
    static char info[64];
    static bool initialized = false;

    if (!initialized) {
        snprintf(info, sizeof(info), "%s, ptr_size=%zu",
                 kFramePointerRegName, kSystemPointerSize);
        initialized = true;
    }

    return info;
}

const char* malwi_get_type_name(MalwiValueType type) {
    if (type >= 0 && type <= MALWI_TYPE_UNKNOWN) {
        return kTypeNames[type];
    }
    return "invalid";
}

uint16_t malwi_get_raw_instance_type(uintptr_t tagged_value) {
    Tagged tagged = static_cast<Tagged>(tagged_value);

    // Check if it's a Smi (not a heap object)
    if (IsSmi(tagged)) {
        return 0xFFFE; // Special marker for Smi
    }

    // Get instance type
    uint16_t instance_type;
    if (!SafeGetInstanceType(tagged, &instance_type)) {
        return 0xFFFF; // Invalid
    }

    return instance_type;
}

} // extern "C" - temporarily close for C++ helper functions

// Helper to convert V8 String to heap-allocated C string
static char* V8StringToCString(v8::Isolate* isolate, v8::Local<v8::String> str) {
    if (str.IsEmpty()) {
        return nullptr;
    }

    // Get UTF-8 length
#if NODE_MAJOR_VERSION >= 24
    size_t len = str->Utf8LengthV2(isolate);
#else
    int len = str->Utf8Length(isolate);
#endif
    if (len <= 0) {
        return nullptr;
    }

    // Allocate buffer
    char* result = static_cast<char*>(malloc(len + 1));
    if (!result) {
        return nullptr;
    }

    // Write UTF-8
#if NODE_MAJOR_VERSION >= 24
    str->WriteUtf8V2(isolate, result, len + 1, v8::String::WriteFlags::kNullTerminate);
#else
    str->WriteUtf8(isolate, result, len + 1);
#endif
    return result;
}

// Convert raw tagged value to v8::Local<v8::Value>
// This mirrors how N-API's V8LocalValueFromJsValue works
static v8::Local<v8::Value> TaggedToLocal(Tagged tagged_value) {
    v8::Local<v8::Value> local;
    // The tagged value is stored in the Local's internal slot
    // v8::Local is just a wrapper around a pointer to a slot
    memcpy(static_cast<void*>(&local), &tagged_value, sizeof(tagged_value));
    return local;
}

// Extract string value from tagged pointer using V8's public API
// Returns heap-allocated string or nullptr. Caller must free().
static char* ExtractStringValueV8(v8::Isolate* isolate, Tagged tagged_value, size_t max_len) {
    if (!isolate) {
        return nullptr;
    }

    // Convert to Local
    v8::Local<v8::Value> local = TaggedToLocal(tagged_value);

    // Check if it's a string
    if (!local->IsString()) {
        return nullptr;
    }

    v8::Local<v8::String> str = local.As<v8::String>();

    // Get UTF-8 length
#if NODE_MAJOR_VERSION >= 24
    size_t utf8_len = str->Utf8LengthV2(isolate);
#else
    int utf8_len = str->Utf8Length(isolate);
#endif
    if (utf8_len <= 0) {
        return nullptr;
    }

    // Cap at max_len
    size_t copy_len = (static_cast<size_t>(utf8_len) > max_len) ? max_len : static_cast<size_t>(utf8_len);

    // Allocate buffer
    char* result = static_cast<char*>(malloc(copy_len + 1));
    if (!result) {
        return nullptr;
    }

    // Write UTF-8 with null termination
#if NODE_MAJOR_VERSION >= 24
    str->WriteUtf8V2(isolate, result, copy_len + 1,
                     v8::String::WriteFlags::kReplaceInvalidUtf8);
#else
    str->WriteUtf8(isolate, result, copy_len + 1, nullptr,
                   v8::String::REPLACE_INVALID_UTF8 | v8::String::NO_NULL_TERMINATION);
#endif
    result[copy_len] = '\0';

    return result;
}

extern "C" {

char* malwi_get_current_function_name(void* isolate_ptr) {
    // Get isolate
    v8::Isolate* isolate = isolate_ptr
        ? static_cast<v8::Isolate*>(isolate_ptr)
        : v8::Isolate::GetCurrent();

    if (!isolate) {
        return nullptr;
    }

    // Create a scope for V8 handles
    v8::HandleScope handle_scope(isolate);

    // Read the function name directly from the V8 JS frame instead of using
    // v8::StackTrace::CurrentStackTrace. CurrentStackTrace walks ALL frames
    // including TurboFan-optimized ones, and crashes with "Missing deoptimization
    // information for OptimizedFrame::Summarize" when an optimized frame lacks
    // deopt metadata. Reading from the frame directly avoids this entirely.

    // Get the top JS frame from isolate (walks c_entry_fp -> JS frame)
    uintptr_t js_fp = malwi_get_js_frame_from_isolate(isolate);
    if (js_fp == 0) {
        return nullptr;
    }

    // Read the JSFunction tagged value from the frame's function slot
    using namespace malwi::v8_internal;
    Address func_addr = static_cast<Address>(js_fp) + kFunctionOffset;
    if (!IsValidPointer(func_addr)) {
        return nullptr;
    }

    Tagged func_tagged = *reinterpret_cast<Tagged*>(func_addr);
    if (!IsHeapObject(func_tagged)) {
        return nullptr;
    }

    // Create a v8::Local pointing to the frame's function slot.
    // v8::Local<T> stores a T** (pointer to a handle slot). The stack slot
    // at func_addr holds the tagged JSFunction value, which serves as a
    // valid handle slot since it contains a full-width tagged pointer.
    Tagged* func_slot = reinterpret_cast<Tagged*>(func_addr);
    v8::Local<v8::Value> local;
    memcpy(static_cast<void*>(&local), &func_slot, sizeof(func_slot));

    if (!local->IsFunction()) {
        return nullptr;
    }

    v8::Local<v8::Function> func = local.As<v8::Function>();
    v8::Local<v8::Value> name = func->GetName();
    if (!name.IsEmpty() && name->IsString()) {
        v8::Local<v8::String> name_str = name.As<v8::String>();
        if (name_str->Length() > 0) {
            return V8StringToCString(isolate, name_str);
        }
    }

    // No function name found
    return nullptr;
}

char* malwi_capture_stack_trace(void* isolate_ptr, int max_frames) {
    // Get isolate
    v8::Isolate* isolate = isolate_ptr
        ? static_cast<v8::Isolate*>(isolate_ptr)
        : v8::Isolate::GetCurrent();

    if (!isolate) {
        return nullptr;
    }

    // Default max frames
    if (max_frames <= 0) {
        max_frames = 10;
    }

    // Create a scope for V8 handles
    v8::HandleScope handle_scope(isolate);

    // Capture stack trace
    v8::Local<v8::StackTrace> stack = v8::StackTrace::CurrentStackTrace(
        isolate,
        max_frames,
        v8::StackTrace::kDetailed
    );

    if (stack.IsEmpty()) {
        return nullptr;
    }

    // Build JSON array
    std::ostringstream json;
    json << "[";

    int frame_count = stack->GetFrameCount();
    for (int i = 0; i < frame_count; i++) {
        v8::Local<v8::StackFrame> frame = stack->GetFrame(isolate, i);
        if (frame.IsEmpty()) {
            continue;
        }

        if (i > 0) {
            json << ",";
        }

        json << "{";

        // Function name
        v8::Local<v8::String> func_name = frame->GetFunctionName();
        json << "\"function\":\"";
        if (!func_name.IsEmpty()) {
            v8::String::Utf8Value utf8(isolate, func_name);
            if (*utf8) {
                // Escape JSON string
                for (const char* p = *utf8; *p; p++) {
                    switch (*p) {
                        case '"': json << "\\\""; break;
                        case '\\': json << "\\\\"; break;
                        case '\n': json << "\\n"; break;
                        case '\r': json << "\\r"; break;
                        case '\t': json << "\\t"; break;
                        default: json << *p; break;
                    }
                }
            }
        }
        json << "\"";

        // Script name
        v8::Local<v8::String> script_name = frame->GetScriptName();
        json << ",\"script\":\"";
        if (!script_name.IsEmpty()) {
            v8::String::Utf8Value utf8(isolate, script_name);
            if (*utf8) {
                for (const char* p = *utf8; *p; p++) {
                    switch (*p) {
                        case '"': json << "\\\""; break;
                        case '\\': json << "\\\\"; break;
                        default: json << *p; break;
                    }
                }
            }
        }
        json << "\"";

        // Line and column
        json << ",\"line\":" << frame->GetLineNumber();
        json << ",\"column\":" << frame->GetColumn();

        json << "}";
    }

    json << "]";

    // Convert to C string
    std::string str = json.str();
    char* result = static_cast<char*>(malloc(str.size() + 1));
    if (result) {
        strcpy(result, str.c_str());
    }
    return result;
}

} // extern "C"
