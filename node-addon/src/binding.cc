// Pure N-API Function Wrapping for V8 Tracing
//
// This addon wraps JavaScript functions with C++ wrappers to trace calls.
// Uses napi_get_cb_info() for clean argument access.
// No --trace flag, no frame walking.

#include <node_api.h>
#include <node_version.h>
#include <v8.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <mutex>
#include <atomic>
#include <thread>
#include <ctime>
#include <unordered_set>

// Stack parser for direct parameter type detection
#include "v8-internal/stack_parser.h"

// =============================================================================
// FFI STRUCTS (shared with Rust)
// =============================================================================

// FFI struct for passing argument data to Rust (no JSON)
struct V8TraceArgument {
    uint32_t index;
    const char* type_hint;      // nullable
    uint32_t type_hint_len;
    const char* display;
    uint32_t display_len;
};

// FFI struct for passing trace event data to Rust (no JSON)
struct V8TraceEventData {
    uint64_t timestamp_ns;
    uint64_t thread_id;
    uint8_t event_type;         // 0 = Enter, 1 = Leave
    const char* function;
    uint32_t function_len;
    const char* script_path;    // Script origin path (e.g., "node:fs")
    uint32_t script_path_len;
    const char* return_value;   // nullable, for Leave events
    uint32_t return_value_len;
    uint32_t arg_count;
    const V8TraceArgument* arguments;  // pointer to array
};

// =============================================================================
// TYPES AND GLOBALS
// =============================================================================

// Callback signature for trace events (called into Rust)
// Returns 1 to continue execution, 0 to block the function call.
// This enables review mode where the user can approve/deny function calls.
// Uses int32_t instead of bool for reliable C ABI compatibility with Rust.
typedef int32_t (*TraceCallback)(const V8TraceEventData* event);

// Global state with thread safety
static std::mutex g_state_mutex;
static TraceCallback g_trace_callback = nullptr;
static napi_env g_env = nullptr;
static std::atomic<bool> g_tracing_enabled{false};

// Pending filters (stored before g_env is available)
struct PendingFilter {
    std::string pattern;
    bool capture_stack;
};
static std::vector<PendingFilter> g_pending_filters;

// Active filters (kept after Init for require hook matching)
static std::vector<PendingFilter> g_active_filters;

// Reference to original Module.prototype.require
static napi_ref g_original_require_ref = nullptr;

// Reference to Module.prototype for installing hooks
static napi_ref g_module_proto_ref = nullptr;

// Wrapper context - stores original function and metadata
struct WrapperContext {
    napi_ref original_ref;      // Reference to original function
    std::string function_name;  // Full function name (e.g., "console.log")
    std::string script_path;    // Script origin path (e.g., "node:fs")
    bool capture_stack;         // Whether to capture stack traces
};

// Store all wrapper contexts to prevent GC
static std::vector<WrapperContext*> g_contexts;

// =============================================================================
// CONSTANTS
// =============================================================================

namespace limits {
    constexpr size_t MAX_ARGS = 32;              // Maximum function arguments to capture
    constexpr size_t MAX_FUNC_NAME = 128;        // Maximum function name buffer size
    constexpr size_t MAX_MODULE_NAME = 256;      // Maximum module name buffer size
    constexpr int MAX_RECURSION_DEPTH = 3;       // Maximum depth for recursive wrapping
    constexpr size_t MAX_STRING_DISPLAY = 200;   // Maximum string length to display
    constexpr size_t MAX_ERROR_MSG = 50;         // Maximum error message length
    constexpr size_t MAX_ARRAY_EXPAND = 10;      // Maximum array elements to expand (string arrays)
    constexpr uint32_t MAX_OBJECT_PROPS = 5;     // Maximum object properties to show
}

// =============================================================================
// CLEANUP HELPERS
// =============================================================================

// Clean up hook references (called on error paths)
static void CleanupHookReferences(napi_env env) {
    if (g_original_require_ref) {
        napi_delete_reference(env, g_original_require_ref);
        g_original_require_ref = nullptr;
    }
    if (g_module_proto_ref) {
        napi_delete_reference(env, g_module_proto_ref);
        g_module_proto_ref = nullptr;
    }
}

// =============================================================================
// JSON ESCAPING
// =============================================================================

static std::string escape_json_string(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
            case '"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if (c <= '\x1f') {
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)(unsigned char)c;
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

// Shell characters that require quoting
static bool needs_shell_quoting(const std::string& s) {
    if (s.empty()) return true;
    for (char c : s) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '"' || c == '\'' ||
            c == '\\' || c == '$' || c == '`' || c == '!' || c == '*' ||
            c == '?' || c == '[' || c == ']' || c == '#' || c == '~' ||
            c == '=' || c == '%' || c == '|' || c == '&' || c == ';' ||
            c == '<' || c == '>' || c == '(' || c == ')' || c == '{' ||
            c == '}' || c == '^') {
            return true;
        }
    }
    return false;
}

// Quote a shell argument if needed
static std::string quote_shell_arg(const std::string& s) {
    if (s.empty()) return "''";
    if (!needs_shell_quoting(s)) return s;

    // Prefer single quotes if no single quotes in string
    if (s.find('\'') == std::string::npos) {
        return "'" + s + "'";
    }

    // Use double quotes with escaping
    std::string result = "\"";
    for (char c : s) {
        if (c == '"' || c == '\\' || c == '$' || c == '`') {
            result += '\\';
        }
        result += c;
    }
    result += "\"";
    return result;
}

// Format string array as shell command
static std::string format_shell_command(const std::vector<std::string>& args) {
    std::string result;
    for (size_t i = 0; i < args.size(); i++) {
        if (i > 0) result += " ";
        result += quote_shell_arg(args[i]);
    }
    return result;
}

// =============================================================================
// VALUE INFO (unified type and display extraction)
// =============================================================================

// Unified struct containing both type name and display value
struct ValueInfo {
    std::string type_name;
    std::string display;
};

// Get both type name and formatted display value in a single pass
static ValueInfo get_value_info(napi_env env, napi_value val, int depth = 2) {
    ValueInfo info;

    if (!val) {
        info.type_name = "undefined";
        info.display = "undefined";
        return info;
    }

    napi_valuetype type;
    if (napi_typeof(env, val, &type) != napi_ok) {
        info.type_name = "unknown";
        info.display = "[error]";
        return info;
    }

    switch (type) {
        case napi_undefined:
            info.type_name = "undefined";
            info.display = "undefined";
            break;

        case napi_null:
            info.type_name = "null";
            info.display = "null";
            break;

        case napi_boolean: {
            bool b;
            if (napi_get_value_bool(env, val, &b) == napi_ok) {
                info.type_name = b ? "true" : "false";
                info.display = b ? "true" : "false";
            } else {
                info.type_name = "boolean";
                info.display = "[boolean]";
            }
            break;
        }

        case napi_number: {
            double d;
            if (napi_get_value_double(env, val, &d) == napi_ok) {
                // Type: Smi for small integers, HeapNumber otherwise
                if (d == static_cast<int64_t>(d) && d >= -2147483648.0 && d <= 2147483647.0) {
                    info.type_name = "Smi";
                } else {
                    info.type_name = "HeapNumber";
                }
                // Display: format nicely (no decimals for integers)
                if (d == static_cast<int64_t>(d) && d >= -9007199254740992.0 && d <= 9007199254740992.0) {
                    info.display = std::to_string(static_cast<int64_t>(d));
                } else {
                    std::ostringstream oss;
                    oss << d;
                    info.display = oss.str();
                }
            } else {
                info.type_name = "number";
                info.display = "[number]";
            }
            break;
        }

        case napi_string: {
            info.type_name = "String";
            size_t len;
            if (napi_get_value_string_utf8(env, val, NULL, 0, &len) != napi_ok) {
                info.display = "[string]";
                break;
            }
            std::string str(len, '\0');
            if (napi_get_value_string_utf8(env, val, &str[0], len + 1, NULL) != napi_ok) {
                info.display = "[string]";
                break;
            }
            // Truncate long strings
            if (str.length() > limits::MAX_STRING_DISPLAY) {
                str = str.substr(0, limits::MAX_STRING_DISPLAY) + "...";
            }
            info.display = "\"" + escape_json_string(str) + "\"";
            break;
        }

        case napi_symbol:
            info.type_name = "Symbol";
            info.display = "[Symbol]";
            break;

        case napi_object: {
            // Check for specific object subtypes
            bool is_array;
            if (napi_is_array(env, val, &is_array) == napi_ok && is_array) {
                info.type_name = "Array";
                uint32_t length;
                if (napi_get_array_length(env, val, &length) != napi_ok) {
                    info.display = "[Array]";
                    break;
                }

                // Try to expand small string arrays as shell commands
                if (length <= limits::MAX_ARRAY_EXPAND) {
                    bool all_strings = true;
                    std::vector<std::string> elements;
                    elements.reserve(length);

                    for (uint32_t i = 0; i < length && all_strings; i++) {
                        napi_value elem;
                        if (napi_get_element(env, val, i, &elem) != napi_ok) {
                            all_strings = false;
                            break;
                        }
                        napi_valuetype elem_type;
                        if (napi_typeof(env, elem, &elem_type) != napi_ok || elem_type != napi_string) {
                            all_strings = false;
                            break;
                        }
                        size_t len;
                        if (napi_get_value_string_utf8(env, elem, NULL, 0, &len) != napi_ok) {
                            all_strings = false;
                            break;
                        }
                        std::string str(len, '\0');
                        if (napi_get_value_string_utf8(env, elem, &str[0], len + 1, NULL) != napi_ok) {
                            all_strings = false;
                            break;
                        }
                        elements.push_back(str);
                    }

                    if (all_strings && !elements.empty()) {
                        info.display = format_shell_command(elements);
                        break;
                    }

                    // Expand small mixed-type arrays
                    if (length <= limits::MAX_ARRAY_EXPAND && depth > 0) {
                        std::string result = "[";
                        for (uint32_t i = 0; i < length; i++) {
                            napi_value elem;
                            napi_get_element(env, val, i, &elem);
                            ValueInfo vi = get_value_info(env, elem, depth - 1);
                            if (i > 0) result += ", ";
                            result += vi.display;
                        }
                        result += "]";
                        info.display = result;
                        break;
                    }
                }

                info.display = "[Array(" + std::to_string(length) + ")]";
                break;
            }

            bool is_buffer;
            if (napi_is_buffer(env, val, &is_buffer) == napi_ok && is_buffer) {
                info.type_name = "Buffer";
                size_t length;
                void* data;
                if (napi_get_buffer_info(env, val, &data, &length) == napi_ok) {
                    if (length <= 64 && data && length > 0) {
                        // Show content preview for small buffers
                        const uint8_t* bytes = static_cast<const uint8_t*>(data);
                        bool printable = true;
                        for (size_t i = 0; i < length && printable; i++) {
                            printable = (bytes[i] >= 0x20 && bytes[i] < 0x7f) || bytes[i] == '\n' || bytes[i] == '\t';
                        }
                        if (printable) {
                            std::string preview(static_cast<const char*>(data), std::min(length, (size_t)64));
                            info.display = "[Buffer \"" + escape_json_string(preview) + "\"]";
                        } else {
                            info.display = "[Buffer(" + std::to_string(length) + " bytes)]";
                        }
                    } else {
                        info.display = "[Buffer(" + std::to_string(length) + " bytes)]";
                    }
                } else {
                    info.display = "[Buffer]";
                }
                break;
            }

            bool is_promise;
            if (napi_is_promise(env, val, &is_promise) == napi_ok && is_promise) {
                info.type_name = "Promise";
                info.display = "[Promise]";
                break;
            }

            bool is_arraybuffer;
            if (napi_is_arraybuffer(env, val, &is_arraybuffer) == napi_ok && is_arraybuffer) {
                info.type_name = "ArrayBuffer";
                info.display = "[ArrayBuffer]";
                break;
            }

            bool is_typedarray;
            if (napi_is_typedarray(env, val, &is_typedarray) == napi_ok && is_typedarray) {
                napi_typedarray_type arr_type;
                size_t ta_length;
                void* ta_data;
                napi_value arraybuf;
                size_t ta_offset;
                if (napi_get_typedarray_info(env, val, &arr_type, &ta_length, &ta_data, &arraybuf, &ta_offset) == napi_ok) {
                    const char* type_names[] = {
                        "Int8Array", "Uint8Array", "Uint8ClampedArray",
                        "Int16Array", "Uint16Array", "Int32Array", "Uint32Array",
                        "Float32Array", "Float64Array", "BigInt64Array", "BigUint64Array"
                    };
                    const char* name = (arr_type < 11) ? type_names[arr_type] : "TypedArray";
                    info.type_name = name;
                    info.display = "[" + std::string(name) + "(" + std::to_string(ta_length) + ")]";
                } else {
                    info.type_name = "TypedArray";
                    info.display = "[TypedArray]";
                }
                break;
            }

            bool is_dataview;
            if (napi_is_dataview(env, val, &is_dataview) == napi_ok && is_dataview) {
                info.type_name = "DataView";
                info.display = "[DataView]";
                break;
            }

            // Check if it's a Date by looking for getTime method
            bool has_get_time;
            if (napi_has_named_property(env, val, "getTime", &has_get_time) == napi_ok && has_get_time) {
                napi_value get_time_fn;
                if (napi_get_named_property(env, val, "getTime", &get_time_fn) == napi_ok) {
                    napi_valuetype fn_type;
                    if (napi_typeof(env, get_time_fn, &fn_type) == napi_ok && fn_type == napi_function) {
                        info.type_name = "Date";
                        // Try to get ISO string via getTime
                        napi_value result_val;
                        if (napi_call_function(env, val, get_time_fn, 0, nullptr, &result_val) == napi_ok) {
                            double ms;
                            if (napi_get_value_double(env, result_val, &ms) == napi_ok) {
                                time_t secs = (time_t)(ms / 1000.0);
                                struct tm utc;
                                gmtime_r(&secs, &utc);
                                char buf[32];
                                strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
                                info.display = std::string(buf);
                                break;
                            }
                        }
                        info.display = "[Date]";
                        break;
                    }
                }
            }

            // Check for Error (has message and stack)
            bool has_message;
            if (napi_has_named_property(env, val, "message", &has_message) == napi_ok && has_message) {
                bool has_stack;
                if (napi_has_named_property(env, val, "stack", &has_stack) == napi_ok && has_stack) {
                    info.type_name = "Error";
                    // Get error message for display
                    napi_value msg;
                    if (napi_get_named_property(env, val, "message", &msg) == napi_ok) {
                        napi_valuetype msg_type;
                        if (napi_typeof(env, msg, &msg_type) == napi_ok && msg_type == napi_string) {
                            size_t len;
                            if (napi_get_value_string_utf8(env, msg, NULL, 0, &len) == napi_ok && len > 0) {
                                std::string msg_str(len, '\0');
                                napi_get_value_string_utf8(env, msg, &msg_str[0], len + 1, NULL);
                                if (msg_str.length() > limits::MAX_ERROR_MSG) {
                                    msg_str = msg_str.substr(0, limits::MAX_ERROR_MSG) + "...";
                                }
                                info.display = "[Error: " + msg_str + "]";
                                break;
                            }
                        }
                    }
                    info.display = "[Error]";
                    break;
                }
            }

            // Default object - expand properties
            info.type_name = "Object";
            if (depth > 0) {
                napi_value prop_names;
                if (napi_get_all_property_names(env, val,
                        napi_key_own_only, napi_key_enumerable,
                        napi_key_numbers_to_strings, &prop_names) == napi_ok) {
                    uint32_t count;
                    if (napi_get_array_length(env, prop_names, &count) == napi_ok) {
                        uint32_t show = std::min(count, (uint32_t)limits::MAX_OBJECT_PROPS);
                        std::string result = "{";
                        for (uint32_t i = 0; i < show; i++) {
                            napi_value key;
                            napi_get_element(env, prop_names, i, &key);
                            size_t key_len;
                            napi_get_value_string_utf8(env, key, NULL, 0, &key_len);
                            std::string key_str(key_len, '\0');
                            napi_get_value_string_utf8(env, key, &key_str[0], key_len + 1, NULL);
                            napi_value prop_val;
                            napi_get_property(env, val, key, &prop_val);
                            ValueInfo vi = get_value_info(env, prop_val, depth - 1);
                            if (i > 0) result += ", ";
                            result += key_str + ": " + vi.display;
                        }
                        if (count > show) result += ", ...";
                        result += "}";
                        info.display = result;
                        break;
                    }
                }
                info.display = "[Object]";
            } else {
                info.display = "{...}";
            }
            break;
        }

        case napi_function: {
            info.type_name = "Function";
            // Try to get function name
            napi_value name_val;
            if (napi_get_named_property(env, val, "name", &name_val) == napi_ok) {
                napi_valuetype name_type;
                if (napi_typeof(env, name_val, &name_type) == napi_ok && name_type == napi_string) {
                    size_t len;
                    if (napi_get_value_string_utf8(env, name_val, NULL, 0, &len) == napi_ok && len > 0) {
                        std::string name(len, '\0');
                        napi_get_value_string_utf8(env, name_val, &name[0], len + 1, NULL);
                        info.display = "[Function: " + name + "]";
                        break;
                    }
                }
            }
            info.display = "[Function]";
            break;
        }

        case napi_external:
            info.type_name = "External";
            info.display = "[External]";
            break;

        case napi_bigint: {
            info.type_name = "BigInt";
            int sign_bit;
            size_t word_count = 1;
            uint64_t words[1];
            if (napi_get_value_bigint_words(env, val, &sign_bit, &word_count, words) == napi_ok) {
                std::string result = sign_bit ? "-" : "";
                result += std::to_string(words[0]) + "n";
                info.display = result;
            } else {
                info.display = "[BigInt]";
            }
            break;
        }

        default:
            info.type_name = "unknown";
            info.display = "[unknown]";
            break;
    }

    return info;
}

// Helper to get just the display string (for return values)
static std::string format_value(napi_env env, napi_value val) {
    return get_value_info(env, val).display;
}

// format_arguments removed - no longer needed with direct struct FFI

// =============================================================================
// GLOB PATTERN MATCHING
// =============================================================================

static bool glob_match(const char* pattern, const char* str) {
    while (*pattern && *str) {
        if (*pattern == '*') {
            pattern++;
            if (!*pattern) return true;
            while (*str) {
                if (glob_match(pattern, str)) return true;
                str++;
            }
            return false;
        } else if (*pattern == '?' || *pattern == *str) {
            pattern++;
            str++;
        } else {
            return false;
        }
    }
    while (*pattern == '*') pattern++;
    return !*pattern && !*str;
}

// =============================================================================
// GENERIC WRAPPER FUNCTION
// =============================================================================

static napi_value GenericWrapper(napi_env env, napi_callback_info info) {
    void* data;
    size_t argc = limits::MAX_ARGS;
    napi_value args[limits::MAX_ARGS];
    napi_value this_arg;

    // Get arguments and wrapper context
    if (napi_get_cb_info(env, info, &argc, args, &this_arg, &data) != napi_ok) {
        napi_value undefined;
        napi_get_undefined(env, &undefined);
        return undefined;
    }

    WrapperContext* ctx = static_cast<WrapperContext*>(data);
    if (!ctx) {
        napi_value undefined;
        napi_get_undefined(env, &undefined);
        return undefined;
    }

    // Build ENTER trace event via direct struct (no JSON)
    // The callback returns 1 to continue, 0 to block the function call (review mode)
    int32_t should_continue = 1;
    if (g_trace_callback) {
        // Build arguments array on stack
        // IMPORTANT: Reserve capacity upfront to prevent reallocation,
        // which would invalidate c_str() pointers stored in args_data
        std::vector<V8TraceArgument> args_data;
        std::vector<std::string> type_hints;
        std::vector<std::string> displays;
        args_data.reserve(argc);
        type_hints.reserve(argc);
        displays.reserve(argc);

        for (size_t i = 0; i < argc; i++) {
            ValueInfo info = get_value_info(env, args[i]);
            type_hints.push_back(std::move(info.type_name));
            displays.push_back(std::move(info.display));
            args_data.push_back({
                .index = (uint32_t)i,
                .type_hint = type_hints.back().c_str(),
                .type_hint_len = (uint32_t)type_hints.back().length(),
                .display = displays.back().c_str(),
                .display_len = (uint32_t)displays.back().length(),
            });
        }

        V8TraceEventData event = {
            .timestamp_ns = (uint64_t)std::chrono::steady_clock::now().time_since_epoch().count(),
            .thread_id = std::hash<std::thread::id>{}(std::this_thread::get_id()),
            .event_type = 0,  // ENTER
            .function = ctx->function_name.c_str(),
            .function_len = (uint32_t)ctx->function_name.length(),
            .script_path = ctx->script_path.c_str(),
            .script_path_len = (uint32_t)ctx->script_path.length(),
            .return_value = nullptr,
            .return_value_len = 0,
            .arg_count = (uint32_t)argc,
            .arguments = args_data.empty() ? nullptr : args_data.data(),
        };
        should_continue = g_trace_callback(&event);
    }

    // If callback blocked (review mode denied), return undefined without calling original
    if (should_continue == 0) {
        napi_value undefined;
        napi_get_undefined(env, &undefined);
        return undefined;
    }

    // Get original function from reference
    napi_value original_func;
    if (napi_get_reference_value(env, ctx->original_ref, &original_func) != napi_ok) {
        napi_value undefined;
        napi_get_undefined(env, &undefined);
        return undefined;
    }

    // Call original function
    napi_value result;
    napi_status call_status = napi_call_function(env, this_arg, original_func, argc, args, &result);

    // Build LEAVE trace event via direct struct (no JSON)
    if (g_trace_callback) {
        std::string return_val_str;
        const char* return_val_ptr = nullptr;
        uint32_t return_val_len = 0;

        // Capture return value if call succeeded
        if (call_status == napi_ok && result) {
            return_val_str = format_value(env, result);
            return_val_ptr = return_val_str.c_str();
            return_val_len = (uint32_t)return_val_str.length();
        }

        V8TraceEventData event = {
            .timestamp_ns = (uint64_t)std::chrono::steady_clock::now().time_since_epoch().count(),
            .thread_id = std::hash<std::thread::id>{}(std::this_thread::get_id()),
            .event_type = 1,  // LEAVE
            .function = ctx->function_name.c_str(),
            .function_len = (uint32_t)ctx->function_name.length(),
            .script_path = ctx->script_path.c_str(),
            .script_path_len = (uint32_t)ctx->script_path.length(),
            .return_value = return_val_ptr,
            .return_value_len = return_val_len,
            .arg_count = 0,
            .arguments = nullptr,
        };
        g_trace_callback(&event);
    }

    // Handle call errors
    if (call_status != napi_ok) {
        // Check for pending exception and rethrow
        bool has_exception;
        if (napi_is_exception_pending(env, &has_exception) == napi_ok && has_exception) {
            // Exception will propagate automatically
            return nullptr;
        }
        napi_value undefined;
        napi_get_undefined(env, &undefined);
        return undefined;
    }

    return result;
}

// =============================================================================
// WRAP FUNCTION
// =============================================================================

static bool wrap_function(napi_env env, napi_value obj, const char* name,
                          const char* prefix, bool capture_stack) {
    // Get original function
    napi_value original;
    if (napi_get_named_property(env, obj, name, &original) != napi_ok) {
        return false;
    }

    // Verify it's a function
    napi_valuetype type;
    if (napi_typeof(env, original, &type) != napi_ok || type != napi_function) {
        return false;
    }

    // Check if already wrapped (has __malwi_wrapped marker)
    bool has_marker = false;
    if (napi_has_named_property(env, original, "__malwi_wrapped", &has_marker) == napi_ok && has_marker) {
        return false;  // Already wrapped, skip
    }

    // Skip wrapping dangerous global constructors that break JavaScript internals
    // Wrapping these causes errors like "Function.prototype.bind called on incompatible undefined"
    static const std::unordered_set<std::string> dangerous_globals = {
        "Function", "Object", "Array", "String", "Number", "Boolean",
        "Symbol", "BigInt", "Error", "TypeError", "ReferenceError",
        "SyntaxError", "RangeError", "URIError", "EvalError", "Promise",
        "Proxy", "Reflect", "Map", "Set", "WeakMap", "WeakSet",
        "ArrayBuffer", "SharedArrayBuffer", "DataView",
        "Int8Array", "Uint8Array", "Uint8ClampedArray",
        "Int16Array", "Uint16Array", "Int32Array", "Uint32Array",
        "Float32Array", "Float64Array", "BigInt64Array", "BigUint64Array"
    };
    if (prefix[0] == '\0' && dangerous_globals.count(name)) {
        if (getenv("MALWI_DEBUG")) {
            fprintf(stderr, "[malwi] Skipping dangerous global constructor: %s\n", name);
        }
        return false;  // Don't wrap built-in constructors
    }

    // Extract script origin using V8 API
    std::string script_path;
    {
        v8::Local<v8::Value> v8_val = v8::Local<v8::Value>::Cast(
            *reinterpret_cast<v8::Local<v8::Value>*>(&original));

        if (v8_val->IsFunction()) {
            v8::Isolate* isolate = v8::Isolate::GetCurrent();
            v8::Local<v8::Function> v8_func = v8_val.As<v8::Function>();
            v8::ScriptOrigin origin = v8_func->GetScriptOrigin();
            v8::Local<v8::Value> resource_name = origin.ResourceName();

            if (!resource_name.IsEmpty() && resource_name->IsString()) {
                v8::String::Utf8Value utf8(isolate, resource_name);
                if (*utf8) {
                    script_path = *utf8;
                }
            }
        }
    }

    // Create wrapper context
    WrapperContext* ctx = new WrapperContext();
    ctx->function_name = std::string(prefix) + name;
    ctx->script_path = script_path;
    ctx->capture_stack = capture_stack;
    g_contexts.push_back(ctx);

    // Save reference to original function
    if (napi_create_reference(env, original, 1, &ctx->original_ref) != napi_ok) {
        delete ctx;
        g_contexts.pop_back();
        return false;
    }

    // Create wrapper function with context as data
    napi_value wrapper;
    if (napi_create_function(env, name, NAPI_AUTO_LENGTH, GenericWrapper, ctx, &wrapper) != napi_ok) {
        napi_delete_reference(env, ctx->original_ref);
        delete ctx;
        g_contexts.pop_back();
        return false;
    }

    // Copy function length property
    napi_value length_val;
    if (napi_get_named_property(env, original, "length", &length_val) == napi_ok) {
        napi_set_named_property(env, wrapper, "length", length_val);
    }

    // Copy function name property
    napi_value name_val;
    if (napi_get_named_property(env, original, "name", &name_val) == napi_ok) {
        napi_set_named_property(env, wrapper, "name", name_val);
    }

    // Add marker to indicate this function is wrapped (prevents double-wrapping)
    napi_value marker_val;
    napi_get_boolean(env, true, &marker_val);
    napi_set_named_property(env, wrapper, "__malwi_wrapped", marker_val);

    // Replace original with wrapper
    if (napi_set_named_property(env, obj, name, wrapper) != napi_ok) {
        napi_delete_reference(env, ctx->original_ref);
        delete ctx;
        g_contexts.pop_back();
        return false;
    }

    return true;
}

// =============================================================================
// WRAP MATCHING FUNCTIONS
// =============================================================================

static int wrap_matching_functions(napi_env env, napi_value obj,
                                    const char* pattern, const char* prefix,
                                    bool capture_stack) {
    int count = 0;

    // Get property names
    napi_value prop_names;
    if (napi_get_property_names(env, obj, &prop_names) != napi_ok) {
        return 0;
    }

    uint32_t length;
    if (napi_get_array_length(env, prop_names, &length) != napi_ok) {
        return 0;
    }

    for (uint32_t i = 0; i < length; i++) {
        napi_value key;
        if (napi_get_element(env, prop_names, i, &key) != napi_ok) {
            continue;
        }

        // Get key as string
        size_t name_len;
        if (napi_get_value_string_utf8(env, key, NULL, 0, &name_len) != napi_ok) {
            continue;
        }

        std::string name(name_len, '\0');
        if (napi_get_value_string_utf8(env, key, &name[0], name_len + 1, NULL) != napi_ok) {
            continue;
        }

        // Check if name matches pattern
        if (!glob_match(pattern, name.c_str())) {
            continue;
        }

        // Get property value
        napi_value value;
        if (napi_get_property(env, obj, key, &value) != napi_ok) {
            continue;
        }

        // Check if it's a function
        napi_valuetype type;
        if (napi_typeof(env, value, &type) != napi_ok || type != napi_function) {
            continue;
        }

        // Wrap it
        if (wrap_function(env, obj, name.c_str(), prefix, capture_stack)) {
            count++;
        }
    }

    return count;
}

// =============================================================================
// PATTERN PARSING
// =============================================================================

struct ParsedPattern {
    std::string object_path;   // e.g., "fs" or "console" or ""
    std::string func_pattern;  // e.g., "readFile" or "*" or "*Handler"
    bool is_glob;
};

static ParsedPattern parse_pattern(const char* pattern) {
    std::string p(pattern);
    auto dot = p.rfind('.');

    if (dot == std::string::npos) {
        // Global function: "myFunc" or "*"
        return {"", p, p.find('*') != std::string::npos};
    }

    // Object.function: "fs.readFile" or "fs.*"
    return {
        p.substr(0, dot),
        p.substr(dot + 1),
        p.find('*') != std::string::npos
    };
}

// =============================================================================
// RESOLVE OBJECT PATH
// =============================================================================

static napi_value resolve_object(napi_env env, const std::string& path) {
    napi_value current;
    if (napi_get_global(env, &current) != napi_ok) {
        return nullptr;
    }

    if (path.empty()) {
        return current;
    }

    size_t start = 0;
    while (start < path.length()) {
        auto dot = path.find('.', start);
        std::string part = (dot == std::string::npos)
            ? path.substr(start)
            : path.substr(start, dot - start);

        napi_value next;
        if (napi_get_named_property(env, current, part.c_str(), &next) != napi_ok) {
            return nullptr;
        }

        napi_valuetype type;
        if (napi_typeof(env, next, &type) != napi_ok || type == napi_undefined) {
            return nullptr;
        }

        current = next;
        start = (dot == std::string::npos) ? path.length() : dot + 1;
    }

    return current;
}

// =============================================================================
// APPLY FILTER
// =============================================================================

static int apply_filter(napi_env env, const char* pattern, bool capture_stack) {
    auto parsed = parse_pattern(pattern);

    // Get target object (global if empty path)
    napi_value obj = resolve_object(env, parsed.object_path);
    if (!obj) {
        return 0;
    }

    std::string prefix = parsed.object_path.empty()
        ? ""
        : parsed.object_path + ".";

    if (parsed.is_glob) {
        // Glob pattern: wrap matching functions
        return wrap_matching_functions(env, obj, parsed.func_pattern.c_str(),
                                       prefix.c_str(), capture_stack);
    } else {
        // Exact match: wrap single function
        if (wrap_function(env, obj, parsed.func_pattern.c_str(),
                         prefix.c_str(), capture_stack)) {
            return 1;
        }
        return 0;
    }
}

// =============================================================================
// REQUIRE HOOK SUPPORT
// =============================================================================

// Check if a module name matches any active filter
static bool should_trace_module(const char* module_name) {
    for (const auto& filter : g_active_filters) {
        // Extract the object path from the filter pattern (e.g., "fs" from "fs.*")
        std::string pattern = filter.pattern;
        auto dot = pattern.find('.');
        std::string filter_prefix = (dot != std::string::npos)
            ? pattern.substr(0, dot)
            : pattern;

        // Check if module name matches the filter prefix
        // For "fs.*" filter, match module "fs"
        // For "*" filter, match everything
        if (filter_prefix == "*" || filter_prefix == module_name) {
            return true;
        }
    }
    return false;
}

// Get the function pattern part from a filter (e.g., "*" from "fs.*")
static std::string get_function_pattern(const std::string& filter_pattern) {
    auto dot = filter_pattern.find('.');
    if (dot != std::string::npos) {
        return filter_pattern.substr(dot + 1);
    }
    return "*";  // Default to all functions
}

// Recursively wrap functions in an object that match the pattern
static int apply_wildcard_wrapping(napi_env env, const std::string& prefix,
                                    napi_value obj, const char* func_pattern,
                                    bool capture_stack, int depth = 0) {
    if (depth > limits::MAX_RECURSION_DEPTH) return 0;  // Prevent infinite recursion

    // Verify obj is an object
    napi_valuetype obj_type;
    if (napi_typeof(env, obj, &obj_type) != napi_ok ||
        (obj_type != napi_object && obj_type != napi_function)) {
        return 0;
    }

    int count = 0;

    // Get all property names
    napi_value keys;
    if (napi_get_all_property_names(env, obj,
            napi_key_own_only, napi_key_skip_symbols,
            napi_key_numbers_to_strings, &keys) != napi_ok) {
        return 0;
    }

    uint32_t len;
    if (napi_get_array_length(env, keys, &len) != napi_ok) {
        return 0;
    }

    for (uint32_t i = 0; i < len; i++) {
        napi_value key;
        if (napi_get_element(env, keys, i, &key) != napi_ok) {
            continue;
        }

        // Get key as string
        char func_name[limits::MAX_FUNC_NAME];
        size_t name_len;
        if (napi_get_value_string_utf8(env, key, func_name, sizeof(func_name), &name_len) != napi_ok) {
            continue;
        }

        // Get property value
        napi_value prop_value;
        if (napi_get_property(env, obj, key, &prop_value) != napi_ok) {
            continue;
        }

        napi_valuetype type;
        if (napi_typeof(env, prop_value, &type) != napi_ok) {
            continue;
        }

        std::string full_path = prefix + "." + func_name;

        if (type == napi_function) {
            // Check if function name matches the pattern
            if (glob_match(func_pattern, func_name)) {
                // Try to wrap the function
                if (wrap_function(env, obj, func_name, (prefix + ".").c_str(), capture_stack)) {
                    count++;
                    // Debug: wrapped full_path (logging removed - using direct struct FFI)
                }
            }
        } else if (type == napi_object) {
            // Recurse for nested objects (e.g., fs.promises.*)
            count += apply_wildcard_wrapping(env, full_path, prop_value,
                                              func_pattern, capture_stack, depth + 1);
        }
    }

    return count;
}

// The require hook callback
static napi_value RequireHook(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_value this_arg;

    if (napi_get_cb_info(env, info, &argc, args, &this_arg, nullptr) != napi_ok) {
        napi_value undefined;
        napi_get_undefined(env, &undefined);
        return undefined;
    }

    // Get module name
    char module_name[limits::MAX_MODULE_NAME] = {0};
    if (argc > 0) {
        napi_get_value_string_utf8(env, args[0], module_name, sizeof(module_name), nullptr);
    }

    // Call original require
    napi_value original_require;
    if (napi_get_reference_value(env, g_original_require_ref, &original_require) != napi_ok) {
        napi_value undefined;
        napi_get_undefined(env, &undefined);
        return undefined;
    }

    napi_value exports_obj;
    napi_status call_status = napi_call_function(env, this_arg, original_require, argc, args, &exports_obj);

    if (call_status != napi_ok) {
        // Check for exception and propagate
        bool has_exception;
        if (napi_is_exception_pending(env, &has_exception) == napi_ok && has_exception) {
            return nullptr;
        }
        napi_value undefined;
        napi_get_undefined(env, &undefined);
        return undefined;
    }

    // Check if this module matches any filter
    if (should_trace_module(module_name)) {
        if (getenv("MALWI_DEBUG")) {
            fprintf(stderr, "[malwi] RequireHook: module '%s' matches filter, wrapping...\n", module_name);
        }
        // Find all matching filters and apply wrapping
        for (const auto& filter : g_active_filters) {
            std::string pattern = filter.pattern;
            auto dot = pattern.find('.');
            std::string filter_prefix = (dot != std::string::npos)
                ? pattern.substr(0, dot)
                : pattern;

            // Check if this filter applies to this module
            if (filter_prefix == "*" || filter_prefix == module_name) {
                std::string func_pattern = get_function_pattern(pattern);
                int wrapped = apply_wildcard_wrapping(env, module_name, exports_obj,
                                                       func_pattern.c_str(),
                                                       filter.capture_stack, 0);
                if (getenv("MALWI_DEBUG")) {
                    fprintf(stderr, "[malwi] RequireHook: wrapped %d functions for pattern '%s'\n",
                            wrapped, pattern.c_str());
                }
            }
        }
    } else if (getenv("MALWI_DEBUG") && module_name[0] != 0) {
        // Only log if module name is not empty and doesn't match
        if (strcmp(module_name, "path") != 0 && strcmp(module_name, "module") != 0) {
            fprintf(stderr, "[malwi] RequireHook: module '%s' doesn't match any filter\n", module_name);
        }
    }

    return exports_obj;
}

// =============================================================================
// FFI STRUCTS AND IMPORTS FROM RUST AGENT
// =============================================================================

#include <dlfcn.h>

// FFI struct for filter data from Rust agent
struct FilterData {
    const char* pattern;
    uint32_t pattern_len;
    bool capture_stack;
};

// FFI function for envvar access check (called into Rust)
// Returns 1 to allow, 0 to block
typedef int32_t (*CheckEnvVarFn)(const uint8_t* key, size_t key_len);

// Function pointer types for Rust FFI
typedef uint32_t (*GetFiltersFn)(FilterData* out_filters, uint32_t max_count);
typedef void (*FreeFiltersFn)(FilterData* filters, uint32_t count);
typedef TraceCallback (*GetTraceCallbackFn)();

// Cached function pointers (resolved via dlsym at runtime)
static GetFiltersFn g_get_filters_fn = nullptr;
static FreeFiltersFn g_free_filters_fn = nullptr;
static GetTraceCallbackFn g_get_trace_callback_fn = nullptr;
static CheckEnvVarFn g_check_envvar_fn = nullptr;
static bool g_ffi_resolution_attempted = false;

// Resolve FFI function pointers from the injected agent library
static bool resolve_ffi_functions() {
    if (g_ffi_resolution_attempted) {
        return g_get_filters_fn != nullptr;
    }
    g_ffi_resolution_attempted = true;

    // Use RTLD_DEFAULT to search all loaded libraries
    g_get_filters_fn = (GetFiltersFn)dlsym(RTLD_DEFAULT, "malwi_addon_get_filters");
    g_free_filters_fn = (FreeFiltersFn)dlsym(RTLD_DEFAULT, "malwi_addon_free_filters");
    g_get_trace_callback_fn = (GetTraceCallbackFn)dlsym(RTLD_DEFAULT, "malwi_nodejs_get_trace_callback");
    g_check_envvar_fn = (CheckEnvVarFn)dlsym(RTLD_DEFAULT, "malwi_nodejs_envvar_access");

    if (g_get_filters_fn && g_free_filters_fn) {
        return true;
    }

    // Debug output if resolution failed
    if (getenv("MALWI_DEBUG")) {
        fprintf(stderr, "[malwi] FFI resolution: get_filters=%p, free_filters=%p, get_trace_callback=%p\n",
                (void*)g_get_filters_fn, (void*)g_free_filters_fn, (void*)g_get_trace_callback_fn);
        if (!g_get_filters_fn || !g_free_filters_fn) {
            const char* err = dlerror();
            if (err) {
                fprintf(stderr, "[malwi] dlsym error: %s\n", err);
            }
        }
    }

    return false;
}

// =============================================================================
// C FFI EXPORTS (for direct Rust calls via dlopen/dlsym)
// =============================================================================

extern "C" {

/**
 * Enable N-API tracing with a Rust callback.
 * Called directly from Rust via dlsym.
 *
 * @param callback Function pointer to call on trace events (receives JSON string)
 * @return true if tracing was enabled successfully
 */
__attribute__((visibility("default")))
bool malwi_addon_enable_tracing(TraceCallback callback) {
    if (!callback) {
        return false;
    }

    std::lock_guard<std::mutex> lock(g_state_mutex);
    g_trace_callback = callback;
    g_tracing_enabled.store(true, std::memory_order_release);
    return true;
}

/**
 * Disable tracing.
 */
__attribute__((visibility("default")))
void malwi_addon_disable_tracing() {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    g_tracing_enabled.store(false, std::memory_order_release);
    g_trace_callback = nullptr;

    // Clean up wrapper contexts
    for (auto* ctx : g_contexts) {
        if (g_env && ctx->original_ref) {
            napi_delete_reference(g_env, ctx->original_ref);
        }
        delete ctx;
    }
    g_contexts.clear();
}

/**
 * Store napi_env for later use.
 * Must be called from addon init before applying filters.
 */
__attribute__((visibility("default")))
void malwi_addon_set_env(napi_env env) {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    g_env = env;
}

/**
 * Apply a filter pattern to wrap matching functions.
 *
 * If g_env is not yet available (addon not loaded by Node.js),
 * the filter is stored and will be applied when Init runs.
 *
 * @param pattern Pattern like "console.log", "fs.*", "myFunc"
 * @param capture_stack Whether to capture stack traces
 * @return Number of functions wrapped (0 if pending)
 */
__attribute__((visibility("default")))
int malwi_addon_add_filter(const char* pattern, bool capture_stack) {
    if (!pattern) {
        return 0;
    }

    std::lock_guard<std::mutex> lock(g_state_mutex);

    // If g_env is not available yet, store for later
    if (!g_env) {
        g_pending_filters.push_back({pattern, capture_stack});
        return 0;  // Return 0 to indicate pending
    }

    // IMPORTANT: Also add to active filters for the require hook
    // This ensures that modules loaded AFTER this filter is added
    // will have their functions wrapped when require() is called
    g_active_filters.push_back({pattern, capture_stack});

    return apply_filter(g_env, pattern, capture_stack);
}

/**
 * Check if tracing is enabled.
 */
__attribute__((visibility("default")))
bool malwi_addon_is_tracing_enabled() {
    return g_tracing_enabled.load(std::memory_order_acquire);
}

/**
 * Clear all wrapped functions (cleanup).
 */
__attribute__((visibility("default")))
void malwi_addon_clear_filters() {
    std::lock_guard<std::mutex> lock(g_state_mutex);

    // Clean up wrapper contexts properly
    for (auto* ctx : g_contexts) {
        if (g_env && ctx->original_ref) {
            napi_delete_reference(g_env, ctx->original_ref);
        }
        delete ctx;
    }
    g_contexts.clear();
    g_active_filters.clear();
}

/**
 * Get the NODE_MODULE_VERSION this addon was built for.
 * Used to validate that the addon matches the runtime Node.js version.
 */
__attribute__((visibility("default")))
uint32_t malwi_addon_get_module_version() {
    return NODE_MODULE_VERSION;
}

} // extern "C"

// =============================================================================
// N-API EXPORTED FUNCTIONS
// =============================================================================

// N-API function: installRequireHook(ModuleClass)
// Called from JS wrapper with require('module') as argument
static napi_value NapiInstallRequireHook(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    if (argc < 1) {
        napi_throw_error(env, nullptr, "installRequireHook requires Module class as argument");
        return nullptr;
    }

    napi_value module_class = args[0];

    // Get Module.prototype
    napi_value module_proto;
    if (napi_get_named_property(env, module_class, "prototype", &module_proto) != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to get Module.prototype");
        return nullptr;
    }

    // Verify it's an object
    napi_valuetype proto_type;
    if (napi_typeof(env, module_proto, &proto_type) != napi_ok || proto_type != napi_object) {
        napi_throw_error(env, nullptr, "Module.prototype is not an object");
        return nullptr;
    }

    // Get original require function
    napi_value original_require;
    if (napi_get_named_property(env, module_proto, "require", &original_require) != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to get Module.prototype.require");
        return nullptr;
    }

    // Verify it's a function
    napi_valuetype require_type;
    if (napi_typeof(env, original_require, &require_type) != napi_ok || require_type != napi_function) {
        napi_throw_error(env, nullptr, "Module.prototype.require is not a function");
        return nullptr;
    }

    // Create persistent reference to original require
    if (napi_create_reference(env, original_require, 1, &g_original_require_ref) != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to create reference to original require");
        return nullptr;
    }

    // Save reference to module_proto
    if (napi_create_reference(env, module_proto, 1, &g_module_proto_ref) != napi_ok) {
        CleanupHookReferences(env);
        napi_throw_error(env, nullptr, "Failed to create reference to Module.prototype");
        return nullptr;
    }

    // Create and install our hook function
    napi_value hook_fn;
    if (napi_create_function(env, "require", NAPI_AUTO_LENGTH, RequireHook, nullptr, &hook_fn) != napi_ok) {
        CleanupHookReferences(env);
        napi_throw_error(env, nullptr, "Failed to create hook function");
        return nullptr;
    }

    // Replace Module.prototype.require with our hook
    if (napi_set_named_property(env, module_proto, "require", hook_fn) != napi_ok) {
        CleanupHookReferences(env);
        napi_throw_error(env, nullptr, "Failed to replace Module.prototype.require");
        return nullptr;
    }

    // Debug: Installed require hook via JS wrapper (logging removed - using direct struct FFI)

    // Return true to indicate success
    napi_value result;
    napi_get_boolean(env, true, &result);
    return result;
}

// N-API function: enableTracing()
// Gets the trace callback from the Rust agent and enables tracing
// Returns true if tracing was enabled, false otherwise
static napi_value NapiEnableTracing(napi_env env, napi_callback_info info) {
    // Resolve FFI functions if not already done
    resolve_ffi_functions();

    napi_value result;

    // Get the trace callback from Rust agent
    if (g_get_trace_callback_fn) {
        TraceCallback callback = g_get_trace_callback_fn();
        if (callback) {
            bool success = malwi_addon_enable_tracing(callback);
            if (getenv("MALWI_DEBUG")) {
                fprintf(stderr, "[malwi] enableTracing: callback=%p, success=%d\n",
                        (void*)callback, success);
            }
            napi_get_boolean(env, success, &result);
            return result;
        } else if (getenv("MALWI_DEBUG")) {
            fprintf(stderr, "[malwi] enableTracing: callback is null\n");
        }
    } else if (getenv("MALWI_DEBUG")) {
        fprintf(stderr, "[malwi] enableTracing: get_trace_callback_fn not found\n");
    }

    napi_get_boolean(env, false, &result);
    return result;
}

// N-API function: addFilter(pattern, captureStack)
// Wraps functions matching the pattern for tracing
// Returns the number of functions wrapped
static napi_value NapiAddFilter(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    if (argc < 1) {
        napi_throw_error(env, nullptr, "addFilter requires at least pattern argument");
        return nullptr;
    }

    // Get pattern string
    char pattern[512];
    size_t pattern_len;
    if (napi_get_value_string_utf8(env, args[0], pattern, sizeof(pattern), &pattern_len) != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to get pattern string");
        return nullptr;
    }

    // Get optional captureStack boolean (default false)
    bool capture_stack = false;
    if (argc >= 2) {
        napi_get_value_bool(env, args[1], &capture_stack);
    }

    // Call the C FFI function to add the filter
    int count = malwi_addon_add_filter(pattern, capture_stack);

    if (getenv("MALWI_DEBUG")) {
        fprintf(stderr, "[malwi] addFilter: pattern=%s, captureStack=%d, wrapped=%d\n",
                pattern, capture_stack, count);
    }

    // Return number of functions wrapped
    napi_value result;
    napi_create_int32(env, count, &result);
    return result;
}

// N-API function: getFilters()
// Returns an array of filter objects from the Rust agent
// Each object has: { pattern: string, captureStack: boolean }
static napi_value NapiGetFilters(napi_env env, napi_callback_info info) {
    // Resolve FFI functions if not already done
    if (!resolve_ffi_functions()) {
        // FFI not available - return empty array
        if (getenv("MALWI_DEBUG")) {
            fprintf(stderr, "[malwi] getFilters: FFI not available\n");
        }
        napi_value result_array;
        napi_create_array_with_length(env, 0, &result_array);
        return result_array;
    }

    constexpr size_t MAX_FILTERS = 64;
    FilterData filters[MAX_FILTERS];

    // Get filters from Rust agent via FFI
    uint32_t count = g_get_filters_fn(filters, MAX_FILTERS);

    if (getenv("MALWI_DEBUG")) {
        fprintf(stderr, "[malwi] getFilters: got %u filters\n", count);
    }

    // Create result array
    napi_value result_array;
    if (napi_create_array_with_length(env, count, &result_array) != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to create filters array");
        return nullptr;
    }

    // Populate array with filter objects
    for (uint32_t i = 0; i < count; i++) {
        napi_value filter_obj;
        if (napi_create_object(env, &filter_obj) != napi_ok) {
            continue;
        }

        // Set pattern property
        if (filters[i].pattern) {
            napi_value pattern_val;
            if (napi_create_string_utf8(env, filters[i].pattern, filters[i].pattern_len, &pattern_val) == napi_ok) {
                napi_set_named_property(env, filter_obj, "pattern", pattern_val);
            }
            if (getenv("MALWI_DEBUG")) {
                fprintf(stderr, "[malwi] getFilters[%u]: pattern=%.*s, captureStack=%d\n",
                        i, filters[i].pattern_len, filters[i].pattern, filters[i].capture_stack);
            }
        }

        // Set captureStack property
        napi_value capture_stack_val;
        if (napi_get_boolean(env, filters[i].capture_stack, &capture_stack_val) == napi_ok) {
            napi_set_named_property(env, filter_obj, "captureStack", capture_stack_val);
        }

        // Add to array
        napi_set_element(env, result_array, i, filter_obj);
    }

    // Free the filter strings allocated by Rust
    if (g_free_filters_fn) {
        g_free_filters_fn(filters, count);
    }

    return result_array;
}

// =============================================================================
// STACK PARSER TEST FUNCTION
// =============================================================================

// Debug function to get instance type of a value
static napi_value NapiGetInstanceType(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    if (argc < 1) {
        napi_value result;
        napi_create_string_utf8(env, "No argument provided", NAPI_AUTO_LENGTH, &result);
        return result;
    }

    // Get the V8 value directly
    v8::Local<v8::Value> v8_val = v8::Local<v8::Value>::Cast(
        *reinterpret_cast<v8::Local<v8::Value>*>(&args[0]));

    // Create result object
    napi_value result;
    napi_create_object(env, &result);

    // Check if it's an integer (Smi-like)
    bool is_smi = v8_val->IsInt32();
    napi_value is_smi_val;
    napi_get_boolean(env, is_smi, &is_smi_val);
    napi_set_named_property(env, result, "isInt32", is_smi_val);

    // Get the type using V8 API
    std::string type_str;
    if (v8_val->IsUndefined()) type_str = "Undefined";
    else if (v8_val->IsNull()) type_str = "Null";
    else if (v8_val->IsTrue()) type_str = "True";
    else if (v8_val->IsFalse()) type_str = "False";
    else if (v8_val->IsString()) type_str = "String";
    else if (v8_val->IsSymbol()) type_str = "Symbol";
    else if (v8_val->IsBigInt()) type_str = "BigInt";
    else if (v8_val->IsNumber()) type_str = "Number";
    else if (v8_val->IsArray()) type_str = "Array";
    else if (v8_val->IsFunction()) type_str = "Function";
    else if (v8_val->IsPromise()) type_str = "Promise";
    else if (v8_val->IsDate()) type_str = "Date";
    else if (v8_val->IsRegExp()) type_str = "RegExp";
    else if (v8_val->IsMap()) type_str = "Map";
    else if (v8_val->IsSet()) type_str = "Set";
    else if (v8_val->IsArrayBuffer()) type_str = "ArrayBuffer";
    else if (v8_val->IsTypedArray()) type_str = "TypedArray";
    else if (v8_val->IsObject()) type_str = "Object";
    else type_str = "Unknown";

    napi_value type_val;
    napi_create_string_utf8(env, type_str.c_str(), NAPI_AUTO_LENGTH, &type_val);
    napi_set_named_property(env, result, "v8Type", type_val);

    return result;
}

// Test function that exercises the stack parser
// Called from JS with arguments to parse
// Returns an object with parameter types detected from the stack
static napi_value NapiTestStackParser(napi_env env, napi_callback_info info) {
    // Get the current V8 isolate
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    if (!isolate) {
        napi_throw_error(env, nullptr, "Failed to get V8 isolate");
        return nullptr;
    }

    // Get JS frame from isolate
    uintptr_t js_fp = malwi_get_js_frame_from_isolate(isolate);

    // Create result object
    napi_value result;
    napi_create_object(env, &result);

    // Add isolate address (for debugging)
    napi_value isolate_addr;
    napi_create_bigint_uint64(env, reinterpret_cast<uint64_t>(isolate), &isolate_addr);
    napi_set_named_property(env, result, "isolate", isolate_addr);

    // Add frame pointer (for debugging)
    napi_value fp_value;
    napi_create_bigint_uint64(env, js_fp, &fp_value);
    napi_set_named_property(env, result, "framePointer", fp_value);

    // Add platform info
    const char* platform_info = malwi_get_platform_info();
    napi_value platform_value;
    napi_create_string_utf8(env, platform_info, NAPI_AUTO_LENGTH, &platform_value);
    napi_set_named_property(env, result, "platform", platform_value);

    if (js_fp == 0) {
        // Could not find JS frame
        napi_value success;
        napi_get_boolean(env, false, &success);
        napi_set_named_property(env, result, "success", success);

        napi_value error_msg;
        napi_create_string_utf8(env, "Could not find JS frame from isolate", NAPI_AUTO_LENGTH, &error_msg);
        napi_set_named_property(env, result, "error", error_msg);

        return result;
    }

    // Parse frame parameters
    MalwiFrameParseResult* parse_result = malwi_parse_frame_parameters(js_fp);

    if (!parse_result) {
        napi_value success;
        napi_get_boolean(env, false, &success);
        napi_set_named_property(env, result, "success", success);

        napi_value error_msg;
        napi_create_string_utf8(env, "Parse returned null", NAPI_AUTO_LENGTH, &error_msg);
        napi_set_named_property(env, result, "error", error_msg);

        return result;
    }

    // Add success status
    napi_value success;
    napi_get_boolean(env, parse_result->success, &success);
    napi_set_named_property(env, result, "success", success);

    if (!parse_result->success) {
        // Add error message
        if (parse_result->error) {
            napi_value error_msg;
            napi_create_string_utf8(env, parse_result->error, NAPI_AUTO_LENGTH, &error_msg);
            napi_set_named_property(env, result, "error", error_msg);
        }
        malwi_free_frame_result(parse_result);
        return result;
    }

    // Add parameter count
    napi_value param_count;
    napi_create_int32(env, parse_result->parameter_count, &param_count);
    napi_set_named_property(env, result, "parameterCount", param_count);

    // Add parameters array
    napi_value params_array;
    napi_create_array_with_length(env, parse_result->parameter_count, &params_array);

    // Get the caller_sp to read raw tagged values
    uintptr_t caller_sp = js_fp + 2 * sizeof(void*);  // fp + 16 on 64-bit

    for (int32_t i = 0; i < parse_result->parameter_count; i++) {
        napi_value param_obj;
        napi_create_object(env, &param_obj);

        // Add type name
        napi_value type_name;
        napi_create_string_utf8(env, parse_result->parameters[i].type_name,
                                 NAPI_AUTO_LENGTH, &type_name);
        napi_set_named_property(env, param_obj, "type", type_name);

        // Add type enum value
        napi_value type_id;
        napi_create_int32(env, parse_result->parameters[i].type, &type_id);
        napi_set_named_property(env, param_obj, "typeId", type_id);

        // Add Smi value if applicable
        if (parse_result->parameters[i].type == MALWI_TYPE_SMI) {
            napi_value smi_val;
            napi_create_int64(env, parse_result->parameters[i].smi_value, &smi_val);
            napi_set_named_property(env, param_obj, "smiValue", smi_val);
        }

        // Add raw instance type for debugging
        uintptr_t param_slot = caller_sp + (i + 1) * sizeof(void*);
        if (param_slot != 0) {
            uintptr_t tagged_value = *reinterpret_cast<uintptr_t*>(param_slot);
            uint16_t raw_type = malwi_get_raw_instance_type(tagged_value);

            napi_value raw_type_val;
            char hex_str[16];
            snprintf(hex_str, sizeof(hex_str), "0x%04x", raw_type);
            napi_create_string_utf8(env, hex_str, NAPI_AUTO_LENGTH, &raw_type_val);
            napi_set_named_property(env, param_obj, "rawInstanceType", raw_type_val);
        }

        napi_set_element(env, params_array, i, param_obj);
    }

    napi_set_named_property(env, result, "parameters", params_array);

    // Clean up
    malwi_free_frame_result(parse_result);

    return result;
}

// =============================================================================
// ENVVAR ACCESS CHECK
// =============================================================================

// N-API function: checkEnvVar(key)
// Called from JS Proxy when process.env.KEY is accessed
// Returns 1 to allow, 0 to block
static napi_value NapiCheckEnvVar(napi_env env, napi_callback_info info) {
    // Resolve FFI functions if not already done
    resolve_ffi_functions();

    if (!g_check_envvar_fn) {
        // FFI not available — allow by default
        napi_value result;
        napi_create_int32(env, 1, &result);
        return result;
    }

    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    if (argc < 1) {
        napi_value result;
        napi_create_int32(env, 1, &result);
        return result;
    }

    // Get key string
    size_t key_len;
    if (napi_get_value_string_utf8(env, args[0], NULL, 0, &key_len) != napi_ok) {
        napi_value result;
        napi_create_int32(env, 1, &result);
        return result;
    }

    std::string key(key_len, '\0');
    if (napi_get_value_string_utf8(env, args[0], &key[0], key_len + 1, NULL) != napi_ok) {
        napi_value result;
        napi_create_int32(env, 1, &result);
        return result;
    }

    // Call Rust FFI function
    int32_t allowed = g_check_envvar_fn(
        reinterpret_cast<const uint8_t*>(key.c_str()), key_len);

    napi_value result;
    napi_create_int32(env, allowed, &result);
    return result;
}

// =============================================================================
// N-API MODULE INITIALIZATION
// =============================================================================

static napi_value Init(napi_env env, napi_value exports) {
    // Store env for FFI calls
    g_env = env;

    // Apply any pending filters that were added before g_env was available
    // Also keep them as active filters for the require hook
    if (!g_pending_filters.empty()) {
        int total_wrapped = 0;
        for (const auto& filter : g_pending_filters) {
            // Try to apply filter to currently existing objects (like console)
            int count = apply_filter(env, filter.pattern.c_str(), filter.capture_stack);
            total_wrapped += count;

            // Keep filter active for require hook
            g_active_filters.push_back(filter);
        }
        g_pending_filters.clear();

        // Debug: Applied total_wrapped pending filters (logging removed - using direct struct FFI)
        (void)total_wrapped;  // suppress unused warning when logging is disabled
    }

    // Export installRequireHook function for JS wrapper to call
    napi_value install_hook_fn;
    if (napi_create_function(env, "installRequireHook", NAPI_AUTO_LENGTH,
                              NapiInstallRequireHook, nullptr, &install_hook_fn) == napi_ok) {
        napi_set_named_property(env, exports, "installRequireHook", install_hook_fn);
    }

    // Export getFilters function for JS wrapper to get filters from Rust agent
    napi_value get_filters_fn;
    if (napi_create_function(env, "getFilters", NAPI_AUTO_LENGTH,
                              NapiGetFilters, nullptr, &get_filters_fn) == napi_ok) {
        napi_set_named_property(env, exports, "getFilters", get_filters_fn);
    }

    // Export addFilter function for JS wrapper to add filters
    napi_value add_filter_fn;
    if (napi_create_function(env, "addFilter", NAPI_AUTO_LENGTH,
                              NapiAddFilter, nullptr, &add_filter_fn) == napi_ok) {
        napi_set_named_property(env, exports, "addFilter", add_filter_fn);
    }

    // Export enableTracing function for JS wrapper to enable tracing
    napi_value enable_tracing_fn;
    if (napi_create_function(env, "enableTracing", NAPI_AUTO_LENGTH,
                              NapiEnableTracing, nullptr, &enable_tracing_fn) == napi_ok) {
        napi_set_named_property(env, exports, "enableTracing", enable_tracing_fn);
    }

    // Export testStackParser function for testing parameter type detection
    napi_value test_stack_parser_fn;
    if (napi_create_function(env, "testStackParser", NAPI_AUTO_LENGTH,
                              NapiTestStackParser, nullptr, &test_stack_parser_fn) == napi_ok) {
        napi_set_named_property(env, exports, "testStackParser", test_stack_parser_fn);
    }

    // Export getInstanceType function for debugging instance types
    napi_value get_instance_type_fn;
    if (napi_create_function(env, "getInstanceType", NAPI_AUTO_LENGTH,
                              NapiGetInstanceType, nullptr, &get_instance_type_fn) == napi_ok) {
        napi_set_named_property(env, exports, "getInstanceType", get_instance_type_fn);
    }

    // Export checkEnvVar function for envvar access monitoring
    napi_value check_envvar_fn;
    if (napi_create_function(env, "checkEnvVar", NAPI_AUTO_LENGTH,
                              NapiCheckEnvVar, nullptr, &check_envvar_fn) == napi_ok) {
        napi_set_named_property(env, exports, "checkEnvVar", check_envvar_fn);
    }

    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
