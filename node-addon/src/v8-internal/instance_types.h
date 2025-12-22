// V8 Instance Type Constants
//
// This header defines the V8 instance type constants used to identify
// JavaScript value types from their Map's instance_type field.
//
// These values are derived from V8's InstanceType enum in objects-definitions.h
// and may vary slightly between V8 versions. We define ranges and key values
// that are relatively stable across Node.js 18/20/22.
//
// Instance Type Organization:
// ===========================
//
// 0x00-0x7F: String types (various encodings and representations)
// 0x80:      Symbol
// 0x81:      BigInt
// 0x82:      HeapNumber
// 0x83:      Oddball (undefined, null, true, false, etc.)
// 0x84+:     Various heap object types
// 0x400+:    JSObject types
// 0x800+:    Specific JS types (Array, Function, Promise, etc.)

#ifndef MALWI_INSTANCE_TYPES_H
#define MALWI_INSTANCE_TYPES_H

#include <cstdint>
#include <v8-version.h>

namespace malwi {
namespace v8_internal {

// =============================================================================
// Instance Type Boundaries
// =============================================================================

// String types are below this value
constexpr uint16_t kFirstNonstringType = 0x80;

// =============================================================================
// Primitive-like Types
// =============================================================================

constexpr uint16_t kSymbolType = 0x80;
constexpr uint16_t kBigIntType = 0x81;
constexpr uint16_t kHeapNumberType = 0x82;
constexpr uint16_t kOddballType = 0x83;

// =============================================================================
// Oddball Kind Values
// =============================================================================

// Oddball objects have a "kind" field that distinguishes them.
// Values 0-3 are stable across versions.
constexpr int kOddballKindFalse = 0;
constexpr int kOddballKindTrue = 1;
constexpr int kOddballKindTheHole = 2;  // Internal V8 marker
constexpr int kOddballKindNull = 3;

// V8 12.x removed arguments_marker (which was kind=4 in V8 11.x),
// shifting undefined and uninitialized down by one.
#if V8_MAJOR_VERSION >= 12
constexpr int kOddballKindUndefined = 4;
constexpr int kOddballKindUninitialized = 5;  // Internal V8 marker
constexpr int kOddballKindOther = 6;
#else
// V8 11.x: arguments_marker at kind=4, undefined at kind=5
constexpr int kOddballKindUndefined = 5;
constexpr int kOddballKindUninitialized = 6;  // Internal V8 marker
constexpr int kOddballKindOther = 7;
#endif

// =============================================================================
// JSObject Types (V8 12.x / Node.js 22)
// =============================================================================

// These values are specific to V8 12.x as used in Node.js 22.
// Determined empirically by probing actual instance types.

// Lower bound for JS objects
constexpr uint16_t kFirstJSObjectType = 0x400;

// JSFunction range (covers various function subtypes)
// Empirically determined: 0x080f-0x0815 in V8 12.x
constexpr uint16_t kJSFunctionTypeFirst = 0x080f;
constexpr uint16_t kJSFunctionTypeLast = 0x0815;

// JSArray - Empirically determined: 0x0843 in V8 12.x
constexpr uint16_t kJSArrayType = 0x0843;

// JSObject (generic) - 0x0421
constexpr uint16_t kJSObjectType = 0x421;

// Other specific types (may need verification for V8 12.x)
constexpr uint16_t kJSPromiseType = 0x0425;
constexpr uint16_t kJSDateType = 0x0423;
constexpr uint16_t kJSRegExpType = 0x0428;
constexpr uint16_t kJSMapType = 0x0426;
constexpr uint16_t kJSSetType = 0x0427;
constexpr uint16_t kJSArrayBufferType = 0x0424;

// Error types (there are multiple: Error, TypeError, RangeError, etc.)
constexpr uint16_t kJSErrorTypeFirst = 0x0440;
constexpr uint16_t kJSErrorTypeLast = 0x0450;

// TypedArray types
constexpr uint16_t kJSTypedArrayTypeFirst = 0x0460;
constexpr uint16_t kJSTypedArrayTypeLast = 0x0480;

// =============================================================================
// Type Classification Helpers
// =============================================================================

// Check if instance type is a string (any encoding/representation)
inline bool IsStringInstanceType(uint16_t instance_type) {
    return instance_type < kFirstNonstringType;
}

// Check if instance type is a symbol
inline bool IsSymbolInstanceType(uint16_t instance_type) {
    return instance_type == kSymbolType;
}

// Check if instance type is a BigInt
inline bool IsBigIntInstanceType(uint16_t instance_type) {
    return instance_type == kBigIntType;
}

// Check if instance type is a HeapNumber
inline bool IsHeapNumberInstanceType(uint16_t instance_type) {
    return instance_type == kHeapNumberType;
}

// Check if instance type is an Oddball
inline bool IsOddballInstanceType(uint16_t instance_type) {
    return instance_type == kOddballType;
}

// Check if instance type is a JSFunction (any subtype)
inline bool IsJSFunctionInstanceType(uint16_t instance_type) {
    // V8 12.x: JSFunction types are in 0x080f-0x0815 range
    return instance_type >= kJSFunctionTypeFirst &&
           instance_type <= kJSFunctionTypeLast;
}

// Check if instance type is a JSArray
inline bool IsJSArrayInstanceType(uint16_t instance_type) {
    // V8 12.x: JSArray is at 0x0843
    // Also check a range around it for safety
    return instance_type == kJSArrayType ||
           (instance_type >= 0x0840 && instance_type <= 0x0848);
}

// Check if instance type is a JS object (any kind)
inline bool IsJSObjectInstanceType(uint16_t instance_type) {
    return instance_type >= kFirstJSObjectType;
}

// Check if instance type is a JSError (any subtype)
inline bool IsJSErrorInstanceType(uint16_t instance_type) {
    return instance_type >= kJSErrorTypeFirst &&
           instance_type <= kJSErrorTypeLast;
}

// Check if instance type is a TypedArray (any element type)
inline bool IsJSTypedArrayInstanceType(uint16_t instance_type) {
    return instance_type >= kJSTypedArrayTypeFirst &&
           instance_type <= kJSTypedArrayTypeLast;
}

// Check if instance type is JSPromise
inline bool IsJSPromiseInstanceType(uint16_t instance_type) {
    return instance_type == kJSPromiseType ||
           (instance_type >= 0x423 && instance_type <= 0x426);
}

// Check if instance type is JSDate
inline bool IsJSDateInstanceType(uint16_t instance_type) {
    return instance_type == kJSDateType;
}

// Check if instance type is JSRegExp
inline bool IsJSRegExpInstanceType(uint16_t instance_type) {
    return instance_type == kJSRegExpType;
}

// Check if instance type is JSMap
inline bool IsJSMapInstanceType(uint16_t instance_type) {
    return instance_type == kJSMapType;
}

// Check if instance type is JSSet
inline bool IsJSSetInstanceType(uint16_t instance_type) {
    return instance_type == kJSSetType;
}

// Check if instance type is JSArrayBuffer
inline bool IsJSArrayBufferInstanceType(uint16_t instance_type) {
    return instance_type == kJSArrayBufferType;
}

} // namespace v8_internal
} // namespace malwi

#endif // MALWI_INSTANCE_TYPES_H
