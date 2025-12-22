// V8 Tagged Value Detection
//
// This header provides utilities for detecting V8's tagged pointer types
// without relying on internal V8 headers that may not be exported.
//
// V8 Tagged Pointer Encoding (64-bit):
// =====================================
//
// V8 uses a tagged pointer scheme where the low bits indicate the type:
//
// Smi (Small Integer):
//   - Low bit = 0
//   - Value is stored in upper 32 bits (on 64-bit)
//   - Formula: value = tagged_ptr >> 32
//
// HeapObject:
//   - Low bit = 1
//   - Actual address = tagged_ptr - 1 (or tagged_ptr & ~1)
//   - First field of heap object is the Map pointer (also tagged)
//
// HeapObject Layout:
// ==================
//
// Offset 0:  Map pointer (tagged)
// Offset varies: Object-specific data
//
// Map Layout:
// ===========
//
// The Map contains the instance type which tells us what kind of object this is.
// Map layout offsets vary slightly between V8 versions but instance type is
// typically at offset 12 (after map pointer + instance descriptors bits).

#ifndef MALWI_TAGGED_VALUE_H
#define MALWI_TAGGED_VALUE_H

#include "frame_constants.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace malwi {
namespace v8_internal {

// =============================================================================
// Smi Detection and Extraction
// =============================================================================

// Check if a tagged value is a Smi (Small Integer)
// Smi: low bit = 0
inline bool IsSmi(Tagged tagged_value) {
    return (tagged_value & 1) == 0;
}

// Check if a tagged value is a HeapObject
// HeapObject: low bit = 1
inline bool IsHeapObject(Tagged tagged_value) {
    return (tagged_value & 1) == 1;
}

// Extract Smi value from tagged pointer
// On 64-bit: value is in upper 32 bits
// On 32-bit: value is in upper 31 bits (shifted by 1)
inline int32_t SmiValue(Tagged tagged_value) {
#if defined(MALWI_ARCH_X64) || defined(MALWI_ARCH_ARM64)
    // 64-bit: Smi value in upper 32 bits
    return static_cast<int32_t>(tagged_value >> 32);
#else
    // 32-bit: Smi value in upper 31 bits
    return static_cast<int32_t>(tagged_value) >> 1;
#endif
}

// =============================================================================
// HeapObject Address Extraction
// =============================================================================

// Get the actual heap object address from a tagged pointer
// HeapObject tag is 1, so we subtract 1 (or clear low bit)
inline Address HeapObjectAddress(Tagged tagged_value) {
    // Clear the tag bit to get actual address
    return tagged_value & ~static_cast<Address>(1);
}

// =============================================================================
// Map and Instance Type Access
// =============================================================================

// Map structure offsets (these may vary slightly between V8 versions)
// We use conservative values that should work across versions

// Instance type offset within Map object
// In V8, the instance type is stored early in the Map layout
// Typical layout: [map_ptr (offset 0)] ... [instance_type (offset ~12)]
constexpr int kMapInstanceTypeOffset = 12;

// Oddball kind offset within Oddball objects
// V8 12.x layout: [map] [to_number_raw(double)] [to_string] [to_number] [type_of] [kind]
// Formula from V8: 4 * kApiTaggedSize + kApiDoubleSize = 4 * 8 + 8 = 40 bytes
// This equals 5 * pointer_size on 64-bit (map is NOT counted here since it's the heap object header)
constexpr int kOddballKindOffset = 4 * static_cast<int>(kSystemPointerSize) + 8;

// Read the Map pointer from a HeapObject
// Returns the tagged Map pointer (still has tag bit set)
inline Tagged ReadMapPointer(Address heap_object_addr) {
    return *reinterpret_cast<Tagged*>(heap_object_addr);
}

// Read the Map pointer from a tagged HeapObject value
inline Tagged ReadMapPointerFromTagged(Tagged tagged_value) {
    if (!IsHeapObject(tagged_value)) {
        return 0; // Not a heap object
    }
    Address obj_addr = HeapObjectAddress(tagged_value);
    if (!IsValidPointer(obj_addr)) {
        return 0; // Invalid address
    }
    return ReadMapPointer(obj_addr);
}

// Get instance type from Map
// The Map is also a HeapObject, so we need to untag it first
inline uint16_t GetInstanceType(Tagged tagged_value) {
    if (!IsHeapObject(tagged_value)) {
        return 0xFFFF; // Invalid - not a heap object
    }

    // Get heap object address
    Address obj_addr = HeapObjectAddress(tagged_value);
    if (!IsValidPointer(obj_addr)) {
        return 0xFFFF; // Invalid address
    }

    // Read map pointer (still tagged)
    Tagged map_tagged = ReadMapPointer(obj_addr);
    if (!IsHeapObject(map_tagged)) {
        return 0xFFFF; // Map should be a heap object
    }

    // Get map address
    Address map_addr = HeapObjectAddress(map_tagged);
    if (!IsValidPointer(map_addr)) {
        return 0xFFFF; // Invalid map address
    }

    // Read instance type from map
    return *reinterpret_cast<uint16_t*>(map_addr + kMapInstanceTypeOffset);
}

// Get Oddball kind (for undefined, null, true, false detection)
inline int GetOddballKind(Tagged tagged_value) {
    if (!IsHeapObject(tagged_value)) {
        return -1; // Not a heap object
    }

    Address obj_addr = HeapObjectAddress(tagged_value);
    if (!IsValidPointer(obj_addr)) {
        return -1; // Invalid address
    }

    // Read kind from oddball offset
    // Kind is stored as a Smi, so we need to extract the value
    Tagged kind_tagged = *reinterpret_cast<Tagged*>(obj_addr + kOddballKindOffset);

    if (IsSmi(kind_tagged)) {
        return SmiValue(kind_tagged);
    }

    return -1; // Unexpected format
}

// =============================================================================
// Safe Memory Reading
// =============================================================================

// Safely read a pointer from memory with validation
inline bool SafeReadPointer(Address addr, Address* out) {
    if (!IsValidPointer(addr)) {
        return false;
    }

    // TODO: Could add try/catch or signal handling for extra safety
    // For now, we rely on address validation
    *out = *reinterpret_cast<Address*>(addr);
    return true;
}

// Safely read instance type with full validation
inline bool SafeGetInstanceType(Tagged tagged_value, uint16_t* out) {
    if (!IsHeapObject(tagged_value)) {
        return false;
    }

    Address obj_addr = HeapObjectAddress(tagged_value);
    if (!IsValidPointer(obj_addr)) {
        return false;
    }

    Address map_tagged;
    if (!SafeReadPointer(obj_addr, &map_tagged)) {
        return false;
    }

    if (!IsHeapObject(map_tagged)) {
        return false;
    }

    Address map_addr = HeapObjectAddress(map_tagged);
    if (!IsValidPointer(map_addr)) {
        return false;
    }

    // Instance type is a uint16, not a pointer, so just validate map_addr
    *out = *reinterpret_cast<uint16_t*>(map_addr + kMapInstanceTypeOffset);
    return true;
}

// =============================================================================
// Value Extraction
// =============================================================================

// V8 HeapNumber layout: [map (8 bytes)] [double value (8 bytes)]
constexpr int kHeapNumberValueOffset = 8;

// V8 String layout (SeqString): [map (8)] [hash (4)] [length (4)] [data...]
// Note: In V8 12.x, length is stored as raw int32 at offset 12
constexpr int kStringLengthOffset = 12;
constexpr int kSeqStringDataOffset = 16;

// V8 ExternalString layout: [map (8)] [hash (4)] [length (4)] [resource_ptr (8)]
// The resource is a v8::String::ExternalOneByteStringResource or similar
// The resource's data pointer is at offset 0 of the vtable-based object
// We use offset 8 (after vtable) as that's where simple implementations store data ptr
constexpr int kExternalStringResourceOffset = 16;

// V8 JSArray layout: [map] [properties] [elements] [length (Smi)]
constexpr int kJSArrayLengthOffset = 24;

// Extract double value from HeapNumber
inline bool SafeReadHeapNumberValue(Tagged tagged_value, double* out) {
    if (!IsHeapObject(tagged_value)) {
        return false;
    }

    Address obj_addr = HeapObjectAddress(tagged_value);
    if (!IsValidPointer(obj_addr)) {
        return false;
    }

    Address value_addr = obj_addr + kHeapNumberValueOffset;
    if (!IsValidPointer(value_addr)) {
        return false;
    }

    *out = *reinterpret_cast<double*>(value_addr);
    return true;
}

// Debug: set to 1 to enable string extraction debug output
#define MALWI_DEBUG_STRING 0

// Extract string value from V8 String object
// Supports SeqOneByteString, SeqTwoByteString, and InternalizedString
// Returns heap-allocated string or nullptr. Caller must free().
inline char* SafeReadStringValue(Tagged tagged_value, size_t max_len) {
    if (!IsHeapObject(tagged_value)) {
#if MALWI_DEBUG_STRING
        fprintf(stderr, "[malwi-debug] SafeReadStringValue: not a heap object\n");
#endif
        return nullptr;
    }

    Address obj_addr = HeapObjectAddress(tagged_value);
    if (!IsValidPointer(obj_addr)) {
#if MALWI_DEBUG_STRING
        fprintf(stderr, "[malwi-debug] SafeReadStringValue: invalid obj_addr\n");
#endif
        return nullptr;
    }

    // Get instance type to determine string type
    uint16_t instance_type;
    if (!SafeGetInstanceType(tagged_value, &instance_type)) {
#if MALWI_DEBUG_STRING
        fprintf(stderr, "[malwi-debug] SafeReadStringValue: failed to get instance type\n");
#endif
        return nullptr;
    }

#if MALWI_DEBUG_STRING
    fprintf(stderr, "[malwi-debug] String instance_type=0x%04x\n", instance_type);
#endif

    // Check it's a string (instance_type < 0x80)
    if (instance_type >= 0x80) {
#if MALWI_DEBUG_STRING
        fprintf(stderr, "[malwi-debug] SafeReadStringValue: not a string type\n");
#endif
        return nullptr;
    }

    // V8 12.x string instance type encoding (from deps/v8/src/objects/instance-type.h):
    // Bits 0-2: representation (kStringRepresentationMask = 0x07)
    //   - 0x0 = Sequential (data inline at offset 16)
    //   - 0x1 = Cons (concatenated)
    //   - 0x2 = External (resource pointer)
    //   - 0x3 = Sliced
    //   - 0x5 = Thin
    // Bit 3: encoding (kStringEncodingMask = 0x08)
    //   - 0 = Two-byte
    //   - 1 = One-byte
    //
    // Example: instance_type 0x0008 = Sequential One-Byte String
    //   representation = 0x0008 & 0x07 = 0 (Sequential)
    //   is_one_byte = (0x0008 & 0x08) != 0 = true

    uint8_t representation = instance_type & 0x07;  // Bits 0-2 (kStringRepresentationMask)
    bool is_one_byte = (instance_type & 0x08) != 0;  // Bit 3 (kStringEncodingMask)

#if MALWI_DEBUG_STRING
    fprintf(stderr, "[malwi-debug] representation=%d, is_one_byte=%d\n",
            representation, is_one_byte);
    fflush(stderr);
#endif

    // Read length (stored as int32 at offset 12 in V8 12.x)
    // Note: length is at offset 12, which is 4-byte aligned but not 8-byte aligned
    // Use IsValidAddress instead of IsValidPointer to allow non-pointer-aligned access
    Address len_addr = obj_addr + kStringLengthOffset;
    if (!IsValidAddress(len_addr)) {
#if MALWI_DEBUG_STRING
        fprintf(stderr, "[malwi-debug] len_addr is invalid (addr=0x%lx)\n", (unsigned long)len_addr);
        fflush(stderr);
#endif
        return nullptr;
    }
    int32_t length = *reinterpret_cast<int32_t*>(len_addr);

#if MALWI_DEBUG_STRING
    fprintf(stderr, "[malwi-debug] string length=%d\n", length);
    fflush(stderr);
#endif

    // Sanity check length
    if (length <= 0 || length > 100000) {
#if MALWI_DEBUG_STRING
        fprintf(stderr, "[malwi-debug] SafeReadStringValue: bad length %d\n", length);
        fflush(stderr);
#endif
        return nullptr;
    }

    size_t copy_len = (static_cast<size_t>(length) > max_len) ? max_len : static_cast<size_t>(length);

    char* result = static_cast<char*>(malloc(copy_len + 1));
    if (!result) {
        return nullptr;
    }

    // String representation types:
    // 0 = Sequential (data inline)
    // 1 = Cons (two strings concatenated)
    // 2 = External (pointer to external data)
    // 3 = Sliced (substring of another string)
    // 5 = Thin (indirection to another string)

    if (representation == 0) {
        // Sequential string - data is inline
        Address data_addr = obj_addr + kSeqStringDataOffset;
        if (!IsValidPointer(data_addr)) {
            free(result);
            return nullptr;
        }

        if (is_one_byte) {
            memcpy(result, reinterpret_cast<char*>(data_addr), copy_len);
        } else {
            const uint16_t* src = reinterpret_cast<uint16_t*>(data_addr);
            for (size_t i = 0; i < copy_len; i++) {
                result[i] = (src[i] < 128) ? static_cast<char>(src[i]) : '?';
            }
        }
    } else if (representation == 2) {
        // External string handling for V8 12.x
        // In V8 12.x, short external strings may store data inline at offset 16
        // (where the resource pointer would normally be), instead of as a pointer
        // to an external resource.
#if MALWI_DEBUG_STRING
        fprintf(stderr, "[malwi-debug] ENTERING EXTERNAL STRING BRANCH\n");
        fflush(stderr);
#endif

        // First, try reading data directly at offset 16 (inline data for short strings)
        Address data_addr = obj_addr + kExternalStringResourceOffset;
        if (!IsValidAddress(data_addr)) {
#if MALWI_DEBUG_STRING
            fprintf(stderr, "[malwi-debug] data_addr is invalid\n");
            fflush(stderr);
#endif
            free(result);
            return nullptr;
        }

#if MALWI_DEBUG_STRING
        fprintf(stderr, "[malwi-debug] Trying inline read at offset 16\n");
        fflush(stderr);
#endif

        // For short strings, data is stored inline starting at offset 16
        // Read directly as character data
        if (is_one_byte) {
            memcpy(result, reinterpret_cast<char*>(data_addr), copy_len);
        } else {
            const uint16_t* src = reinterpret_cast<uint16_t*>(data_addr);
            for (size_t i = 0; i < copy_len; i++) {
                result[i] = (src[i] < 128) ? static_cast<char>(src[i]) : '?';
            }
        }

#if MALWI_DEBUG_STRING
        fprintf(stderr, "[malwi-debug] Read inline data: first bytes = %02x %02x %02x\n",
                (unsigned char)result[0], (unsigned char)result[1], (unsigned char)result[2]);
        fflush(stderr);
#endif
    } else {
        // Cons, Sliced, Thin - not supported
#if MALWI_DEBUG_STRING
        fprintf(stderr, "[malwi-debug] SafeReadStringValue: unsupported representation=%d\n", representation);
#endif
        free(result);
        return nullptr;
    }

    result[copy_len] = '\0';
#if MALWI_DEBUG_STRING
    fprintf(stderr, "[malwi-debug] extracted string: \"%s\"\n", result);
#endif
    return result;
}

// Extract JSArray length
inline bool SafeReadArrayLength(Tagged tagged_value, int32_t* out) {
    if (!IsHeapObject(tagged_value)) {
        return false;
    }

    Address obj_addr = HeapObjectAddress(tagged_value);
    if (!IsValidPointer(obj_addr)) {
        return false;
    }

    Address len_addr = obj_addr + kJSArrayLengthOffset;
    if (!IsValidPointer(len_addr)) {
        return false;
    }

    Tagged len_tagged = *reinterpret_cast<Tagged*>(len_addr);
    if (!IsSmi(len_tagged)) {
        return false;
    }

    *out = SmiValue(len_tagged);
    return true;
}

} // namespace v8_internal
} // namespace malwi

#endif // MALWI_TAGGED_VALUE_H
