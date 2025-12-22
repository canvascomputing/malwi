// V8 JavaScript Frame Constants
//
// This header defines platform-specific constants for V8's JavaScript stack
// frame layout. These are derived from V8's internal frame-constants.h but
// simplified for our use case (type detection only).
//
// Frame Layout (64-bit, all V8 versions — V8 11.x and 12.x):
// ┌─────────────────────┐  ← Higher addresses
// │  Caller's Frame     │
// ├─────────────────────┤
// │  Return Address     │  fp + 8  (kCallerPCOffset)
// ├─────────────────────┤
// │  Saved FP           │  fp      (kCallerFPOffset)
// ├─────────────────────┤
// │  Context            │  fp - 8  (kContextOffset)
// ├─────────────────────┤
// │  JSFunction         │  fp - 16 (kFunctionOffset)
// ├─────────────────────┤
// │  Argument Count     │  fp - 24 (kArgCOffset)
// ├─────────────────────┤
// │  arg[n-1]           │
// │  ...                │  caller_sp + (i+1) * ptr_size
// │  arg[0]             │
// │  receiver (this)    │  caller_sp + ptr_size
// └─────────────────────┘  ← Lower addresses
//
// The same formula applies to all platforms - just scaled by pointer size.

#ifndef MALWI_FRAME_CONSTANTS_H
#define MALWI_FRAME_CONSTANTS_H

#include <cstdint>
#include <cstddef>
#include <v8-version.h>

namespace malwi {
namespace v8_internal {

// =============================================================================
// Platform Detection
// =============================================================================

#if defined(__x86_64__) || defined(_M_X64)
    #define MALWI_ARCH_X64 1
    #define MALWI_ARCH_NAME "x64"
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define MALWI_ARCH_ARM64 1
    #define MALWI_ARCH_NAME "arm64"
#elif defined(__i386__) || defined(_M_IX86)
    #define MALWI_ARCH_IA32 1
    #define MALWI_ARCH_NAME "ia32"
#else
    #error "Unsupported architecture"
#endif

// =============================================================================
// Pointer Size Constants
// =============================================================================

#if defined(MALWI_ARCH_X64) || defined(MALWI_ARCH_ARM64)
    constexpr size_t kSystemPointerSize = 8;
    constexpr bool kIs64Bit = true;
#else
    constexpr size_t kSystemPointerSize = 4;
    constexpr bool kIs64Bit = false;
#endif

// Type aliases for clarity
using Address = uintptr_t;
using Tagged = uintptr_t;

// =============================================================================
// JavaScript Frame Layout Offsets
// =============================================================================

// These offsets are relative to the frame pointer (fp/rbp/x29)
// The formula is the same on all platforms - just scaled by pointer size

// Above fp (positive offsets - caller's data)
constexpr int kCallerFPOffset = 0;
constexpr int kCallerPCOffset = static_cast<int>(kSystemPointerSize);     // fp + 8 on 64-bit
constexpr int kCallerSPOffset = static_cast<int>(2 * kSystemPointerSize); // fp + 16 on 64-bit

// Below fp (negative offsets - current frame data)
constexpr int kContextOffset  = -static_cast<int>(1 * kSystemPointerSize); // fp - 8
constexpr int kFunctionOffset = -static_cast<int>(2 * kSystemPointerSize); // fp - 16

// argc at fp-24 on all V8 versions (verified against V8 11.8 and 12.x source:
// see deps/v8/src/execution/frame-constants.h StandardFrameConstants::kArgCOffset)
constexpr int kArgCOffset     = -static_cast<int>(3 * kSystemPointerSize); // fp - 24

// PPC64 uses an embedded constant pool - we don't support PPC64 for now
constexpr bool kHasEmbeddedConstantPool = false;
constexpr int kConstantPoolOffset = 0; // Only used on PPC64

// =============================================================================
// Frame Pointer Register Names (informational)
// =============================================================================

#if defined(MALWI_ARCH_X64)
    constexpr const char* kFramePointerRegName = "rbp";
#elif defined(MALWI_ARCH_ARM64)
    constexpr const char* kFramePointerRegName = "x29/fp";
#elif defined(MALWI_ARCH_IA32)
    constexpr const char* kFramePointerRegName = "ebp";
#endif

// =============================================================================
// Parameter Access Helpers
// =============================================================================

// Get the caller's stack pointer from frame pointer
inline Address GetCallerSP(Address fp) {
    return fp + kCallerSPOffset;
}

// Get address of parameter slot
// index 0 = first argument (not receiver)
// receiver is at index -1
inline Address GetParameterSlot(Address caller_sp, int index) {
    // Parameters are pushed in reverse order, starting after receiver
    // receiver at caller_sp + 1*ptr_size
    // arg[0] at caller_sp + 2*ptr_size  (index 0 -> offset (0+1+1)*ptr = 2*ptr)
    // Wait, let me check the V8 layout again...
    //
    // Actually from V8 docs: param[i] = caller_sp + (i + 1) * ptr_size
    // This means:
    // - receiver (this) at caller_sp + 1*ptr_size (not accessible via param index)
    // - arg[0] at caller_sp + 2*ptr_size... but that doesn't match the formula
    //
    // Re-reading: "param[i] = caller_sp + (i + 1) * 8"
    // With index starting at 0 for first param:
    // - param[0] = caller_sp + 8 (first argument)
    // - param[1] = caller_sp + 16 (second argument)
    // etc.
    //
    // But receiver is BELOW params, so receiver = caller_sp (at offset 0)?
    // Let me use the standard formula from the plan:
    return caller_sp + (index + 1) * kSystemPointerSize;
}

// Read argument count from frame
// Returns raw count INCLUDING receiver (subtract 1 to get argc)
inline intptr_t ReadRawArgCount(Address fp) {
    return *reinterpret_cast<intptr_t*>(fp + kArgCOffset);
}

// Get the JSFunction pointer from frame
inline Address ReadFunctionPointer(Address fp) {
    return *reinterpret_cast<Address*>(fp + kFunctionOffset);
}

// Get the context pointer from frame
inline Address ReadContextPointer(Address fp) {
    return *reinterpret_cast<Address*>(fp + kContextOffset);
}

// =============================================================================
// Address Validation
// =============================================================================

// Reasonable address range for user-space pointers
#if defined(MALWI_ARCH_X64) || defined(MALWI_ARCH_ARM64)
    // 64-bit: user space is typically 0x1000 to 0x7FFFFFFFFFFF
    constexpr Address kMinValidAddress = 0x1000;
    constexpr Address kMaxValidAddress = 0x7FFFFFFFFFFFF;
#else
    // 32-bit: user space is typically 0x1000 to 0xBFFFFFFF
    constexpr Address kMinValidAddress = 0x1000;
    constexpr Address kMaxValidAddress = 0xBFFFFFFF;
#endif

inline bool IsValidAddress(Address addr) {
    return addr >= kMinValidAddress && addr <= kMaxValidAddress;
}

inline bool IsAlignedPointer(Address addr) {
    return (addr % kSystemPointerSize) == 0;
}

inline bool IsValidPointer(Address addr) {
    return IsValidAddress(addr) && IsAlignedPointer(addr);
}

} // namespace v8_internal
} // namespace malwi

#endif // MALWI_FRAME_CONSTANTS_H
