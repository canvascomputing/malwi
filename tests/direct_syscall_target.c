// Test target that issues a direct syscall (bypassing libc wrappers).
// Used to verify direct syscall detection.

#include <stdio.h>

#if defined(__APPLE__) && defined(__aarch64__)
// macOS ARM64: socket() syscall via SVC #0x80
// x16 = syscall number (97 = socket)
// x0 = domain (AF_INET = 2), x1 = type (SOCK_STREAM = 1), x2 = protocol (0)
static long direct_socket_syscall(void) {
    register long x16 __asm__("x16") = 97;  // SYS_socket
    register long x0 __asm__("x0") = 2;     // AF_INET
    register long x1 __asm__("x1") = 1;     // SOCK_STREAM
    register long x2 __asm__("x2") = 0;     // protocol
    __asm__ volatile(
        "svc #0x80"
        : "+r"(x0)
        : "r"(x16), "r"(x1), "r"(x2)
        : "memory", "cc"
    );
    return x0;
}
#elif defined(__APPLE__) && defined(__x86_64__)
// macOS x86_64: socket() syscall via syscall instruction
// rax = syscall number (0x2000000 | 97 = socket with BSD class)
static long direct_socket_syscall(void) {
    long result;
    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(0x2000000 | 97), "D"(2), "S"(1), "d"(0)
        : "rcx", "r11", "memory", "cc"
    );
    return result;
}
#elif defined(__linux__) && defined(__x86_64__)
// Linux x86_64: socket() syscall via syscall instruction
// rax = 41 (SYS_socket)
static long direct_socket_syscall(void) {
    long result;
    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(41), "D"(2), "S"(1), "d"(0)
        : "rcx", "r11", "memory", "cc"
    );
    return result;
}
#elif defined(__linux__) && defined(__aarch64__)
// Linux ARM64: socket() syscall via SVC #0
// x8 = syscall number (198 = socket)
static long direct_socket_syscall(void) {
    register long x8 __asm__("x8") = 198;   // SYS_socket
    register long x0 __asm__("x0") = 2;     // AF_INET
    register long x1 __asm__("x1") = 1;     // SOCK_STREAM
    register long x2 __asm__("x2") = 0;     // protocol
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2)
        : "memory", "cc"
    );
    return x0;
}
#else
static long direct_socket_syscall(void) {
    printf("direct_syscall_target: unsupported platform\n");
    return -1;
}
#endif

int main(void) {
    printf("direct_syscall_target: issuing direct socket() syscall\n");
    long result = direct_socket_syscall();
    printf("direct_syscall_target: result=%ld\n", result);

    // Close the fd if it succeeded
    if (result >= 0) {
#if defined(__APPLE__) && defined(__aarch64__)
        // Direct close() syscall: x16=6 (SYS_close)
        register long x16 __asm__("x16") = 6;
        register long x0 __asm__("x0") = result;
        __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x16) : "memory", "cc");
#elif defined(__APPLE__) && defined(__x86_64__)
        long ret;
        __asm__ volatile("syscall" : "=a"(ret) : "a"(0x2000000 | 6), "D"(result) : "rcx", "r11", "memory", "cc");
#elif defined(__linux__) && defined(__x86_64__)
        long ret;
        __asm__ volatile("syscall" : "=a"(ret) : "a"(3), "D"(result) : "rcx", "r11", "memory", "cc");
#elif defined(__linux__) && defined(__aarch64__)
        register long x8 __asm__("x8") = 57;  // SYS_close
        register long x0 __asm__("x0") = result;
        __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory", "cc");
#endif
    }

    return 0;
}
