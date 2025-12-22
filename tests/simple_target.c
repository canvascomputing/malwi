// Simple target binary for exec tests (SIP-safe).
// This binary can be exec'd by other test fixtures without SIP blocking injection.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Unique marker function for verifying this binary was traced.
// Named distinctly to avoid matching any system or Node.js functions.
__attribute__((noinline))
void simple_target_marker(int id) {
    // Prevent optimization
    volatile int x = id;
    (void)x;
    printf("simple_target_marker called with id=%d\n", id);
}

int main(int argc, char *argv[]) {
    printf("simple_target: PID=%d\n", getpid());

    // Call marker function - this can be hooked to verify tracing works
    simple_target_marker(1);

    // Do some allocations to trigger hooks
    void *p1 = malloc(100);
    void *p2 = malloc(200);
    free(p1);
    free(p2);

    // Call marker again after allocations
    simple_target_marker(2);

    // Print args if any
    for (int i = 1; i < argc; i++) {
        printf("arg[%d]=%s\n", i, argv[i]);
    }

    return 0;
}
