/*
 * hello.c - Simple example for native function tracing
 *
 * Build:   make
 * Trace:   ../malwi x -c malloc -c free ./hello
 * Stack:   ../malwi x -t -c malloc ./hello
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* greet(const char* name) {
    size_t len = strlen(name) + 10;
    char* msg = malloc(len);
    snprintf(msg, len, "Hello, %s!", name);
    return msg;
}

int main(int argc, char* argv[]) {
    const char* name = argc > 1 ? argv[1] : "World";

    char* message = greet(name);
    printf("%s\n", message);
    free(message);

    return 0;
}
