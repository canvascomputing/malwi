#include <stdlib.h>

/* Non-leaf function: calls malloc, gets PACIASP prologue at -O0 on arm64 */
int __attribute__((noinline)) compute(int a, int b) {
    int *p = (int *)malloc(sizeof(int));
    *p = a + b;
    int result = *p;
    free(p);
    return result;
}

int main(int argc, char **argv) {
    return compute(40, 2);
}
