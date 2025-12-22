// Multi-threaded test program for thread safety validation.
// Creates multiple threads that call hooked functions concurrently.

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#define NUM_THREADS 4
#define ITERATIONS 5

// Custom marker function for tracing - avoids hooking malloc which is called
// constantly by system threads and can overwhelm HTTP
__attribute__((noinline))
void multithread_marker(int thread_id, int iteration) {
    volatile int x = thread_id + iteration;
    (void)x;
    printf("multithread_marker: thread=%d iter=%d\n", thread_id, iteration);
}

void* thread_func(void* arg) {
    int id = *(int*)arg;
    printf("Thread %d started (tid approx)\n", id);

    for (int i = 0; i < ITERATIONS; i++) {
        // Call our marker function which can be traced
        multithread_marker(id, i);

        // Also do some malloc/free but these won't be traced
        size_t size = 100 + (id * 10) + i;
        void* p = malloc(size);
        if (p) {
            ((char*)p)[0] = (char)id;
            free(p);
        }
        // Small delay to interleave threads
        usleep(1000);
    }

    printf("Thread %d finished\n", id);
    return NULL;
}

int main() {
    pthread_t threads[NUM_THREADS];
    int ids[NUM_THREADS];

    printf("multithread: starting %d threads\n", NUM_THREADS);

    // Create threads
    for (int i = 0; i < NUM_THREADS; i++) {
        ids[i] = i;
        if (pthread_create(&threads[i], NULL, thread_func, &ids[i]) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    // Wait for all threads
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("multithread: all threads completed\n");
    return 0;
}
