// Simple test target for injection testing.
// Sleeps for a while, printing messages to show it's alive.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

volatile int running = 1;

void signal_handler(int sig) {
    printf("[test_target] Received signal %d, exiting...\n", sig);
    running = 0;
}

int main(int argc, char *argv[]) {
    // Setup signal handler
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    printf("[test_target] Started with PID %d\n", getpid());
    fflush(stdout);

    int count = 0;
    while (running && count < 30) {  // Run for up to 30 seconds
        sleep(1);
        count++;
        printf("[test_target] Alive for %d seconds...\n", count);
        fflush(stdout);
    }

    printf("[test_target] Exiting normally\n");
    return 0;
}
