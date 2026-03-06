// Test fixture for fork/daemon scenarios with network calls.
// Modes: fork-connect, fork-thread-connect, daemon-connect, fork-multi-connect

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>

// Marker function for trace identification
__attribute__((noinline))
void daemon_net_marker(const char *label) {
    volatile int x = 42;
    (void)x;
    printf("daemon_net_marker: %s (pid=%d)\n", label, getpid());
}

// Perform network calls that trigger hookable symbols.
// connect() to localhost:1 will fail with ECONNREFUSED — that's fine,
// the hook still fires on the syscall entry.
static void do_network_calls(const char *label) {
    printf("[%s] Starting network calls (pid=%d)\n", label, getpid());

    // getaddrinfo — DNS resolution
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *result = NULL;
    int rc = getaddrinfo("localhost", "80", &hints, &result);
    printf("[%s] getaddrinfo: %s\n", label, rc == 0 ? "ok" : gai_strerror(rc));
    if (result) freeaddrinfo(result);

    // socket + connect
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd >= 0) {
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(1); // port 1 — will ECONNREFUSED
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        printf("[%s] connect: %s\n", label, rc == 0 ? "ok" : strerror(errno));
        close(fd);
    } else {
        printf("[%s] socket failed: %s\n", label, strerror(errno));
    }

    daemon_net_marker(label);
}

// Thread entry point for fork-thread-connect mode
static void *thread_network(void *arg) {
    const char *label = (const char *)arg;
    do_network_calls(label);
    return NULL;
}

// Mode: fork-connect
// Fork once, child does network calls, parent waits.
static void mode_fork_connect(void) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }

    if (pid == 0) {
        do_network_calls("child");
        exit(0);
    }

    // Parent waits
    int status;
    waitpid(pid, &status, 0);
    printf("Parent: child exited %d\n", WEXITSTATUS(status));
}

// Mode: fork-thread-connect
// Fork once, child spawns a thread that does network calls, parent waits.
static void mode_fork_thread_connect(void) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }

    if (pid == 0) {
        pthread_t t;
        pthread_create(&t, NULL, thread_network, (void *)"child-thread");
        pthread_join(t, NULL);
        exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    printf("Parent: child exited %d\n", WEXITSTATUS(status));
}

// Mode: daemon-connect
// Classic double-fork daemon: fork → setsid → fork.
// Grandchild does network calls. Parent exits immediately.
// Known limitation: CLI's 500ms post-exit timeout may miss grandchild events.
static void mode_daemon_connect(void) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }

    if (pid > 0) {
        // Parent exits immediately (classic daemon pattern)
        printf("Parent exiting (pid=%d)\n", getpid());
        exit(0);
    }

    // First child: become session leader
    setsid();

    pid = fork();
    if (pid < 0) { perror("fork2"); exit(1); }

    if (pid > 0) {
        // First child exits
        printf("First child exiting (pid=%d)\n", getpid());
        exit(0);
    }

    // Grandchild: the actual daemon
    printf("Daemon grandchild running (pid=%d)\n", getpid());
    do_network_calls("daemon");
    exit(0);
}

// Mode: fork-multi-connect
// Fork 3 children, each does network calls concurrently, parent waits for all.
static void mode_fork_multi_connect(void) {
    const int nchildren = 3;
    pid_t pids[3];

    for (int i = 0; i < nchildren; i++) {
        pids[i] = fork();
        if (pids[i] < 0) { perror("fork"); exit(1); }

        if (pids[i] == 0) {
            char label[32];
            snprintf(label, sizeof(label), "child-%d", i);
            do_network_calls(label);
            exit(0);
        }
    }

    // Parent waits for all children
    for (int i = 0; i < nchildren; i++) {
        int status;
        waitpid(pids[i], &status, 0);
        printf("Parent: child %d exited %d\n", i, WEXITSTATUS(status));
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <fork-connect|fork-thread-connect|daemon-connect|fork-multi-connect>\n",
               argv[0]);
        return 1;
    }

    // Delay to allow hooks and child gating to be set up
    usleep(500000); // 500ms

    if (strcmp(argv[1], "fork-connect") == 0) {
        mode_fork_connect();
    } else if (strcmp(argv[1], "fork-thread-connect") == 0) {
        mode_fork_thread_connect();
    } else if (strcmp(argv[1], "daemon-connect") == 0) {
        mode_daemon_connect();
    } else if (strcmp(argv[1], "fork-multi-connect") == 0) {
        mode_fork_multi_connect();
    } else {
        printf("Unknown mode: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
