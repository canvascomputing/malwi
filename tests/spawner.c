// Process spawning test fixture (SIP-safe).
// Tests fork, exec, and posix_spawn with custom binaries (not system binaries).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>

extern char **environ;

// Custom function that can be hooked to verify tracing works
// Named distinctly to avoid matching system functions
__attribute__((noinline))
void spawner_marker(int id) {
    // Prevent optimization
    volatile int x = id;
    (void)x;
    printf("spawner_marker called with id=%d\n", id);
}

// Get path to simple_target relative to this binary
static const char* get_simple_target_path() {
    // Assumes simple_target is in same directory
    // Use relative path - tests should run from fixtures dir or set PATH
    return "./simple_target";
}

void test_fork() {
    printf("spawner: testing fork()\n");
    spawner_marker(1);  // Mark parent before fork
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        exit(1);
    } else if (pid == 0) {
        // Child process
        printf("spawner: child PID=%d\n", getpid());
        spawner_marker(2);  // Mark child
        _exit(0);
    } else {
        // Parent
        printf("spawner: parent waiting for child %d\n", pid);
        int status;
        waitpid(pid, &status, 0);
        printf("spawner: child exited with %d\n", WEXITSTATUS(status));
        spawner_marker(3);  // Mark parent after child exits
    }
}

void test_exec() {
    printf("spawner: testing fork+exec()\n");
    spawner_marker(10);  // Mark before fork
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        exit(1);
    } else if (pid == 0) {
        // Child: exec simple_target
        const char *target = get_simple_target_path();
        printf("spawner: child about to exec %s\n", target);
        spawner_marker(11);  // Mark before exec
        char *args[] = {(char*)target, "from_exec", NULL};
        execv(target, args);
        perror("execv");
        _exit(1);
    } else {
        // Parent
        int status;
        waitpid(pid, &status, 0);
        printf("spawner: exec child exited with %d\n", WEXITSTATUS(status));
        spawner_marker(12);  // Mark after child exits
    }
}

void test_spawn() {
    printf("spawner: testing posix_spawn()\n");
    spawner_marker(20);  // Mark before spawn
    pid_t pid;
    const char *target = get_simple_target_path();
    char *args[] = {(char*)target, "from_spawn", NULL};

    int ret = posix_spawn(&pid, target, NULL, NULL, args, environ);
    if (ret != 0) {
        printf("posix_spawn failed: %d\n", ret);
        exit(1);
    }

    printf("spawner: spawned child %d\n", pid);
    int status;
    waitpid(pid, &status, 0);
    printf("spawner: spawn child exited with %d\n", WEXITSTATUS(status));
    spawner_marker(21);  // Mark after child exits
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <fork|exec|spawn|all>\n", argv[0]);
        return 1;
    }

    // Small delay to allow hooks to be set up
    usleep(100000); // 100ms

    if (strcmp(argv[1], "fork") == 0) {
        test_fork();
    } else if (strcmp(argv[1], "exec") == 0) {
        test_exec();
    } else if (strcmp(argv[1], "spawn") == 0) {
        test_spawn();
    } else if (strcmp(argv[1], "all") == 0) {
        test_fork();
        test_exec();
        test_spawn();
    } else {
        printf("Unknown test: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
