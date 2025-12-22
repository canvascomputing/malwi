// Simple fork test program
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>

void test_fork() {
    printf("Parent PID: %d\n", getpid());

    pid_t pid = fork();

    if (pid < 0) {
        perror("fork failed");
        exit(1);
    } else if (pid == 0) {
        // Child process
        printf("Child PID: %d, Parent: %d\n", getpid(), getppid());

        // Do some malloc to trigger hooks
        void *ptr = malloc(1024);
        printf("Child malloc: %p\n", ptr);
        free(ptr);

        exit(0);
    } else {
        // Parent process
        printf("Parent: child PID is %d\n", pid);

        // Parent also does malloc
        void *ptr = malloc(2048);
        printf("Parent malloc: %p\n", ptr);
        free(ptr);

        // Wait for child
        int status;
        waitpid(pid, &status, 0);
        printf("Child exited with status %d\n", WEXITSTATUS(status));
    }
}

void test_exec() {
    printf("About to exec /bin/echo\n");

    char *args[] = {"/bin/echo", "Hello from exec!", NULL};
    execv("/bin/echo", args);

    // Only reached if exec fails
    perror("exec failed");
    exit(1);
}

void test_fork_exec() {
    printf("Parent PID: %d\n", getpid());

    pid_t pid = fork();

    if (pid < 0) {
        perror("fork failed");
        exit(1);
    } else if (pid == 0) {
        // Child will exec
        printf("Child PID: %d about to exec\n", getpid());

        char *args[] = {"/bin/echo", "Hello from child exec!", NULL};
        execv("/bin/echo", args);

        perror("exec failed");
        exit(1);
    } else {
        // Parent waits
        int status;
        waitpid(pid, &status, 0);
        printf("Child exited with status %d\n", WEXITSTATUS(status));
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <fork|exec|fork_exec>\n", argv[0]);
        return 1;
    }

    // Delay to allow hooks and child gating to be set up
    // The agent needs time to receive EnableChildGating before fork
    usleep(500000); // 500ms

    if (strcmp(argv[1], "fork") == 0) {
        test_fork();
    } else if (strcmp(argv[1], "exec") == 0) {
        test_exec();
    } else if (strcmp(argv[1], "fork_exec") == 0) {
        test_fork_exec();
    } else {
        printf("Unknown test: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
