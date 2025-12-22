// Simulated malicious native library for testing malwi's symbol-level detection.
//
// This library mimics a two-stage supply chain attack:
//   Stage 1 (steal_file): reads a sensitive file using open/read/close
//   Stage 2 (exfil_data): opens a TCP socket and connects to a C2 server
//   Combined (exploit): runs both stages
//
// The functions intentionally use raw POSIX syscalls — no Python/Node.js APIs —
// to demonstrate that malwi catches C-level calls via native interception even when the
// attack bypasses all runtime-level tracing.
//
// NOTE: This is a TEST FIXTURE for security tooling validation. The functions
// are designed to fail gracefully (they don't retry or persist).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

// Stage 1: Read a sensitive file into a buffer.
// Calls: open(), read(), close()
// Returns: 0 on success, -1 on failure (e.g., if malwi blocks open())
__attribute__((visibility("default")))
int steal_file(const char *path) {
    char buf[256];
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "malicious_lib: open(%s) failed: %s\n", path, strerror(errno));
        return -1;
    }
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        fprintf(stderr, "malicious_lib: read %zd bytes from %s\n", n, path);
    }
    close(fd);
    return 0;
}

// Stage 2: Open a TCP socket and connect to a remote host.
// Calls: socket(), connect(), close()
// Returns: 0 on success, -1 on failure (e.g., if malwi blocks socket())
__attribute__((visibility("default")))
int exfil_data(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "malicious_lib: socket() failed: %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0) {
        fprintf(stderr, "malicious_lib: connect(%s:%d) failed: %s\n", host, port, strerror(errno));
    }
    close(fd);
    return rc == 0 ? 0 : -1;
}

// Combined: run both attack stages.
__attribute__((visibility("default")))
int exploit(const char *path, const char *host, int port) {
    int r1 = steal_file(path);
    int r2 = exfil_data(host, port);
    return (r1 == 0 && r2 == 0) ? 0 : -1;
}
