# Build example programs

CC = clang
CFLAGS = -g -O0

TARGETS = hello

all: $(TARGETS)

hello: hello.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

.PHONY: all clean
