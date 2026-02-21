# Makefile for test fixtures
# Builds C test programs for integration testing

CC ?= cc
# -rdynamic exports all symbols to the dynamic symbol table (needed for hooking on Linux)
CFLAGS = -Wall -g -O0 -rdynamic

# Detect current platform
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Platform-specific shared library extension and flags
ifeq ($(UNAME_S),Darwin)
  SHLIB_EXT = dylib
  SHLIB_FLAGS = -shared -fPIC -dynamiclib
  # Make intra-image function calls interposable, so our macOS hook backend can
  # fall back to symbol-pointer rebinding when inline patching is not possible.
  #
  # This is intentionally applied only to fixtures where we need to hook local
  # functions (e.g. simple_target_marker).
  INTERPOSABLE_FLAGS = -Wl,-interposable
else
  SHLIB_EXT = so
  SHLIB_FLAGS = -shared -fPIC
  INTERPOSABLE_FLAGS =
endif

# All targets
TARGETS = simple_target multithread spawner forker test_target malicious_target malicious_lib.$(SHLIB_EXT) direct_syscall_target

# pac_target only on arm64 (requires -mbranch-protection=standard)
ifeq ($(UNAME_M),arm64)
  TARGETS += pac_target
endif

.PHONY: all clean check-platform

# Check platform before building - clean if binaries are from different OS
all: check-platform $(TARGETS)

check-platform:
	@if [ -f simple_target ]; then \
		FILE_TYPE=$$(file simple_target 2>/dev/null); \
		if [ "$(UNAME_S)" = "Darwin" ] && echo "$$FILE_TYPE" | grep -q "ELF"; then \
			echo "Detected Linux binaries on macOS - cleaning..."; \
			$(MAKE) clean; \
		elif [ "$(UNAME_S)" = "Linux" ] && echo "$$FILE_TYPE" | grep -q "Mach-O"; then \
			echo "Detected macOS binaries on Linux - cleaning..."; \
			$(MAKE) clean; \
		fi \
	fi

simple_target: simple_target.c
	$(CC) $(CFLAGS) $(INTERPOSABLE_FLAGS) -o $@ $<

multithread: multithread.c
	$(CC) $(CFLAGS) -pthread -o $@ $<

spawner: spawner.c
	$(CC) $(CFLAGS) -o $@ $<

forker: forker.c
	$(CC) $(CFLAGS) -o $@ $<

test_target: test_target.c
	$(CC) $(CFLAGS) -o $@ $<

malicious_lib.$(SHLIB_EXT): malicious_lib.c
	$(CC) $(SHLIB_FLAGS) -Wall -g -O0 -o $@ $<

malicious_target: malicious_target.c
	$(CC) $(CFLAGS) -o $@ $<

direct_syscall_target: direct_syscall_target.c
	$(CC) $(CFLAGS) -o $@ $<

pac_target: pac_target.c
	$(CC) $(CFLAGS) -mbranch-protection=standard -o $@ $<

clean:
	rm -f $(TARGETS)
