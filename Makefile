.PHONY: all build addon addon-install addon-all addon-node25 test clean fixtures

# Detect platform for addon installation
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
    ifeq ($(UNAME_M),arm64)
        ADDON_PLATFORM := darwin-arm64
        TEST_PLATFORM := arm64/mac
    else
        ADDON_PLATFORM := darwin-x64
        TEST_PLATFORM := x64/mac
    endif
else ifeq ($(UNAME_S),Linux)
    ifeq ($(UNAME_M),aarch64)
        ADDON_PLATFORM := linux-arm64
        TEST_PLATFORM := arm64/linux
    else
        ADDON_PLATFORM := linux-x64
        TEST_PLATFORM := x64/linux
    endif
else
    ADDON_PLATFORM := windows-x64
    TEST_PLATFORM := x64/windows
endif

# Default MALWI_TEST_BINARIES to in-project binaries/ if present
MALWI_TEST_BINARIES ?= $(shell [ -d binaries ] && echo binaries)

# Detect Node.js major version
NODE_VERSION := $(shell node --version 2>/dev/null | sed 's/v\([0-9]*\).*/node\1/')
ifeq ($(NODE_VERSION),)
    NODE_VERSION := node22
endif

# Default target: build addon and Rust project
all: addon-install build

build:
	cargo build --release
	ln -sf target/release/malwi .

addon:
	cd node-addon && npm install && npm audit --audit-level=high && npm run build

addon-install: addon
	@mkdir -p node-addon/prebuilt/$(ADDON_PLATFORM)/$(NODE_VERSION)
	cp node-addon/build/Release/v8_introspect.node \
		node-addon/prebuilt/$(ADDON_PLATFORM)/$(NODE_VERSION)/v8_introspect.node
	@echo "Installed addon for $(ADDON_PLATFORM)/$(NODE_VERSION)"

# Build addons for all Node versions in MALWI_TEST_BINARIES
# Usage: MALWI_TEST_BINARIES=/path/to/binaries make addon-all
# Note: Node 25+ on macOS requires LLVM 17+ (set LLVM_PATH)
addon-all:
	@if [ -z "$(MALWI_TEST_BINARIES)" ]; then \
		echo "Error: MALWI_TEST_BINARIES not set"; \
		exit 1; \
	fi
	cd node-addon && npm install
	@# Build for current platform only (can't cross-compile native addons)
	@for platform_spec in \
		"darwin-arm64:arm64/mac/node" \
		"linux-arm64:arm64/linux/node" \
		"linux-x64:x64/linux/node"; do \
		platform=$${platform_spec%%:*}; \
		subpath=$${platform_spec#*:}; \
		if [ "$$platform" != "$(ADDON_PLATFORM)" ]; then \
			continue; \
		fi; \
		for node_path in $(MALWI_TEST_BINARIES)/$$subpath/node-v*; do \
			[ -e "$$node_path" ] || continue; \
			node_bin=""; \
			if [ -d "$$node_path" ] && [ -x "$$node_path/bin/node" ]; then \
				node_bin="$$node_path/bin/node"; \
				node_dir="$$node_path/bin"; \
			elif [ -f "$$node_path" ] && [ -x "$$node_path" ]; then \
				node_bin="$$node_path"; \
				node_dir="$$(dirname "$$node_path")"; \
			fi; \
			[ -z "$$node_bin" ] && continue; \
			version=$$("$$node_bin" --version 2>/dev/null | sed 's/v\([0-9.]*\)/\1/'); \
			if [ -z "$$version" ]; then \
				version=$$(basename "$$node_path" | sed -n 's/node-v\([0-9.]*\).*/\1/p'); \
			fi; \
			[ -z "$$version" ] && continue; \
			major=$$(echo "$$version" | cut -d. -f1); \
			echo "Building addon for $$platform Node $$version (node$$major)..."; \
			./scripts/build-addon.sh "$$node_path" \
				"node-addon/prebuilt/$$platform/node$$major" "$(LLVM_PATH)" || \
				echo "Warning: $$platform Node $$major build failed"; \
		done; \
	done
	@echo "Built addons for all Node versions in $(MALWI_TEST_BINARIES)"

# Build addon for Node 25+ on macOS using LLVM
# Usage: NODE_TARGET=25.4.0 make addon-node25
# LLVM is auto-detected from PATH, or set LLVM_PATH explicitly
addon-node25:
	@if [ -z "$(NODE_TARGET)" ]; then \
		echo "Error: NODE_TARGET not set (e.g., NODE_TARGET=25.4.0)"; \
		exit 1; \
	fi
	cd node-addon && npm install
	@major=$$(echo $(NODE_TARGET) | cut -d. -f1); \
	./scripts/build-addon.sh "$$(which node)" \
		"node-addon/prebuilt/$(ADDON_PLATFORM)/node$$major" "$(LLVM_PATH)"

fixtures:
	$(MAKE) -C tests

test: fixtures
	cargo build --release -p malwi-agent
	cargo test --release
	@if [ -n "$(MALWI_TEST_BINARIES)" ]; then \
		echo ""; \
		echo "=== MULTI-VERSION TEST SUMMARY ==="; \
		echo ""; \
		echo "Node.js versions tested:"; \
		(for d in $(MALWI_TEST_BINARIES)/$(TEST_PLATFORM)/node/node-v*; do \
			[ -x "$$d" ] && echo "  - $$($$d --version 2>/dev/null)"; \
		done) 2>/dev/null | sort -V; \
		echo ""; \
		echo "Python versions tested:"; \
		(for d in $(MALWI_TEST_BINARIES)/$(TEST_PLATFORM)/python/python3.*; do \
			if [ -x "$$d" ] && [ -f "$$d" ]; then \
				echo "  - $$($$d --version 2>&1 | head -1)"; \
			elif [ -x "$$d/bin/python3" ]; then \
				echo "  - $$($$d/bin/python3 --version 2>&1 | head -1)"; \
			fi; \
		done) 2>/dev/null | sort -V; \
		echo ""; \
		echo "Bash versions tested:"; \
		(for d in $(MALWI_TEST_BINARIES)/$(TEST_PLATFORM)/bash/bash-*; do \
			[ -x "$$d" ] && echo "  - Bash $$($$d --version 2>/dev/null | head -1 | sed 's/.*version \([0-9][0-9.]*\).*/\1/')"; \
		done) 2>/dev/null | sort -V; \
		echo ""; \
	fi

clean:
	cargo clean
	rm -rf node-addon/build node-addon/node_modules
	rm -f malwi
	$(MAKE) -C tests clean
