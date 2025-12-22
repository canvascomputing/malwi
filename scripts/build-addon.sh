#!/bin/bash
# Build addon for a specific Node.js binary
# Usage: build-addon.sh <node_path> <target_dir> [LLVM_PATH]
#
# Arguments:
#   node_path  - Path to Node.js binary (standalone file) or installation directory (with bin/node)
#   target_dir - Directory to install the built addon
#   LLVM_PATH  - Optional path to LLVM installation (required for Node 25+ on macOS)
#
# Examples:
#   ./scripts/build-addon.sh /usr/local/bin/node node-addon/prebuilt/linux-x64/node22
#   ./scripts/build-addon.sh /path/to/node-v25.0.0 node-addon/prebuilt/darwin-arm64/node25 /opt/homebrew/opt/llvm

set -e

NODE_PATH="$1"
TARGET_DIR="$2"
LLVM_PATH="${3:-}"

if [[ -z "$NODE_PATH" ]] || [[ -z "$TARGET_DIR" ]]; then
    echo "Usage: $0 <node_path> <target_dir> [LLVM_PATH]"
    exit 1
fi

# Detect node binary - handle both directory and standalone binary formats
if [[ -d "$NODE_PATH" ]] && [[ -x "$NODE_PATH/bin/node" ]]; then
    NODE_BIN="$NODE_PATH/bin/node"
    NODE_DIR="$NODE_PATH/bin"
elif [[ -f "$NODE_PATH" ]] && [[ -x "$NODE_PATH" ]]; then
    NODE_BIN="$NODE_PATH"
    NODE_DIR="$(dirname "$NODE_PATH")"
else
    echo "Error: Invalid node path: $NODE_PATH"
    echo "Expected: executable file or directory with bin/node"
    exit 1
fi

VERSION=$("$NODE_BIN" --version | sed 's/v\([0-9.]*\)/\1/')
MAJOR=$(echo "$VERSION" | cut -d. -f1)

echo "Building addon for Node $VERSION..."

# Change to node-addon directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/../node-addon"

# Node 25+ on macOS needs LLVM with C++20 support
if [[ "$MAJOR" -ge 25 ]] && [[ "$(uname)" == "Darwin" ]]; then
    # Auto-detect LLVM_PATH if not set
    if [[ -z "$LLVM_PATH" ]]; then
        # Search PATH entries and well-known install locations
        search_dirs=()
        IFS=: read -ra path_dirs <<< "$PATH"
        for dir in "${path_dirs[@]}"; do search_dirs+=("$dir"); done
        # Common LLVM install locations (not package-manager-specific)
        search_dirs+=(/usr/local/llvm/bin /usr/local/bin /opt/llvm/bin)

        for dir in "${search_dirs[@]}"; do
            candidate="$dir/clang++"
            [[ ! -x "$candidate" ]] && continue
            # Skip Apple clang (doesn't support the C++20 features we need)
            if "$candidate" --version 2>&1 | grep -q "Apple"; then
                continue
            fi
            # Found LLVM clang++, derive LLVM_PATH (bin/clang++ -> parent)
            LLVM_PATH="$(cd "$(dirname "$candidate")/.." && pwd)"
            break
        done
    fi

    if [[ -z "$LLVM_PATH" ]]; then
        echo "Error: Node $MAJOR on macOS requires LLVM 17+"
        echo "Install LLVM and add it to PATH, or set LLVM_PATH=/path/to/llvm"
        exit 1
    fi

    echo "Using LLVM at $LLVM_PATH for Node $MAJOR"

    # Auto-detect clang resource directory (works with any LLVM version)
    CLANG_RESOURCE_DIR=$("$LLVM_PATH/bin/clang" -print-resource-dir)

    # Create wrapper script for hybrid compilation
    # Uses LLVM clang++ for compiling (C++20), Apple clang++ for linking (system libs)
    cat > /tmp/cxx_wrapper.sh << 'WRAPPER'
#!/bin/bash
LLVM_CXX="__LLVM_PATH__/bin/clang++"
APPLE_CXX="/usr/bin/clang++"

is_link=false
has_c=false
has_o_file=false

for arg in "$@"; do
    case "$arg" in
        -bundle|-shared|-dynamiclib) is_link=true ;;
        -c) has_c=true ;;
        *.o) has_o_file=true ;;
    esac
done

# Heuristic: if we have .o files but no -c flag, we're linking
[ "$has_o_file" = true ] && [ "$has_c" = false ] && is_link=true

if [ "$is_link" = true ]; then
    exec "$APPLE_CXX" "$@" __LLVM_PATH__/lib/libc++.a __LLVM_PATH__/lib/libc++abi.a
else
    exec "$LLVM_CXX" "$@"
fi
WRAPPER
    sed -i.bak "s|__LLVM_PATH__|$LLVM_PATH|g" /tmp/cxx_wrapper.sh
    chmod +x /tmp/cxx_wrapper.sh

    CC="$LLVM_PATH/bin/clang" \
    CXX="/tmp/cxx_wrapper.sh" \
    CXXFLAGS="-std=c++20 -nostdlibinc -isystem $LLVM_PATH/include/c++/v1 -isystem $CLANG_RESOURCE_DIR/include -isystem $(xcrun --show-sdk-path)/usr/include" \
    LDFLAGS="-nostdlib++" \
    PATH="$NODE_DIR:$PATH" npx node-gyp rebuild --target="$VERSION"
else
    PATH="$NODE_DIR:$PATH" npx node-gyp rebuild --target="$VERSION"
fi

# Install the built addon
mkdir -p "$SCRIPT_DIR/../$TARGET_DIR"
cp build/Release/v8_introspect.node "$SCRIPT_DIR/../$TARGET_DIR/"
echo "Installed addon to $TARGET_DIR"
