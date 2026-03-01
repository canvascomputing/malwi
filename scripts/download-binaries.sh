#!/usr/bin/env bash
#
# download-binaries.sh - Download Node.js, Python and Bash binaries for Mac and Linux
#
# Usage: ./download-binaries.sh [--node-only] [--python-only] [--bash-only] [--clean]
#

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../binaries" && pwd)"
PYTHON_BASE_URL="https://github.com/astral-sh/python-build-standalone/releases/download"
NODE_BASE_URL="https://nodejs.org/dist"
BASH_BASE_URL="https://ftp.gnu.org/gnu/bash"

# Versions to download
NODE_VERSIONS=("v25.4.0" "v24.13.0" "v23.11.1" "v22.13.1" "v21.7.3")
# Python: "full_version:release_date" pairs
PYTHON_VERSIONS=("3.14.3:20260211" "3.14.2:20260114" "3.13.12:20260211" "3.13.11:20260114" "3.12.12:20260114" "3.11.14:20260114" "3.10.19:20260114")
BASH_VERSIONS=("5.3" "5.2" "5.1" "5.0" "4.4")

# Platform mappings
ARCHS=("arm64" "x64")
OSES=("mac" "linux")

# -----------------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------------

log_info() {
    echo "[INFO] $*"
}

log_error() {
    echo "[ERROR] $*" >&2
}

log_success() {
    echo "[OK] $*"
}

# -----------------------------------------------------------------------------
# Directory Setup
# -----------------------------------------------------------------------------

create_directory_structure() {
    log_info "Creating directory structure..."

    for arch in "${ARCHS[@]}"; do
        for os in "${OSES[@]}"; do
            mkdir -p "${SCRIPT_DIR}/${arch}/${os}/node"
            mkdir -p "${SCRIPT_DIR}/${arch}/${os}/python"
            mkdir -p "${SCRIPT_DIR}/${arch}/${os}/bash"
        done
    done

    log_success "Directory structure created"
}

# -----------------------------------------------------------------------------
# Node.js Functions
# -----------------------------------------------------------------------------

get_node_platform() {
    local arch="$1"
    local os="$2"

    local platform_os
    local platform_arch

    case "$os" in
        mac)   platform_os="darwin" ;;
        linux) platform_os="linux" ;;
    esac

    case "$arch" in
        arm64) platform_arch="arm64" ;;
        x64)   platform_arch="x64" ;;
    esac

    echo "${platform_os}-${platform_arch}"
}

download_node_binary() {
    local version="$1"
    local arch="$2"
    local os="$3"

    local platform
    platform=$(get_node_platform "$arch" "$os")

    local url="${NODE_BASE_URL}/${version}/node-${version}-${platform}.tar.gz"
    local dest_dir="${SCRIPT_DIR}/${arch}/${os}/node"
    local dest_file="${dest_dir}/node-${version}"

    if [[ -f "$dest_file" ]]; then
        log_info "Node ${version} for ${arch}/${os} already exists, skipping"
        return 0
    fi

    log_info "Downloading Node ${version} for ${arch}/${os}..."

    local tmpdir
    tmpdir=$(mktemp -d)
    trap "rm -rf '$tmpdir'" RETURN

    if curl -sL "$url" | tar -xzf - -C "$tmpdir"; then
        cp "${tmpdir}/node-${version}-${platform}/bin/node" "$dest_file"
        chmod +x "$dest_file"
        log_success "Node ${version} for ${arch}/${os}"
    else
        log_error "Failed to download Node ${version} for ${arch}/${os}"
        return 1
    fi
}

download_all_node() {
    log_info "Downloading Node.js binaries..."

    for version in "${NODE_VERSIONS[@]}"; do
        for arch in "${ARCHS[@]}"; do
            for os in "${OSES[@]}"; do
                download_node_binary "$version" "$arch" "$os" &
            done
        done
    done

    wait
    log_success "All Node.js binaries downloaded"
}

# -----------------------------------------------------------------------------
# Python Functions
# -----------------------------------------------------------------------------

get_python_platform() {
    local arch="$1"
    local os="$2"

    local platform_arch
    local platform_os

    case "$arch" in
        arm64) platform_arch="aarch64" ;;
        x64)   platform_arch="x86_64" ;;
    esac

    case "$os" in
        mac)   platform_os="apple-darwin" ;;
        linux) platform_os="unknown-linux-gnu" ;;
    esac

    echo "${platform_arch}-${platform_os}"
}

download_python_binary() {
    local version_spec="$1"
    local arch="$2"
    local os="$3"

    local full_version="${version_spec%%:*}"
    local release="${version_spec#*:}"
    local platform
    platform=$(get_python_platform "$arch" "$os")

    local filename="cpython-${full_version}+${release}-${platform}-install_only.tar.gz"
    local url="${PYTHON_BASE_URL}/${release}/${filename}"
    local dest_dir="${SCRIPT_DIR}/${arch}/${os}/python"

    # Full installation needed for both Mac and Linux (stdlib required for tests)
    local dest_path="${dest_dir}/python${full_version}"

    if [[ -d "$dest_path" ]]; then
        log_info "Python ${full_version} for ${arch}/${os} already exists, skipping"
        return 0
    fi

    log_info "Downloading Python ${full_version} for ${arch}/${os}..."

    local tmpdir
    tmpdir=$(mktemp -d)
    trap "rm -rf '$tmpdir'" RETURN

    if curl -sL "$url" | tar -xzf - -C "$tmpdir"; then
        mv "${tmpdir}/python" "$dest_path"
        log_success "Python ${full_version} for ${arch}/${os}"
    else
        log_error "Failed to download Python ${full_version} for ${arch}/${os}"
        return 1
    fi
}

download_all_python() {
    log_info "Downloading Python binaries..."

    for version in "${PYTHON_VERSIONS[@]}"; do
        for arch in "${ARCHS[@]}"; do
            for os in "${OSES[@]}"; do
                download_python_binary "$version" "$arch" "$os" &
            done
        done
    done

    wait
    log_success "All Python binaries downloaded"
}

# -----------------------------------------------------------------------------
# Bash Functions (compile from source)
# -----------------------------------------------------------------------------

get_bash_configure_host() {
    local arch="$1"
    local os="$2"

    local host_arch
    local host_os

    case "$arch" in
        arm64) host_arch="aarch64" ;;
        x64)   host_arch="x86_64" ;;
    esac

    case "$os" in
        mac)   host_os="apple-darwin" ;;
        linux) host_os="unknown-linux-gnu" ;;
    esac

    echo "${host_arch}-${host_os}"
}

get_bash_cc() {
    local arch="$1"
    local os="$2"
    local current_os
    current_os="$(uname -s)"

    if [[ "$os" == "mac" && "$current_os" == "Darwin" ]]; then
        # macOS: use clang with -arch flag for cross-compilation
        local clang_arch
        case "$arch" in
            arm64) clang_arch="arm64" ;;
            x64)   clang_arch="x86_64" ;;
        esac
        echo "clang -arch ${clang_arch}"
    elif [[ "$os" == "linux" && "$current_os" == "Linux" ]]; then
        local current_arch
        current_arch="$(uname -m)"
        local target_arch
        case "$arch" in
            arm64) target_arch="aarch64" ;;
            x64)   target_arch="x86_64" ;;
        esac
        if [[ "$current_arch" == "$target_arch" ]]; then
            echo "gcc"
        else
            local cross_cc="${target_arch}-linux-gnu-gcc"
            if command -v "$cross_cc" > /dev/null 2>&1; then
                echo "$cross_cc"
            else
                echo ""
            fi
        fi
    else
        # Cross-OS compilation not supported, skip silently
        echo ""
    fi
}

download_bash_binary() {
    local version="$1"
    local arch="$2"
    local os="$3"

    local dest_dir="${SCRIPT_DIR}/${arch}/${os}/bash"
    local dest_file="${dest_dir}/bash-${version}"

    if [[ -f "$dest_file" ]]; then
        log_info "Bash ${version} for ${arch}/${os} already exists, skipping"
        return 0
    fi

    # Check if we can compile for this target from current host
    local cc
    cc=$(get_bash_cc "$arch" "$os")
    if [[ -z "$cc" ]]; then
        log_info "Skipping Bash ${version} for ${arch}/${os} (cross-OS compilation not supported)"
        return 0
    fi

    log_info "Building Bash ${version} for ${arch}/${os}..."

    local url="${BASH_BASE_URL}/bash-${version}.tar.gz"
    local tmpdir
    tmpdir=$(mktemp -d)
    trap "rm -rf '$tmpdir'" RETURN

    if ! curl -sL "$url" | tar -xzf - -C "$tmpdir"; then
        log_error "Failed to download Bash ${version} source"
        return 1
    fi

    local src_dir="${tmpdir}/bash-${version}"
    local build_dir="${tmpdir}/build"
    mkdir -p "$build_dir"

    local host
    host=$(get_bash_configure_host "$arch" "$os")

    # Determine if this is a native or cross build
    local current_arch
    current_arch="$(uname -m)"
    local target_arch
    case "$arch" in
        arm64) target_arch="arm64" ;;
        x64)   target_arch="x86_64" ;;
    esac
    # macOS reports arm64, Linux reports aarch64
    local is_native=false
    if [[ "$current_arch" == "$target_arch" ]] || \
       [[ "$current_arch" == "aarch64" && "$target_arch" == "arm64" ]]; then
        is_native=true
    fi

    # Configure and build
    local configure_args=(
        --disable-nls
        --without-bash-malloc
        --without-installed-readline
    )
    # Only set --host for cross-compilation; native builds auto-detect
    if [[ "$is_native" == false ]]; then
        configure_args+=(--host="$host")
    fi

    (
        cd "$build_dir"
        CC="$cc" \
        "${src_dir}/configure" \
            "${configure_args[@]}" \
            > /dev/null 2>&1

        # Fix build issues on modern macOS: old bash versions fail because
        # configure mis-detects snprintf/vsnprintf and sys_siglist
        if [[ -f config.h ]]; then
            sed -i.bak 's/^#define HAVE_SNPRINTF 0/#define HAVE_SNPRINTF 1/' config.h
            sed -i.bak 's/^#define HAVE_VSNPRINTF 0/#define HAVE_VSNPRINTF 1/' config.h
            sed -i.bak 's|/\* #undef HAVE_SYS_SIGLIST \*/|#define HAVE_SYS_SIGLIST 1|' config.h
        fi
        if [[ -f Makefile ]]; then
            sed -i.bak 's/^SIGLIST_O = siglist.o/SIGLIST_O =/' Makefile
        fi

        local cflags="-g -O2"
        cflags+=" -Wno-deprecated-non-prototype -Wno-implicit-function-declaration"
        cflags+=" -Wno-implicit-int -Wno-incompatible-function-pointer-types -Wno-int-conversion"

        make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)" \
            CFLAGS="$cflags" \
            > /dev/null 2>&1
    )

    if [[ -f "${build_dir}/bash" ]]; then
        cp "${build_dir}/bash" "$dest_file"
        chmod +x "$dest_file"
        log_success "Bash ${version} for ${arch}/${os}"
    else
        log_error "Failed to build Bash ${version} for ${arch}/${os}"
        return 1
    fi
}

download_all_bash() {
    log_info "Building Bash binaries from source..."

    for version in "${BASH_VERSIONS[@]}"; do
        for arch in "${ARCHS[@]}"; do
            for os in "${OSES[@]}"; do
                download_bash_binary "$version" "$arch" "$os"
            done
        done
    done

    log_success "All Bash binaries built"
}

# -----------------------------------------------------------------------------
# Cleanup Function
# -----------------------------------------------------------------------------

clean_all() {
    log_info "Cleaning all downloaded binaries..."

    for arch in "${ARCHS[@]}"; do
        for os in "${OSES[@]}"; do
            rm -rf "${SCRIPT_DIR:?}/${arch}/${os}/node/"*
            rm -rf "${SCRIPT_DIR:?}/${arch}/${os}/python/"*
            rm -rf "${SCRIPT_DIR:?}/${arch}/${os}/bash/"*
        done
    done

    log_success "Cleanup complete"
}

# -----------------------------------------------------------------------------
# Verification Function
# -----------------------------------------------------------------------------

verify_binaries() {
    log_info "Verifying downloaded binaries..."

    local errors=0

    # Verify Node.js
    for version in "${NODE_VERSIONS[@]}"; do
        for arch in "${ARCHS[@]}"; do
            for os in "${OSES[@]}"; do
                local binary="${SCRIPT_DIR}/${arch}/${os}/node/node-${version}"
                if [[ ! -f "$binary" ]]; then
                    log_error "Missing: ${arch}/${os}/node/node-${version}"
                    ((errors++))
                fi
            done
        done
    done

    # Verify Python
    for version_spec in "${PYTHON_VERSIONS[@]}"; do
        local full_version="${version_spec%%:*}"
        local minor_version="${full_version%.*}"
        for arch in "${ARCHS[@]}"; do
            for os in "${OSES[@]}"; do
                local binary="${SCRIPT_DIR}/${arch}/${os}/python/python${full_version}/bin/python${minor_version}"

                if [[ ! -f "$binary" ]]; then
                    log_error "Missing: ${arch}/${os}/python${full_version}"
                    ((errors++))
                fi
            done
        done
    done

    # Verify Bash
    for version in "${BASH_VERSIONS[@]}"; do
        for arch in "${ARCHS[@]}"; do
            for os in "${OSES[@]}"; do
                local binary="${SCRIPT_DIR}/${arch}/${os}/bash/bash-${version}"

                if [[ ! -f "$binary" ]]; then
                    log_error "Missing: ${arch}/${os}/bash/bash-${version}"
                    ((errors++))
                fi
            done
        done
    done

    if [[ $errors -eq 0 ]]; then
        log_success "All binaries verified"
        return 0
    else
        log_error "${errors} binaries missing"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Usage
# -----------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Download Node.js, Python and Bash binaries for Mac and Linux (arm64 and x64).
Bash is compiled from source; Node.js and Python are downloaded as pre-built binaries.

Options:
    --node-only     Download only Node.js binaries
    --python-only   Download only Python binaries
    --bash-only     Build only Bash binaries from source
    --clean         Remove all downloaded binaries
    --verify        Verify all binaries are present
    -h, --help      Show this help message

Versions downloaded:
    Node.js: ${NODE_VERSIONS[*]}
    Python:  $(printf '%s ' "${PYTHON_VERSIONS[@]}" | sed 's/:[^ ]*//g')
    Bash:    ${BASH_VERSIONS[*]}

EOF
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

main() {
    local node_only=false
    local python_only=false
    local bash_only=false
    local clean=false
    local verify=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --node-only)
                node_only=true
                shift
                ;;
            --python-only)
                python_only=true
                shift
                ;;
            --bash-only)
                bash_only=true
                shift
                ;;
            --clean)
                clean=true
                shift
                ;;
            --verify)
                verify=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    cd "$SCRIPT_DIR"

    if [[ "$clean" == true ]]; then
        clean_all
        exit 0
    fi

    if [[ "$verify" == true ]]; then
        verify_binaries
        exit $?
    fi

    create_directory_structure

    # Determine which runtimes to build
    local any_only=false
    if [[ "$node_only" == true || "$python_only" == true || "$bash_only" == true ]]; then
        any_only=true
    fi

    if [[ "$any_only" == false || "$node_only" == true ]]; then
        download_all_node
    fi

    if [[ "$any_only" == false || "$python_only" == true ]]; then
        download_all_python
    fi

    if [[ "$any_only" == false || "$bash_only" == true ]]; then
        download_all_bash
    fi

    verify_binaries

    log_success "Download complete!"
}

main "$@"
