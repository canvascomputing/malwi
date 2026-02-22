#!/usr/bin/env bash
#
# Assemble a Python wheel from pre-built malwi binaries.
#
# Usage:
#   build-wheel.sh <version> <platform-tag> <cli-binary> <agent-lib> <output-dir>
#
# Example:
#   build-wheel.sh 0.0.24 macosx_11_0_arm64 target/release/malwi target/release/libmalwi_agent.dylib dist/
#
set -euo pipefail

VERSION="${1:?Usage: build-wheel.sh <version> <platform-tag> <cli-binary> <agent-lib> <output-dir>}"
PLATFORM_TAG="$2"
CLI_BINARY="$3"
AGENT_LIB="$4"
OUTPUT_DIR="$5"

WHEEL_TAG="py3-none-${PLATFORM_TAG}"
DIST_INFO="malwi-${VERSION}.dist-info"
DATA_DIR="malwi-${VERSION}.data"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# --- Package files ---
mkdir -p "$WORK/malwi"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cp "$REPO_ROOT/python/malwi/__init__.py" "$WORK/malwi/__init__.py"

# --- Data files (installed onto PATH / lib) ---
mkdir -p "$WORK/${DATA_DIR}/scripts"
cp "$CLI_BINARY" "$WORK/${DATA_DIR}/scripts/malwi"
chmod 755 "$WORK/${DATA_DIR}/scripts/malwi"

mkdir -p "$WORK/${DATA_DIR}/data/lib"
cp "$AGENT_LIB" "$WORK/${DATA_DIR}/data/lib/"

# --- dist-info ---
mkdir -p "$WORK/${DIST_INFO}"

cat > "$WORK/${DIST_INFO}/METADATA" <<EOF
Metadata-Version: 2.1
Name: malwi
Version: ${VERSION}
Summary: Function tracing tool for Python, JavaScript, and native code
License: MIT
Requires-Python: >=3.8
Classifier: Development Status :: 4 - Beta
Classifier: Environment :: Console
Classifier: Intended Audience :: Developers
Classifier: License :: OSI Approved :: MIT License
Classifier: Operating System :: MacOS
Classifier: Operating System :: POSIX :: Linux
Classifier: Programming Language :: Python :: 3
Classifier: Programming Language :: Rust
Classifier: Topic :: Software Development :: Debuggers
EOF

cat > "$WORK/${DIST_INFO}/WHEEL" <<EOF
Wheel-Version: 1.0
Generator: build-wheel.sh
Root-Is-Purelib: false
Tag: ${WHEEL_TAG}
EOF

# entry_points.txt — pip uses this for console_scripts
cat > "$WORK/${DIST_INFO}/entry_points.txt" <<EOF
EOF

# --- RECORD (SHA256 hashes of every file) ---
RECORD_FILE="${DIST_INFO}/RECORD"
: > "$WORK/${RECORD_FILE}"

# Hash every file except RECORD itself
while IFS= read -r -d '' file; do
    rel="${file#$WORK/}"
    [ "$rel" = "$RECORD_FILE" ] && continue
    hash=$(openssl dgst -sha256 -binary "$file" | openssl base64 -A | tr '+/' '-_' | tr -d '=')
    size=$(wc -c < "$file" | tr -d ' ')
    echo "${rel},sha256=${hash},${size}" >> "$WORK/${RECORD_FILE}"
done < <(find "$WORK" -type f -print0 | sort -z)

# RECORD lists itself with no hash
echo "${RECORD_FILE},," >> "$WORK/${RECORD_FILE}"

# --- Zip into wheel ---
mkdir -p "$OUTPUT_DIR"
WHEEL_NAME="malwi-${VERSION}-${WHEEL_TAG}.whl"
(cd "$WORK" && zip -r -q "${WHEEL_NAME}" .)
mv "$WORK/${WHEEL_NAME}" "$OUTPUT_DIR/"

echo "Built: ${OUTPUT_DIR}/${WHEEL_NAME}"
