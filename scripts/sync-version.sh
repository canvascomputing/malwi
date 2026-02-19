#!/bin/bash
# Synchronize version from version.toml to all config files.
#
# Usage:
#   bash scripts/sync-version.sh          # Update all files
#   bash scripts/sync-version.sh --check  # Check consistency (exits non-zero if out of sync)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
VERSION_FILE="$ROOT/version.toml"

if [[ ! -f "$VERSION_FILE" ]]; then
    echo "Error: version.toml not found at $VERSION_FILE"
    exit 1
fi

# Parse version.toml (pure bash, no dependencies)
parse_toml_value() {
    local file="$1" section="$2" key="$3"
    local in_section=false
    while IFS= read -r line; do
        # Strip comments and whitespace
        line="${line%%#*}"
        line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [[ -z "$line" ]] && continue

        if [[ "$line" =~ ^\[(.+)\]$ ]]; then
            [[ "${BASH_REMATCH[1]}" == "$section" ]] && in_section=true || in_section=false
            continue
        fi

        if $in_section && [[ "$line" =~ ^${key}[[:space:]]*=[[:space:]]*\"(.+)\"$ ]]; then
            echo "${BASH_REMATCH[1]}"
            return
        fi
    done < "$file"
}

MALWI_VERSION=$(parse_toml_value "$VERSION_FILE" "malwi" "version")

if [[ -z "$MALWI_VERSION" ]]; then
    echo "Error: Could not parse malwi version from version.toml"
    exit 1
fi

CHECK_MODE=false
if [[ "${1:-}" == "--check" ]]; then
    CHECK_MODE=true
fi

errors=0

# Helper: check or update a file
sync_file() {
    local file="$1" pattern="$2" replacement="$3" description="$4"

    if [[ ! -f "$file" ]]; then
        echo "Warning: $file not found, skipping"
        return
    fi

    if grep -q "$replacement" "$file"; then
        if $CHECK_MODE; then
            echo "  OK: $description"
        fi
        return
    fi

    if $CHECK_MODE; then
        echo "  MISMATCH: $description"
        echo "    Expected: $replacement"
        echo "    In file:  $file"
        grep "$pattern" "$file" | head -1 | sed 's/^/    Found:    /'
        errors=$((errors + 1))
    else
        # Use a temp file for portability (macOS sed -i differs from GNU)
        local tmp
        tmp=$(mktemp)
        sed "s|$pattern|$replacement|" "$file" > "$tmp"
        mv "$tmp" "$file"
        echo "  Updated: $description ($file)"
    fi
}

echo "malwi version: $MALWI_VERSION"
echo ""

# 1. Cargo.toml — workspace version
sync_file "$ROOT/Cargo.toml" \
    '^version = ".*"' \
    "version = \"$MALWI_VERSION\"" \
    "Cargo.toml workspace version"

# 2. pyproject.toml — project version
sync_file "$ROOT/pyproject.toml" \
    '^version = ".*"' \
    "version = \"$MALWI_VERSION\"" \
    "pyproject.toml project version"

# 3. python/malwi/__init__.py — __version__
sync_file "$ROOT/python/malwi/__init__.py" \
    '^__version__ = ".*"' \
    "__version__ = \"$MALWI_VERSION\"" \
    "python/malwi/__init__.py __version__"

# 4. node-addon/package.json — version
sync_file "$ROOT/node-addon/package.json" \
    '"version": ".*"' \
    "\"version\": \"$MALWI_VERSION\"" \
    "node-addon/package.json version"

if $CHECK_MODE; then
    echo ""
    if [[ $errors -gt 0 ]]; then
        echo "FAILED: $errors file(s) out of sync with version.toml"
        echo "Run 'bash scripts/sync-version.sh' to fix."
        exit 1
    else
        echo "All versions are in sync."
    fi
else
    echo ""
    echo "Done. All versions synced to malwi=$MALWI_VERSION"
fi
