#!/bin/bash
# Bump patch version, sync all files, and tag the latest commit.
#
# Usage:
#   bash scripts/bump-version.sh          # Bump patch (0.0.24 → 0.0.25)
#   bash scripts/bump-version.sh 0.1.0    # Set explicit version

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
VERSION_FILE="$ROOT/version.toml"

# Parse current version
CURRENT=$(grep 'version' "$VERSION_FILE" | head -1 | sed 's/.*"\(.*\)"/\1/')
if [[ -z "$CURRENT" ]]; then
    echo "Error: Could not parse version from version.toml"
    exit 1
fi

if [[ -n "${1:-}" ]]; then
    NEW="$1"
else
    # Increment patch: 0.0.24 → 0.0.25
    IFS='.' read -r major minor patch <<< "$CURRENT"
    NEW="$major.$minor.$((patch + 1))"
fi

echo "$CURRENT → $NEW"

# Update version.toml
sed "s/version = \"$CURRENT\"/version = \"$NEW\"/" "$VERSION_FILE" > "$VERSION_FILE.tmp"
mv "$VERSION_FILE.tmp" "$VERSION_FILE"

# Propagate to all files
bash "$SCRIPT_DIR/sync-version.sh"

# Tag
git -C "$ROOT" tag "v$NEW"
echo ""
echo "Tagged v$NEW"
