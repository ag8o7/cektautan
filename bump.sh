#!/usr/bin/env bash
set -euo pipefail

DIR="$(dirname "$0")"
VERSION_FILE="$DIR/VERSION"
CURRENT=$(cat "$VERSION_FILE")

if [[ "$CURRENT" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  MAJOR="${BASH_REMATCH[1]}"
  MINOR="${BASH_REMATCH[2]}"
  PATCH="${BASH_REMATCH[3]}"
else
  echo "ERROR: invalid version format in $VERSION_FILE: $CURRENT" >&2
  exit 1
fi

PART="${1:-patch}"

case "$PART" in
  major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
  minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
  patch) PATCH=$((PATCH + 1)) ;;
  *)
    echo "usage: $0 [major|minor|patch]" >&2
    exit 1
    ;;
esac

NEW="v$MAJOR.$MINOR.$PATCH"
NEWV="${NEW#v}"

# VERSION stamp in footer HTML: "Version vX.Y.Z"
sed -i.bak -E "s/Version [v]?[0-9]+\.[0-9]+\.[0-9]+/Version $NEW/g" "$DIR/index.html" 2>/dev/null || true
rm -f "$DIR/index.html.bak"

# Engine version constant: VERSION: 'X.Y.Z'
sed -i.bak -E "s/(VERSION[[:space:]]*:[[:space:]]*)'[0-9]+\.[0-9]+\.[0-9]+'/\1'$NEWV'/" "$DIR/engine.js"
rm -f "$DIR/engine.js.bak"

# UI fallback version string in app.js
sed -i.bak -E "s/\|\| '[0-9]+\.[0-9]+\.[0-9]+'/|| '$NEWV'/" "$DIR/app.js"
rm -f "$DIR/app.js.bak"

echo "$NEW" > "$VERSION_FILE"
echo "version bumped: $CURRENT -> $NEW"
