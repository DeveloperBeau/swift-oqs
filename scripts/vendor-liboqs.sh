#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION=$(cat "$REPO_ROOT/LIBOQS_VERSION")
DEST="$REPO_ROOT/Sources/Cliboqs"

echo "Vendoring liboqs $VERSION..."

if [ -d "$DEST/src" ]; then
    rm -rf "$DEST/src"
fi

TMPDIR=$(mktemp -d)
TARBALL="$TMPDIR/liboqs-$VERSION.tar.gz"
curl -sL "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/$VERSION.tar.gz" -o "$TARBALL"
tar -xzf "$TARBALL" -C "$TMPDIR"
LIBOQS_SRC="$TMPDIR/liboqs-$VERSION/src"

mkdir -p "$DEST/src"
cp -R "$LIBOQS_SRC/common" "$DEST/src/"
cp -R "$LIBOQS_SRC/kem" "$DEST/src/"
cp -R "$LIBOQS_SRC/sig" "$DEST/src/"

mkdir -p "$DEST/include/oqs"
for header in oqs.h common.h rand.h aes.h sha2.h sha3.h sha3x4.h kem.h sig.h; do
    if [ -f "$LIBOQS_SRC/oqs/$header" ]; then
        cp "$LIBOQS_SRC/oqs/$header" "$DEST/include/oqs/"
    fi
done

cp "$LIBOQS_SRC/kem/kem.h" "$DEST/src/kem/" 2>/dev/null || true
cp "$LIBOQS_SRC/sig/sig.h" "$DEST/src/sig/" 2>/dev/null || true

rm -rf "$TMPDIR"

echo "Done. Vendored liboqs $VERSION into $DEST"
