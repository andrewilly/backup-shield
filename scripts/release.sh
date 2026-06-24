#!/usr/bin/env bash
set -euo pipefail

NAME="backup-shield"
VERSION="${1:-$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)}"
TARGET_DIR="target/release"

echo "=== Building $NAME v$VERSION ==="

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
  darwin)  PLATFORM="macos" ;;
  linux)   PLATFORM="linux" ;;
  mingw*|msys*|cygwin*) PLATFORM="windows" ;;
  *)       echo "Unknown OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *)          echo "Unknown arch: $ARCH"; exit 1 ;;
esac

echo "Building for $PLATFORM-$ARCH..."

# Build release
cargo build --release --workspace

# Locate the binary
if [ "$PLATFORM" = "windows" ]; then
  BINARY="$TARGET_DIR/backup-shield.exe"
else
  BINARY="$TARGET_DIR/backup-shield"
fi

if [ ! -f "$BINARY" ]; then
  echo "Binary not found at $BINARY"
  exit 1
fi

# Prepare package
PKG_DIR="$TARGET_DIR/$NAME-$VERSION-$PLATFORM-$ARCH"
mkdir -p "$PKG_DIR"

cp "$BINARY" "$PKG_DIR/"
cp README.md "$PKG_DIR/" 2>/dev/null || true
cp LICENSE "$PKG_DIR/" 2>/dev/null || true

# Package
if [ "$PLATFORM" = "windows" ]; then
  ARCHIVE="$TARGET_DIR/$NAME-$VERSION-$PLATFORM-$ARCH.zip"
  rm -f "$ARCHIVE"
  (cd "$TARGET_DIR" && zip -r "$(basename "$ARCHIVE")" "$(basename "$PKG_DIR")")
else
  ARCHIVE="$TARGET_DIR/$NAME-$VERSION-$PLATFORM-$ARCH.tar.gz"
  rm -f "$ARCHIVE"
  tar -czf "$ARCHIVE" -C "$TARGET_DIR" "$(basename "$PKG_DIR")"
fi

echo ""
echo "=== Release package created ==="
echo "  Archive: $ARCHIVE"
echo "  Size:    $(du -sh "$ARCHIVE" | cut -f1)"
echo "  Binary:  $PKG_DIR/$(basename "$BINARY")"
echo "  Version: $VERSION"
echo ""
echo "  SHA-256: $(shasum -a 256 "$ARCHIVE" | cut -d' ' -f1)"
