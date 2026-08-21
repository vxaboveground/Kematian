#!/usr/bin/env bash
set -euo pipefail

export GOWORK=off

PLUGIN_DIR="$(cd "$(dirname "$0")" && pwd)"
NATIVE_DIR="$PLUGIN_DIR/native"
PLUGIN_NAME="kematian"
ZIP_OUT="$PLUGIN_DIR/$PLUGIN_NAME.zip"

if [ ! -d "$NATIVE_DIR" ]; then
  echo "[error] native folder not found: $NATIVE_DIR"
  exit 1
fi

# Default targets: build for the current host. Override with BUILD_TARGETS env var.
# Examples:
#   BUILD_TARGETS="linux-amd64"
#   BUILD_TARGETS="linux-amd64 darwin-amd64 darwin-arm64"
#   BUILD_TARGETS="linux-amd64 windows-amd64"
if [ -z "${BUILD_TARGETS:-}" ]; then
  HOST_OS="$(go env GOOS)"
  HOST_ARCH="$(go env GOARCH)"
  BUILD_TARGETS="$HOST_OS-$HOST_ARCH"
fi

# ── Build recovery-key-extractor.dll (Rust injected DLL, Windows only) ────
build_extractor_dll() {
  local RUST_DIR="$PLUGIN_DIR/rust-extractor"
  # Output must live next to platform/embedded_dll.go (go:embed resolution).
  local EXTRACTOR_OUT="$NATIVE_DIR/recovery/platform/recovery-key-extractor.dll"
  local RUST_DLL="$RUST_DIR/target/x86_64-pc-windows-gnu/release/recovery_key_extractor.dll"

  if [ ! -f "$RUST_DIR/Cargo.toml" ]; then
    echo "[warn] rust-extractor/Cargo.toml missing — skipping DLL build"
    return
  fi

  echo "[build] recovery-key-extractor.dll (Rust)"

  # Cross-compiling from a non-Windows host needs a MinGW linker; native
  # Windows GNU builds pick up the system gcc automatically.
  if command -v x86_64-w64-mingw32-gcc &>/dev/null; then
    export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
  fi

  (cd "$RUST_DIR" && cargo build --release --target x86_64-pc-windows-gnu)
  if [ ! -f "$RUST_DLL" ]; then
    echo "[error] cargo build produced no DLL at $RUST_DLL"
    return 1
  fi
  if [ ! -f "$EXTRACTOR_OUT" ] || ! cmp -s "$RUST_DLL" "$EXTRACTOR_OUT"; then
    cp -f "$RUST_DLL" "$EXTRACTOR_OUT"
  fi
  echo "[ok] $EXTRACTOR_OUT"
}

# Check if any target is Windows
NEEDS_DLL=false
for target in $BUILD_TARGETS; do
  if [[ "$target" == windows-* ]]; then
    NEEDS_DLL=true
  fi
done

if [ "$NEEDS_DLL" = true ]; then
  build_extractor_dll
fi

# ── Build Go native plugin for each target ─────────────────────────────────
cd "$NATIVE_DIR"

for target in $BUILD_TARGETS; do
  TARGET_OS="${target%%-*}"
  TARGET_ARCH="${target#*-}"

  case "$TARGET_OS" in
    windows) EXT="dll" ;;
    darwin)  EXT="dylib" ;;
    *)       EXT="so" ;;
  esac

  OUTFILE="$PLUGIN_DIR/$PLUGIN_NAME-$TARGET_OS-$TARGET_ARCH.$EXT"

  NEED_BUILD=1
  if [ -f "$OUTFILE" ]; then
    if ! find "$NATIVE_DIR" -type f \
        \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' -o -name 'recovery-key-extractor.dll' \) \
        -newer "$OUTFILE" -print -quit | grep -q .; then
      NEED_BUILD=0
    fi
  fi

  if [ "$NEED_BUILD" = 0 ]; then
    echo "[skip] $OUTFILE up to date"
    continue
  fi

  rm -f "$OUTFILE" "${OUTFILE%.*}.h"

  echo "[build] GOOS=$TARGET_OS GOARCH=$TARGET_ARCH > $OUTFILE"

  # Set CC for cross-compilation
  export GOOS="$TARGET_OS"
  export GOARCH="$TARGET_ARCH"
  export CGO_ENABLED=1

  case "$TARGET_OS-$TARGET_ARCH" in
    linux-amd64)
      export CC="${CC:-gcc}"
      ;;
    linux-arm64)
      export CC="${CC_LINUX_ARM64:-aarch64-linux-gnu-gcc}"
      ;;
    darwin-amd64)
      export CC="${CC_DARWIN_AMD64:-o64-clang}"
      ;;
    darwin-arm64)
      export CC="${CC_DARWIN_ARM64:-oa64-clang}"
      ;;
    windows-amd64)
      export CC="${CC_WINDOWS_AMD64:-x86_64-w64-mingw32-gcc}"
      ;;
  esac

  go build -buildmode=c-shared -o "$OUTFILE" .
  echo "[ok] $OUTFILE"
done

unset GOOS GOARCH CGO_ENABLED CC

cd "$PLUGIN_DIR"

# ── Bundle server.js ───────────────────────────────────────────────────────
echo "[build] bundling server.js"
if [ ! -d "node_modules" ]; then
  bun install --frozen-lockfile 2>/dev/null || bun install
fi
echo "[build] generating icons (simple-icons + lucide)"
bun gen-icons.mjs || { echo "[error] icon generation failed"; exit 1; }
bun build ./server.src.js --outfile ./server.js --target node --external bun:sqlite
echo "[ok] server.js (bundled)"

# ── Create ZIP bundle ──────────────────────────────────────────────────────
rm -f "$ZIP_OUT"

ZIP_SOURCES=()
for target in $BUILD_TARGETS; do
  TARGET_OS="${target%%-*}"
  TARGET_ARCH="${target#*-}"
  case "$TARGET_OS" in
    windows) ZIP_SOURCES+=("$PLUGIN_NAME-$TARGET_OS-$TARGET_ARCH.dll") ;;
    darwin)  ZIP_SOURCES+=("$PLUGIN_NAME-$TARGET_OS-$TARGET_ARCH.dylib") ;;
    *)       ZIP_SOURCES+=("$PLUGIN_NAME-$TARGET_OS-$TARGET_ARCH.so") ;;
  esac
done

[ -f "$PLUGIN_NAME.html" ] && ZIP_SOURCES+=("$PLUGIN_NAME.html")
[ -f "$PLUGIN_NAME.css" ]  && ZIP_SOURCES+=("$PLUGIN_NAME.css")
[ -f "$PLUGIN_NAME.js" ]   && ZIP_SOURCES+=("$PLUGIN_NAME.js")
[ -f "config.json" ]       && ZIP_SOURCES+=("config.json")
[ -f "server.js" ]         && ZIP_SOURCES+=("server.js")

zip -j "$ZIP_OUT" "${ZIP_SOURCES[@]}"

# ── Optional signing ──────────────────────────────────────────────────────
if [ -n "${PLUGIN_SIGN_KEY:-}" ]; then
  SIGN_SCRIPT="$PLUGIN_DIR/../../Overlord-Server/scripts/plugin-sign.ts"
  if [ -f "$SIGN_SCRIPT" ] && command -v bun &>/dev/null; then
    echo "[sign] Signing with key: $PLUGIN_SIGN_KEY"
    bun run "$SIGN_SCRIPT" --key "$PLUGIN_SIGN_KEY" "$ZIP_OUT"
  else
    echo "[warn] plugin-sign.ts or bun not found, skipping signing"
  fi
fi

echo "[ok] $ZIP_OUT"
