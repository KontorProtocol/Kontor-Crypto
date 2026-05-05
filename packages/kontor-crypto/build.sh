#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WASM_CRATE="$SCRIPT_DIR/../../crates/kontor-crypto-wasm"

echo "==> Building WASM..."
(cd "$WASM_CRATE" && wasm-pack build --target web --release)

echo "==> Compiling TypeScript..."
(cd "$SCRIPT_DIR" && npx tsc)

echo "==> Copying WASM artifacts to dist/..."
cp "$WASM_CRATE/pkg/kontor_crypto_wasm.js" "$SCRIPT_DIR/dist/"
cp "$WASM_CRATE/pkg/kontor_crypto_wasm_bg.wasm" "$SCRIPT_DIR/dist/"
cp "$WASM_CRATE/pkg/kontor_crypto_wasm.d.ts" "$SCRIPT_DIR/dist/"

echo "==> Done. Package ready in dist/"
