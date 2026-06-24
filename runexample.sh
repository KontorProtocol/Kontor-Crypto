#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "==> Building package (WASM + TypeScript)..."
(cd packages/kontor-crypto && npm run build)

echo "==> Starting server on http://127.0.0.1:4000"
echo "    Open: http://127.0.0.1:4000/examples/browser_prepare_file.html"
cd crates/kontor-crypto-wasm
python3 -m http.server 4000 --bind 127.0.0.1
