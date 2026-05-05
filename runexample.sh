#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "==> Building package (WASM + TypeScript)..."
(cd packages/kontor-crypto && npm run build)

echo "==> Starting server on http://localhost:4000"
echo "    Open: http://localhost:4000/crates/kontor-crypto-wasm/examples/browser_prepare_file.html"
npx serve . -l 4000
