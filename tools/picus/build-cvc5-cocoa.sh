#!/usr/bin/env bash
set -euo pipefail

# Build and install a CoCoA-enabled cvc5 (GPL build) for Picus (QF_FF).
#
# Usage:
#   tools/picus/build-cvc5-cocoa.sh [/install/prefix]
#
# Default prefix:
#   $HOME/.local
#
# Outputs:
#   <prefix>/bin/cvc5
#
# After install:
#   export SOLVER_PATH="<prefix>/bin/cvc5"

PREFIX="${1:-$HOME/.local}"
BUILD_ROOT="${BUILD_ROOT:-/tmp/cvc5-cocoa-build}"

mkdir -p "$BUILD_ROOT"

if [[ ! -d "$BUILD_ROOT/cvc5/.git" ]]; then
  rm -rf "$BUILD_ROOT/cvc5"
  git clone --depth 1 https://github.com/cvc5/cvc5.git "$BUILD_ROOT/cvc5"
fi

cd "$BUILD_ROOT/cvc5"

rm -rf build-cocoa
./configure.sh production \
  --auto-download \
  --cocoa \
  --gpl \
  --ninja \
  --name=build-cocoa \
  --prefix="$PREFIX"

cd build-cocoa
ninja
ninja install

echo "Installed: $PREFIX/bin/cvc5"
echo "Verify:    $PREFIX/bin/cvc5 --show-config | rg 'cocoa'"
