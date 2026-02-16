#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PICUS_BIN_ARG=()

PICUS_BIN_ARG=(--picus-bin "${SCRIPT_DIR}/run-picus-docker.sh")

# Optional explicit Picus binary/script override.
if [[ -n "${PICUS_BIN:-}" ]]; then
  PICUS_BIN_ARG=(--picus-bin "${PICUS_BIN}")
fi

cargo run --release --bin picus_verify -- "${PICUS_BIN_ARG[@]}" "$@"
