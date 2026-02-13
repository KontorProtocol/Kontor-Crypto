#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PICUS_BIN="${PICUS_BIN:-${SCRIPT_DIR}/run-picus-docker.sh}"

exec cargo run --bin picus_verify -- --picus-bin "${PICUS_BIN}" "$@"
