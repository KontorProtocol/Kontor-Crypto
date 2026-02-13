#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PICUS_BIN_ARG=()

# Opt-in cvc5 parallel portfolio wrapper (local runs).
#   export CVC5_BIN=/path/to/cvc5
#   export CVC5_PORTFOLIO_JOBS=16
#   PICUS_USE_CVC5_PORTFOLIO=1 tools/picus/run.sh --all
if [[ "${PICUS_USE_CVC5_PORTFOLIO:-0}" == "1" ]] && [[ -z "${SOLVER_PATH:-}" ]]; then
  export SOLVER_PATH="${SCRIPT_DIR}/cvc5-portfolio-wrapper.sh"
fi

# Opt-in Dockerized Picus wrapper:
#   PICUS_USE_DOCKER=1 tools/picus/run.sh --all
if [[ "${PICUS_USE_DOCKER:-0}" == "1" ]]; then
  PICUS_BIN_ARG=(--picus-bin "${SCRIPT_DIR}/run-picus-docker.sh")
fi

# Optional explicit Picus binary/script override.
if [[ -n "${PICUS_BIN:-}" ]]; then
  PICUS_BIN_ARG=(--picus-bin "${PICUS_BIN}")
fi

cargo run --bin picus_verify -- "${PICUS_BIN_ARG[@]}" "$@"
