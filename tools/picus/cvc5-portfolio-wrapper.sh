#!/usr/bin/env bash
set -euo pipefail

# cvc5 wrapper enabling parallel portfolio mode.
#
# Usage:
#   export SOLVER_PATH=/path/to/this/script
#   export CVC5_BIN=/path/to/cvc5          # optional (default: cvc5 from PATH)
#   export CVC5_PORTFOLIO_JOBS=16          # optional (default: auto)
#   export CVC5_EXTRA_ARGS="--tlimit=0"    # optional extra args appended
#
# Notes:
# - Picus invokes the solver with its own arguments; this wrapper only prepends
#   portfolio flags (unless already present) and forwards everything else.

CVC5_BIN="${CVC5_BIN:-cvc5}"
CVC5_EXTRA_ARGS="${CVC5_EXTRA_ARGS:-}"

if ! command -v "${CVC5_BIN}" >/dev/null 2>&1; then
  echo "cvc5 wrapper: missing CVC5_BIN='${CVC5_BIN}' on PATH" >&2
  exit 127
fi

detect_nproc() {
  if command -v getconf >/dev/null 2>&1; then
    getconf _NPROCESSORS_ONLN 2>/dev/null && return 0
  fi
  if command -v nproc >/dev/null 2>&1; then
    nproc 2>/dev/null && return 0
  fi
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.ncpu 2>/dev/null && return 0
  fi
  echo 1
}

JOBS="${CVC5_PORTFOLIO_JOBS:-}"
if [[ -z "${JOBS}" ]]; then
  NPROC="$(detect_nproc)"
  # Cap to avoid absurd oversubscription by default; override via env.
  if [[ "${NPROC}" -ge 32 ]]; then
    JOBS=32
  elif [[ "${NPROC}" -ge 16 ]]; then
    JOBS=16
  elif [[ "${NPROC}" -ge 8 ]]; then
    JOBS=8
  elif [[ "${NPROC}" -ge 4 ]]; then
    JOBS=4
  else
    JOBS=2
  fi
fi

WANT_PORTFOLIO=1
for arg in "$@"; do
  case "${arg}" in
    --use-portfolio|--portfolio-jobs=*)
      WANT_PORTFOLIO=0
      break
      ;;
  esac
done

ARGS=()
if [[ "${WANT_PORTFOLIO}" == "1" ]]; then
  ARGS+=(--use-portfolio "--portfolio-jobs=${JOBS}")
fi

if [[ -n "${CVC5_EXTRA_ARGS}" ]]; then
  # shellcheck disable=SC2206
  ARGS+=(${CVC5_EXTRA_ARGS})
fi

exec "${CVC5_BIN}" "${ARGS[@]}" "$@"

