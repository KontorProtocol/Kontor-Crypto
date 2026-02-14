#!/usr/bin/env bash
set -euo pipefail

# Minimal cvc5 wrapper that only appends extra arguments from CVC5_EXTRA_ARGS.
#
# This is useful when you want to run many independent Picus/cvc5 processes in
# parallel (process-level portfolio) without also enabling cvc5's internal
# portfolio engine.
#
# Usage:
#   export SOLVER_PATH=tools/picus/cvc5-args-wrapper.sh
#   export CVC5_BIN=/path/to/cvc5          # optional (default: cvc5 from PATH)
#   export CVC5_EXTRA_ARGS="--ff --seed=1" # optional args appended

CVC5_BIN="${CVC5_BIN:-cvc5}"
CVC5_EXTRA_ARGS="${CVC5_EXTRA_ARGS:-}"

if ! command -v "${CVC5_BIN}" >/dev/null 2>&1; then
  echo "cvc5 args wrapper: missing CVC5_BIN='${CVC5_BIN}' on PATH" >&2
  exit 127
fi

ARGS=()
if [[ -n "${CVC5_EXTRA_ARGS}" ]]; then
  # shellcheck disable=SC2206
  ARGS+=(${CVC5_EXTRA_ARGS})
fi

exec "${CVC5_BIN}" "${ARGS[@]}" "$@"

