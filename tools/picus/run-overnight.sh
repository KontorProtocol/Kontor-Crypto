#!/usr/bin/env bash
set -euo pipefail

# Overnight Picus determinism run plan (local host).
#
# Prereqs:
# - Picus (run-picus) installed or available at a known path.
# - CoCoA-enabled cvc5 on PATH, or set SOLVER_PATH to it.
#
# Example:
#   export SOLVER_PATH=/tmp/cvc5-install/bin/cvc5
#   tools/picus/run-overnight.sh /Users/adam/dev/Picus/run-picus

PICUS_BIN="${1:-}"
if [[ -z "${PICUS_BIN}" ]]; then
  echo "usage: $0 /path/to/run-picus" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

OUT_ROOT="artifacts/picus-overnight/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT_ROOT"

echo "Output: $OUT_ROOT"
echo "Picus:   $PICUS_BIN"
echo "Solver:  ${SOLVER_PATH:-cvc5-on-PATH}"

# Ensure artifacts exist (and keep it deterministic).
cargo run -q --release --bin picus_export -- --all

# Phase A: witness-guided precondition, root-only target.
# Goal: get conclusive signal quickly that exported R1CS is not trivially underconstrained.
for fx in single-file-minimal single-file-depth10 multi-file-minimal multi-file-mixed-depth multi-file-padding; do
  echo
  echo "=== Phase A: $fx (precondition, prefix=1, 30m budget) ==="
  cargo run -q --release --bin picus_verify -- \
    --fixture "$fx" \
    --picus-bin "$PICUS_BIN" \
    --solver cvc5 \
    --picus-log-level PROGRESS \
    --timeout-secs 1800 \
    --hard-timeout-grace-secs 120 \
    --output-prefix-len 1 \
    --picus-witness-precondition \
    --allow-inconclusive \
    --summary-json "$OUT_ROOT/$fx.phase-a.summary.json" \
    --summary-md "$OUT_ROOT/$fx.phase-a.summary.md" \
    || true
done

# Phase B: no precondition, root-only target, longer budget on the smallest fixture(s).
# Goal: start accumulating evidence without extra assumptions (may still be inconclusive).
for fx in single-file-minimal multi-file-minimal; do
  echo
  echo "=== Phase B: $fx (no precondition, prefix=1, 2h budget) ==="
  cargo run -q --release --bin picus_verify -- \
    --fixture "$fx" \
    --picus-bin "$PICUS_BIN" \
    --solver cvc5 \
    --picus-log-level PROGRESS \
    --timeout-secs 7200 \
    --hard-timeout-grace-secs 300 \
    --output-prefix-len 1 \
    --allow-inconclusive \
    --summary-json "$OUT_ROOT/$fx.phase-b.summary.json" \
    --summary-md "$OUT_ROOT/$fx.phase-b.summary.md" \
    || true
done

echo
echo "Done. Summaries in $OUT_ROOT"
