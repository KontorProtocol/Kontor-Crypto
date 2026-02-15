#!/usr/bin/env bash
set -euo pipefail

# Autopilot for Picus determinism work: keep a target number of active nopre
# cases running by launching diversified portfolios (fixtures x modes x seeds).
#
# This script does not kill any processes. It only starts new ones when the
# number of active cases drops below the target.
#
# Usage:
#   export CVC5_BIN=/tmp/cvc5-install/bin/cvc5
#   export SOLVER_PATH=tools/picus/cvc5-args-wrapper.sh
#   tools/picus/autopilot.sh --picus-bin /Users/adam/dev/Picus/run-picus
#
# Notes:
# - Active cases are detected file-wise: directories with picus.json but no
#   exit_code.txt. This works even if ps is restricted.
# - Tune --target-active for your machine.

usage() {
  cat <<'EOF' >&2
usage:
  tools/picus/autopilot.sh --picus-bin /path/to/run-picus

optional:
  --target-active <n>     default: 16
  --poll-secs <n>         default: 60
  --prefix-len <n>        default: 1
  --log-level <level>     default: PROGRESS
  --solver <solver>       default: cvc5
  --stage <stage>         default: inputs (values: inputs | nopre)
  --selector <selector>   default: first
  --noprop                disable Picus propagation for launched jobs

environment:
  CVC5_BIN and SOLVER_PATH should point to a CoCoA-enabled cvc5 setup.
EOF
  exit 2
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PICUS_BIN=""
TARGET_ACTIVE=16
POLL_SECS=60
PREFIX_LEN=1
LOG_LEVEL="PROGRESS"
SOLVER="cvc5"
STAGE="inputs"
SELECTOR="first"
NOPROP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --picus-bin) PICUS_BIN="${2:-}"; shift 2 ;;
    --target-active) TARGET_ACTIVE="${2:-}"; shift 2 ;;
    --poll-secs) POLL_SECS="${2:-}"; shift 2 ;;
    --prefix-len) PREFIX_LEN="${2:-}"; shift 2 ;;
    --log-level) LOG_LEVEL="${2:-}"; shift 2 ;;
    --solver) SOLVER="${2:-}"; shift 2 ;;
    --stage) STAGE="${2:-}"; shift 2 ;;
    --selector) SELECTOR="${2:-}"; shift 2 ;;
    --noprop) NOPROP=1; shift ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; usage ;;
  esac
done

if [[ -z "${PICUS_BIN}" ]]; then
  echo "missing --picus-bin" >&2
  usage
fi

count_active_cases() {
  # Count case directories for the selected stage where picus.json exists but exit_code.txt does not.
  local n
  n="$(
    find artifacts/picus-runs -type f -path "*/${STAGE}/picus.json" 2>/dev/null | while IFS= read -r j; do
      d="$(dirname "$j")"
      if [[ ! -f "${d}/exit_code.txt" ]]; then
        echo 1
      fi
    done | wc -l | tr -d ' '
  )"
  echo "${n}"
}

seed_block() {
  # Emit a small seed block based on wall clock to avoid repeating the same seeds.
  local base
  base="$(date +%s | awk '{print ($1 % 100000) + 1}')"
  echo "${base} $((base+1)) $((base+2)) $((base+3))"
}

launch_portfolio() {
  local fixture="$1"
  local timeout="$2"
  local ff_solvers="$3"
  local max_par="$4"
  local seeds="$5"

  local run_base
  run_base="$(date +%Y%m%d-%H%M%S)-auto"

  local args=(
    tools/picus/run-nopre-portfolio.sh
      --picus-bin "${PICUS_BIN}"
      --fixture "${fixture}"
      --prefix-len "${PREFIX_LEN}"
      --stage "${STAGE}"
      --timeout-secs "${timeout}"
      --seeds "${seeds}"
      --ff-solvers "${ff_solvers}"
      --max-parallel "${max_par}"
      --solver "${SOLVER}"
      --log-level "${LOG_LEVEL}"
      --run-base-id "${run_base}"
      --selector "${SELECTOR}"
  )
  if [[ "${NOPROP}" == "1" ]]; then
    args+=(--noprop)
  fi

  echo "launch: fixture=${fixture} timeout=${timeout}s ff_solvers='${ff_solvers}' max_parallel=${max_par} seeds='${seeds}' selector=${SELECTOR} noprop=${NOPROP}"
  "${args[@]}" >/dev/null 2>&1 &
}

echo "autopilot: stage=${STAGE} target_active=${TARGET_ACTIVE} poll=${POLL_SECS}s prefix=${PREFIX_LEN} selector=${SELECTOR} noprop=${NOPROP}"
echo "autopilot: picus_bin=${PICUS_BIN}"
echo "autopilot: solver=${SOLVER} log_level=${LOG_LEVEL} SOLVER_PATH=${SOLVER_PATH:-<unset>} CVC5_BIN=${CVC5_BIN:-<unset>}"
echo

campaign=0
while true; do
  active="$(count_active_cases)"
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "${ts} active_cases=${active} target=${TARGET_ACTIVE}"

  if [[ "${active}" -lt "${TARGET_ACTIVE}" ]]; then
    seeds="$(seed_block)"

    # Rotate campaigns to diversify attempts.
    #
    # For UNSAT-heavy checks (especially with finite-field solvers), short timeouts tend to
    # produce lots of inconclusive results. Bias toward longer budgets on the main fixtures.
    case $((campaign % 6)) in
      0) launch_portfolio "single-file-minimal" 7200 "split split_polys" 2 "${seeds}" ;;
      1) launch_portfolio "single-file-minimal" 7200 "gb_polys split_polys" 2 "${seeds}" ;;
      2) launch_portfolio "single-file-depth10" 7200 "split split_polys" 1 "${seeds}" ;;
      3) launch_portfolio "multi-file-minimal" 7200 "split split_polys" 1 "${seeds}" ;;
      4) launch_portfolio "single-file-tiny-depth1" 3600 "split split_polys" 1 "${seeds}" ;;
      5) launch_portfolio "single-file-tiny-depth1-ch1" 3600 "split split_polys" 1 "${seeds}" ;;
    esac
    campaign=$((campaign + 1))
  fi

  sleep "${POLL_SECS}"
done
