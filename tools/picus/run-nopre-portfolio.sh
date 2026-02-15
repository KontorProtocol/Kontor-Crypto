#!/usr/bin/env bash
set -euo pipefail

# Run multiple independent Picus determinism checks in parallel (a "portfolio")
# to increase the chance of convergence, since cvc5/Picus is often single-core
# per solve and QF_FF can be sensitive to solver heuristics.
#
# This script does NOT kill solver processes and is safe to run alongside other
# long-running Picus/cvc5 solves.
#
# Example:
#   export SOLVER_PATH=tools/picus/cvc5-portfolio-wrapper.sh
#   export CVC5_BIN=/tmp/cvc5-install/bin/cvc5
#   tools/picus/run-nopre-portfolio.sh --picus-bin /Users/adam/dev/Picus/run-picus \
#     --fixture single-file-minimal --prefix-len 1 --timeout-secs 7200 \
#     --seeds "1 2 3 4" --ff-solvers "gb split" --max-parallel 4

usage() {
  cat <<'EOF' >&2
usage:
  tools/picus/run-nopre-portfolio.sh --picus-bin /path/to/run-picus --fixture <id>

optional:
  --run-base-id <id>        default: YYYYmmdd-HHMMSS
  --prefix-len <n>          default: 1
  --stage <stage>           default: nopre (values: inputs | nopre)
  --timeout-secs <n>        default: 7200 (applies to chosen stage)
  --max-parallel <n>        default: 4
  --seeds "<list>"          default: "1 2 3 4"
  --ff-solvers "<list>"     default: "gb split"
                            supported:
                              - gb:         --ff
                              - split:      --ff --ff-solver=split
                              - gb_polys:   --ff --ff-field-polys
                              - split_polys:--ff --ff-solver=split --ff-field-polys
  --selector <selector>     default: (Picus default)
                            values: counter | first
  --noprop                  disable Picus propagation
  --solver <solver>         default: cvc5
  --log-level <level>       default: PROGRESS

environment:
  SOLVER_PATH should point to a CoCoA-enabled cvc5 (recommended: wrapper).
  If SOLVER_PATH is unset, we default it to tools/picus/cvc5-args-wrapper.sh.
  If CVC5_BIN is unset, we default it to /tmp/cvc5-install/bin/cvc5.
EOF
  exit 2
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PICUS_BIN=""
FIXTURE=""
RUN_BASE_ID="$(date +%Y%m%d-%H%M%S)"
PREFIX_LEN=1
STAGE="nopre"
TIMEOUT_SECS=7200
MAX_PARALLEL=4
SEEDS_RAW="1 2 3 4"
FF_SOLVERS_RAW="gb split"
SOLVER="cvc5"
LOG_LEVEL="PROGRESS"
SELECTOR=""
NOPROP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --picus-bin) PICUS_BIN="${2:-}"; shift 2 ;;
    --fixture) FIXTURE="${2:-}"; shift 2 ;;
    --run-base-id) RUN_BASE_ID="${2:-}"; shift 2 ;;
    --prefix-len) PREFIX_LEN="${2:-}"; shift 2 ;;
    --stage) STAGE="${2:-}"; shift 2 ;;
    --timeout-secs) TIMEOUT_SECS="${2:-}"; shift 2 ;;
    --max-parallel) MAX_PARALLEL="${2:-}"; shift 2 ;;
    --seeds) SEEDS_RAW="${2:-}"; shift 2 ;;
    --ff-solvers) FF_SOLVERS_RAW="${2:-}"; shift 2 ;;
    --selector) SELECTOR="${2:-}"; shift 2 ;;
    --noprop) NOPROP=1; shift ;;
    --solver) SOLVER="${2:-}"; shift 2 ;;
    --log-level) LOG_LEVEL="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; usage ;;
  esac
done

if [[ -z "${PICUS_BIN}" ]] || [[ -z "${FIXTURE}" ]]; then
  echo "missing --picus-bin or --fixture" >&2
  usage
fi

if [[ -z "${SOLVER_PATH:-}" ]]; then
  export SOLVER_PATH="tools/picus/cvc5-args-wrapper.sh"
fi
if [[ -z "${CVC5_BIN:-}" ]]; then
  export CVC5_BIN="/tmp/cvc5-install/bin/cvc5"
fi

echo "Run base:    ${RUN_BASE_ID}"
echo "Fixture:     ${FIXTURE}"
echo "Prefix len:  ${PREFIX_LEN}"
echo "Stage:       ${STAGE}"
echo "Timeout:     ${TIMEOUT_SECS}s"
echo "Max parallel:${MAX_PARALLEL}"
echo "Seeds:       ${SEEDS_RAW}"
echo "FF solvers:  ${FF_SOLVERS_RAW}"
echo "Picus bin:   ${PICUS_BIN}"
echo "Solver:      ${SOLVER} (SOLVER_PATH=${SOLVER_PATH}, CVC5_BIN=${CVC5_BIN})"
if [[ -n "${SELECTOR}" ]]; then
  echo "Selector:    ${SELECTOR}"
fi
if [[ "${NOPROP}" == "1" ]]; then
  echo "Propagation: disabled (--noprop)"
fi
echo

if [[ "${STAGE}" != "nopre" ]] && [[ "${STAGE}" != "inputs" ]]; then
  echo "invalid --stage '${STAGE}' (expected: inputs | nopre)" >&2
  exit 2
fi

throttle() {
  while [[ "$(jobs -pr | wc -l | tr -d ' ')" -ge "${MAX_PARALLEL}" ]]; do
    sleep 1
  done
}

split_list() {
  echo "$1" | tr ',' ' ' | tr -s ' ' '\n' | sed '/^$/d'
}

SEEDS=()
while IFS= read -r x; do SEEDS+=("${x}"); done < <(split_list "${SEEDS_RAW}")
FF_SOLVERS=()
while IFS= read -r x; do FF_SOLVERS+=("${x}"); done < <(split_list "${FF_SOLVERS_RAW}")

for ff in "${FF_SOLVERS[@]}"; do
  for seed in "${SEEDS[@]}"; do
    throttle
    (
      set -euo pipefail

      case "${ff}" in
        gb)
          export CVC5_EXTRA_ARGS="--ff --seed=${seed}"
          ;;
        split)
          export CVC5_EXTRA_ARGS="--ff --ff-solver=split --seed=${seed}"
          ;;
        gb_polys)
          export CVC5_EXTRA_ARGS="--ff --ff-field-polys --seed=${seed}"
          ;;
        split_polys)
          export CVC5_EXTRA_ARGS="--ff --ff-solver=split --ff-field-polys --seed=${seed}"
          ;;
        *)
          echo "unknown ff solver mode: ${ff} (expected: gb, split, gb_polys, split_polys)" >&2
          exit 2
          ;;
      esac

      run_id="${RUN_BASE_ID}-${FIXTURE}-p${PREFIX_LEN}-${STAGE}-${ff}-seed${seed}"

      matrix_args=(
        --run-id "${run_id}"
        --picus-bin "${PICUS_BIN}"
        --fixture "${FIXTURE}"
        --prefix-lens "${PREFIX_LEN}"
        --stages "${STAGE}"
        --solver "${SOLVER}"
        --log-level "${LOG_LEVEL}"
        --jobs 1
      )
      if [[ "${STAGE}" == "nopre" ]]; then
        matrix_args+=(--timeout-nopre-secs "${TIMEOUT_SECS}")
      else
        matrix_args+=(--timeout-inputs-secs "${TIMEOUT_SECS}")
      fi
      if [[ -n "${SELECTOR}" ]]; then
        matrix_args+=(--selector "${SELECTOR}")
      fi
      if [[ "${NOPROP}" == "1" ]]; then
        matrix_args+=(--noprop)
      fi

      tools/picus/run-matrix-safe.sh "${matrix_args[@]}"
    ) &
  done
done

wait

echo
echo "All portfolio jobs finished. To inspect:"
echo "  ls -1 artifacts/picus-runs | rg \"^${RUN_BASE_ID}\""
echo "  tools/picus/status.sh --watch --interval-secs 30"
