#!/usr/bin/env bash
set -euo pipefail

# Parallelize *independent* Picus proofs (fixture x prefix_len x stage) safely.
# This does not kill solver processes and is safe to run alongside other long
# running solves.
#
# Compared to run-ladder-safe.sh:
# - This schedules each (fixture, prefix_len, stage) as its own job so you can
#   easily saturate multiple CPU cores.
# - Exports into each case directory to avoid export races under parallelism.
#
# Usage examples:
#   export SOLVER_PATH=/tmp/cvc5-install/bin/cvc5
#   tools/picus/run-matrix-safe.sh --picus-bin /Users/adam/dev/Picus/run-picus --all \
#     --prefix-lens 1,2,4 --stages witness --timeout-witness-secs 1800 --jobs 6
#
#   tools/picus/run-matrix-safe.sh --picus-bin /Users/adam/dev/Picus/run-picus \
#     --fixture single-file-minimal --prefix-lens 1 --stages nopre --timeout-nopre-secs 7200 --jobs 1

usage() {
  cat <<'EOF' >&2
usage:
  tools/picus/run-matrix-safe.sh --picus-bin /path/to/run-picus [--all | --fixture <id> ...]

optional:
  --run-id <id>                 default: YYYYmmdd-HHMMSS
  --solver <solver>             default: cvc5
  --log-level <level>           default: PROGRESS
  --jobs <n>                    default: 4
  --heartbeat-secs <n>          default: 60
  --prefix-lens <list>          default: 1   (comma/space-separated, e.g. "1,2,4")
  --stages <list>               default: witness,nopre (comma/space-separated; values: witness, nopre)
  --timeout-witness-secs <n>    default: 1800 (30m)
  --timeout-nopre-secs <n>      default: 1200 (20m)
EOF
  exit 2
}

PICUS_BIN=""
RUN_ID="$(date +%Y%m%d-%H%M%S)"
SOLVER="cvc5"
LOG_LEVEL="PROGRESS"
JOBS=4
HEARTBEAT_SECS=60
PREFIX_LENS_RAW="1"
STAGES_RAW="witness,nopre"
TIMEOUT_WITNESS_SECS=1800
TIMEOUT_NOPRE_SECS=1200
ALL=0
FIXTURES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --picus-bin) PICUS_BIN="${2:-}"; shift 2 ;;
    --run-id) RUN_ID="${2:-}"; shift 2 ;;
    --solver) SOLVER="${2:-}"; shift 2 ;;
    --log-level) LOG_LEVEL="${2:-}"; shift 2 ;;
    --jobs) JOBS="${2:-}"; shift 2 ;;
    --heartbeat-secs) HEARTBEAT_SECS="${2:-}"; shift 2 ;;
    --prefix-lens) PREFIX_LENS_RAW="${2:-}"; shift 2 ;;
    --stages) STAGES_RAW="${2:-}"; shift 2 ;;
    --timeout-witness-secs) TIMEOUT_WITNESS_SECS="${2:-}"; shift 2 ;;
    --timeout-nopre-secs) TIMEOUT_NOPRE_SECS="${2:-}"; shift 2 ;;
    --all) ALL=1; shift ;;
    --fixture) FIXTURES+=("${2:-}"); shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; usage ;;
  esac
done

if [[ -z "${PICUS_BIN}" ]]; then
  echo "missing --picus-bin" >&2
  usage
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ "${ALL}" == "1" ]]; then
  FIXTURES=()
  while IFS= read -r line; do
    [[ -n "${line}" ]] && FIXTURES+=("${line}")
  done < <(python3 -c 'import json; print("\n".join(json.load(open("tools/picus/manifest.json"))["fixtures"]))')
fi

if [[ "${#FIXTURES[@]}" -eq 0 ]]; then
  echo "no fixtures selected (use --all or --fixture <id>)" >&2
  exit 2
fi

split_list() {
  # Split comma/space separated list into one item per line.
  echo "$1" | tr ',' ' ' | tr -s ' ' '\n' | sed '/^$/d'
}

PREFIX_LENS=()
while IFS= read -r x; do PREFIX_LENS+=("${x}"); done < <(split_list "${PREFIX_LENS_RAW}")
STAGES=()
while IFS= read -r x; do STAGES+=("${x}"); done < <(split_list "${STAGES_RAW}")

OUT_ROOT="artifacts/picus-runs/${RUN_ID}"
mkdir -p "${OUT_ROOT}"

PROGRESS_TSV="${OUT_ROOT}/progress.tsv"
if [[ ! -f "${PROGRESS_TSV}" ]]; then
  printf "ts_utc\tfixture\tcase\tprefix_len\tprecondition\ttimeout_ms\texit_code\truntime_s\tout_dir\n" > "${PROGRESS_TSV}"
fi

LOCK_DIR="${OUT_ROOT}/.progress_lock"

append_progress_line() {
  local line="$1"
  while ! mkdir "${LOCK_DIR}" 2>/dev/null; do
    sleep 0.05
  done
  printf "%s\n" "${line}" >> "${PROGRESS_TSV}"
  rmdir "${LOCK_DIR}" 2>/dev/null || true
}

echo "Run ID:     ${RUN_ID}"
echo "Output:     ${OUT_ROOT}"
echo "Picus bin:  ${PICUS_BIN}"
echo "Solver:     ${SOLVER} (SOLVER_PATH=${SOLVER_PATH:-<unset>})"
echo "Prefixes:   ${PREFIX_LENS[*]}"
echo "Stages:     ${STAGES[*]}"
echo "Jobs:       ${JOBS}"
echo "Heartbeat:  ${HEARTBEAT_SECS}s"
echo

# Build once up-front to avoid `cargo` lock contention under parallel jobs.
cargo build -q --release --bin picus_export
PICUS_EXPORT_BIN="${ROOT}/target/release/picus_export"

throttle() {
  while [[ "$(jobs -pr | wc -l | tr -d ' ')" -ge "${JOBS}" ]]; do
    sleep 1
  done
}

run_with_heartbeat() {
  local label="$1"; shift
  local hb_secs="$1"; shift

  "$@" &
  local pid=$!
  local start_s
  start_s="$(date +%s)"

  while kill -0 "${pid}" 2>/dev/null; do
    sleep "${hb_secs}" || true
    if kill -0 "${pid}" 2>/dev/null; then
      local now_s
      now_s="$(date +%s)"
      local elapsed_s=$((now_s - start_s))
      echo "still running: ${label} (pid=${pid} elapsed=${elapsed_s}s)"
    fi
  done
  wait "${pid}"
}

run_case() {
  local fx="$1"
  local prefix_len="$2"
  local stage="$3" # witness|nopre

  local pre_label="none"
  local want_pre=0
  local timeout_secs="${TIMEOUT_NOPRE_SECS}"
  if [[ "${stage}" == "witness" ]]; then
    pre_label="witness"
    want_pre=1
    timeout_secs="${TIMEOUT_WITNESS_SECS}"
  fi

  local case_id="prefix${prefix_len}/${stage}"
  local out_dir="${OUT_ROOT}/${fx}/${case_id}"
  mkdir -p "${out_dir}"

  # Export into this case's directory to avoid races between parallel jobs.
  local export_dir="${out_dir}/export"
  local export_args=(
    --fixture "${fx}"
    --artifacts-dir "${export_dir}"
    --output-prefix-len "${prefix_len}"
  )
  if [[ "${want_pre}" == "1" ]]; then
    export_args+=(--picus-witness-precondition)
  fi

  "${PICUS_EXPORT_BIN}" "${export_args[@]}"

  local r1cs="${export_dir}/${fx}/circuit.prefix${prefix_len}.r1cs"
  local pre="${export_dir}/${fx}/picus-precondition.json"
  local json="${out_dir}/picus.json"
  local out="${out_dir}/stdout.log"
  local err="${out_dir}/stderr.log"

  if [[ ! -f "${r1cs}" ]]; then
    echo "missing exported r1cs: ${r1cs}" >&2
    return 3
  fi
  if [[ "${want_pre}" == "1" ]] && [[ ! -f "${pre}" ]]; then
    echo "missing exported precondition: ${pre}" >&2
    return 3
  fi

  local timeout_ms=$((timeout_secs * 1000))
  local start_s
  start_s="$(date +%s)"

  if [[ "${want_pre}" == "1" ]]; then
    run_with_heartbeat "${fx} ${case_id}" "${HEARTBEAT_SECS}" \
      script -q "${out}" \
        "${PICUS_BIN}" \
          --json "${json}" \
          --timeout "${timeout_ms}" \
          --solver "${SOLVER}" \
          --log-level "${LOG_LEVEL}" \
          --precondition "${pre}" \
          "${r1cs}" 2>"${err}"
  else
    run_with_heartbeat "${fx} ${case_id}" "${HEARTBEAT_SECS}" \
      script -q "${out}" \
        "${PICUS_BIN}" \
          --json "${json}" \
          --timeout "${timeout_ms}" \
          --solver "${SOLVER}" \
          --log-level "${LOG_LEVEL}" \
          "${r1cs}" 2>"${err}"
  fi

  local code=$?
  local end_s
  end_s="$(date +%s)"
  local runtime_s=$((end_s - start_s))

  echo "${code}" > "${out_dir}/exit_code.txt"
  echo "${runtime_s}" > "${out_dir}/runtime_s.txt"

  append_progress_line "$(printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "${fx}" \
    "${case_id}" \
    "${prefix_len}" \
    "${pre_label}" \
    "${timeout_ms}" \
    "${code}" \
    "${runtime_s}" \
    "${out_dir}")"

  echo "${fx} ${case_id} => exit=${code} runtime=${runtime_s}s (${out_dir})"
}

for fx in "${FIXTURES[@]}"; do
  for prefix_len in "${PREFIX_LENS[@]}"; do
    for stage in "${STAGES[@]}"; do
      if [[ "${stage}" != "witness" ]] && [[ "${stage}" != "nopre" ]]; then
        echo "invalid stage: ${stage} (expected witness or nopre)" >&2
        exit 2
      fi
      throttle
      (
        set +e
        run_case "${fx}" "${prefix_len}" "${stage}"
        exit $?
      ) &
    done
  done
done

wait

echo
echo "Done. Progress log: ${PROGRESS_TSV}"
echo "Tip: column -t -s $'\\t' ${PROGRESS_TSV} | less -S"

