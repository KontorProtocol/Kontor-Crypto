#!/usr/bin/env bash
set -euo pipefail

# Safe incremental Picus runs that do NOT kill solver processes.
#
# Why "safe"? The repository's `picus_verify` binary performs best-effort cleanup
# of stale Picus/cvc5 processes, which can accidentally terminate unrelated long
# running solves. This script avoids that by calling `run-picus` directly.
#
# Usage:
#   tools/picus/run-ladder-safe.sh --picus-bin /path/to/run-picus --all
#   tools/picus/run-ladder-safe.sh --picus-bin /path/to/run-picus --fixture single-file-minimal
#
# Environment:
# - SOLVER_PATH should point to a CoCoA-enabled cvc5 for `--solver cvc5`.
#   Example: export SOLVER_PATH=/tmp/cvc5-install/bin/cvc5
#
# Output:
# - artifacts/picus-runs/<run-id>/progress.tsv (append-only status log)
# - per-case folders with stdout/stderr + Picus JSON logs + exit code

usage() {
  cat <<'EOF' >&2
usage:
  tools/picus/run-ladder-safe.sh --picus-bin /path/to/run-picus [--all | --fixture <id> ...]

optional:
  --run-id <id>                 default: YYYYmmdd-HHMMSS
  --solver <solver>             default: cvc5
  --log-level <level>           default: PROGRESS
  --jobs <n>                    default: 4
  --prefix-len <n>              default: 1
  --timeout-witness-secs <n>    default: 1800 (30m)
  --timeout-nopre-secs <n>      default: 1200 (20m)
  --no-nopre                    only run witness-precondition stage
EOF
  exit 2
}

PICUS_BIN=""
RUN_ID="$(date +%Y%m%d-%H%M%S)"
SOLVER="cvc5"
LOG_LEVEL="PROGRESS"
JOBS=4
PREFIX_LEN=1
TIMEOUT_WITNESS_SECS=1800
TIMEOUT_NOPRE_SECS=1200
DO_NOPRE=1
ALL=0
FIXTURES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --picus-bin) PICUS_BIN="${2:-}"; shift 2 ;;
    --run-id) RUN_ID="${2:-}"; shift 2 ;;
    --solver) SOLVER="${2:-}"; shift 2 ;;
    --log-level) LOG_LEVEL="${2:-}"; shift 2 ;;
    --jobs) JOBS="${2:-}"; shift 2 ;;
    --prefix-len) PREFIX_LEN="${2:-}"; shift 2 ;;
    --timeout-witness-secs) TIMEOUT_WITNESS_SECS="${2:-}"; shift 2 ;;
    --timeout-nopre-secs) TIMEOUT_NOPRE_SECS="${2:-}"; shift 2 ;;
    --no-nopre) DO_NOPRE=0; shift ;;
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

OUT_ROOT="artifacts/picus-runs/${RUN_ID}"
EXPORT_DIR="${OUT_ROOT}/export"
mkdir -p "${OUT_ROOT}"

PROGRESS_TSV="${OUT_ROOT}/progress.tsv"
if [[ ! -f "${PROGRESS_TSV}" ]]; then
  printf "ts_utc\tfixture\tcase\tprefix_len\tprecondition\ttimeout_ms\texit_code\truntime_s\tout_dir\n" > "${PROGRESS_TSV}"
fi

echo "Run ID:     ${RUN_ID}"
echo "Output:     ${OUT_ROOT}"
echo "Picus bin:  ${PICUS_BIN}"
echo "Solver:     ${SOLVER} (SOLVER_PATH=${SOLVER_PATH:-<unset>})"
echo "Prefix len: ${PREFIX_LEN}"
echo "Jobs:       ${JOBS}"
echo

# Build once up-front to avoid `cargo` lock contention under parallel jobs.
cargo build -q --release --bin picus_export
PICUS_EXPORT_BIN="${ROOT}/target/release/picus_export"

throttle() {
  while [[ "$(jobs -pr | wc -l | tr -d ' ')" -ge "${JOBS}" ]]; do
    sleep 1
  done
}

run_case() {
  local fx="$1"
  local case_id="$2"
  local want_pre="$3" # 1/0
  local timeout_secs="$4"

  local out_dir="${OUT_ROOT}/${fx}/${case_id}"
  mkdir -p "${out_dir}"

  local export_args=(
    --fixture "${fx}"
    --artifacts-dir "${EXPORT_DIR}"
    --output-prefix-len "${PREFIX_LEN}"
  )
  if [[ "${want_pre}" == "1" ]]; then
    export_args+=(--picus-witness-precondition)
  fi

  # Export is deterministic and should be fast; run it in the case subshell so
  # each case is self-contained (no shared mutable state besides EXPORT_DIR).
  "${PICUS_EXPORT_BIN}" "${export_args[@]}"

  local r1cs="${EXPORT_DIR}/${fx}/circuit.prefix${PREFIX_LEN}.r1cs"
  local pre="${EXPORT_DIR}/${fx}/picus-precondition.json"
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
    script -q "${out}" \
      "${PICUS_BIN}" \
        --json "${json}" \
        --timeout "${timeout_ms}" \
        --solver "${SOLVER}" \
        --log-level "${LOG_LEVEL}" \
        --precondition "${pre}" \
        "${r1cs}" 2>"${err}"
  else
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

  local pre_label="none"
  if [[ "${want_pre}" == "1" ]]; then
    pre_label="witness"
  fi

  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "${fx}" \
    "${case_id}" \
    "${PREFIX_LEN}" \
    "${pre_label}" \
    "${timeout_ms}" \
    "${code}" \
    "${runtime_s}" \
    "${out_dir}" >> "${PROGRESS_TSV}"

  echo "${fx} ${case_id} => exit=${code} runtime=${runtime_s}s (${out_dir})"
}

for fx in "${FIXTURES[@]}"; do
  throttle
  (
    set +e
    run_case "${fx}" "prefix${PREFIX_LEN}/witness" 1 "${TIMEOUT_WITNESS_SECS}"
    rc=$?
    if [[ "${rc}" -ne 0 ]]; then
      echo "${fx} witness case failed (rc=${rc})" >&2
      exit "${rc}"
    fi

    if [[ "${DO_NOPRE}" == "1" ]]; then
      run_case "${fx}" "prefix${PREFIX_LEN}/nopre" 0 "${TIMEOUT_NOPRE_SECS}"
      exit $?
    fi
    exit 0
  ) &
done

wait

echo
echo "Done. Progress log: ${PROGRESS_TSV}"
echo "Tip: column -t -s $'\\t' ${PROGRESS_TSV} | less -S"
