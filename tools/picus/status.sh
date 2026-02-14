#!/usr/bin/env bash
set -euo pipefail

# File-based status for Picus runs (works even when you cannot or do not want to
# inspect solver PIDs). This does not touch any solver processes.
#
# Usage:
#   tools/picus/status.sh                 # latest run under artifacts/picus-runs/
#   tools/picus/status.sh --run-id <id>
#   tools/picus/status.sh --watch

usage() {
  cat <<'EOF' >&2
usage:
  tools/picus/status.sh [--run-id <id>] [--watch] [--interval-secs <n>]

notes:
  - A case is considered "done" if it has exit_code.txt.
  - For running cases, we show stdout.log size + last line.
EOF
  exit 2
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

RUN_ID=""
WATCH=0
INTERVAL_SECS=30

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id) RUN_ID="${2:-}"; shift 2 ;;
    --watch) WATCH=1; shift ;;
    --interval-secs) INTERVAL_SECS="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; usage ;;
  esac
done

pick_latest_run_id() {
  # Newest-by-mtime directory name (not recursive).
  ls -1t artifacts/picus-runs 2>/dev/null | head -n 1 || true
}

render_once() {
  local id="$1"
  local dir="artifacts/picus-runs/${id}"

  if [[ -z "${id}" ]] || [[ ! -d "${dir}" ]]; then
    echo "No run found under artifacts/picus-runs/ (or invalid --run-id)." >&2
    return 2
  fi

  echo "Run: ${id} (${dir})"
  if [[ -f "${dir}/progress.tsv" ]]; then
    local lines
    lines="$(wc -l < "${dir}/progress.tsv" | tr -d ' ')"
    echo "progress.tsv: ${lines} lines"
  else
    echo "progress.tsv: missing"
  fi

  local total=0
  local done=0
  local running=0

  # We define "case dir" as any directory containing picus.json.
  local tmp_list
  tmp_list="$(mktemp "${TMPDIR:-/tmp}/picus-status.XXXXXX")"
  find "${dir}" -type f -name picus.json -print > "${tmp_list}" 2>/dev/null || true

  while IFS= read -r json; do
    [[ -z "${json}" ]] && continue
    total=$((total + 1))
    local case_dir
    case_dir="$(cd "$(dirname "${json}")" && pwd)"

    if [[ -f "${case_dir}/exit_code.txt" ]]; then
      done=$((done + 1))
      continue
    fi

    running=$((running + 1))

    local out="${case_dir}/stdout.log"
    local out_sz="0"
    if [[ -f "${out}" ]]; then
      out_sz="$(wc -c < "${out}" | tr -d ' ')"
    fi

    local last=""
    if [[ -f "${out}" ]]; then
      last="$(tail -n 1 "${out}" 2>/dev/null || true)"
    fi

    # Shorten absolute paths to keep output readable.
    local pretty="${case_dir#${ROOT}/}"
    echo "RUNNING: ${pretty} stdout_bytes=${out_sz} last='${last}'"
  done < "${tmp_list}"

  rm -f "${tmp_list}"

  echo "Summary: total_cases=${total} done=${done} running=${running}"
}

if [[ -z "${RUN_ID}" ]]; then
  RUN_ID="$(pick_latest_run_id)"
fi

if [[ "${WATCH}" == "1" ]]; then
  while true; do
    echo
    echo "== $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
    render_once "${RUN_ID}" || true
    sleep "${INTERVAL_SECS}"
  done
else
  render_once "${RUN_ID}"
fi

