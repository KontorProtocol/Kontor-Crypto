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
  tools/picus/status.sh --all --summary

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
SUMMARY=0
ALL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id) RUN_ID="${2:-}"; shift 2 ;;
    --summary) SUMMARY=1; shift ;;
    --all) ALL=1; shift ;;
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
  local ok=0
  local unsafe=0
  local inconc=0
  local other=0

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
      local ec
      ec="$(cat "${case_dir}/exit_code.txt" 2>/dev/null || true)"
      case "${ec}" in
        8) ok=$((ok + 1)) ;;
        9) unsafe=$((unsafe + 1)) ;;
        0) inconc=$((inconc + 1)) ;;
        *) other=$((other + 1)) ;;
      esac
      continue
    fi

    running=$((running + 1))

    if [[ "${SUMMARY}" == "1" ]]; then
      continue
    fi

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

  echo "Summary: total_cases=${total} done=${done} running=${running} ok=${ok} unsafe=${unsafe} inconclusive=${inconc} other_done=${other}"
}

render_all_summaries() {
  local ids
  ids="$(ls -1 artifacts/picus-runs 2>/dev/null || true)"
  if [[ -z "${ids}" ]]; then
    echo "No runs found under artifacts/picus-runs/." >&2
    return 2
  fi
  while IFS= read -r id; do
    [[ -z "${id}" ]] && continue
    SUMMARY=1 render_once "${id}" | tail -n 1 | sed "s/^/Run: ${id} /"
  done <<< "${ids}"
}

if [[ "${ALL}" == "1" ]]; then
  if [[ "${WATCH}" == "1" ]]; then
    while true; do
      echo
      echo "== $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
      render_all_summaries || true
      sleep "${INTERVAL_SECS}"
    done
  else
    render_all_summaries
  fi
  exit $?
fi

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
