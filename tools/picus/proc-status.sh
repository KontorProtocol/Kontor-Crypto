#!/usr/bin/env bash
set -euo pipefail

# Show status of all running Picus/cvc5 proof processes (does not touch them).
#
# Usage:
#   tools/picus/proc-status.sh
#   tools/picus/proc-status.sh --watch
#   tools/picus/proc-status.sh --watch --interval-secs 10

usage() {
  cat <<'EOF' >&2
usage:
  tools/picus/proc-status.sh [--watch] [--interval-secs <n>]

filters:
  - cvc5 processes running Picus-generated .smt2
  - racket picus.rkt
  - run-picus wrapper
  - script -q ... stdout capture used by our runners
EOF
  exit 2
}

WATCH=0
INTERVAL_SECS=5

while [[ $# -gt 0 ]]; do
  case "$1" in
    --watch) WATCH=1; shift ;;
    --interval-secs) INTERVAL_SECS="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; usage ;;
  esac
done

render_once() {
  local py
  py="$(mktemp "${TMPDIR:-/tmp}/picus-proc-status.XXXXXX.py")"
  cat >"${py}" <<'PY'
import re, sys

rows = []

def kind(cmd: str) -> str:
    if " /cvc5" in cmd or cmd.strip().startswith("cvc5 ") or "/tmp/cvc5-install/bin/cvc5" in cmd:
        return "cvc5"
    if "racket " in cmd and "picus.rkt" in cmd:
        return "racket"
    if "run-picus" in cmd:
        return "run-picus"
    if cmd.lstrip().startswith("script -q ") or " script -q " in cmd:
        return "script"
    return "other"

runid_re = re.compile(r"artifacts/picus-runs/([^/\s]+)")
fixture_re = re.compile(r"artifacts/picus/([^/\s]+)")
case_re = re.compile(r"artifacts/picus-runs/([^/\s]+)/([^/\s]+)/([^/\s]+)/picus\.json")
json_arg_re = re.compile(r"--json\s+(\S+)")
run_id_arg_re = re.compile(r"--run-id\s+(\S+)")
tmp_picus_re = re.compile(r"/T/(picus\d+)/\1\.smt2")
any_picus_id_re = re.compile(r"\b(picus\d{10,})\b")

def extract_tag(cmd: str) -> str:
    m = case_re.search(cmd)
    if m:
        run_id, fx, case = m.group(1), m.group(2), m.group(3)
        return f"{run_id} {fx}/{case}"
    m = run_id_arg_re.search(cmd)
    if m:
        return m.group(1)
    m = runid_re.search(cmd)
    if m:
        return m.group(1)
    m = fixture_re.search(cmd)
    if m:
        return f"picus/{m.group(1)}"
    m = json_arg_re.search(cmd)
    if m:
        j = m.group(1)
        m2 = case_re.search(j)
        if m2:
            run_id, fx, case = m2.group(1), m2.group(2), m2.group(3)
            return f"{run_id} {fx}/{case}"
        m2 = runid_re.search(j)
        if m2:
            return m2.group(1)
        m2 = fixture_re.search(j)
        if m2:
            return f"picus/{m2.group(1)}"
    m = tmp_picus_re.search(cmd)
    if m:
        return m.group(1)
    m = any_picus_id_re.search(cmd)
    if m:
        return m.group(1)
    return "-"

def short_cmd(cmd: str, max_len: int = 88) -> str:
    cmd = cmd.strip()
    cmd = re.sub(r"\s+", " ", cmd)
    if len(cmd) <= max_len:
        return cmd
    return cmd[: max_len - 3] + "..."

for line in sys.stdin:
    line = line.rstrip("\n")
    if not line.strip():
        continue
    parts = line.split(None, 5)
    if len(parts) < 6:
        continue
    pid, ppid, etime, pcpu, rss_kb, cmd = parts

    # Only show proof-ish processes.
    if not (
        "picus.rkt" in cmd
        or "run-picus" in cmd
        or ".smt2" in cmd
        or ("script -q " in cmd and "picus" in cmd)
        or "cvc5" in cmd
    ):
        continue

    k = kind(cmd)
    tag = extract_tag(cmd)
    rss_mb = int(rss_kb) / 1024.0
    rows.append(
        (tag, k, int(pid), int(ppid), etime, float(pcpu), rss_mb, short_cmd(cmd))
    )

rows.sort(key=lambda r: (r[0], r[1], -r[5], r[2]))

from datetime import datetime, UTC
print(f"ts_utc={datetime.now(UTC).isoformat(timespec='seconds').replace('+00:00','Z')}")
print(f"{'tag':40} {'kind':9} {'pid':>6} {'ppid':>6} {'etime':>12} {'cpu%':>6} {'rssMB':>8}  cmd")
for tag, k, pid, ppid, etime, pcpu, rss_mb, cmd in rows:
    print(f"{tag:40} {k:9} {pid:6d} {ppid:6d} {etime:>12} {pcpu:6.1f} {rss_mb:8.0f}  {cmd}")

if not rows:
    print("(no matching proof processes found)")
PY
  # -ww on macOS: do not truncate long command lines (we need artifact paths).
  ps -axww -o pid=,ppid=,etime=,pcpu=,rss=,command= | python3 "${py}"
  rm -f "${py}"
}

if [[ "${WATCH}" == "1" ]]; then
  while true; do
    echo
    render_once
    sleep "${INTERVAL_SECS}"
  done
else
  render_once
fi
