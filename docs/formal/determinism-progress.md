# Determinism Verification Progress

This document tracks *process*, not a final claim. The final spec and claim live in:
- `docs/formal/determinism-spec.md`
- `docs/formal/determinism-report.md`

## Tracking Conventions
For any run that matters:
- Always run Picus with `--json <path>` and keep stdout/stderr logs.
- Always record the exit code immediately after the run finishes (`echo $?` in bash).

Picus exit codes (from `Picus/picus/exit.rkt`):
- `8`: safe (properly constrained)
- `9`: unsafe (underconstrained)
- `0`: unknown (timeout/unknown)

## Incremental Ladder (Per Fixture)
We aim to climb this ladder, stopping only when we get conclusive `8`/`9` results:
1. `prefix=1`, witness precondition, bounded time
2. `prefix=1`, no precondition, bounded time (may return `0`)
3. `prefix=all`, witness precondition, bounded time
4. `prefix=all`, no precondition, bounded time (hardest)

Notes:
- A `pass` under witness precondition is a smoke/sanity check, not the final proof.
- The key evidence is `pass` under no precondition.

## Where Runs Are Stored
- `artifacts/picus-runs/<run-id>/progress.tsv` (append-only index)
- `artifacts/picus-runs/<run-id>/<fixture>/<case>/` (stdout/stderr, JSON log, exit code)

The recommended runner is:
- `tools/picus/run-ladder-safe.sh` (never kills solver processes)

