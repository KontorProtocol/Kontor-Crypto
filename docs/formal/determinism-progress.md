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

## Recorded Runs

### February 14, 2026 (Root-Only Target, Output Prefix Len = 1)
Run: `artifacts/picus-runs/20260214-111246/` (witness precondition, 30m budget)
- `single-file-minimal prefix1/witness`: `exit=8` (`pass`), 346s
- `single-file-depth10 prefix1/witness`: `exit=8` (`pass`), 408s
- `multi-file-minimal prefix1/witness`: `exit=8` (`pass`), 827s
- `multi-file-mixed-depth prefix1/witness`: `exit=8` (`pass`), 959s
- `multi-file-padding prefix1/witness`: `exit=8` (`pass`), 1797s

Run: `artifacts/picus-runs/20260214-115934/` (no precondition, 20m budget)
- `single-file-minimal prefix1/nopre`: `exit=0` (`inconclusive`), 1260s

### February 14, 2026 (Prefix Len = 2, Witness Precondition)
Run: `artifacts/picus-runs/20260214-120130/` (witness precondition, 30m budget)
- `single-file-minimal prefix2/witness`: `exit=8` (`pass`), 360s
- `single-file-depth10 prefix2/witness`: `exit=8` (`pass`), 420s
- `multi-file-minimal prefix2/witness`: `exit=8` (`pass`), 840s
- `multi-file-mixed-depth prefix2/witness`: `exit=8` (`pass`), 1020s

## Where Runs Are Stored
- `artifacts/picus-runs/<run-id>/progress.tsv` (append-only index)
- `artifacts/picus-runs/<run-id>/<fixture>/<case>/` (stdout/stderr, JSON log, exit code)

Recommended helpers:
- `tools/picus/run-ladder-safe.sh` (never kills solver processes)
- `tools/picus/run-matrix-safe.sh` (parallelize independent proofs to use more cores)
- `tools/picus/status.sh` (file-based status: shows what is still running vs done)
