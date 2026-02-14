# Determinism Verification Report

Last updated: February 14, 2026

## Scope
- Circuit: `PorCircuit` one-step relation.
- Fixture matrix: `tools/picus/manifest.json`.

## Tooling
- Exporter: `src/bin/picus_export.rs`
- Runner: `src/bin/picus_verify.rs`
- Fixture schema: `src/formal/mod.rs`
- Picus input artifact: `artifacts/picus/<fixture>/circuit.r1cs`

## Latest Results
From `artifacts/picus-runs/*/progress.tsv`:

1. Root-only target (output prefix len = 1), witness precondition, 30m per fixture:
   - Run: `artifacts/picus-runs/20260214-111246/`
   - `single-file-minimal`: `pass` (`exit=8`, 346s)
   - `single-file-depth10`: `pass` (`exit=8`, 408s)
   - `multi-file-minimal`: `pass` (`exit=8`, 827s)
   - `multi-file-mixed-depth`: `pass` (`exit=8`, 959s)
   - `multi-file-padding`: `pass` (`exit=8`, 1797s)

2. Root-only target (output prefix len = 1), no precondition, 20m:
   - Run: `artifacts/picus-runs/20260214-115934/`
   - `single-file-minimal`: `inconclusive` (`exit=0`, 1260s)

3. Output prefix len = 2, witness precondition, 30m:
   - Run: `artifacts/picus-runs/20260214-120130/`
   - `single-file-minimal`: `pass` (`exit=8`, 360s)
   - `single-file-depth10`: `pass` (`exit=8`, 420s)
   - `multi-file-minimal`: `pass` (`exit=8`, 840s)
   - `multi-file-mixed-depth`: `pass` (`exit=8`, 1020s)

Current conclusion:
- Harness is functioning and bounded.
- At least one conclusive `pass` has been achieved on a minimal non-trivial scope.
- Determinism is not yet proven for the main fixture matrix in `tools/picus/manifest.json`.
  - Phase A `pass` results used a witness-guided precondition and only targeted the first output; this is useful evidence that the exported constraints are not trivially underconstrained in that scoped configuration, but it is not sufficient to claim full determinism.

## Coverage
Fixture matrix currently defined:
1. `single-file-minimal`: `(files_per_step=1, file_tree_depth=8, aggregated_tree_depth=0)`.
2. `single-file-depth10`: `(1, 10, 0)`.
3. `multi-file-minimal`: `(2, 8, 1)`.
4. `multi-file-mixed-depth`: `(2, 10, 1)`.
5. `multi-file-padding`: `(4, 8, 2)`.

This covers:
1. Single-file and multi-file modes.
2. Depth variation (8 and 10).
3. Aggregation depth transitions (`0 -> 1 -> 2`).
4. Files-per-step padding behavior.

## Findings
1. Previously observed: `cvc5` without CoCoA support yields Picus `[solver] skipped` and `unknown`.
2. Engineering fixes completed:
- timeout unit mismatch corrected (seconds -> milliseconds for Picus);
- hard timeout enforcement and process-tree cleanup in `src/bin/picus_verify.rs`;
- stale solver cleanup between fixtures/runs.
3. New prerequisite: use a CoCoA-enabled `cvc5` for finite-field (`QF_FF`) solving. See `docs/formal/picus-runbook.md`.
4. Remaining blocker: reaching `pass`/`violation` on main fixtures without relying on witness-guided preconditions (and eventually expanding targets beyond `--output-prefix-len 1`).

## Residual Risk
1. Current evidence does not establish `pass` for the main fixture matrix, so the determinism claim is pending.
2. Fixture matrix is finite and may not cover all pathological witness patterns.
3. Picus one-step analysis does not prove full Nova recursion system correctness.

## Next Steps
1. Run one fixture at a time with larger budgets and solver/model sweeps until first `pass`/`violation`.
2. Apply the converged settings across all five fixtures.
3. If all pass, record acceptance against `docs/formal/determinism-spec.md`.
4. Add targeted edge fixtures and at least one negative-control mutant fixture to validate detection power.
