# Determinism Verification Report

Last updated: February 12, 2026

## Scope
- Circuit: `PorCircuit` one-step relation.
- Fixture matrix: `tools/picus/manifest.json`.

## Tooling
- Exporter: `src/bin/picus_export.rs`
- Runner: `src/bin/picus_verify.rs`
- Fixture schema: `src/formal/mod.rs`
- Picus input artifact: `artifacts/picus/<fixture>/circuit.r1cs`

## Latest Results
From `artifacts/picus/summary.json` (most recent run in workspace):
1. Included fixtures: `single-file-minimal` (single fixture run).
2. Runtime limits: `--timeout-secs 120`, `--hard-timeout-grace-secs 30`.
3. Classification: `inconclusive` (hard timeout).

Current conclusion:
- Harness is functioning and bounded.
- Determinism is not yet proven because no fixture has reached `pass`.

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
1. `single-file-minimal`: `inconclusive`.
2. Root cause: solver runtime exceeded configured hard timeout window.
3. Engineering fixes completed:
- timeout unit mismatch corrected (seconds -> milliseconds for Picus);
- hard timeout enforcement and process-tree cleanup in `src/bin/picus_verify.rs`;
- stale solver cleanup between fixtures/runs.
4. Remaining blocker: solver convergence to `safe`/`unsafe` on target fixture shapes.

## Residual Risk
1. Current evidence does not establish `pass` for any fixture, so determinism claim is pending.
2. Fixture matrix is finite and may not cover all pathological witness patterns.
3. Picus one-step analysis does not prove full Nova recursion system correctness.

## Next Steps
1. Run one fixture at a time with larger budgets and solver/model sweeps until first `pass`/`violation`.
2. Apply the converged settings across all five fixtures.
3. If all pass, record acceptance against `docs/formal/determinism-spec.md`.
4. Add targeted edge fixtures and at least one negative-control mutant fixture to validate detection power.
