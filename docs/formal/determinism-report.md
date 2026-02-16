# Determinism Verification Report

Last updated: February 15, 2026

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

4. Output prefix len = 2, leaf+path precondition, 60m budgets as needed:
   - `single-file-minimal`: `pass` (`exit=8`, 480s)
     - Run: `artifacts/picus-runs/20260215-single-file-minimal-leafpath-prefix2/`
   - `single-file-depth10`: `pass` (`exit=8`, 420s)
     - Run: `artifacts/picus-runs/20260215-single-file-depth10-leafpath-prefix2/`
   - `multi-file-minimal`: `pass` (`exit=8`, 900s)
     - Run: `artifacts/picus-runs/20260215-multi-file-minimal-leafpath-prefix2/`
   - `multi-file-mixed-depth`: `pass` (`exit=8`, 1020s)
     - Run: `artifacts/picus-runs/20260215-multi-file-mixed-depth-leafpath-prefix2/`
   - `multi-file-padding`: `pass` (`exit=8`, 1860s)
     - Run: `artifacts/picus-runs/20260215-multi-file-padding-leafpath-prefix2/`

Current conclusion:
- Harness is functioning and bounded.
- Picus reaches conclusive `safe` (`exit=8`) on the full fixture matrix in `tools/picus/manifest.json` under the leaf+path precondition.
- "No precondition" determinism on public `z` alone is not an expected property of the production circuit (it is a relation).

## Output Threading Fix (February 16, 2026)
We added explicit equality constraints for the “carry-forward” outputs in `PorCircuit`
so that the exported step outputs are actually bound to their intended public inputs:
- `root_out = root`
- `ledger_index_out_* = ledger_index_public_*`
- `depth_out_* = depth_public_*`
- `seed_out_* = seed_public_*`

This closes the previously identified gap where some outputs could be unconstrained in the
exported R1CS.

## Post-Fix Sanity Run (Root-Only Target)
Run: `artifacts/picus-runs/20260216-prefix1-leafpath-after-output-threading-fix/`

Scope: `--output-prefix-len 1` (root only), leaf+path precondition, 5 minute budgets.
All fixtures in `tools/picus/manifest.json` were `safe` (`exit=8`) and concluded quickly via
Picus propagation:
- `single-file-minimal`: `exit=8` (60s)
- `single-file-depth10`: `exit=8` (60s)
- `multi-file-minimal`: `exit=8` (60s)
- `multi-file-mixed-depth`: `exit=8` (60s)
- `multi-file-padding`: `exit=8` (120s)

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
4. Achieved: conclusive `pass` on all manifest fixtures under a leaf+path precondition with `--output-prefix-len 2`.
5. Remaining work: decide whether to formalize additional properties (e.g., strict uniqueness of gating selectors from public depth) and/or add a negative-control mutant circuit to validate detection power.

## Residual Risk
1. Root-only conclusive results are a necessary sanity check but do not by themselves establish
   determinism for `state_out` or deeper output prefixes.
2. Fixture matrix is finite and may not cover all pathological witness patterns.
3. Picus one-step analysis does not prove full Nova recursion system correctness.

## Next Steps
1. Run one fixture at a time with larger budgets and solver/model sweeps until first `pass`/`violation`.
2. Apply the converged settings across all five fixtures.
3. If all pass, record acceptance against `docs/formal/determinism-spec.md`.
4. Add targeted edge fixtures and at least one negative-control mutant fixture to validate detection power.
