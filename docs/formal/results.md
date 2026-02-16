# Results

This file records *conclusive* Picus outcomes for the production fixture matrix in `tools/picus/manifest.json`.

## Fixture Matrix
1. `single-file-minimal`: shape `(files_per_step=1, file_tree_depth=8, aggregated_tree_depth=0)`
2. `single-file-depth10`: shape `(1, 10, 0)`
3. `multi-file-minimal`: shape `(2, 8, 1)`
4. `multi-file-mixed-depth`: shape `(2, 10, 1)`
5. `multi-file-padding`: shape `(4, 8, 2)`

## Latest Recorded Pass (After Output-Binding Fix)
Date: 2026-02-16

Scope:
- Precondition: **leaf+path** (`--picus-leafpath-precondition`)
- Targets: output prefix len = 2 (`root_out`, `state_out`)

Run directory:
- `artifacts/picus-runs/20260216-prefix2-leafpath-after-output-threading-fix/`

Outcome:
- All fixtures: `safe` (exit `8`)

Notes:
- This run is the post-fix sanity check after adding explicit equality constraints for carry-forward outputs in `src/circuit/synth.rs`.

