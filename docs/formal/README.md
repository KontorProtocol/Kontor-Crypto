# Formal Verification (Picus)

## Purpose
Detect and prevent ZK-circuit **underconstraints** (missing constraints that allow multiple satisfying assignments with different step outputs) in the Nova one-step circuit implemented by `PorCircuit`.

This repo integrates Veridise **Picus** to check *uniqueness/determinism* of selected step outputs under an explicit scope.

## Scope
- Circuit: `PorCircuit` one-step relation (Nova primary step circuit) in `src/circuit/synth.rs`.
- Verification target: uniqueness of the selected step outputs (we typically use a small output prefix for tractability).
- Fixture matrix: `tools/picus/manifest.json` (production fixtures).

## What We Prove (The Intended Statement)
The production circuit is a **relation**, not a function of public `z` alone (it includes witness-private values, e.g. `leaf`, that directly affect `state_out`).

Accordingly, the determinism property we target is:

For a fixed circuit shape, fixed public input vector `z`, and fixed witness material that defines the transition (leaf + Merkle siblings, plus required selector/gating bits), the chosen step outputs are uniquely determined by the constraints.

Details: `docs/formal/determinism.md`.

## What We Do Not Prove
- Determinism from public `z` alone (generally not expected for this circuit).
- Cryptographic properties (e.g. hash injectivity, uniqueness of Merkle preimages).
- Full Nova recursion system correctness (this is one-step only).
- Exhaustive coverage over all shapes and all witnesses (fixtures are finite).

## Success Criteria
- For every fixture in `tools/picus/manifest.json`, Picus returns `safe` (exit code `8`) under the **leaf+path** precondition for the CI target outputs (currently `--output-prefix-len 2`).
- Any `unsafe` (exit `9`) is treated as a real determinism/underconstraint bug.
- Any `unknown` (exit `0`) is tracked as inconclusive and should not be considered a pass.

Latest recorded results: `docs/formal/results.md`.

## How To Run (Docker-First)
1. Sanity-check the Docker Picus toolchain:
```bash
tools/picus/check-docker.sh
```

2. Run the full fixture matrix (recommended scope used in CI):
```bash
tools/picus/run.sh --all \
  --output-prefix-len 2 \
  --picus-leafpath-precondition \
  --timeout-secs 1200 \
  --hard-timeout-grace-secs 120 \
  --picus-log-level PROGRESS
```

More operational details and troubleshooting: `docs/formal/picus.md`.

## Future Work
- Increase target scope (larger output prefixes; eventually full output vector).
- Add negative controls (known-bad mutant circuits) to validate detection power.
- Expand and diversify fixtures (edge cases, adversarial witness patterns).
- Investigate solver configuration sweeps for any remaining `unknown` instances.

