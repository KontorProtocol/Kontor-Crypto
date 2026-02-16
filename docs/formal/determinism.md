# Determinism / Underconstraint Verification

## Big Picture
Picus checks whether a circuit is **properly constrained** with respect to chosen outputs under a chosen scope.

Conceptually, Picus:
1. Creates two copies of the circuit constraints.
2. Forces the “known/fixed” wires to be equal across both copies (the *precondition*).
3. Asks an SMT solver whether any chosen “target” output can differ while both copies still satisfy all constraints.

Outcomes (Picus exit codes):
- `8`: **safe** (no counterexample; properly constrained for the chosen scope/targets)
- `9`: **unsafe** (counterexample exists; underconstrained for the chosen scope/targets)
- `0`: **unknown** (timeout/solver could not conclude)

## Why We Do Not Target “Public-Input Determinism”
`PorCircuit` is a **relation**: witness-private values (notably `leaf`) participate directly in the transition (e.g. `state_out` depends on `leaf`).

So “fix public `z` and prove outputs are unique” is generally not the right property and is expected to be hard/inconclusive without additional assumptions.

## The Statement We Target
For a fixed circuit shape, fixed public input vector `z`, and fixed witness material that defines the transition:
- `leaf`
- file Merkle siblings
- aggregated Merkle siblings (if multi-file)
- plus the derived selector/gating bits used by the Merkle gadgets and slot activation logic (pinned for convergence)

the selected step outputs are uniquely determined by the constraints.

This is implemented as the **leaf+path** precondition:
- CLI flag: `--picus-leafpath-precondition`
- Exporter: `src/formal/mod.rs` (`PicusPreconditionKind::InputsPlusLeafPathOnly`)
- Trace support: `src/circuit/synth.rs` (witness tracing to find the relevant aux wires)

## Output Scope (Why Prefixes Exist)
The Nova step output vector is large. For tractable, regression-friendly checks we typically verify only a prefix:
- `--output-prefix-len 1`: `root_out` only (fastest sanity check)
- `--output-prefix-len 2`: `root_out` and `state_out` (current CI target)

The exporter always writes `circuit.r1cs` (full outputs) and optionally also writes `circuit.prefixN.r1cs` for reduced-scope proofs.

## Key Circuit Fix: Carry-Forward Output Binding
During validation we found a real underconstraint risk: some “carry-forward” outputs were allocated as fresh variables without explicit equality constraints tying them to their intended values.

Fix: add explicit equality constraints in `src/circuit/synth.rs` so that:
- `root_out = root`
- `ledger_index_out_* = ledger_index_public_*`
- `depth_out_* = depth_public_*`
- `seed_out_* = seed_public_*`

This makes the exported step outputs reflect the actual step relation, and prevents silent unconstrained-output regressions.

