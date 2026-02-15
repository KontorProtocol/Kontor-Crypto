# Determinism/Uniqueness Specification for `PorCircuit`

## Scope
This specification covers the one-step `PorCircuit` relation used by the Nova primary step circuit implementation in `src/circuit/synth.rs`.

This does not claim determinism for Nova recursion internals; it targets the step relation itself.

## Statement
The production `PorCircuit` is inherently a *relation*, not a function of public `z` alone:
`state_out = Poseidon(state_in, leaf)` where `leaf` is witness-private.

We therefore target the following determinism/uniqueness statement for formal verification:

For a fixed circuit shape `(files_per_step, file_tree_depth, aggregated_tree_depth)`, fixed public vector `z`,
and fixed witness material that defines the transition (leaf + Merkle siblings, and the associated selector/gating bits),
Picus must conclude the circuit is properly constrained (no alternative satisfying assignments that change the step outputs).

## Required Properties
1. Public output binding:
The output tuple `[root_out, state_out, ledger_indices_out..., depths_out..., seeds_out..., leaves_out...]` is uniquely constrained by valid witness semantics and the fixed public vector `z`.
2. Path/depth binding:
Witness values cannot bypass depth gating or Merkle membership checks in a way that changes semantic correctness while preserving satisfiability.
3. State-chain binding:
Conditional state updates for active slots are uniquely determined by witness/public depth semantics and cannot be under-constrained.

## Mapping to Circuit Regions
1. Public layout and arity checks:
`src/circuit/synth.rs` (public layout extraction and assertion).
2. Depth gating and active flags:
`src/circuit/synth.rs` (`active_flags`, `depth_is_positive`, `depth_equals_public_file*`).
3. File path and ledger membership constraints:
`src/circuit/synth.rs` (`verify_file_merkle`, `verify_ledger_membership`, root equality gates).
4. State and public leaf outputs:
`src/circuit/synth.rs` (`gate_state_update`, `public_leaf_select`).
5. Output threading:
`src/circuit/synth.rs` (construction of final output vector).

## Verification Artifacts
Each fixture export must include:
1. R1CS shape artifact (`shape.bin` in Nova serialization).
2. Picus-ready R1CS artifact (`circuit.r1cs`).
3. Instance and witness artifacts (`instance.bin`, `witness.bin`).
4. Deterministic metadata (`export-metadata.json`) including derived shape and checksums.

## Acceptance Criteria
1. For each fixture in `tools/picus/manifest.json`, artifacts export deterministically.
2. Picus analysis classifies each fixture as `safe` (`exit=8`) under the leaf+path precondition.
3. Any `unsafe` classification (`exit=9`) is treated as a determinism/underconstraint violation and must be fixed before acceptance.
4. `unknown`/timeout (`exit=0`) is inconclusive and must be explicitly tracked.
