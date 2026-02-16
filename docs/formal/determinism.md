# Determinism Model (Comprehensive)

## Why Components
`PorCircuit` as a whole is a relation and can be difficult for SMT-based tools when exported monolithically.

This branch verifies determinism in both:
- component circuits built from production gadgets, and
- monolithic `PorCircuit` production fixtures.

## Picus outcomes
- `8`: safe (no counterexample)
- `9`: unsafe (counterexample found)
- `0`: unknown/inconclusive

Fixture `expected_result` is enforced:
- non-mutant fixtures are expected `safe`
- mutant fixtures are expected `unsafe`

## Required Statement
For each blocking fixture:
- under the selected scope (`leafpath` by default),
- there does not exist a pair of satisfying assignments that agree on fixed wires and differ on target outputs.
- if Picus is inconclusive (`0`) after configured solver policy, the fixture fails (fail-closed).

## Scope options
- `leafpath` (default): exported as `InputsPlusLeafPathOnly` with strict trace enforcement.
  If trace capture fails, export fails by default (`KONTOR_PICUS_STRICT_SCOPE=0` allows fallback).
- `public-z`: exported as input-fixed (`InputsOnly`).

## Composition boundary
Component interface expectations are specified in `tools/picus/components/contracts.json` and validated before verification runs.
Each declared `consumes_from` edge must have role overlap between producer outputs and consumer required inputs.

## Fixture-level Policy
Fixtures may declare `verification` policy fields:
- `scope`
- `output_prefix_len`
- `solver_policy` (`primary`, `fallbacks`)
- `timeout_secs`
- `hard_timeout_grace_secs`

If a field is omitted, CLI defaults are used.

Fixtures can additionally pin `expected_num_constraints`; export fails if the synthesized
constraint count drifts.

For the monolithic broad manifest (`tools/picus/manifest-broad.json`), fixtures currently pin
`output_prefix_len = 0`, i.e. determinism is checked over the full step output vector.
