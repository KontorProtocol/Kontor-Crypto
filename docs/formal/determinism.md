# Determinism Model (Component-First)

## Why Components
`PorCircuit` as a whole is a relation and can be difficult for SMT-based tools when exported monolithically.

This branch verifies determinism on smaller component circuits built from production gadgets, then enforces composition expectations through contracts.

## Picus outcomes
- `8`: safe (no counterexample)
- `9`: unsafe (counterexample found)
- `0`: unknown/inconclusive

## Required Statement
For each component fixture and full component output scope:
- under the selected scope (`leafpath` by default),
- there does not exist a pair of satisfying assignments that agree on fixed wires and differ on target outputs.

## Scope options
- `leafpath` (default): exported as `InputsPlusLeafPathOnly`, with component fallback to input-fixed when trace-only data is unavailable.
- `public-z`: exported as input-fixed (`InputsOnly`).

## Composition boundary
Component interface expectations are specified in `tools/picus/components/contracts.json` and validated before verification runs.
