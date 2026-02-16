# Component Contracts

## Component kinds
- `component_challenge_derivation`
- `component_challenge_derivation_mutant`
- `component_file_merkle`
- `component_file_merkle_mutant`
- `component_aggregation_merkle`
- `component_aggregation_merkle_mutant`
- `component_state_update`
- `component_state_update_mutant`
- `component_carry_forward`
- `component_carry_forward_mutant`

## Contract file
`tools/picus/components/contracts.json` declares:
- required input roles
- produced output roles
- forbidden output roles
- determinism targets
- composition dependencies (`consumes_from`)

Fixture sets:
- `tools/picus/components/manifest.json`: CI-fast component matrix.
- `tools/picus/components/manifest-full.json`: exhaustive matrix including heavier mutants.

Verifier preflight validates:
- each fixture is component-backed,
- each fixture has a matching contract,
- each contract declares non-empty input/output roles and determinism targets,
- no contract both produces and forbids the same role,
- mutant fixtures are marked `expected_result = unsafe`.
