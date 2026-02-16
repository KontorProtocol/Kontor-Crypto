# Component Contracts

## Component kinds
- `component_challenge_derivation`
- `component_file_merkle`
- `component_aggregation_merkle`
- `component_state_update`
- `component_carry_forward`

## Contract file
`tools/picus/components/contracts.json` declares required input/output roles for each component.

Verifier preflight validates:
- each fixture is component-backed,
- each fixture has a matching contract,
- each contract declares non-empty input and output role sets.
