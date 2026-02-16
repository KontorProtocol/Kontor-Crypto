# Formal Verification (Picus, Comprehensive)

## Purpose
Maximize formal assurance against underconstraints by verifying determinism in two blocking lanes:
- component-level proofs (modular production gadgets),
- monolithic `PorCircuit` broad production fixtures.

## Scope
- Component fixtures: `tools/picus/components/manifest.json`
- Monolithic broad fixtures:
  - `tools/picus/manifest-broad.json`
  - policy target: full output vector (`output_prefix_len = 0`)
- Contracts: `tools/picus/components/contracts.json`.
- Constraint-count regression guard: fixtures pin `expected_num_constraints` and export fails on drift.

## Required Claim (Determinism++)
For each blocking fixture, under configured scope and output target, Picus is conclusive and matches expected result:
- `safe` for production fixtures,
- `unsafe` for mutation controls.

## Non-Goals
- Cryptographic security proofs (e.g. hash injectivity).
- Full recursive Nova system proof.

## Success Criteria
- Component CI manifest: all expected outcomes met and no inconclusive/error.
- Monolithic broad manifest: all expected outcomes met and no inconclusive/error.
- Contract validation succeeds for component fixtures.
- Contract dependency edges (`consumes_from`) have role-compatible boundaries.
- `leafpath` strict mode is default (no silent fallback to input-only scope).

## Quick Start
```bash
tools/picus/check-docker.sh

# Component blocking lane (wrapper defaults)
tools/picus/run.sh --all --scope leafpath --simplify safe
```

For monolithic runs and full command variants, use the canonical runbook: `docs/formal/picus.md`.
Determinism model and component interface checks are documented in `docs/formal/determinism.md` and `docs/formal/components.md`.
