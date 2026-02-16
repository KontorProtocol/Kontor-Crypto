# Formal Verification (Picus, Component-First)

## Purpose
Maximize formal assurance against underconstraints by verifying determinism on modular sub-circuits built from production gadgets.

## Scope
- Primary target: component circuits (`challenge_derivation`, `file_merkle`, `aggregation_merkle`, `state_update`, `carry_forward`).
- CI fixture matrix: `tools/picus/components/manifest.json` (fast profile).
- Exhaustive fixture matrix: `tools/picus/components/manifest-full.json` (includes heavier mutants).
- Contracts: `tools/picus/components/contracts.json`.

## Required Claim (Determinism++)
For each component fixture, under the selected scope (default: `leafpath`), all component outputs are uniquely determined by constraints (`safe`, Picus exit `8`).

## Non-Goals
- Public-`z` determinism as a required CI gate.
- Cryptographic security proofs (e.g. hash injectivity).
- Full recursive Nova system proof.

## Success Criteria
- All non-mutant component fixtures in `tools/picus/components/manifest.json` are `safe`.
- All mutant fixtures in `tools/picus/components/manifest.json` are `unsafe`.
- Contract validation succeeds for all component fixtures.
- Leafpath scope runs are strict by default (no silent fallback to input-only scope).

## Quick Start
```bash
tools/picus/check-docker.sh

cargo run --release --bin picus_verify -- \
  --all \
  --scope leafpath \
  --simplify safe \
  --picus-bin tools/picus/run-picus-docker.sh
```

More details: `docs/formal/picus.md`, `docs/formal/determinism.md`, `docs/formal/components.md`.
