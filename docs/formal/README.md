# Formal Verification (Picus, Comprehensive)

## Purpose
Maximize formal assurance against underconstraints by verifying determinism in two blocking lanes:
- component-level proofs (modular production gadgets),
- monolithic `PorCircuit` broad production fixtures.

## Scope
- Component fixtures:
  - CI-fast: `tools/picus/components/manifest.json`
  - Exhaustive: `tools/picus/components/manifest-full.json`
- Monolithic broad fixtures:
  - `tools/picus/manifest-broad.json`
  - policy target: full output vector (`output_prefix_len = 0`)
- Contracts: `tools/picus/components/contracts.json`.

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
- `leafpath` strict mode is default (no silent fallback to input-only scope).

## Quick Start
```bash
tools/picus/check-docker.sh

# Component blocking lane
cargo run --release --bin picus_verify -- \
  --all \
  --manifest tools/picus/components/manifest.json \
  --fixtures-dir tools/picus/components/fixtures \
  --scope leafpath \
  --simplify safe \
  --picus-bin tools/picus/run-picus-docker.sh \
  --artifacts-dir artifacts/picus-components

# Monolithic blocking lane
cargo run --release --bin picus_verify -- \
  --all \
  --manifest tools/picus/manifest-broad.json \
  --fixtures-dir tools/picus/fixtures \
  --scope leafpath \
  --simplify safe \
  --picus-bin tools/picus/run-picus-docker.sh \
  --artifacts-dir artifacts/picus-monolithic
```

More details: `docs/formal/picus.md`, `docs/formal/determinism.md`, `docs/formal/components.md`.
