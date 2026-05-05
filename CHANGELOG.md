# Changelog

All notable changes to this project are documented in this file.

## [0.2.0] - 2026-04-23

### Breaking changes

- `field_to_hex` and `field_from_hex` now use canonical little-endian byte order (`ff::PrimeField::to_repr()`) in Rust and npm/WASM surfaces.
- Hex strings produced by `0.1.x` are legacy big-endian and must be byte-reversed before being consumed by `0.2.0`.
- The repository moved from a single-crate layout to a Cargo workspace; git/path consumers must update crate paths.

### Added

- New `kontor-crypto-core` crate with shared primitives:
  - Reed-Solomon symbol encoding/decoding
  - Poseidon Merkle tree logic
  - `prepare_file` pipeline and shared metadata/types
- New `kontor-crypto-wasm` crate exposing browser/Node bindings for `prepare_file`.
- New npm package in `packages/kontor-crypto` for JavaScript/TypeScript integration.
- New release automation workflow for publishing Rust crates and the npm package.
- Expanded verification and hardening assets:
  - formal verification tooling and docs (Picus lane)
  - fuzzing harness and seed corpus
  - additional regression/security test coverage

### Changed

- Project reorganized into a 3-crate workspace:
  - `kontor-crypto` (main Nova prover/verifier API + CLI)
  - `kontor-crypto-core` (shared non-Nova primitives)
  - `kontor-crypto-wasm` (WASM bindings)
- `kontor-crypto` now depends on `kontor-crypto-core` for shared cryptographic/data-preparation logic.
- Documentation updated for workspace usage, WASM/browser usage, and release process.

### Fixed

- Corrected field hex endianness mismatch with indexer/filestorage expectations.
- CI and release pipeline stability improvements for multi-package publication.
- Dependency pinning to avoid edition2024 transitive breakage in constrained toolchains.

### Upgrade notes (from `0.1.6`)

- Regenerate or migrate any persisted field hex strings from `0.1.x` before verification/use in `0.2.0`.
- If you depend on this repo via git path, update package paths to the workspace crate locations.
- For browser-only `prepare_file` use cases, prefer `kontor-crypto-wasm` (or npm package) instead of shipping the full Nova stack.

## [0.1.6] - 2026-01-28

- Latest published crates.io release in the `0.1.x` line.
