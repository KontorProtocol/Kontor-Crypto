# Kontor Proof-of-Retrievability (PoR)

[![Crates.io](https://img.shields.io/crates/v/kontor-crypto.svg)](https://crates.io/crates/kontor-crypto)
[![CI](https://github.com/KontorProtocol/Kontor-Crypto/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/KontorProtocol/Kontor-Crypto/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/KontorProtocol/Kontor-Crypto/blob/main/LICENSE)

> **⚠️ WARNING: This code is unaudited and experimental. Use at your own risk.**

This project implements a Proof-of-Retrievability (PoR) system designed to provide economically enforceable guarantees that Storage Nodes are actually storing the data they have committed to. It is a core component for decentralized storage metaprotocols where a network of Indexers (Verifiers) must continuously audit Storage Nodes (Provers).

The system uses [Nova](https://eprint.iacr.org/2021/370) recursive SNARKs via Microsoft's [`nova-snark`](https://github.com/microsoft/Nova) library to generate constant-size (~10 kB) cryptographic proofs that a prover possesses a specific set of data. These proofs are efficient to verify (~30ms), making it feasible to enforce storage guarantees at scale.

## Workspace structure

The repository is a Cargo workspace with three crates:

- **`kontor-crypto`** – Main library and CLI: full PoR API (`PorSystem`, `prepare_file`, `prove`, `verify`), Nova proving/verification, benchmarks, and formal verification tooling. Lives in `crates/kontor-crypto`.
- **`kontor-crypto-core`** – Core logic shared by the main crate and WASM: Reed–Solomon encoding, Poseidon Merkle trees, and `prepare_file` (no Nova). Lives in `crates/kontor-crypto-core`.
- **`kontor-crypto-wasm`** – WASM bindings for `prepare_file` only, for use in the browser or Node.js. Depends on `kontor-crypto-core` (no Nova). Lives in `crates/kontor-crypto-wasm`.

From the repo root, use `cargo build --workspace`, `cargo test --workspace`, or build the WASM crate with `cargo build -p kontor-crypto-wasm --target wasm32-unknown-unknown --release`.

## Core Capabilities

- Partition files into fixed 31-byte symbols for direct field element encoding.
- Apply multi-codeword Reed-Solomon (GF(2^8)) for fault tolerance.
- Generate Poseidon Merkle trees over all symbols (data + parity).
- Create recursive SNARKs proving possession of randomly sampled symbols.
- Compress proofs to constant ~10 kB size regardless of file count or challenge count.
- Support dynamic circuit parameters with in-memory caching.
- Reconstruct original files from partial symbol availability (≥90% per codeword).

## Performance Characteristics

- **Proof Size:** ~10 kB (constant across challenge count and file set within a shape).
- **Verification Time:** ~50 ms for compressed SNARK verification.
- **Proving Time:** Approximately linear in the number of recursive steps.

## API Reference

The high-level API centers on a `PorSystem` object, which consolidates setup, proving, and verification concerns.

### Core Interface

```rust
// Construction
struct PorSystem<'a> { /* holds reference to FileLedger */ }

impl<'a> PorSystem<'a> {
    pub fn new(ledger: &'a FileLedger) -> Self;

    // Prepares a file for proving. Symbol size (31 bytes) and codeword structure (231+24)
    // are fixed by protocol constants in config.rs.
    pub fn prepare_file(
        &self,
        data: &[u8],
        filename: &str,
    ) -> Result<(PreparedFile, FileMetadata)>;

    // Generates a single compact proof for any set of open Challenges.
    pub fn prove(
        &self,
        files: Vec<&PreparedFile>,
        challenges: &[Challenge],
    ) -> Result<Proof>;

    // Verifies a proof against the Challenges it claims to answer.
    pub fn verify(
        &self,
        proof: &Proof,
        challenges: &[Challenge],
    ) -> Result<bool>;
}
```

### Usage Example

A complete example demonstrating the API workflow:

```rust,no_run
use kontor_crypto::api::{
    prepare_file, Challenge, FieldElement, PorSystem,
    tree_depth_from_metadata,
};
use kontor_crypto::FileLedger;

// 1. Prepare the file with fixed Reed-Solomon encoding (231 data + 24 parity symbols per codeword)
let my_data = b"This is a test file for the PoR system.";
let (prepared_file, metadata) = prepare_file(my_data, "test.dat").unwrap();

// 2. Create ledger and add the file
let mut ledger = FileLedger::new();
ledger.add_file(&metadata).unwrap();

// 3. Create PorSystem and challenge
let system = PorSystem::new(&ledger);
let num_challenges = 5;
let seed = FieldElement::from(12345u64); // Deterministic seed
let challenge = Challenge::new(metadata.clone(), 1000, num_challenges, seed, String::from("node_1"));

// 4. Generate proof using the unified API
let files = vec![&prepared_file];
let proof = system.prove(files, &[challenge.clone()]).unwrap();

// 5. Verify the proof
let is_valid = system.verify(&proof, &[challenge]).unwrap();
assert!(is_valid, "Proof verification failed!");

println!("Proof successfully generated and verified with Nova PoR API.");
```

## Using prepare_file in the browser (WASM)

The `prepare_file()` pipeline is available in the browser and in Node.js via the **`kontor-crypto-wasm`** package. It uses the same core logic as the main crate (Reed–Solomon, Poseidon Merkle), so metadata and prepared file output are compatible with the Nova-based prover/verifier.

**Build (from repo root or `crates/kontor-crypto-wasm`):**

- Raw WASM: `cargo build -p kontor-crypto-wasm --target wasm32-unknown-unknown --release`
- Full JS/TS bindings: [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) then  
  `wasm-pack build -p kontor-crypto-wasm --target web` (browser) or `--target nodejs` (Node)

**Usage (after wasm-pack build):** import the module, initialise the WASM runtime, then call `prepareFile`:

- **Browser:** `import init, { prepareFile } from '.../pkg/kontor_crypto_wasm'; await init(); const result = prepareFile(fileBytes, filename, nonce);`
- **Node:** same `init` + `prepareFile`; the `pkg/` directory is a valid npm package.

The returned object includes:
- `metadata` (root hex + IDs + sizes)
- `preparedFile` (tree leaves for prover workflow)
- `descriptor` (**ready for filestorage `create_agreement`**): `{ fileId, objectId, nonce, root, paddedLen, originalSize, filename }`, where `root` is the canonical 32-byte field representation.

**Compatibility:** The main crate uses `kontor-crypto-core` with Nova’s Poseidon; the WASM crate uses the same core without Nova. Regression tests ensure Poseidon and `prepare_file` output stay compatible when the main crate uses the core with Nova.

**Limitations:** Large files in the browser may hit memory or performance limits; consider size and UX. The WASM build does not use the `asm` optimisations available for `pasta_curves` on native targets.

## CLI & Simulation

The project includes a CLI that simulates storage node operations with heterogeneous file sizes, staggered challenges, and multi-file proof aggregation.

### Usage

From the repo root, run the CLI with `-p kontor-crypto`:

```bash
# Default: small demo (100 files in ledger, node stores 10, 5 challenges)
cargo run -p kontor-crypto

# Large-scale test with memory profiling
cargo run -p kontor-crypto --features memory-profiling -- \
  --total-files-in-ledger 1000 \
  --files-stored-by-node 100 \
  --challenges-to-simulate 20 \
  --profile-memory
```

### Flags

- `--total-files-in-ledger <N>`: Network size (default: 100).
- `--files-stored-by-node <N>`: Files this node stores (default: 10).
- `--challenges-to-simulate <N>`: Challenges to batch (default: 5).
- `--file-size-distribution <TYPE>`: "uniform", "mixed", or "large-heavy" (default: mixed).
- `--no-verify`: Skip verification phase.
- `--profile-memory`: Track peak memory usage.
- `-v`, `-vv`: Increase verbosity (debug/trace).

## Benchmark Suite

Run performance benchmarks with statistical analysis and CI integration via CodSpeed:

```bash
# Run all benchmarks locally
cargo bench

# For CI/CD integration with CodSpeed (optional):
cargo install cargo-codspeed --locked
cargo codspeed build
cargo codspeed run
```

## Development

### Test Suite

Run the extensive unit and integration test suite:

```bash
cargo install cargo-nextest
cargo nextest run
```

### Git Hooks

Enable the pre-push hook to automatically run formatting, clippy, tests, and security audits:

```bash
git config core.hooksPath .githooks
```

### Errors and Failure Modes

Key error variants surfaced at API boundaries (see `KontorPoRError`):

- `InvalidInput`, `InvalidChallengeCount`, `ChallengeMismatch` (e.g., non-uniform `num_challenges` across the batch).
- `FileNotFound`, `FileNotInLedger`, `MetadataMismatch`.
- `MerkleTree`, `Circuit`, `Snark`.
- `Serialization`, `IO`.

## Documentation

- **[Protocol Specification](https://github.com/KontorProtocol/Kontor-Crypto/blob/main/PROTOCOL.md)** - Network protocol, glossary, data types, and challenge lifecycle
- **[Library Architecture](https://github.com/KontorProtocol/Kontor-Crypto/blob/main/ARCHITECTURE.md)** - Implementation details and circuit design
- **[Formal Verification (Picus)](https://github.com/KontorProtocol/Kontor-Crypto/blob/main/docs/formal/README.md)** - Purpose/scope/success criteria + how to run
- **[Determinism Statement](https://github.com/KontorProtocol/Kontor-Crypto/blob/main/docs/formal/determinism.md)** - What Picus is checking (and what it is not)
- **[Component Contracts](https://github.com/KontorProtocol/Kontor-Crypto/blob/main/docs/formal/components.md)** - Component boundaries and interface contract checks
- **[Picus Runbook](https://github.com/KontorProtocol/Kontor-Crypto/blob/main/docs/formal/picus.md)** - Operational details for running Picus here

## Formal Verification (Picus)

Comprehensive formal verification is provided for deterministic underconstraint checks in:
- component sub-circuits built from production gadgets,
- monolithic `PorCircuit` broad production fixtures.

Blocking controls include:
- mutation fixtures expected `unsafe` across all 5 component families,
- a monolithic carry-forward mutant expected `unsafe`,
- fixture-pinned `expected_num_constraints` regression checks during export.

Quick start (Dockerized Picus):

```bash
# sanity-check Dockerized run-picus
tools/picus/check-docker.sh

# run component blocking lane (defaults to component manifest/artifacts)
tools/picus/run.sh --all --scope leafpath --simplify safe
```

If `run-picus` is not on image `PATH`, mount your Picus checkout (the wrapper auto-uses `/Picus/run-picus`):

```bash
PICUS_SOURCE_DIR=/path/to/Picus \
tools/picus/run.sh --all --scope leafpath --simplify safe
```

Canonical export/verify commands (component + monolithic), solver/toolchain notes, and CI profile details are maintained in `docs/formal/picus.md`.
The PyPI package `picus==0.0.5` is unrelated to Veridise Picus and does not support this flow.

Current verification results are tracked in `docs/formal/results.md`.
