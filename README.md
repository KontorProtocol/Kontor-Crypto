# Kontor Proof-of-Retrievability (PoR)

[![Crates.io](https://img.shields.io/crates/v/kontor-crypto.svg)](https://crates.io/crates/kontor-crypto)
[![CI](https://github.com/KontorProtocol/Kontor-Crypto/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/KontorProtocol/Kontor-Crypto/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/KontorProtocol/Kontor-Crypto/blob/main/LICENSE)

> **⚠️ WARNING: This code is unaudited and experimental. Use at your own risk.**

This project implements a Proof-of-Retrievability (PoR) system designed to provide economically enforceable guarantees that Storage Nodes are actually storing the data they have committed to. It is a core component for decentralized storage metaprotocols where a network of Indexers (Verifiers) must continuously audit Storage Nodes (Provers).

The system uses [Nova](https://eprint.iacr.org/2021/370) recursive SNARKs via Microsoft's [`nova-snark`](https://github.com/microsoft/Nova) library to generate constant-size (~10 kB) cryptographic proofs that a prover possesses a specific set of data. These proofs are efficient to verify (~30ms), making it feasible to enforce storage guarantees at scale.

## Core Capabilities

-   Partition files into fixed 31-byte symbols for direct field element encoding.
-   Apply multi-codeword Reed-Solomon (GF(2^8)) for fault tolerance.
-   Generate Poseidon Merkle trees over all symbols (data + parity).
-   Create recursive SNARKs proving possession of randomly sampled symbols.
-   Compress proofs to constant ~10 kB size regardless of file count or challenge count.
-   Support dynamic circuit parameters with in-memory caching.
-   Reconstruct original files from partial symbol availability (≥90% per codeword).

## Performance Characteristics

-   **Proof Size:** ~10 kB (constant across challenge count and file set within a shape).
-   **Verification Time:** ~30 ms for compressed SNARK verification.
-   **Proving Time:** Approximately linear in the number of recursive steps.

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
ledger.add_file(metadata.file_id.clone(), metadata.root, tree_depth_from_metadata(&metadata)).unwrap();

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

## CLI & Simulation

The project includes a CLI that serves as a **Storage Node Simulator** to demonstrate the system at scale. It simulates storage node operations with heterogeneous file sizes, staggered challenges, and multi-file proof aggregation.

### Usage

```bash
# Default: small demo (100 files in ledger, node stores 10, 5 challenges)
cargo run --release

# Realistic scenario with many files
cargo run --release -- --files-stored-by-node 50

# Large-scale test with memory profiling
cargo run --release --features memory-profiling -- \
  --total-files-in-ledger 1000 \
  --files-stored-by-node 100 \
  --challenges-to-simulate 20 \
  --profile-memory
```

### Flags

-   `--total-files-in-ledger <N>`: Network size (default: 100).
-   `--files-stored-by-node <N>`: Files this node stores (default: 10).
-   `--challenges-to-simulate <N>`: Challenges to batch (default: 5).
-   `--file-size-distribution <TYPE>`: "uniform", "mixed", or "large-heavy" (default: mixed).
-   `--no-verify`: Skip verification phase.
-   `--profile-memory`: Track peak memory usage.
-   `-v`, `-vv`: Increase verbosity (debug/trace).

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

**Benchmark Groups:**
- **Primitives**: Poseidon hashing, Merkle tree operations, erasure coding
- **File Preparation**: Encoding across protocol file sizes (10KB - 100MB)
- **Single-File Proving**: Various file sizes × challenge counts
- **Multi-File Aggregation**: 1, 2, 4, 8 files (demonstrates constant proof size)
- **Verification**: Constant-time verification across file counts
- **E2E Workflows**: Complete prepare → prove → verify cycles

All benchmarks align with protocol parameters from the specification (file sizes, challenge counts, tree depths).

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

-   `InvalidInput`, `InvalidChallengeCount`, `ChallengeMismatch` (e.g., non-uniform `num_challenges` across the batch).
-   `FileNotFound`, `FileNotInLedger`, `MetadataMismatch`.
-   `MerkleTree`, `Circuit`, `Snark`.
-   `Serialization`, `IO`.

## Documentation

-   **[Protocol Specification](https://github.com/KontorProtocol/Kontor-Crypto/blob/main/PROTOCOL.md)** - Network protocol, glossary, data types, and challenge lifecycle
-   **[Technical Architecture](https://github.com/KontorProtocol/Kontor-Crypto/blob/main/ARCHITECTURE.md)** - Implementation details and circuit design
