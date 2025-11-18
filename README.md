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

## Documentation

-   **[Protocol Specification](https://github.com/KontorProtocol/Kontor-Crypto/blob/main/PROTOCOL.md)** - Network protocol, glossary, data types, and challenge lifecycle
-   **[Technical Architecture](https://github.com/KontorProtocol/Kontor-Crypto/blob/main/ARCHITECTURE.md)** - Implementation details and circuit design
-   **[Developer Guide](https://github.com/KontorProtocol/Kontor-Crypto/blob/main/DEVELOPER_GUIDE.md)** - CLI usage, testing, and benchmarking
