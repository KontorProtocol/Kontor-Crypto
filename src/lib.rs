//! Kontor Proof-of-Retrievability (PoR) library
//!
//! This library provides a unified Proof-of-Retrievability system using Nova recursive SNARKs.
//! It supports both single-file and multi-file proofs through a consistent API.
//!
//! ## Main Components
//!
//! - [`api`]: High-level unified API for single and multi-file proofs
//! - [`merkle`]: Merkle tree implementation with Poseidon hashing
//! - [`erasure`]: Reed-Solomon erasure coding for fault tolerance
//! - [`circuit`]: Unified Nova circuit supporting dynamic numbers of files
//! - [`ledger`]: File ledger for multi-file aggregation
//! - [`config`]: Centralized configuration constants
//!
//! ## Error Handling
//!
//! This library uses `Result` types for robust error handling. Core functions return
//! `Result<T, KontorPoRError>` to provide detailed error information:
//!
//! - `prepare_file()` returns `Result<(PreparedFile, FileMetadata), KontorPoRError>`
//! - `reconstruct_file()` returns `Result<Vec<u8>, KontorPoRError>`
//! - `build_tree()` returns `Result<(MerkleTree, F), KontorPoRError>`
//! - `get_padded_proof_for_leaf()` returns `Result<CircuitMerkleProof, KontorPoRError>`
//!
//! ## Quick Start
//!
//! ### Basic Usage
//! ```rust,no_run
//! use kontor_crypto::{api::{self, PorSystem}, FileLedger, KontorPoRError};
//!
//! // 1. Prepare file with Reed-Solomon erasure coding (fixed 31-byte symbols)
//! let data = b"Hello, world! This is test data for Nova PoR.";
//! let (prepared, metadata) = api::prepare_file(data, "test.dat")?;
//!
//! // 2. Create ledger and add the file
//! let mut ledger = FileLedger::new();
//! ledger.add_file(&metadata)?;
//!
//! // 3. Create PorSystem and generate proof
//! let system = PorSystem::new(&ledger);
//! let challenge = api::Challenge::new(metadata.clone(), 1000, 3, api::FieldElement::from(42u64), String::from("node_1"));
//! let proof = system.prove(vec![&prepared], &[challenge.clone()])?;
//!
//! // 4. Verify the proof
//! let is_valid = system.verify(&proof, &[challenge])?;
//! assert!(is_valid);
//! # Ok::<(), KontorPoRError>(())
//! ```
//!
//! ### Multi-File Proof
//! ```rust,no_run
//! use kontor_crypto::{api::{self, PorSystem}, FileLedger, KontorPoRError};
//!
//! // 1. Prepare multiple files
//! let (prepared1, metadata1) = api::prepare_file(b"File 1 content", "file1.dat")?;
//! let (prepared2, metadata2) = api::prepare_file(b"File 2 content", "file2.dat")?;
//!
//! // 2. Build ledger
//! let mut ledger = FileLedger::new();
//! ledger.add_file(&metadata1)?;
//! ledger.add_file(&metadata2)?;
//!
//! // 3. Create challenges and prove (different seeds supported for multi-batch aggregation)
//! let system = PorSystem::new(&ledger);
//! let challenges = vec![
//!     api::Challenge::new(metadata1.clone(), 1000, 2, api::FieldElement::from(42u64), String::from("node_1")),
//!     api::Challenge::new(metadata2.clone(), 1001, 2, api::FieldElement::from(43u64), String::from("node_1")),
//! ];
//!
//! let files = vec![&prepared1, &prepared2];
//! let proof = system.prove(files, &challenges)?;
//! let is_valid = system.verify(&proof, &challenges)?;
//! assert!(is_valid);
//! # Ok::<(), KontorPoRError>(())
//! ```

pub mod api;
pub mod circuit;
pub mod circuit_safety;
pub mod config;
pub mod erasure;
pub mod error;
pub mod ledger;
pub mod merkle;
pub mod params;
pub mod poseidon;
pub mod utils;

// Re-export commonly used types and functions for convenience
pub use api::{prepare_file, reconstruct_file, tree_depth_from_metadata, PorSystem};
pub use api::{Challenge, FieldElement, FileMetadata, PorParams, PreparedFile, Proof};
pub use circuit::{CircuitWitness, FileProofWitness, PorCircuit};
pub use error::{KontorPoRError, Result};
pub use ledger::FileLedger;
pub use merkle::{
    build_tree, build_tree_from_leaves, get_leaf_hash, get_padded_proof_for_leaf, hash_leaf_data,
    hash_node, verify_merkle_proof_in_place, CircuitMerkleProof, MerkleTree,
};
pub use utils::{derive_index_from_bits, leaf_to_bytes31};
