//! A high-level, unified API for the Nova-based Proof-of-Retrievability system.
//!
//! This module provides a single, consistent interface for both single-file and multi-file proofs,
//! abstracting away the complexities of the underlying SNARK operations.
//!
//! ## Core Workflow
//!
//! 1. **`prepare_file()`**: Processes raw data into a `PreparedFile` (private to the prover)
//!    and a `FileMetadata` object (public commitment). Data is erasure coded, concatenated,
//!    chunked, and built into a Merkle tree.
//! 2. **`Challenge::new()`**: Creates a challenge object specifying the file to be proven,
//!    the number of proof iterations, deterministic seed, and prover ID.
//! 3. **`prove()`**: Generates a succinct `Proof` for one or more file challenges.
//!    Supports any number of files with automatic padding to the next power of two.
//!    Challenges may have different seeds (enables multi-batch aggregation).
//! 4. **`verify()`**: Verifies the `Proof` against the public `FileMetadata` and `Challenge`.
//!
//! ## Security Considerations
//!
//! - **Challenge Generation**: Leaf indices are derived from a hash by taking the least significant
//!   bits corresponding to the tree depth. This method ensures a uniform, unbiased distribution
//!   of challenges across all leaves.
//! - **Private Data**: The `PreparedFile` struct contains the entire Merkle tree and should be
//!   treated as sensitive, private data by the prover. Leaking it would compromise the zero-knowledge
//!   property of the proof, as it reveals the underlying data.
//! - **Chunk Size**: The `chunk_size` in `prepare_file` must be ≤ 31 bytes, which ensures
//!   each chunk can be represented as a single field element. This constraint is enforced
//!   by the API.
//!
//! ## Example
//!
//! A complete example demonstrating the API workflow:
//!
//! ```rust,no_run
//! use kontor_crypto::api::{
//!     prepare_file, Challenge, FieldElement, PorSystem,
//!     tree_depth_from_metadata,
//! };
//! use kontor_crypto::FileLedger;
//!
//! // 1. Prepare the file (nonce can be user_id, timestamp, or any unique bytes)
//! let my_data = b"This is a test file for the PoR system.";
//! let nonce = b"user_123"; // User-provided nonce for unique file_id
//! let (prepared_file, metadata) = prepare_file(my_data, "test.dat", nonce).unwrap();
//!
//! // 2. Create ledger and add the file
//! let mut ledger = FileLedger::new();
//! ledger.add_file(&metadata).unwrap();
//!
//! // 3. Create PorSystem and challenge
//! let system = PorSystem::new(&ledger);
//! let num_challenges = 5;
//! let seed = FieldElement::from(12345u64); // Deterministic seed
//! let challenge = Challenge::new(metadata.clone(), 1000, num_challenges, seed, String::from("node_1"));
//!
//! // 4. Generate proof using the unified API
//! let files = vec![&prepared_file];
//! let proof = system.prove(files, &[challenge.clone()]).unwrap();
//!
//! // 5. Verify the proof
//! let is_valid = system.verify(&proof, &[challenge]).unwrap();
//! assert!(is_valid, "Proof verification failed!");
//!
//! println!("Proof successfully generated and verified with Nova PoR API.");
//! ```

// Declare sub-modules
mod plan;
mod prove;
mod system;
mod types;
mod verify;
mod witness;

// Re-export the public API
pub use system::PorSystem;
pub use types::{
    Challenge, ChallengeID, FieldElement, FileMetadata, KeyPair, PorParams, PreparedFile, Proof,
};

// Stateless verification: verify a constant-size proof from bare registry data (the
// valid-root set + a `file_id -> (slot, rc)` snapshot) instead of a live `FileLedger`.
// For hosts that keep the file registry in contract storage.
pub use verify::{verify_stateless, LedgerView, StatelessLedger};

// Internal modules can access these for implementation
// Export for testing - these are implementation details
#[doc(hidden)]
pub use verify::verify as verify_raw;
#[doc(hidden)]
pub use witness::generate_circuit_witness;

// Re-export key external types for easier access.
pub use crate::{KontorPoRError, Result};

use tracing::debug_span;

/// Processes raw data into a `PreparedFile` (private) and `FileMetadata` (public).
/// Delegates to `kontor_crypto_core::prepare_file` and converts results to main-crate types.
///
/// Note: This is also available as `PorSystem::prepare_file()` method. The free function
/// is provided for cases where you need to prepare files before creating the ledger.
///
/// # Arguments
///
/// * `data` - The raw data to be processed
/// * `filename` - Filename for operator UX and integration
/// * `nonce` - A user-provided nonce included in the file_id hash. This enables the
///   same data to have different file_ids (e.g., for different users or uploads).
///   The nonce is stored in the returned `FileMetadata`.
///
/// # Returns
///
/// Returns a tuple of `(PreparedFile, FileMetadata)` where:
/// - `PreparedFile` contains the private Merkle tree for the prover
/// - `FileMetadata` contains the public commitment and reconstruction information
///
/// # ID Generation
///
/// - `object_id = object_<SHA256(data)>` - content-based, not unique, for file discovery
/// - `file_id = file_<SHA256(domain || len(data) || data || len(nonce) || nonce)>`
///   - unique per upload, for storage protocol
pub fn prepare_file(
    data: &[u8],
    filename: &str,
    nonce: &[u8],
) -> Result<(types::PreparedFile, types::FileMetadata)> {
    let _span = debug_span!("prepare_file", data_size = data.len(), filename).entered();

    let (core_pf, core_metadata) = kontor_crypto_core::prepare_file(data, filename, nonce)?;

    Ok((core_pf.into(), core_metadata.into()))
}

/// Computes the Merkle tree depth implied by `FileMetadata`.
///
/// Depth is defined as the number of sibling steps from a leaf to the root.
/// For `padded_len` leaves, `depth = log2(padded_len)`.
pub fn tree_depth_from_metadata(metadata: &types::FileMetadata) -> usize {
    metadata.depth()
}

/// Reconstructs the original file from erasure-coded shards.
/// Delegates to `kontor_crypto_core::reconstruct_file` with metadata converted to core type.
///
/// # Arguments
///
/// * `shards` - Vector of shards where `None` represents missing shards
/// * `metadata` - The file metadata containing erasure config and size information
///
/// # Returns
///
/// Returns `Ok(Vec<u8>)` containing the original file data, or an error if:
/// - Too many shards are missing for reconstruction
/// - The reconstructed data is invalid
/// - The metadata is inconsistent
///
/// # Example
///
/// ```rust,no_run
/// use kontor_crypto::api::{prepare_file, reconstruct_file};
///
/// let data = b"Hello, world!";
/// let (prepared_file, metadata) = prepare_file(data, "example.dat", b"").unwrap();
///
/// // Simulate having some symbols with some missing (for reconstruction testing)
/// // In practice, you'd get these from the prepared_file or from storage
/// // Each symbol is a 31-byte chunk of the Reed-Solomon encoded data
/// let total_symbols = metadata.total_symbols();
/// let mut symbols: Vec<Option<Vec<u8>>> = (0..total_symbols)
///     .map(|_| Some(vec![0u8; 31])) // Placeholder symbols
///     .collect();
/// symbols[0] = None; // Simulate missing first symbol
///
/// let reconstructed = reconstruct_file(&symbols, &metadata).unwrap();
/// // Note: This example uses placeholder data, so reconstructed won't match original
/// ```
pub fn reconstruct_file(
    symbols: &[Option<Vec<u8>>],
    metadata: &types::FileMetadata,
) -> Result<Vec<u8>> {
    let core_metadata: kontor_crypto_core::types::FileMetadata = metadata.into();
    Ok(kontor_crypto_core::reconstruct_file(
        symbols,
        &core_metadata,
    )?)
}
