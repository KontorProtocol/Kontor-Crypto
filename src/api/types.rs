//! Core API data types and structures.
//!
//! This module contains the public data structures used by the API:
//! - FileMetadata: Public commitment to a file
//! - PreparedFile: Prover's private representation  
//! - Challenge: Verifier's challenge request
//! - Proof: Final succinct proof object
//! - PorParams: Cryptographic parameters

use bincode::Options;
use nova_snark::{
    nova::{CompressedSNARK, ProverKey, PublicParams, VerifierKey},
    provider::{ipa_pc, PallasEngine, VestaEngine},
    spartan::snark::RelaxedR1CSSNARK,
    traits::Engine,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

// --- Type Aliases for Core SNARK Components ---

type E1 = PallasEngine;
type E2 = VestaEngine;
type EE1 = ipa_pc::EvaluationEngine<E1>;
type EE2 = ipa_pc::EvaluationEngine<E2>;
type S1 = RelaxedR1CSSNARK<E1, EE1>;
type S2 = RelaxedR1CSSNARK<E2, EE2>;

/// A type alias for the scalar field of the primary curve.
pub type FieldElement = <E1 as Engine>::Scalar;

type C = crate::circuit::PorCircuit<FieldElement>;

/// Deterministic identity for a Challenge.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChallengeID(pub [u8; 32]);

/// The final, succinct proof object that is sent to the verifier.
#[derive(Serialize, Deserialize)]
pub struct Proof {
    /// The compressed SNARK proof
    pub compressed_snark: CompressedSNARK<E1, E2, C, S1, S2>,
    /// Exact ordered set of challenges covered by this proof
    pub challenge_ids: Vec<ChallengeID>,
}

/// Constants for proof serialization format
mod proof_format {
    /// Magic bytes identifying Nova PoR proof format
    pub const MAGIC: &[u8] = b"NPOR";

    /// Current format version for forward compatibility
    pub const VERSION: u16 = 1;

    /// Header size in bytes: magic(4) + version(2) + length(4)
    pub const HEADER_SIZE: usize = 10;
}

impl Proof {
    /// Serialize this proof to bytes for network transport.
    ///
    /// The format includes a magic number, version, and the proof data.
    /// This provides a stable, versioned format for cross-network compatibility.
    ///
    /// # Returns
    ///
    /// Returns the serialized proof as bytes, or an error if serialization fails.
    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        use crate::KontorPoRError;

        let mut result = Vec::new();

        // Write magic and version
        result.extend_from_slice(proof_format::MAGIC);
        result.extend_from_slice(&proof_format::VERSION.to_le_bytes());

        // Serialize the proof using pinned bincode options so the wire format
        // stays stable even if bincode's defaults change in the future.
        let options = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian()
            .reject_trailing_bytes();
        let proof_bytes = options.serialize(self).map_err(|e| {
            KontorPoRError::Serialization(format!("Failed to serialize proof: {}", e))
        })?;

        // Write length and data
        let length = proof_bytes.len() as u32;
        result.extend_from_slice(&length.to_le_bytes());
        result.extend_from_slice(&proof_bytes);

        Ok(result)
    }

    /// Deserialize a proof from bytes.
    ///
    /// This function validates the magic number and version before deserializing
    /// the proof data. It provides forward compatibility for future format versions.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The serialized proof bytes
    ///
    /// # Returns
    ///
    /// Returns the deserialized Proof, or an error if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        use crate::KontorPoRError;

        if bytes.len() < proof_format::HEADER_SIZE {
            return Err(KontorPoRError::Serialization(
                "Proof bytes too short for header".to_string(),
            ));
        }

        // Check magic bytes
        let magic = &bytes[0..4];
        if magic != proof_format::MAGIC {
            return Err(KontorPoRError::Serialization(
                "Invalid magic bytes in proof".to_string(),
            ));
        }

        // Check version
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != proof_format::VERSION {
            return Err(KontorPoRError::Serialization(format!(
                "Unsupported proof format version: {}",
                version
            )));
        }

        // Read length
        let length = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;

        let expected_len = proof_format::HEADER_SIZE + length;
        if bytes.len() < expected_len {
            return Err(KontorPoRError::Serialization(
                "Proof bytes truncated".to_string(),
            ));
        }

        if bytes.len() > expected_len {
            return Err(KontorPoRError::Serialization(
                "Proof bytes contain trailing data".to_string(),
            ));
        }

        // Deserialize the proof
        let proof_bytes = &bytes[proof_format::HEADER_SIZE..expected_len];
        let options = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian()
            .reject_trailing_bytes();
        let proof = options.deserialize(proof_bytes).map_err(|e| {
            KontorPoRError::Serialization(format!("Failed to deserialize proof: {}", e))
        })?;

        Ok(proof)
    }
}

// --- Public API Structs ---

#[derive(Clone)]
pub struct KeyPair {
    pub(crate) pk: Arc<ProverKey<E1, E2, C, S1, S2>>,
    pub(crate) vk: Arc<VerifierKey<E1, E2, C, S1, S2>>,
}

/// Holds the universal, reusable cryptographic parameters for the PoR scheme.
/// This struct is opaque and does not expose the complex internal types.
pub struct PorParams {
    pub(crate) pp: Arc<PublicParams<E1, E2, C>>,
    pub(crate) keys: KeyPair,
    /// Shape depth for this parameter set (exact-fit to the circuit)
    pub file_tree_depth: usize,
    /// Maximum file tree depth these params support (gating depth)
    pub max_supported_depth: usize,
    /// Declared aggregated tree depth (0 for single-file params)
    pub aggregated_tree_depth: usize,
}

impl Clone for PorParams {
    fn clone(&self) -> Self {
        Self {
            pp: Arc::clone(&self.pp),
            keys: self.keys.clone(),
            file_tree_depth: self.file_tree_depth,
            max_supported_depth: self.max_supported_depth,
            aggregated_tree_depth: self.aggregated_tree_depth,
        }
    }
}

/// The public commitment to a file, which is shared with verifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMetadata {
    /// The Merkle root over all symbols (data + parity)
    pub root: FieldElement,
    /// SHA256 hash of the original file for identification
    pub file_id: String,
    /// The total number of leaves in the Merkle tree (padded to power of 2)
    pub padded_len: usize,
    /// Size of original file in bytes (for reconstruction)
    pub original_size: usize,
    /// Filename for operator UX and integration
    pub filename: String,
}

impl FileMetadata {
    /// Number of data symbols (31-byte chunks from original file).
    pub fn num_data_symbols(&self) -> usize {
        self.original_size.div_ceil(crate::config::CHUNK_SIZE_BYTES)
    }

    /// Number of RS codewords.
    pub fn num_codewords(&self) -> usize {
        self.num_data_symbols()
            .div_ceil(crate::config::DATA_SYMBOLS_PER_CODEWORD)
    }

    /// Total symbols including parity (num_codewords × 255).
    pub fn total_symbols(&self) -> usize {
        self.num_codewords() * crate::config::TOTAL_SYMBOLS_PER_CODEWORD
    }

    /// Computes the Merkle tree depth from padded_len.
    /// Depth is log2(padded_len), assuming padded_len is a power of 2.
    pub fn depth(&self) -> usize {
        if self.padded_len == 0 {
            0
        } else {
            self.padded_len.trailing_zeros() as usize
        }
    }
}

impl From<&FileMetadata> for crate::ledger::AddFileInput {
    fn from(metadata: &FileMetadata) -> Self {
        crate::ledger::AddFileInput {
            file_id: metadata.file_id.clone(),
            root: metadata.root,
            depth: metadata.depth(),
        }
    }
}

/// The prover's representation of a file, containing the full Merkle tree.
#[derive(Debug, Clone)]
pub struct PreparedFile {
    /// The full Merkle tree structure held by the prover
    pub(crate) tree: crate::merkle::MerkleTree,
    /// SHA256 hash of the original file for identification
    pub file_id: String,
    /// The Merkle root for quick access
    pub root: FieldElement,
}

/// Encapsulates a verifier's challenge request for a specific file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// The public metadata of the file being challenged.
    pub file_metadata: FileMetadata,
    /// The block height when this challenge was created.
    pub block_height: u64,
    /// The number of proof iterations requested.
    pub num_challenges: usize,
    /// A deterministic seed used to generate challenges.
    pub seed: FieldElement,
    /// Identifier of the Storage Node being challenged
    pub prover_id: String,
}

impl Challenge {
    /// Create a new challenge for a file
    pub fn new(
        file_metadata: FileMetadata,
        block_height: u64,
        num_challenges: usize,
        seed: FieldElement,
        prover_id: String,
    ) -> Self {
        Self {
            file_metadata,
            block_height,
            num_challenges,
            seed,
            prover_id,
        }
    }

    /// Create a challenge with default test prover ID (convenience for testing)
    #[doc(hidden)]
    pub fn new_test(
        file_metadata: FileMetadata,
        block_height: u64,
        num_challenges: usize,
        seed: FieldElement,
    ) -> Self {
        Self::new(
            file_metadata,
            block_height,
            num_challenges,
            seed,
            String::from("test_prover"),
        )
    }

    /// Compute the deterministic ID for this challenge
    pub fn id(&self) -> ChallengeID {
        use crate::poseidon::domain_tags;
        use ff::PrimeField;

        let mut hasher = Sha256::new();

        // Add domain tag for challenge ID
        let tag: FieldElement = domain_tags::challenge_id();
        hasher.update(tag.to_repr());

        // Add block height
        hasher.update(self.block_height.to_le_bytes());

        // Add seed (field element as bytes)
        hasher.update(self.seed.to_repr());

        // Add file metadata components
        hasher.update(self.file_metadata.file_id.as_bytes());
        hasher.update(self.file_metadata.root.to_repr());
        hasher.update((self.file_metadata.padded_len.trailing_zeros() as u64).to_le_bytes()); // depth

        // Add num_challenges
        hasher.update((self.num_challenges as u64).to_le_bytes());

        // Add prover_id
        hasher.update(self.prover_id.as_bytes());

        let result = hasher.finalize();
        ChallengeID(result.into())
    }
}
