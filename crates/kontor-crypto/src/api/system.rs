//! PorSystem: Unified API entry point for the Nova-based Proof-of-Retrievability system.
//!
//! This module provides a single, consolidated interface that encapsulates all
//! proving and verification operations, managing dependencies like the FileLedger
//! and parameter caching internally.

use super::types::{Challenge, FileMetadata, PreparedFile, Proof};
use crate::{ledger::FileLedger, KontorPoRError, Result};
use std::collections::BTreeMap;
use tracing::debug;

/// The unified API entry point for the Nova-based Proof-of-Retrievability system.
///
/// PorSystem encapsulates the FileLedger and provides methods for file preparation,
/// proof generation, and verification. It manages parameter caching and shape
/// derivation internally.
pub struct PorSystem<'a> {
    /// Reference to the file ledger containing the aggregated Merkle tree
    ledger: &'a FileLedger,
}

impl<'a> PorSystem<'a> {
    /// Create a new PorSystem with the given FileLedger.
    pub fn new(ledger: &'a FileLedger) -> Self {
        Self { ledger }
    }

    /// Prepare a file for proving by applying erasure coding, chunking, and building a Merkle tree.
    ///
    /// This method uses the fixed chunk size from config::CHUNK_SIZE_BYTES and stores
    /// the filename in the FileMetadata for operator UX.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw file data to be processed
    /// * `erasure_config` - Reed-Solomon erasure coding configuration
    /// * `filename` - Filename for identification and UX
    ///
    /// # Returns
    ///
    /// Returns a tuple of (PreparedFile, FileMetadata) where:
    /// - PreparedFile contains the private Merkle tree and file identifiers
    /// - FileMetadata contains the public commitment and reconstruction information
    pub fn prepare_file(
        &self,
        data: &[u8],
        filename: &str,
        nonce: &[u8],
    ) -> Result<(PreparedFile, FileMetadata)> {
        // Use the existing prepare_file function from mod.rs
        super::prepare_file(data, filename, nonce)
    }

    /// Generate a single compact proof for any set of open Challenges.
    ///
    /// This method accepts a `Vec<PreparedFile>` and internally maps it to the
    /// BTreeMap structure required by the underlying proving logic. Seeds
    /// must be identical across all challenges in the batch.
    ///
    /// # Arguments
    ///
    /// * `files` - Vector of prepared files to prove
    /// * `challenges` - Slice of challenges to answer
    ///
    /// # Returns
    ///
    /// Returns a Proof containing the compressed SNARK and the challenge IDs
    pub fn prove(&self, files: Vec<&PreparedFile>, challenges: &[Challenge]) -> Result<Proof> {
        // Convert Vec<&PreparedFile> to BTreeMap<String, &PreparedFile>
        let mut files_map = BTreeMap::new();
        for file in files {
            if files_map.insert(file.file_id.clone(), file).is_some() {
                return Err(KontorPoRError::InvalidInput(format!(
                    "Duplicate file_id provided: {}",
                    file.file_id
                )));
            }
        }

        // Validate that all files referenced by challenges are present
        for challenge in challenges {
            if !files_map.contains_key(&challenge.file_metadata.file_id) {
                return Err(KontorPoRError::FileNotFound {
                    file_id: challenge.file_metadata.file_id.clone(),
                });
            }
        }

        debug!(
            "PorSystem::prove - {} files, {} challenges",
            files_map.len(),
            challenges.len()
        );

        // Use the existing prove function from prove.rs
        super::prove::prove(challenges, &files_map, self.ledger, None)
    }

    /// Verify a proof against the Challenges it claims to answer.
    ///
    /// This method validates that the proof's challenge_ids exactly match
    /// the provided challenges and then performs SNARK verification.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify
    /// * `challenges` - The challenges that the proof claims to answer
    ///
    /// # Returns
    ///
    /// Returns Ok(true) if the proof is valid, Ok(false) if invalid,
    /// or an error if verification fails unexpectedly.
    pub fn verify(&self, proof: &Proof, challenges: &[Challenge]) -> Result<bool> {
        // Validate that proof.challenge_ids matches the provided challenges
        let expected_ids: Vec<_> = challenges.iter().map(|c| c.id()).collect();

        if proof.challenge_ids.len() != expected_ids.len() {
            return Err(KontorPoRError::InvalidInput(format!(
                "Challenge count mismatch: proof covers {} challenges, provided {}",
                proof.challenge_ids.len(),
                expected_ids.len()
            )));
        }

        // Check that all challenge IDs match (order matters for Nova)
        for (i, (proof_id, expected_id)) in proof
            .challenge_ids
            .iter()
            .zip(expected_ids.iter())
            .enumerate()
        {
            if proof_id != expected_id {
                return Err(KontorPoRError::InvalidInput(format!(
                    "Challenge ID mismatch at position {}: proof has {:?}, expected {:?}",
                    i, proof_id.0, expected_id.0
                )));
            }
        }

        debug!(
            "PorSystem::verify - validated {} challenge IDs",
            challenges.len()
        );

        // Use the existing verify function from verify.rs
        super::verify::verify(challenges, proof, self.ledger)
    }
}
