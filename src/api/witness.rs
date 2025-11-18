//! Circuit witness generation functionality.
//!
//! This module contains all the logic for creating properly structured
//! circuit witnesses for both real files and padding.

use super::types::{Challenge, FieldElement, PreparedFile};
use crate::{
    circuit::{CircuitWitness, FileProofWitness},
    commitment::{domain_tags, poseidon_hash_tagged},
    config, get_padded_proof_for_leaf,
    ledger::FileLedger,
    KontorPoRError, Result,
};
use ff::Field;
use std::collections::BTreeMap;
use tracing::{debug, debug_span};

/// Generates a properly structured CircuitWitness with guaranteed padding.
///
/// This is the SINGLE SOURCE OF TRUTH for creating circuit witness data.
/// It ensures that the witness structure is always correct, with exactly
/// the required number of witnesses (real files + padding to next power of two).
///
/// ## Guarantees
///
/// - Returns exactly `next_power_of_two(num_files)` witnesses
/// - Real file witnesses come first, followed by padding witnesses
/// - All padding witnesses have `actual_depth: 0`
/// - The structure is uniform and suitable for Nova's folding requirements
///
/// ## Special Cases
///
/// - Single-file proofs (aggregated_tree_depth == 0): Returns 1 witness
/// - Multi-file proofs: Returns next_power_of_two(num_files) witnesses
///
/// # Arguments
///
/// * `sorted_challenges` - Challenges sorted by file hash for deterministic ordering
/// * `files` - Map of file hashes to PreparedFile data (None for dummy witnesses)
/// * `ledger` - Optional file ledger containing the aggregated tree
/// * `params` - The public parameters
/// * `current_state` - The current state in the hash chain
/// * `aggregated_tree_depth` - Depth of the aggregated tree (0 for single-file)
/// * `step_num` - The current step number (for debugging)
///
/// # Returns
///
/// Returns a tuple of (CircuitWitness, new_state) where:
/// - `CircuitWitness` is the properly structured witness data
/// - `new_state` is the updated state after processing all files
#[allow(clippy::too_many_arguments)]
pub fn generate_circuit_witness(
    sorted_challenges: &[&Challenge],
    files: Option<&BTreeMap<String, &PreparedFile>>,
    ledger: &FileLedger,
    file_tree_depth: usize,     // Shape depth for uniform structure
    max_supported_depth: usize, // Maximum actual depth supported
    current_state: FieldElement,
    aggregated_tree_depth: usize,
    step_num: usize,
    precomputed_ledger_indices: &[usize], // Pass precomputed indices to ensure consistency
) -> Result<(CircuitWitness<FieldElement>, FieldElement)> {
    let _span = debug_span!(
        "generate_circuit_witness",
        step_num,
        num_challenges = sorted_challenges.len(),
        has_files = files.is_some()
    )
    .entered();

    let mut file_witnesses = Vec::new();
    let mut local_state = current_state;

    debug!("generate_circuit_witness - Step {}:", step_num);
    debug!("  - Input state: {:?}", current_state);
    debug!("  - Processing {} challenges", sorted_challenges.len());
    debug!("  - Aggregated tree depth: {}", aggregated_tree_depth);

    // Process real file challenges
    if let Some(files) = files {
        for (file_idx, challenge) in sorted_challenges.iter().enumerate() {
            let file = files.get(&challenge.file_metadata.file_id).ok_or_else(|| {
                KontorPoRError::InvalidInput(format!(
                    "File {} not found",
                    challenge.file_metadata.file_id
                ))
            })?;

            let (witness, new_state) = create_single_file_witness(
                challenge,
                file,
                file_idx,
                local_state,
                file_tree_depth,
                aggregated_tree_depth,
                ledger,
                precomputed_ledger_indices,
            )?;

            file_witnesses.push(witness);
            local_state = new_state;
        }
    } else {
        // Dummy witnesses for parameter generation
        // Create "worst-case" dummy witnesses with varied depths
        let num_dummies = sorted_challenges.len().max(1);
        for i in 0..num_dummies {
            let mut dummy_witness = create_padding_witness(file_tree_depth, aggregated_tree_depth);
            // Alternate between max depth and 0 for robustness testing
            if i == 0 {
                dummy_witness.actual_depth = max_supported_depth;
            }
            file_witnesses.push(dummy_witness);
        }
    }

    // Count real files as the original number of challenges (before padding)
    // Note: Minimal depth files (depth 1 with erasure (1,1)) are still real files
    let num_real_files = if let Some(_files) = files {
        sorted_challenges.len() // All challenges represent real files
    } else {
        // For parameter generation, count dummy witnesses with depth > 0
        file_witnesses.iter().filter(|w| w.actual_depth > 0).count()
    };

    // Determine target witness count based on exact shape
    // For exact shape, we use derive_shape to get the right count
    let (target_witness_count, _) =
        config::derive_shape(sorted_challenges.len(), max_supported_depth);

    // Pad with null witnesses to reach target count
    while file_witnesses.len() < target_witness_count {
        file_witnesses.push(create_padding_witness(
            file_tree_depth,
            aggregated_tree_depth,
        ));
    }

    // Ensure we have exactly the expected number of witnesses
    assert_eq!(
        file_witnesses.len(),
        target_witness_count,
        "CircuitWitness must have exactly {} witnesses, got {}",
        target_witness_count,
        file_witnesses.len()
    );

    debug!("generate_circuit_witness complete:");
    debug!("  - Real files: {}", num_real_files);
    debug!("  - Total witnesses: {}", file_witnesses.len());
    debug!("  - Output state: {:?}", local_state);

    // Create the CircuitWitness with guaranteed structure
    let circuit_witness = CircuitWitness {
        witnesses: file_witnesses,
        num_real_files,
    };

    Ok((circuit_witness, local_state))
}

/// Create a witness for a single file challenge.
#[allow(clippy::too_many_arguments)]
fn create_single_file_witness(
    challenge: &Challenge,
    file: &PreparedFile,
    file_idx: usize,
    current_state: FieldElement,
    file_tree_depth: usize,
    aggregated_tree_depth: usize,
    ledger: &FileLedger,
    precomputed_ledger_indices: &[usize],
) -> Result<(FileProofWitness<FieldElement>, FieldElement)> {
    let file_depth = file.tree.layers.len() - 1;

    // Calculate leaf index with proper domain separation
    let challenge_hash =
        poseidon_hash_tagged(domain_tags::challenge(), challenge.seed, current_state);
    let hash = if aggregated_tree_depth > 0 {
        // Multi-file: use domain-separated hash to combine challenge with file_idx
        poseidon_hash_tagged(
            domain_tags::challenge_per_file(),
            challenge_hash,
            FieldElement::from(file_idx as u64),
        )
    } else {
        // Single-file: use challenge directly
        challenge_hash
    };
    let leaf_index = crate::utils::derive_index_unbiased(hash, 1usize << file_depth);

    // Get proof padded to MAX depth for circuit uniformity
    let merkle_proof = get_padded_proof_for_leaf(&file.tree, leaf_index, file_tree_depth)?;

    // Get aggregation proof for this file
    let agg_proof = if aggregated_tree_depth > 0 {
        // Multi-file case: get actual aggregation proof
        ledger
            .get_aggregation_proof(&challenge.file_metadata.file_id)
            .ok_or_else(|| KontorPoRError::InvalidInput("File not found in ledger".to_string()))?
    } else {
        // Single-file case: empty aggregation proof
        crate::merkle::CircuitMerkleProof {
            leaf: FieldElement::ZERO,
            siblings: vec![],
            path_indices: vec![],
        }
    };

    // Use precomputed ledger index
    let ledger_index = precomputed_ledger_indices[file_idx];

    let witness = FileProofWitness {
        leaf: merkle_proof.leaf,
        file_siblings: merkle_proof.siblings,
        file_root: challenge.file_metadata.root,
        actual_depth: file_depth,
        agg_siblings: agg_proof.siblings,
        ledger_index,
    };

    // Update state for next file with domain separation
    let new_state = poseidon_hash_tagged(
        domain_tags::state_update(),
        current_state,
        merkle_proof.leaf,
    );

    Ok((witness, new_state))
}

/// Create a padding witness for circuit uniformity.
fn create_padding_witness(
    file_tree_depth: usize,
    aggregated_tree_depth: usize,
) -> FileProofWitness<FieldElement> {
    FileProofWitness {
        leaf: FieldElement::ZERO,
        file_siblings: vec![FieldElement::ZERO; file_tree_depth],
        file_root: FieldElement::ZERO,
        actual_depth: 0, // Padding witnesses have no depth
        agg_siblings: vec![FieldElement::ZERO; aggregated_tree_depth],
        ledger_index: 0,
    }
}
