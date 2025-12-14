//! Proof verification functionality.
//!
//! This module contains the verification logic with automatic
//! secure root derivation from the ledger.

use super::{
    plan::Plan,
    types::{Challenge, FieldElement, Proof},
};
use crate::{config, ledger::FileLedger, KontorPoRError, Result};
use ff::Field;
use tracing::{debug, info_span};

/// Verifies a proof against one or more challenges.
///
/// This function implements secure verification with historical root validation.
/// Parameters are derived automatically to match the proof structure.
///
/// # Historical Root Validation
///
/// For multi-file proofs (k > 1), this function validates that `proof.ledger_root` is
/// in the ledger's set of valid roots (current or historical). This enables cross-block
/// aggregation: proofs generated against older ledger states remain valid as long as
/// the root is in the historical set.
///
/// The proof includes the ledger indices at proof generation time. The SNARK proves
/// these indices are correct for the claimed root, so the verifier doesn't need to
/// recompute them from the current ledger state.
///
/// For single-file proofs (k = 1), the ledger root check is skipped because the circuit
/// uses the file's Merkle root directly instead of the ledger root.
///
/// # Security
///
/// The SNARK cryptographically proves that:
/// - Each file exists at the claimed index in the tree with the claimed root
/// - The Merkle paths are valid
///
/// A prover cannot lie about indices - invalid indices would cause SNARK verification to fail.
///
/// # Arguments
///
/// * `challenges` - Vector of challenges to verify against
/// * `proof` - The proof to verify (includes ledger_root and ledger_indices)
/// * `ledger` - The file ledger (used for historical root validation, not index computation)
///
/// # Returns
///
/// Returns `Ok(true)` if the proof is valid, `Ok(false)` if invalid, or an error
/// if verification fails due to invalid inputs, invalid ledger root, or unexpected errors.
pub fn verify(challenges: &[Challenge], proof: &Proof, ledger: &FileLedger) -> Result<bool> {
    let _span = info_span!(
        "verify",
        num_challenges = challenges.len(),
        has_ledger = true,
        num_iterations = tracing::field::Empty,
        files_per_step = tracing::field::Empty,
    )
    .entered();

    if challenges.is_empty() {
        return Err(KontorPoRError::InvalidInput(
            "Must provide at least one challenge".to_string(),
        ));
    }

    // Create unified preprocessing plan (derives root internally for security)
    let plan = Plan::make_plan(challenges, ledger)?;

    // Validate proof's ledger_root for multi-file proofs
    // For multi-file proofs (aggregated_tree_depth > 0), the proof's ledger_root must be
    // in the ledger's set of valid roots (current or historical).
    //
    // The proof includes the ledger indices at proof generation time, so we don't need
    // to recompute them from the current ledger state. The SNARK proves the indices
    // are correct for the claimed root.
    //
    // For single-file proofs (aggregated_tree_depth == 0), we skip this check because the
    // circuit uses the file's Merkle root directly, not the ledger root.
    if proof.aggregated_tree_depth > 0 {
        if !ledger.is_valid_root(proof.ledger_root) {
            debug!(
                "Proof ledger_root {:?} is not in ledger's valid roots (current: {:?}, historical count: {})",
                proof.ledger_root,
                ledger.root(),
                ledger.historical_root_count()
            );
            return Err(KontorPoRError::InvalidLedgerRoot {
                proof_root: format!("{:?}", proof.ledger_root),
                reason: "Proof's ledger_root is not in the set of valid historical roots"
                    .to_string(),
            });
        }
        debug!(
            "Proof ledger_root {:?} validated as historical root",
            proof.ledger_root
        );
    }

    // Basic validation
    let num_challenges = challenges[0].num_challenges;
    if num_challenges == 0 || num_challenges > config::MAX_NUM_CHALLENGES {
        return Err(KontorPoRError::InvalidChallengeCount {
            count: num_challenges,
        });
    }

    // Load or generate parameters for the exact shape (same as prover)
    // Use proof.aggregated_tree_depth to ensure we match the prover's circuit
    let params = crate::params::load_or_generate_params(
        plan.files_per_step,
        plan.file_tree_depth,
        proof.aggregated_tree_depth,
    )?;

    debug!(
        "verify() - Using shape: files_per_step={}, file_tree_depth={}, aggregated_tree_depth={}",
        plan.files_per_step, plan.file_tree_depth, proof.aggregated_tree_depth
    );

    // Verify all challenges have the same num_challenges and seed
    for challenge in challenges.iter() {
        if challenge.num_challenges != num_challenges {
            return Err(KontorPoRError::InvalidInput(
                "All challenges must have the same num_challenges for verification".to_string(),
            ));
        }
    }

    // Verify all file depths are within the derived circuit shape bounds
    for challenge in challenges {
        let file_depth = crate::api::tree_depth_from_metadata(&challenge.file_metadata);
        if file_depth > plan.file_tree_depth {
            return Err(KontorPoRError::InvalidInput(format!(
                "File {} depth {} exceeds circuit shape depth {} - circuit cannot handle this file",
                challenge.file_metadata.file_id, file_depth, plan.file_tree_depth
            )));
        }
    }

    // Build public inputs using:
    // - proof.ledger_root and proof.ledger_indices (from proof, enables historical validation)
    // - depths and seeds from plan (derived from challenges)
    debug!("Verify: building z0_primary from proof + challenges");
    debug!("  - Using proof.ledger_root: {:?}", proof.ledger_root);
    debug!("  - Using proof.ledger_indices: {:?}", proof.ledger_indices);
    debug!("  - Depths from challenges: {:?}", plan.depths);

    // Build z0_primary with proof's values for root/indices
    let z0_primary = plan.public_io_layout.build_z0_primary(
        proof.ledger_root,
        &proof.ledger_indices,
        &plan.depths,
        &plan.seeds,
    );
    debug!("VERIFIER z0_primary: {:?}", z0_primary);

    let num_iterations = plan.sorted_challenges[0].num_challenges;

    // Record metrics in span
    tracing::Span::current().record("num_iterations", num_iterations);
    tracing::Span::current().record("files_per_step", plan.files_per_step);

    if proof.aggregated_tree_depth == 0 {
        debug!("verify() - Single-file verification:");
    } else {
        debug!("verify() - Multi-file verification:");
    }
    debug!("  - Number of files: {}", plan.sorted_challenges.len());
    debug!("  - Number of iterations to verify: {}", num_iterations);
    debug!("  - z0_primary[0] aggregated_root: {:?}", proof.ledger_root);
    debug!("  - z0_primary[1] initial_state: {:?}", FieldElement::ZERO);
    for (i, idx) in proof.ledger_indices.iter().enumerate() {
        debug!("  - z0_primary[{}] ledger_index_{}: {}", 2 + i, i, idx);
    }
    for (i, depth) in plan.depths.iter().enumerate() {
        debug!(
            "  - z0_primary[{}] depth_{}: {}",
            2 + plan.files_per_step + i,
            i,
            depth
        );
    }
    for (i, seed) in plan.seeds.iter().enumerate() {
        debug!(
            "  - z0_primary[{}] seed_{}: {:?}",
            2 + plan.files_per_step + plan.files_per_step + i,
            i,
            seed
        );
    }

    let result = proof
        .compressed_snark
        .verify(&params.keys.vk, num_iterations, &z0_primary);

    match result {
        Ok(_) => Ok(true),
        Err(nova_snark::errors::NovaError::ProofVerifyError { reason: _ }) => Ok(false),
        Err(e) => Err(KontorPoRError::Snark(format!(
            "An unexpected error occurred during verification: {e:?}"
        ))),
    }
}
