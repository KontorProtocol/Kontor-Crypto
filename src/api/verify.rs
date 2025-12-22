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
/// This function implements the Option 1 security model verification with proper ledger root pinning.
/// Parameters are derived automatically to match the proof structure.
///
/// # Security: Ledger Root Pinning
///
/// **SECURE**: The expected aggregated root is derived from the provided `ledger` automatically.
/// This prevents malicious provers from substituting a different ledger with a different root.
///
/// - Single-file: Uses the file root from the challenge metadata
/// - Multi-file: Uses the canonical ledger root from the ledger
///
/// # Public Inputs Verification
///
/// The verifier reconstructs the same public inputs as the prover:
/// - `aggregated_root`: Derived automatically from the ledger
/// - `ledger_index_0, ..., ledger_index_{F-1}`: Canonical positions in ledger
/// - `actual_depth_0, ..., actual_depth_{F-1}`: Depths computed from challenge metadata
///
/// # Arguments
///
/// * `challenges` - Vector of challenges to verify against
/// * `proof` - The proof to verify
/// * `ledger` - The file ledger containing the file(s) being verified
///
/// # Returns
///
/// Returns `Ok(true)` if the proof is valid, `Ok(false)` if invalid, or an error
/// if verification fails due to invalid inputs or unexpected errors.
pub fn verify(challenges: &[Challenge], proof: &Proof, ledger: &FileLedger) -> Result<bool> {
    let _span = info_span!(
        "verify",
        num_challenges = challenges.len(),
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

    // Basic validation
    let num_challenges = challenges[0].num_challenges;
    if num_challenges == 0 || num_challenges > config::MAX_NUM_CHALLENGES {
        return Err(KontorPoRError::InvalidChallengeCount {
            count: num_challenges,
        });
    }

    // Load or generate parameters for the exact shape (same as prover)
    let params = crate::params::load_or_generate_params(
        plan.files_per_step,
        plan.file_tree_depth,
        plan.aggregated_tree_depth,
    )?;

    debug!(
        "verify() - Using shape: files_per_step={}, file_tree_depth={}, aggregated_tree_depth={}",
        plan.files_per_step, plan.file_tree_depth, plan.aggregated_tree_depth
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

    // All preprocessing is now handled by the plan (eliminates duplication with prove)
    debug!("Verify commitment calculation (from plan):");
    debug!(
        "  - Number of sorted challenges: {}",
        plan.sorted_challenges.len()
    );
    debug!("  - Depths: {:?}", plan.depths);

    // Build public inputs using the plan
    let z0_primary = plan.build_z0_primary();
    debug!("VERIFIER z0_primary: {:?}", z0_primary);

    // In our implementation:
    // - RecursiveSNARK::new() executes step 0
    // - We call prove_step num_challenges times, but the first call is a no-op
    // - So we have num_challenges total synthesized steps (0 through num_challenges-1)
    let num_iterations = plan.sorted_challenges[0].num_challenges;

    // Record metrics in span
    tracing::Span::current().record("num_iterations", num_iterations);
    tracing::Span::current().record("files_per_step", plan.files_per_step);

    if plan.aggregated_tree_depth == 0 {
        debug!("verify() - Single-file verification:");
    } else {
        debug!("verify() - Multi-file verification:");
    }
    debug!("  - Number of files: {}", plan.sorted_challenges.len());
    debug!("  - Number of iterations to verify: {}", num_iterations);
    debug!(
        "  - z0_primary[0] aggregated_root: {:?}",
        plan.aggregated_root
    );
    debug!("  - z0_primary[1] initial_state: {:?}", FieldElement::ZERO);
    for (i, idx) in plan.ledger_indices.iter().enumerate() {
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
