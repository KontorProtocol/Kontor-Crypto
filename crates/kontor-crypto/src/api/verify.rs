//! Proof verification functionality.
//!
//! This module contains the verification logic with automatic
//! secure root derivation from the ledger.

use super::{
    plan::Plan,
    types::{Challenge, FieldElement, Proof},
};
use crate::{config, ledger::FileLedger, KontorPoRError, Result};
use ff::PrimeField;
use std::collections::HashSet;
use tracing::{debug, info_span};

/// What proof verification needs from "the ledger". Verification consumes
/// `proof.ledger_root` and `proof.ledger_indices` as the circuit's public inputs,
/// so it never needs the live aggregated Merkle tree — only the set of valid
/// aggregated roots. This lets verification run either against a full
/// [`FileLedger`] (the prover's view) or against bare data held elsewhere — e.g. a
/// contract's own storage — via [`StatelessLedger`].
pub trait LedgerView {
    /// Whether `root` is an accepted aggregated ledger root (current or historical).
    fn is_valid_root(&self, root: FieldElement) -> bool;

    /// Per-file metadata binding: confirm the challenged file is registered with a
    /// root-commitment matching the challenge's claimed metadata. The default
    /// accepts — for a view that *is* the registry (a contract that builds
    /// challenges from its own storage), this cross-check is vacuous, and "is the
    /// file registered?" is enforced by the caller before verification.
    fn check_registered(&self, _file_id: &str, _expected_rc: FieldElement) -> Result<()> {
        Ok(())
    }
}

impl LedgerView for FileLedger {
    fn is_valid_root(&self, root: FieldElement) -> bool {
        FileLedger::is_valid_root(self, root)
    }
    fn check_registered(&self, file_id: &str, expected_rc: FieldElement) -> Result<()> {
        match self.files.get(file_id).map(|entry| entry.rc) {
            None => Err(KontorPoRError::FileNotInLedger {
                file_id: file_id.to_string(),
            }),
            Some(actual_rc) if actual_rc != expected_rc => Err(KontorPoRError::MetadataMismatch),
            Some(_) => Ok(()),
        }
    }
}

/// A [`LedgerView`] backed by plain data instead of a live [`FileLedger`]: just the
/// set of valid aggregated roots. That is exactly the data a contract holds in its
/// own storage once the file registry moves in-contract, so the host can verify
/// proofs without maintaining an accumulator. The per-file metadata cross-check is
/// skipped (see [`LedgerView::check_registered`]) — the contract is the registry,
/// so it builds challenges from its own files and checks existence itself.
pub struct StatelessLedger<'a> {
    /// Accepted aggregated roots ({current} ∪ historical), each as the 32-byte
    /// little-endian field repr (matching `FileLedger::historical_roots`).
    pub valid_roots: &'a HashSet<[u8; 32]>,
}

impl LedgerView for StatelessLedger<'_> {
    fn is_valid_root(&self, root: FieldElement) -> bool {
        let repr: [u8; 32] = root.to_repr().into();
        self.valid_roots.contains(&repr)
    }
}

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
    verify_with(challenges, proof, ledger)
}

/// Verify a proof against challenges using bare ledger data instead of a live
/// [`FileLedger`] — just the set of valid aggregated roots. Behaves identically to
/// [`verify`] except it skips the per-file metadata cross-check (see
/// [`StatelessLedger`]).
///
/// This is the entry point for hosts that keep the file registry in contract
/// storage rather than an in-memory accumulator.
pub fn verify_stateless(
    challenges: &[Challenge],
    proof: &Proof,
    valid_roots: &HashSet<[u8; 32]>,
) -> Result<bool> {
    let view = StatelessLedger { valid_roots };
    verify_with(challenges, proof, &view)
}

fn verify_with(challenges: &[Challenge], proof: &Proof, ledger: &impl LedgerView) -> Result<bool> {
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

    // Validate challenge structure/metadata invariants before any cryptographic checks.
    for challenge in challenges.iter() {
        challenge.validate()?;
    }

    // Reject duplicate challenges up front.
    let mut seen = HashSet::with_capacity(challenges.len());
    for challenge in challenges.iter() {
        let challenge_id = challenge.id();
        if !seen.insert(challenge_id) {
            return Err(KontorPoRError::InvalidInput(
                "verify: duplicate challenge detected".to_string(),
            ));
        }
    }

    // Bind proof to the exact challenge set (including non-circuit fields such as
    // block_height/prover_id) so callers of verify_raw() cannot bypass this check.
    let expected_ids: Vec<_> = challenges.iter().map(|c| c.id()).collect();
    if proof.challenge_ids.len() != expected_ids.len() {
        return Ok(false);
    }
    if proof
        .challenge_ids
        .iter()
        .zip(expected_ids.iter())
        .any(|(a, b)| a != b)
    {
        return Ok(false);
    }

    // Build the verify-side plan from the challenges alone: the circuit's public
    // inputs come from the proof, so no ledger/tree is needed to construct it.
    let plan = Plan::for_verify(challenges)?;

    // Per-file metadata binding (delegated to the view): for a `FileLedger` this
    // confirms each challenged file is registered with a matching root-commitment;
    // for a stateless view it is a no-op (the contract is the registry). In
    // `make_plan` this lived inside the ledger lookup loop.
    for (i, challenge) in plan.sorted_challenges.iter().enumerate() {
        ledger.check_registered(&challenge.file_metadata.file_id, plan.expected_rcs[i])?;
    }

    // --- Proof shape + index sanity checks ---
    //
    // The circuit consumes `ledger_root` and `ledger_indices` as public inputs. It uses the
    // low `aggregated_tree_depth` bits of each ledger index to select the aggregation path.
    // Enforcing index range here makes the statement canonical (avoids equivalent indices
    // differing only in high bits).
    let is_multi_file = plan.files_per_step > 1;

    if is_multi_file {
        if proof.aggregated_tree_depth == 0 {
            return Err(KontorPoRError::InvalidInput(
                "Multi-file proof must have non-zero aggregated_tree_depth".to_string(),
            ));
        }
    } else if proof.aggregated_tree_depth != 0 {
        return Err(KontorPoRError::InvalidInput(
            "Single-file proof must have aggregated_tree_depth = 0".to_string(),
        ));
    }

    if proof.ledger_indices.len() != plan.files_per_step {
        return Err(KontorPoRError::InvalidInput(format!(
            "Proof ledger_indices length {} does not match circuit files_per_step {}",
            proof.ledger_indices.len(),
            plan.files_per_step
        )));
    }

    if is_multi_file {
        let max_leaf_count = 1usize
            .checked_shl(proof.aggregated_tree_depth as u32)
            .ok_or_else(|| {
                KontorPoRError::InvalidInput(format!(
                    "Invalid aggregated_tree_depth {}: too large for host usize",
                    proof.aggregated_tree_depth
                ))
            })?;

        for (i, idx) in proof.ledger_indices.iter().enumerate() {
            if *idx >= max_leaf_count {
                return Err(KontorPoRError::InvalidInput(format!(
                    "Proof ledger_indices[{}] = {} is out of range for aggregated_tree_depth {} (max {})",
                    i,
                    idx,
                    proof.aggregated_tree_depth,
                    max_leaf_count - 1
                )));
            }
        }
    }

    // --- Historical root validation (multi-file only) ---
    //
    // For multi-file proofs, `proof.ledger_root` must be either the current root or a retained
    // historical root. For single-file proofs, the circuit uses the file's root directly.
    if is_multi_file && !ledger.is_valid_root(proof.ledger_root) {
        debug!(
            "Proof ledger_root {:?} is not in the ledger's set of valid roots",
            proof.ledger_root,
        );
        return Err(KontorPoRError::InvalidLedgerRoot {
            proof_root: format!("{:?}", proof.ledger_root),
            reason: "Proof's ledger_root is not in the set of valid historical roots".to_string(),
        });
    }
    if is_multi_file {
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
        plan.initial_state,
        &proof.ledger_indices,
        &plan.depths,
        &plan.seeds,
        &plan.expected_rcs,
    );
    debug!("VERIFIER z0_primary: {:?}", z0_primary);

    let num_iterations = plan.sorted_challenges[0].num_challenges;

    // Record metrics in span
    tracing::Span::current().record("num_iterations", num_iterations);
    tracing::Span::current().record("files_per_step", plan.files_per_step);

    if !is_multi_file {
        debug!("verify() - Single-file verification:");
    } else {
        debug!("verify() - Multi-file verification:");
    }
    debug!("  - Number of files: {}", plan.sorted_challenges.len());
    debug!("  - Number of iterations to verify: {}", num_iterations);
    debug!("  - z0_primary[0] aggregated_root: {:?}", proof.ledger_root);
    debug!("  - z0_primary[1] initial_state: {:?}", plan.initial_state);
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

// Unit tests for constraint-level statement binding live under `tests/` to avoid
// slow proof-generation in library unit tests.
