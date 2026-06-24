//! Proof verification functionality.
//!
//! This module contains the verification logic with automatic
//! secure root derivation from the ledger.

use super::{
    plan::{AggInputs, Plan},
    types::{Challenge, FieldElement, Proof},
};
use crate::{config, ledger::FileLedger, KontorPoRError, Result};
use ff::PrimeField;
use std::collections::{BTreeMap, HashSet};
use tracing::{debug, info_span};

/// How tightly a ledger view can bind an accepted root to aggregation depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootDepthRequirement {
    /// The root is accepted only at this exact aggregation depth.
    Exact(usize),
    /// The root is accepted for depths up to and including this bound.
    Max(usize),
}

impl RootDepthRequirement {
    fn accepts(self, depth: usize) -> bool {
        match self {
            RootDepthRequirement::Exact(expected) => depth == expected,
            RootDepthRequirement::Max(max) => depth <= max,
        }
    }

    fn describe(self) -> String {
        match self {
            RootDepthRequirement::Exact(expected) => format!("expected exact depth {expected}"),
            RootDepthRequirement::Max(max) => format!("maximum accepted depth {max}"),
        }
    }
}

/// What proof verification needs from "the ledger": resolve each challenged file's
/// stable, append-only slot (and its registered root-commitment), and decide whether
/// a `ledger_root` is accepted.
///
/// The constant-size proof (wire v3) carries neither challenge IDs nor ledger
/// indices, so the verifier resolves indices itself — from whatever holds the file
/// registry. That can be a live [`FileLedger`] (the prover's view) or bare data held
/// elsewhere, e.g. a contract's own on-chain storage (see [`StatelessLedger`]). The
/// SNARK binds the resolved indices to the proof's root, so a prover cannot lie about
/// them.
pub trait LedgerView {
    /// Stable append-only ledger slot and registered root-commitment for `file_id`,
    /// if the file is registered. Returns `None` for an unregistered file.
    fn lookup(&self, file_id: &str) -> Option<(usize, FieldElement)>;

    /// Whether `root` is an accepted aggregated ledger root (current or historical).
    fn is_valid_root(&self, root: FieldElement) -> bool;

    /// Depth policy for an accepted aggregated ledger root.
    fn root_depth_requirement(&self, root: FieldElement) -> Option<RootDepthRequirement>;
}

impl LedgerView for FileLedger {
    fn lookup(&self, file_id: &str) -> Option<(usize, FieldElement)> {
        FileLedger::lookup(self, file_id)
    }

    fn is_valid_root(&self, root: FieldElement) -> bool {
        FileLedger::is_valid_root(self, root)
    }

    fn root_depth_requirement(&self, root: FieldElement) -> Option<RootDepthRequirement> {
        FileLedger::accepted_root_depth(self, root).map(RootDepthRequirement::Exact)
    }
}

/// A [`LedgerView`] backed by plain data instead of a live [`FileLedger`]: the set of
/// valid aggregated roots plus a snapshot of the file registry (`file_id -> (slot,
/// rc)`). That is exactly the data a contract holds once the file registry moves
/// in-contract, so the host can verify proofs without maintaining a mutable
/// accumulator. The registry's stable slots let the verifier resolve ledger indices
/// identically to the prover; the contract is responsible for keeping them (and the
/// valid-root set) consistent with the on-chain files.
///
/// Roots are the 32-byte little-endian field repr (matching
/// `FileLedger::historical_roots`). Compute them from the on-chain files with
/// [`crate::ledger::aggregate_root`] / [`crate::ledger::aggregate_root_from_files`].
///
/// Because this stateless view stores roots without per-root depths, verification bounds
/// `aggregated_tree_depth` by the current registry's implied aggregation depth before
/// parameter loading. Callers that retain historical roots should prefer an external
/// `(root, depth)` policy when they can enforce one at the host/contract boundary.
/// Callers must only admit roots into `valid_roots` that they produced from their own
/// files (e.g. via [`crate::ledger::aggregate_root`]); never roots of unknown provenance.
pub struct StatelessLedger<'a> {
    /// Accepted aggregated roots ({current} ∪ historical).
    pub valid_roots: &'a HashSet<[u8; 32]>,
    /// File registry snapshot: `file_id -> (stable ledger slot, root-commitment)`.
    pub files: &'a BTreeMap<String, (usize, FieldElement)>,
}

impl LedgerView for StatelessLedger<'_> {
    fn lookup(&self, file_id: &str) -> Option<(usize, FieldElement)> {
        self.files.get(file_id).copied()
    }

    fn is_valid_root(&self, root: FieldElement) -> bool {
        let repr: [u8; 32] = root.to_repr().into();
        self.valid_roots.contains(&repr)
    }

    fn root_depth_requirement(&self, root: FieldElement) -> Option<RootDepthRequirement> {
        if !self.is_valid_root(root) {
            return None;
        }
        let max_index = self.files.values().map(|(idx, _rc)| *idx).max()?;
        let leaf_count = max_index.checked_add(1)?;
        let padded_leaf_count = leaf_count.next_power_of_two();
        Some(RootDepthRequirement::Max(
            padded_leaf_count.trailing_zeros() as usize,
        ))
    }
}

/// Verifies a proof against one or more challenges using a live [`FileLedger`].
///
/// # Historical Root Validation
///
/// For multi-file proofs (k > 1), this validates that `proof.ledger_root` is in the
/// ledger's set of valid roots (current or historical). This enables cross-block
/// aggregation: proofs generated against older ledger states remain valid as long as
/// the root is in the historical set.
///
/// The constant-size proof does not carry ledger indices. The verifier resolves each
/// file's canonical, append-only slot from the ledger and supplies them as public
/// inputs, binding the SNARK statement to the verifier's notion of which files are
/// being challenged.
///
/// For single-file proofs (k = 1), the ledger root check is skipped because the
/// circuit uses the file's Merkle root directly instead of the ledger root.
///
/// # Security
///
/// The SNARK cryptographically proves that each file exists at the resolved index in
/// the tree with the claimed root and that the Merkle paths are valid. A prover
/// cannot lie about indices — invalid indices would cause SNARK verification to fail.
pub fn verify(challenges: &[Challenge], proof: &Proof, ledger: &FileLedger) -> Result<bool> {
    verify_with(challenges, proof, ledger)
}

/// Verifies a proof against one or more challenges using bare registry data instead
/// of a live [`FileLedger`] — see [`StatelessLedger`].
///
/// This is the entry point for hosts that keep the file registry in contract storage
/// rather than an in-memory accumulator. Behaves identically to [`verify`]: indices
/// are resolved from the supplied registry snapshot, and `proof.ledger_root` is
/// checked against the supplied valid-root set (multi-file only).
pub fn verify_stateless(
    challenges: &[Challenge],
    proof: &Proof,
    ledger: &StatelessLedger,
) -> Result<bool> {
    verify_with(challenges, proof, ledger)
}

/// Shared verification over any [`LedgerView`]. Every input the circuit consumes is
/// rebuilt by the verifier: indices/depths/seeds/rcs from the challenges + registry,
/// and the aggregated root/depth from the (SNARK-bound) proof.
fn verify_with(challenges: &[Challenge], proof: &Proof, view: &dyn LedgerView) -> Result<bool> {
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

    if challenges.len() > config::PRACTICAL_MAX_FILES {
        return Err(KontorPoRError::TooManyFiles {
            got: challenges.len(),
            max: config::PRACTICAL_MAX_FILES,
        });
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

    // Build the verify-side plan: every challenge-derived field comes from the
    // challenges; the aggregation root/depth come from the proof (SNARK-bound); the
    // per-file indices are resolved from `view` (the proof carries none).
    let plan = Plan::make_plan(
        challenges,
        AggInputs::Proof {
            root: proof.ledger_root,
            aggregated_tree_depth: proof.aggregated_tree_depth,
            view,
        },
    )?;

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

    if is_multi_file {
        let max_leaf_count = 1usize
            .checked_shl(proof.aggregated_tree_depth as u32)
            .ok_or_else(|| {
                KontorPoRError::InvalidInput(format!(
                    "Invalid aggregated_tree_depth {}: too large for host usize",
                    proof.aggregated_tree_depth
                ))
            })?;

        for (i, idx) in plan.ledger_indices.iter().enumerate() {
            if *idx >= max_leaf_count {
                return Err(KontorPoRError::InvalidInput(format!(
                    "Derived ledger_indices[{}] = {} is out of range for aggregated_tree_depth {} (max {})",
                    i,
                    idx,
                    proof.aggregated_tree_depth,
                    max_leaf_count - 1
                )));
            }
        }
    }

    // --- Historical root/depth validation (multi-file only) ---
    //
    // For multi-file proofs, `proof.ledger_root` must be either the current root or a retained
    // historical root at an accepted depth. For single-file proofs, the circuit uses the file's
    // root directly.
    if is_multi_file {
        let depth_requirement =
            view.root_depth_requirement(proof.ledger_root)
                .ok_or_else(|| KontorPoRError::InvalidLedgerRoot {
                    proof_root: format!("{:?}", proof.ledger_root),
                    reason: "Proof's ledger_root is not accepted with a known aggregation depth"
                        .to_string(),
                })?;
        if !depth_requirement.accepts(proof.aggregated_tree_depth) {
            return Err(KontorPoRError::InvalidLedgerRoot {
                proof_root: format!("{:?}", proof.ledger_root),
                reason: format!(
                    "Proof aggregated_tree_depth {} does not satisfy {}",
                    proof.aggregated_tree_depth,
                    depth_requirement.describe()
                ),
            });
        }

        debug!(
            "Proof ledger_root {:?} validated with depth requirement {:?}",
            proof.ledger_root, depth_requirement
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

    // Build public inputs using verifier-derived indices, depths, seeds, and expected_rcs.
    debug!("Verify: building z0_primary from proof root + derived challenge inputs");
    debug!("  - Using proof.ledger_root: {:?}", proof.ledger_root);
    debug!("  - Derived ledger_indices: {:?}", plan.ledger_indices);
    debug!("  - Depths from challenges: {:?}", plan.depths);

    // Build z0_primary with proof's root and verifier-derived indices.
    let z0_primary = plan.public_io_layout.build_z0_primary(
        proof.ledger_root,
        plan.initial_state,
        &plan.ledger_indices,
        &plan.depths,
        &plan.seeds,
        &plan.expected_rcs,
    );
    debug!("VERIFIER z0_primary: {:?}", z0_primary);

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
    debug!("  - z0_primary[0] aggregated_root: {:?}", proof.ledger_root);
    debug!("  - z0_primary[1] initial_state: {:?}", plan.initial_state);
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

// Unit tests for constraint-level statement binding live under `tests/` to avoid
// slow proof-generation in library unit tests.
