//! Preprocessing plan that consolidates logic shared between prove() and verify().
//!
//! The Plan struct eliminates duplication between proving and verification
//! by handling all the common preprocessing steps in one place.

use super::types::{Challenge, FieldElement};
use super::verify::LedgerView;
use crate::poseidon::calculate_root_commitment;
use crate::{config, ledger::FileLedger, KontorPoRError, Result};
use ff::Field;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

/// Internal preprocessing plan that consolidates logic shared between prove() and verify().
/// This eliminates duplication and reduces the chance of drift between the two functions.
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    /// Number of file slots in the circuit (power of 2)
    pub(crate) files_per_step: usize,
    /// Maximum file tree depth for uniform structure
    pub(crate) file_tree_depth: usize,
    /// Aggregated tree depth (0 for single-file)
    pub(crate) aggregated_tree_depth: usize,
    /// Aggregated root (derived from ledger and challenge count)
    pub(crate) aggregated_root: FieldElement,
    /// Initial state for recursive folding, bound to the challenge set.
    pub(crate) initial_state: FieldElement,
    /// Challenges sorted by file hash for deterministic processing
    pub(crate) sorted_challenges: Vec<Challenge>,
    /// Ledger indices for each file slot (padded with zeros)
    pub(crate) ledger_indices: Vec<usize>,
    /// Actual depths for each file slot (padded with zeros)
    pub(crate) depths: Vec<usize>,
    /// Seeds for each file slot (padded with zeros)
    pub(crate) seeds: Vec<FieldElement>,
    /// Expected root commitments for each file slot (padded with zeros)
    pub(crate) expected_rcs: Vec<FieldElement>,
    /// Public I/O layout helper
    pub(crate) public_io_layout: config::PublicIOLayout,
}

/// Where the aggregation public inputs (root + tree depth) come from — the only
/// values whose source differs between proving and verification. The prover derives
/// them from the live ledger's aggregated tree; the verifier takes them from the
/// proof, where they were committed and are SNARK-bound.
///
/// Per-file ledger indices are deliberately NOT here: the constant-size proof (wire
/// v3) omits them, so both paths resolve each file's stable slot from a
/// [`LedgerView`] instead (a prover's live `FileLedger`, or a verifier's on-chain
/// registry). See [`Plan::make_plan`].
pub(crate) enum AggInputs<'a> {
    /// Prove path: root/depth from the live ledger; the same ledger resolves indices.
    Ledger(&'a FileLedger),
    /// Verify path: root/depth from the (SNARK-bound) proof; `view` resolves the
    /// per-file ledger indices (a live `FileLedger` or a stateless registry).
    Proof {
        root: FieldElement,
        aggregated_tree_depth: usize,
        view: &'a dyn LedgerView,
    },
}

impl Plan {
    /// Create a unified preprocessing plan for both prove() and verify().
    ///
    /// Every challenge-derived field is computed once here. Only the aggregation
    /// public inputs differ by source (see [`AggInputs`]); per-file ledger indices
    /// are always resolved from a [`LedgerView`], so a prover's `FileLedger` and a
    /// verifier's stateless registry resolve them identically.
    pub(crate) fn make_plan(challenges: &[Challenge], agg: AggInputs) -> Result<Plan> {
        if challenges.is_empty() {
            return Err(KontorPoRError::InvalidInput(
                "Cannot create plan from empty challenges".to_string(),
            ));
        }

        for challenge in challenges {
            challenge.validate()?;
        }

        // 1. Derive shape from challenges
        let max_file_depth = challenges
            .iter()
            .map(|c| crate::api::tree_depth_from_metadata(&c.file_metadata))
            .max()
            .unwrap_or(0);
        let (files_per_step, file_tree_depth) =
            config::derive_shape(challenges.len(), max_file_depth);

        // 2. Sort challenges canonically by (file_id, challenge_id)
        //
        // We need a total order so proof verification cannot accidentally depend on
        // the caller-provided ordering of `challenges` when multiple challenges refer
        // to the same file.
        let mut sorted_challenges: Vec<Challenge> = challenges.to_vec();
        sorted_challenges.sort_by(|a, b| {
            match a.file_metadata.file_id.cmp(&b.file_metadata.file_id) {
                Ordering::Equal => a.id().0.cmp(&b.id().0),
                other => other,
            }
        });

        // Bind initial recursive state to the exact challenge set (including
        // non-circuit fields captured by Challenge::id()).
        let initial_state = derive_initial_state(&sorted_challenges);

        // 3. Per-slot vectors derived from the challenges alone (no ledger needed).
        let mut expected_rcs = vec![FieldElement::ZERO; files_per_step];
        let mut depths = vec![0usize; files_per_step];
        let mut seeds = vec![FieldElement::ZERO; files_per_step];
        for (i, challenge) in sorted_challenges.iter().enumerate() {
            let file_depth = crate::api::tree_depth_from_metadata(&challenge.file_metadata);
            expected_rcs[i] = calculate_root_commitment(
                challenge.file_metadata.root,
                FieldElement::from(file_depth as u64),
            );
            depths[i] = file_depth;
            seeds[i] = challenge.seed;
        }

        // 4. Aggregation public inputs (root + depth) by source; per-file indices are
        //    always resolved from a LedgerView (the proof never carries them).
        let (aggregated_root, aggregated_tree_depth, ledger_indices) = match agg {
            AggInputs::Ledger(ledger) => {
                // Single-file uses the file's own root; multi-file uses the ledger root.
                let aggregated_root = if sorted_challenges.len() > 1 {
                    ledger.tree.root()
                } else {
                    sorted_challenges[0].file_metadata.root
                };
                let aggregated_tree_depth = if files_per_step > 1 {
                    ledger.tree.layers.len() - 1
                } else {
                    0
                };
                let ledger_indices = resolve_ledger_indices(
                    &sorted_challenges,
                    &expected_rcs,
                    files_per_step,
                    ledger,
                )?;
                (aggregated_root, aggregated_tree_depth, ledger_indices)
            }
            AggInputs::Proof {
                root,
                aggregated_tree_depth,
                view,
            } => {
                let ledger_indices = resolve_ledger_indices(
                    &sorted_challenges,
                    &expected_rcs,
                    files_per_step,
                    view,
                )?;
                (root, aggregated_tree_depth, ledger_indices)
            }
        };

        Ok(Plan {
            files_per_step,
            file_tree_depth,
            aggregated_tree_depth,
            aggregated_root,
            initial_state,
            sorted_challenges,
            ledger_indices,
            depths,
            seeds,
            expected_rcs,
            public_io_layout: config::PublicIOLayout::new(files_per_step),
        })
    }

    /// Build the z0_primary vector using this plan.
    pub(crate) fn build_z0_primary(&self) -> Vec<FieldElement> {
        self.public_io_layout.build_z0_primary(
            self.aggregated_root,
            self.initial_state,
            &self.ledger_indices,
            &self.depths,
            &self.seeds,
            &self.expected_rcs,
        )
    }
}

/// Resolve each challenged file's stable, append-only ledger slot from a
/// [`LedgerView`], cross-checking the registered root-commitment against the
/// challenge's claimed metadata. Used identically on the prove path (a live
/// `FileLedger`) and the verify path (a `FileLedger` or a stateless on-chain
/// registry) — the constant-size proof carries no indices, so both sides resolve
/// them the same way. Indices beyond the challenge count stay zero (slot padding).
fn resolve_ledger_indices(
    sorted_challenges: &[Challenge],
    expected_rcs: &[FieldElement],
    files_per_step: usize,
    view: &dyn LedgerView,
) -> Result<Vec<usize>> {
    let mut ledger_indices = vec![0usize; files_per_step];
    for (i, challenge) in sorted_challenges.iter().enumerate() {
        let (ledger_idx, actual_rc) =
            view.lookup(&challenge.file_metadata.file_id)
                .ok_or_else(|| KontorPoRError::FileNotInLedger {
                    file_id: challenge.file_metadata.file_id.clone(),
                })?;
        if actual_rc != expected_rcs[i] {
            return Err(KontorPoRError::MetadataMismatch);
        }
        ledger_indices[i] = ledger_idx;
    }
    Ok(ledger_indices)
}

/// Derive the initial recursive state from the full ordered challenge set.
///
/// This hardens verification against rebinding of non-circuit challenge fields:
/// changing any Challenge::id() value changes the recursive start state.
fn derive_initial_state(sorted_challenges: &[Challenge]) -> FieldElement {
    const DOMAIN_V1: &[u8] = b"kontor.challenge_set.initial_state.v1";
    const DOMAIN_V1_EXPAND: &[u8] = b"kontor.challenge_set.initial_state.v1.expand";

    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_V1);
    let count = u64::try_from(sorted_challenges.len()).unwrap_or(u64::MAX);
    hasher.update(count.to_le_bytes());
    for challenge in sorted_challenges {
        hasher.update(challenge.id().0);
    }
    let digest_a = hasher.finalize();

    let mut expander = Sha256::new();
    expander.update(DOMAIN_V1_EXPAND);
    expander.update(digest_a);
    let digest_b = expander.finalize();

    let mut uniform_bytes = [0u8; 64];
    uniform_bytes[..32].copy_from_slice(&digest_a);
    uniform_bytes[32..].copy_from_slice(&digest_b);

    crate::utils::field_from_uniform_bytes(&uniform_bytes)
}
