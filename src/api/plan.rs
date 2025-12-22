//! Preprocessing plan that consolidates logic shared between prove() and verify().
//!
//! The Plan struct eliminates duplication between proving and verification
//! by handling all the common preprocessing steps in one place.

use super::types::{Challenge, FieldElement};
use crate::{config, ledger::FileLedger, KontorPoRError, Result};
use ff::Field;
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
    /// Aggregated root (pinned from challenge, not current ledger state)
    pub(crate) aggregated_root: FieldElement,
    /// Challenges sorted by file hash for deterministic processing
    pub(crate) sorted_challenges: Vec<Challenge>,
    /// Ledger indices for each file slot (padded with zeros)
    pub(crate) ledger_indices: Vec<usize>,
    /// Actual depths for each file slot (padded with zeros)
    pub(crate) depths: Vec<usize>,
    /// Seeds for each file slot (padded with zeros)
    pub(crate) seeds: Vec<FieldElement>,
    /// Public I/O layout helper
    pub(crate) public_io_layout: config::PublicIOLayout,
}

impl Plan {
    /// Create a unified preprocessing plan for both prove() and verify().
    pub(crate) fn make_plan(challenges: &[Challenge], ledger: &FileLedger) -> Result<Plan> {
        if challenges.is_empty() {
            return Err(KontorPoRError::InvalidInput(
                "Cannot create plan from empty challenges".to_string(),
            ));
        }

        // Derive aggregated root from pinned ledger_root in challenges
        // Single challenge = single-file proof (use file root directly)
        // Multiple challenges = multi-file proof (use pinned ledger_root)
        let aggregated_root = if challenges.len() > 1 {
            // Multi-file case: use pinned ledger root from challenges
            // All challenges must have the same ledger_root for aggregation
            let pinned_root = challenges[0].ledger_root;
            for (i, c) in challenges.iter().enumerate().skip(1) {
                if c.ledger_root != pinned_root {
                    return Err(KontorPoRError::ChallengeMismatch {
                        field: format!(
                            "ledger_root (challenge 0 has {:?}, challenge {} has {:?})",
                            pinned_root, i, c.ledger_root
                        ),
                    });
                }
            }
            pinned_root
        } else {
            // Single-file case: always use file root (even if ledger is provided)
            challenges[0].file_metadata.root
        };

        // 1. Derive shape from challenges
        let max_file_depth = challenges
            .iter()
            .map(|c| crate::api::tree_depth_from_metadata(&c.file_metadata))
            .max()
            .unwrap_or(0);
        let (files_per_step, file_tree_depth) =
            config::derive_shape(challenges.len(), max_file_depth);
        let aggregated_tree_depth = if files_per_step > 1 {
            ledger.tree.layers.len() - 1
        } else {
            0
        };

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

        // 3. Compute ledger indices
        let mut ledger_indices = vec![0usize; files_per_step];
        use crate::poseidon::calculate_root_commitment;

        for (i, challenge) in sorted_challenges.iter().enumerate() {
            let file_depth = crate::api::tree_depth_from_metadata(&challenge.file_metadata);
            let rc = calculate_root_commitment(
                challenge.file_metadata.root,
                FieldElement::from(file_depth as u64),
            );

            let ledger_idx = ledger.get_canonical_index_for_rc(rc).ok_or_else(|| {
                KontorPoRError::FileNotInLedger {
                    file_id: challenge.file_metadata.file_id.clone(),
                }
            })?;

            ledger_indices[i] = ledger_idx;
        }

        // Compute actual depths for each challenge
        let mut depths = vec![0usize; files_per_step];
        for (i, challenge) in sorted_challenges.iter().enumerate() {
            let depth = crate::api::tree_depth_from_metadata(&challenge.file_metadata);
            depths[i] = depth;
        }

        // Collect seeds for each challenge
        let mut seeds = vec![FieldElement::ZERO; files_per_step];
        for (i, challenge) in sorted_challenges.iter().enumerate() {
            seeds[i] = challenge.seed;
        }

        // 4. Create public I/O layout helper
        let public_io_layout = config::PublicIOLayout::new(files_per_step);

        Ok(Plan {
            files_per_step,
            file_tree_depth,
            aggregated_tree_depth,
            aggregated_root,
            sorted_challenges,
            ledger_indices,
            depths,
            seeds,
            public_io_layout,
        })
    }

    /// Build the z0_primary vector using this plan
    pub(crate) fn build_z0_primary(&self) -> Vec<FieldElement> {
        self.public_io_layout.build_z0_primary(
            self.aggregated_root,
            &self.ledger_indices,
            &self.depths,
            &self.seeds,
        )
    }
}
