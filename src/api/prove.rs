//! Proof generation functionality.
//!
//! This module contains all the logic for generating proofs,
//! broken down into focused, manageable functions.

use super::{
    plan::Plan,
    types::{Challenge, FieldElement, PorParams, PreparedFile, Proof},
    witness::generate_circuit_witness,
};
use crate::{config, ledger::FileLedger, NovaPoRError, Result};
use arecibo::{
    provider::{PallasEngine, VestaEngine},
    traits::{circuit::TrivialCircuit, Engine},
    CompressedSNARK, RecursiveSNARK,
};
use ff::Field;
use std::collections::BTreeMap;
use tracing::{debug, debug_span, info_span, trace};

// Type aliases needed for proving
type E1 = PallasEngine;
type E2 = VestaEngine;
type C1 = crate::circuit::PorCircuit<FieldElement>;
type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;
type NovaProof = RecursiveSNARK<E1, E2, C1, C2>;

/// Generates a proof for one or more file challenges.
///
/// This function implements the Option 1 security model with public ledger indices.
/// Parameters are derived automatically from the challenges.
pub fn prove(
    challenges: &[Challenge],
    files: &BTreeMap<String, &PreparedFile>,
    ledger: &FileLedger,
    progress_callback: Option<&dyn Fn()>,
) -> Result<Proof> {
    let _span = info_span!(
        "prove",
        num_challenges = challenges.len(),
        num_files = files.len(),
        has_ledger = true
    )
    .entered();

    // Setup: validate inputs, create plan, load parameters
    let (plan, params, num_challenges) = setup_proving_environment(challenges, files, ledger)?;

    // Initialize recursive SNARK with first witness and circuit
    let (mut recursive_snark, current_state) =
        initialize_recursive_snark(&plan, &params, files, ledger)?;

    // Execute the main proving loop
    let _final_state = execute_proving_loop(
        &mut recursive_snark,
        &plan,
        &params,
        files,
        ledger,
        num_challenges,
        current_state,
        progress_callback,
    )?;

    let _compress_span = info_span!("CompressedSNARK::prove").entered();
    let compressed_snark = CompressedSNARK::prove(&params.pp, &params.keys.pk, &recursive_snark)
        .map_err(|e| NovaPoRError::Snark(format!("Proof compression failed: {e:?}")))?;

    // Collect challenge IDs in order
    let challenge_ids: Vec<super::types::ChallengeID> = challenges.iter().map(|c| c.id()).collect();

    Ok(super::types::Proof {
        compressed_snark,
        challenge_ids,
    })
}

/// Setup proving environment: validate inputs, create plan, load parameters.
fn setup_proving_environment(
    challenges: &[Challenge],
    files: &BTreeMap<String, &PreparedFile>,
    ledger: &FileLedger,
) -> Result<(Plan, PorParams, usize)> {
    if challenges.is_empty() {
        return Err(NovaPoRError::InvalidInput(
            "prove: Must provide at least one challenge to generate a proof".to_string(),
        ));
    }

    // Practical limit for number of files (can be adjusted based on needs)
    if challenges.len() > config::PRACTICAL_MAX_FILES {
        return Err(NovaPoRError::TooManyFiles {
            got: challenges.len(),
            max: config::PRACTICAL_MAX_FILES,
        });
    }

    // Verify all challenges use the same num_challenges (Nova requirement)
    let num_challenges = challenges[0].num_challenges;

    if num_challenges == 0 || num_challenges > config::MAX_NUM_CHALLENGES {
        return Err(NovaPoRError::InvalidChallengeCount {
            count: num_challenges,
        });
    }

    for challenge in challenges.iter() {
        if challenge.num_challenges != num_challenges {
            return Err(NovaPoRError::ChallengeMismatch {
                field: "num_challenges".to_string(),
            });
        }
    }

    // Validate all files
    for challenge in challenges.iter() {
        let file = files.get(&challenge.file_metadata.file_id).ok_or_else(|| {
            NovaPoRError::FileNotFound {
                file_id: challenge.file_metadata.file_id.clone(),
            }
        })?;

        if file.tree.root() != challenge.file_metadata.root {
            return Err(NovaPoRError::MetadataMismatch);
        }
    }

    // Create unified preprocessing plan
    let plan = Plan::make_plan(challenges, ledger)?;

    // Load or generate parameters for the exact shape
    let params = crate::params::load_or_generate_params(
        plan.files_per_step,
        plan.file_tree_depth,
        plan.aggregated_tree_depth,
    )?;

    debug!(
        "prove() - Using shape: files_per_step={}, file_tree_depth={}, aggregated_tree_depth={}",
        plan.files_per_step, plan.file_tree_depth, plan.aggregated_tree_depth
    );

    if plan.aggregated_tree_depth == 0 {
        debug!("[DEBUG] prove() - Single-file proof:");
        debug!("  - Number of challenges: {}", plan.sorted_challenges.len());
        debug!("  - Aggregated depth: {}", plan.aggregated_tree_depth);
    } else {
        debug!("[DEBUG] prove() - Multi-file proof:");
        debug!("  - Number of challenges: {}", plan.sorted_challenges.len());
        debug!("  - Aggregated depth: {}", plan.aggregated_tree_depth);
    }

    debug!(
        "[DEBUG] prove() - Multi-file proof with {} challenges per file",
        num_challenges
    );

    debug!("prove() - Multi-file proof generation:");
    debug!("  - Number of files: {}", plan.sorted_challenges.len());
    debug!("  - Challenges per file: {}", num_challenges);
    debug!("  - Aggregated tree depth: {}", plan.aggregated_tree_depth);
    debug!("  - Aggregated root: {:?}", plan.aggregated_root);

    Ok((plan, params, num_challenges))
}

/// Initialize the recursive SNARK with the first witness and circuit.
fn initialize_recursive_snark(
    plan: &Plan,
    params: &PorParams,
    files: &BTreeMap<String, &PreparedFile>,
    ledger: &FileLedger,
) -> Result<(NovaProof, FieldElement)> {
    // Generate witnesses for the first step using the canonical function
    let current_state = FieldElement::ZERO;
    let sorted_challenges_refs: Vec<&Challenge> = plan.sorted_challenges.iter().collect();
    let (circuit_witness, new_state) = generate_circuit_witness(
        &sorted_challenges_refs,
        Some(files), // Pass actual files for proving
        ledger,
        plan.file_tree_depth,
        plan.file_tree_depth, // For exact shape, both are the same
        current_state,
        plan.aggregated_tree_depth,
        0,                    // step 0
        &plan.ledger_indices, // Pass precomputed indices from plan
    )?;

    debug!("prove() - After initial witness generation:");
    debug!("  - State after step 0: {:?}", new_state);
    debug!("  - Witness count: {}", circuit_witness.witnesses().len());
    debug!("  - Real files: {}", circuit_witness.num_real_files());

    // Build public inputs using the plan
    let z0_primary = plan.build_z0_primary();
    debug!("PROVER z0_primary: {:?}", z0_primary);

    let z0_secondary = vec![<E2 as Engine>::Scalar::ZERO];
    let circuit_secondary = C2::default();

    // Create the circuit for new() with witness from first challenge
    let circuit_first = C1::new(
        plan.files_per_step,
        plan.file_tree_depth,
        plan.aggregated_tree_depth,
        Some(circuit_witness.witnesses().to_vec()),
    );
    trace!(
        "Created circuit_first for new() with agg_depth={}, witnesses={}",
        plan.aggregated_tree_depth,
        circuit_witness.witnesses().len()
    );

    // Log initial witness structure for debugging
    for (i, w) in circuit_witness.witnesses().iter().enumerate().take(2) {
        trace!(
            "Initial witness {}: actual_depth={}, file_siblings.len={}, agg_siblings.len={}",
            i,
            w.actual_depth,
            w.file_siblings.len(),
            w.agg_siblings.len()
        );
    }

    // Create initial recursive SNARK (handles first challenge)
    debug!("prove() - Creating NovaProof::new with z0_primary:");
    debug!("  [0] aggregated_root: {:?}", z0_primary[0]);
    debug!("  [1] initial_state: {:?}", z0_primary[1]);
    for (i, idx) in plan.ledger_indices.iter().enumerate() {
        debug!("  [{}] ledger_index_{}: {:?}", 2 + i, i, idx);
    }
    for (i, depth) in plan.depths.iter().enumerate() {
        debug!("  [{}] depth_{}: {}", 2 + plan.files_per_step + i, i, depth);
    }
    for (i, seed) in plan.seeds.iter().enumerate() {
        debug!(
            "  [{}] seed_{}: {:?}",
            2 + plan.files_per_step + plan.files_per_step + i,
            i,
            seed
        );
    }

    let recursive_snark = {
        let _span = debug_span!("RecursiveSNARK::new").entered();
        NovaProof::new(
            &params.pp,
            &circuit_first,
            &circuit_secondary,
            &z0_primary,
            &z0_secondary,
        )
        .map_err(|e| NovaPoRError::Snark(format!("Initial SNARK creation failed: {e:?}")))?
    };

    trace!("NovaProof::new completed successfully");

    Ok((recursive_snark, new_state))
}

/// Execute the main proving loop with prove_step calls.
#[allow(clippy::too_many_arguments)]
fn execute_proving_loop(
    recursive_snark: &mut NovaProof,
    plan: &Plan,
    params: &PorParams,
    files: &BTreeMap<String, &PreparedFile>,
    ledger: &FileLedger,
    num_challenges: usize,
    mut current_state: FieldElement,
    progress_callback: Option<&dyn Fn()>,
) -> Result<FieldElement> {
    // THIS IS IMPORTANT: Main proving loop - call prove_step N times (first call is a no-op)
    // ATTENTION: Arecibo's prove_step explicitly no-ops on first call after new()
    // DO NOT REMOVE THIS COMMENT OR THE CODE WILL NOT WORK
    debug!(
        "Entering main proving loop - will call prove_step {} times",
        num_challenges
    );
    debug!(
        "Note: First prove_step call is a no-op (Arecibo design), actual steps start from call #2"
    );

    let sorted_challenges_refs: Vec<&Challenge> = plan.sorted_challenges.iter().collect();
    let circuit_secondary = C2::default();

    for challenge_num in 0..num_challenges {
        let _step_span =
            debug_span!("prove_step", challenge_num, is_noop = (challenge_num == 0)).entered();

        debug!(
            "Loop iteration: challenge_num={} of {}",
            challenge_num,
            num_challenges - 1
        );
        debug!(
            "prove() - Processing challenge {} of {}",
            challenge_num + 1,
            num_challenges
        );
        debug!("  - Current state before step: {:?}", current_state);

        // Generate witnesses and circuit for this iteration
        let (circuit_step, new_state) = if challenge_num == 0 {
            // First prove_step call is a no-op - it doesn't synthesize
            // We can pass any valid circuit structure (it won't be used)
            debug!("Creating dummy circuit for no-op prove_step");
            let dummy_circuit = C1::new(
                plan.files_per_step,
                plan.file_tree_depth,
                plan.aggregated_tree_depth,
                None, // No witnesses needed for no-op
            );
            (dummy_circuit, current_state) // Don't update state for no-op
        } else {
            // For real steps (challenge_num >= 1), generate witnesses and update state
            debug!("Generating witnesses for step {}", challenge_num);
            let (step_circuit_witness, new_state) = generate_circuit_witness(
                &sorted_challenges_refs,
                Some(files), // Pass actual files
                ledger,
                plan.file_tree_depth,
                plan.file_tree_depth, // For exact shape, both are the same
                current_state,
                plan.aggregated_tree_depth,
                challenge_num,        // Step number matches challenge_num
                &plan.ledger_indices, // Pass precomputed indices from plan
            )?;
            let circuit = C1::new(
                plan.files_per_step,
                plan.file_tree_depth,
                plan.aggregated_tree_depth,
                Some(step_circuit_witness.witnesses().to_vec()),
            );
            (circuit, new_state)
        };

        if challenge_num > 0 {
            // Only update state for real steps
            current_state = new_state;
        }

        trace!("Created circuit_step for iteration {}", challenge_num);

        // Fold this step into the proof
        trace!(
            "About to call prove_step #{} ({})",
            challenge_num + 1,
            if challenge_num == 0 {
                "no-op call"
            } else {
                "will synthesize"
            }
        );
        trace!(
            "params.file_tree_depth: {}, params.aggregated_tree_depth: {}",
            params.file_tree_depth,
            params.aggregated_tree_depth
        );
        let prove_result =
            recursive_snark.prove_step(&params.pp, &circuit_step, &circuit_secondary);
        trace!(
            "prove_step returned: {:?}{}",
            prove_result.is_ok(),
            if challenge_num == 0 {
                " (expected fast no-op)"
            } else {
                ""
            }
        );
        prove_result.map_err(|e| {
            NovaPoRError::Snark(format!("Prove step {} failed: {e:?}", challenge_num))
        })?;

        // Report progress after each successful step (excluding the no-op)
        if let Some(cb) = progress_callback {
            if challenge_num > 0 {
                cb();
            }
        }
    }

    debug!("prove() - Proof generation complete:");
    debug!("  - NovaProof::new performed step 0");
    debug!(
        "  - Called prove_step {} times (first was no-op)",
        num_challenges
    );
    debug!(
        "  - Total synthesized steps: {} (step 0 + {} actual prove_step calls)",
        num_challenges,
        num_challenges.saturating_sub(1)
    );
    debug!("  - Final state: {:?}", current_state);

    Ok(current_state)
}
