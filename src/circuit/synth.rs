//! Circuit synthesis logic for the Nova PoR circuit.
//!
//! This module contains the main synthesize function that implements the
//! Step Circuit logic for Proof-of-Retrievability verification.

use ff::PrimeField;
use ff::PrimeFieldBits;
use nova_snark::frontend::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        num::AllocatedNum,
    },
    ConstraintSystem, SynthesisError,
};
#[cfg(debug_assertions)]
use tracing::debug;

use super::gadgets::{
    hash::{conditional_select, poseidon_hash_tagged_gadget},
    merkle::{verify_aggregation_path_gated, verify_merkle_path_gated},
};
use super::witness::{CircuitWitness, FileProofWitness};
use crate::commitment::domain_tags;
use crate::config;

/// Main circuit synthesis function for the Nova PoR circuit
pub fn synthesize_por_circuit<F: PrimeField + PrimeFieldBits, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    z: &[AllocatedNum<F>],
    files_per_step: usize,
    file_tree_depth: usize,
    aggregated_tree_depth: usize,
    witness: Option<&CircuitWitness<F>>,
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    // Use centralized layout helper
    let layout = config::PublicIOLayout::new(files_per_step);

    // Assert that the public inputs match the expected circuit arity
    assert_eq!(
        z.len(),
        layout.arity(),
        "Public input count mismatch: expected {} (FIXED={} + ledger_indices={} + depths={} + seeds={} + leaves={}), got {}",
        layout.arity(),
        config::PublicIOLayout::FIXED,
        files_per_step,
        files_per_step,
        files_per_step,
        files_per_step,
        z.len()
    );

    // Deconstruct the public input vector using centralized layout
    let root = &z[layout.idx_agg_root()]; // The public root (aggregated tree root)
    let state_in = &z[layout.idx_state_in()]; // The input state for the current step's hash chain.

    // Extract public ledger indices for each file slot using layout helper
    let ledger_indices_public: Vec<&AllocatedNum<F>> = (0..files_per_step)
        .map(|i| &z[layout.idx_ledger(i)])
        .collect();

    // Extract public depths for each file slot
    let depths_public: Vec<&AllocatedNum<F>> = (0..files_per_step)
        .map(|i| &z[layout.idx_depth(i)])
        .collect();

    // Extract public seeds for each file slot
    let seeds_public: Vec<&AllocatedNum<F>> = (0..files_per_step)
        .map(|i| &z[layout.idx_seed(i)])
        .collect();

    #[cfg(debug_assertions)]
    {
        debug!("PorCircuit::synthesize() entry:");
        debug!("  - file_tree_depth (uniform): {}", file_tree_depth);
        debug!("  - aggregated_tree_depth: {}", aggregated_tree_depth);
        debug!("  - has witness: {}", witness.is_some());
        if let Some(circuit_witness) = witness {
            debug!("  - total witnesses: {}", circuit_witness.witnesses().len());
            debug!("  - num_real_files: {}", circuit_witness.num_real_files());
            for (i, w) in circuit_witness.witnesses().iter().enumerate().take(5) {
                // Show first 5
                debug!("    - witness {}: actual_depth={}", i, w.actual_depth);
            }
        }
        debug!(
            "  - Input z[{}] (aggregated_root): {:?}",
            layout.idx_agg_root(),
            root.get_value()
        );
        debug!(
            "  - Input z[{}] (state_in): {:?}",
            layout.idx_state_in(),
            state_in.get_value()
        );
        for (i, idx) in ledger_indices_public.iter().enumerate() {
            debug!(
                "  - Input z[{}] (ledger_index_{}): {:?}",
                layout.idx_ledger(i),
                i,
                idx.get_value()
            );
        }
        for (i, depth) in depths_public.iter().enumerate() {
            debug!(
                "  - Input z[{}] (depth_{}): {:?}",
                layout.idx_depth(i),
                i,
                depth.get_value()
            );
        }
        for (i, seed) in seeds_public.iter().enumerate() {
            debug!(
                "  - Input z[{}] (seed_{}): {:?}",
                layout.idx_seed(i),
                i,
                seed.get_value()
            );
        }
    }

    // CircuitWitness ensures we have exactly the right number of witnesses,
    // properly padded, with padding determined by actual_depth == 0

    // For setup phase, create a minimal default witness structure
    let default_circuit_witness = if witness.is_none() {
        let files_count = files_per_step;
        let default_witness = FileProofWitness {
            leaf: F::ZERO,
            file_siblings: vec![F::ZERO; file_tree_depth],
            file_root: F::ZERO,
            actual_depth: 0,
            agg_siblings: vec![F::ZERO; aggregated_tree_depth.max(1)],
            ledger_index: 0,
        };
        Some(CircuitWitness::new(vec![default_witness; files_count], 0))
    } else {
        None
    };

    // Get the circuit witness (either provided or default)
    let circuit_witness = witness
        .or(default_circuit_witness.as_ref())
        .expect("Must have either witness or default");

    let witnesses = circuit_witness.witnesses();

    #[cfg(debug_assertions)]
    {
        debug!("  - Witness count: {}", witnesses.len());
        debug!(
            "  - Number of actual files: {}",
            circuit_witness.num_real_files()
        );
    }

    // Track state through all file verifications for replay protection
    let mut current_state = state_in.clone();

    // Collect public leaf values (gated by depth > 0)
    let mut public_leaf_values: Vec<AllocatedNum<F>> = Vec::new();

    // Process each witness in the guaranteed structure
    for (file_idx, witness) in witnesses.iter().enumerate() {
        let mut file_cs = cs.namespace(|| format!("file_{}", file_idx));

        #[cfg(debug_assertions)]
        {
            debug!("synthesize() - Processing file_idx={}:", file_idx);
            debug!("  - Leaf value: {:?}", witness.leaf);
            debug!("  - File siblings count: {}", witness.file_siblings.len());
            debug!("  - File root: {:?}", witness.file_root);
            debug!("  - Actual depth: {}", witness.actual_depth);
            debug!("  - Agg siblings count: {}", witness.agg_siblings.len());
            debug!("  - Ledger index: {}", witness.ledger_index);
        }

        // Get public depth and seed for this slot
        let depth_public = depths_public[file_idx];
        let seed_public = seeds_public[file_idx];

        // 1. Allocate leaf for this file
        let leaf_alloc = AllocatedNum::alloc(file_cs.namespace(|| "leaf"), || Ok(witness.leaf))?;

        // Allocate file siblings
        let file_siblings_alloc: Vec<AllocatedNum<F>> = witness
            .file_siblings
            .iter()
            .enumerate()
            .map(|(i, s)| {
                AllocatedNum::alloc(file_cs.namespace(|| format!("file_sibling_{}", i)), || {
                    Ok(*s)
                })
            })
            .collect::<Result<_, _>>()?;

        // 2. Calculate challenge index for this file
        // Include file_idx to ensure different challenges per file (only for multi-file)
        let file_idx_field = if aggregated_tree_depth > 0 {
            F::from(file_idx as u64)
        } else {
            F::ZERO // Single-file doesn't use file_idx
        };
        let file_idx_alloc =
            AllocatedNum::alloc(file_cs.namespace(|| "file_index"), || Ok(file_idx_field))?;

        #[cfg(debug_assertions)]
        {
            debug!(
                "synthesize() - Calculating challenge for file_idx={}:",
                file_idx
            );
            if let (Some(seed_val), Some(state_val)) =
                (seed_public.get_value(), current_state.get_value())
            {
                debug!("  - Seed for this file: {:?}", seed_val);
                debug!("  - Current state: {:?}", state_val);
            }
        }

        // 2. Calculate challenge index for this file using per-file seed
        let challenge_with_idx = {
            let challenge = poseidon_hash_tagged_gadget(
                file_cs.namespace(|| "challenge_hash"),
                domain_tags::challenge(),
                seed_public,
                &current_state,
            )?;

            if aggregated_tree_depth > 0 {
                // Multi-file: use domain-separated hash to combine challenge with file_idx
                poseidon_hash_tagged_gadget(
                    file_cs.namespace(|| "challenge_with_file_idx"),
                    domain_tags::challenge_per_file(),
                    &challenge,
                    &file_idx_alloc,
                )?
            } else {
                // Single-file: use challenge directly without file_idx
                challenge
            }
        };

        // 3. Get binary decomposition of challenge and extract path bits
        let index_bits = {
            let mut bits_ns = file_cs.namespace(|| "challenge_with_idx_bits");
            challenge_with_idx.to_bits_le(&mut bits_ns)?
        };
        // Build exactly file_tree_depth bits, allocating false for padding (not constants!)
        let mut file_path_indices: Vec<Boolean> = Vec::with_capacity(file_tree_depth);
        for i in 0..file_tree_depth {
            if let Some(b) = index_bits.get(i) {
                file_path_indices.push(b.clone());
            } else {
                // Allocate padding bit as variable (not constant)
                let pad = AllocatedBit::alloc(
                    file_cs.namespace(|| format!("file_pad_bit_{}", i)),
                    Some(false),
                )
                .map_err(|_| SynthesisError::AssignmentMissing)?;
                file_path_indices.push(Boolean::from(pad));
            }
        }

        // 4. Verify Merkle path within this file's tree (gated for correct depth)
        // IMPORTANT: active_flags must be allocated variables (not constants) to maintain uniform constraint count
        // Boolean::Constant() would create different circuit shapes between parameter generation and proving
        let active_flags: Vec<Boolean> = (0..file_tree_depth)
            .map(|level| {
                let bit = AllocatedBit::alloc(
                    file_cs.namespace(|| format!("active_flag_file{}_lvl{}", file_idx, level)),
                    // Witness value determines gating, but shape stays constant
                    Some(level < witness.actual_depth),
                )
                .map_err(|_| SynthesisError::AssignmentMissing)?;
                Ok(Boolean::from(bit))
            })
            .collect::<Result<Vec<Boolean>, SynthesisError>>()?;

        // Gating logic: only process slots with public_depth > 0
        // This prevents padding files from being processed regardless of slot position
        let public_depth_bits = {
            let mut bits_ns = file_cs.namespace(|| "public_depth_bits");
            depth_public.to_bits_le(&mut bits_ns)?
        };

        // Check if public_depth > 0 by OR-ing all depth bits
        let mut depth_is_positive = Boolean::constant(false);
        for (bit_idx, bit) in public_depth_bits.iter().enumerate() {
            depth_is_positive = Boolean::or(
                file_cs.namespace(|| format!("depth_positive_or_file{}_bit{}", file_idx, bit_idx)),
                &depth_is_positive,
                bit,
            )?;
        }

        let gate_for_slot = depth_is_positive;

        let computed_file_root = verify_merkle_path_gated(
            file_cs.namespace(|| "verify_file_merkle"),
            &leaf_alloc,
            &file_siblings_alloc,
            &file_path_indices,
            Some(&active_flags),
            file_tree_depth,
        )?;

        #[cfg(debug_assertions)]
        {
            if let Some(computed_val) = computed_file_root.get_value() {
                debug!("synthesize() - Computed file root: {:?}", computed_val);
            }
        }

        // Compute declared depth as sum of active_flags
        let depth_num = if active_flags.is_empty() {
            // Handle edge case: file_tree_depth = 0
            AllocatedNum::alloc(file_cs.namespace(|| "depth_direct"), || {
                Ok(F::from(witness.actual_depth as u64))
            })?
        } else {
            let mut sum_active =
                AllocatedNum::alloc(file_cs.namespace(|| "sum_active_init"), || Ok(F::ZERO))?;
            for (j, flag) in active_flags.iter().enumerate() {
                let new_sum = AllocatedNum::alloc(
                    file_cs.namespace(|| format!("sum_active_file{}_lvl{}", file_idx, j)),
                    || {
                        let cur = sum_active
                            .get_value()
                            .ok_or(SynthesisError::AssignmentMissing)?;
                        let bit_val = match flag {
                            Boolean::Is(b) => b.get_value().unwrap_or(false),
                            Boolean::Not(b) => !b.get_value().unwrap_or(false),
                            Boolean::Constant(c) => *c,
                        };
                        Ok(cur + if bit_val { F::ONE } else { F::ZERO })
                    },
                )?;
                sum_active = new_sum;
            }

            // Enforce computed depth equals public depth
            file_cs.enforce(
                || format!("depth_equals_public_file{}", file_idx),
                |lc| lc + sum_active.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + depth_public.get_variable(),
            );
            sum_active
        };

        // Compute rc = Poseidon(TAG_RC, root, depth) for this file
        let rc = poseidon_hash_tagged_gadget(
            file_cs.namespace(|| "compute_rc"),
            domain_tags::root_commitment(),
            &computed_file_root,
            &depth_num,
        )?;

        if aggregated_tree_depth > 0 {
            // Multi-file case: verify rc is in aggregated tree at public ledger_index

            // Get the public ledger index for this slot
            let ledger_index_public = ledger_indices_public[file_idx];

            // Decompose public ledger index to bits for Merkle path verification
            let ledger_index_bits = {
                let mut bits_ns = file_cs.namespace(|| "ledger_index_bits");
                ledger_index_public.to_bits_le(&mut bits_ns)?
            };

            // Take only the bits needed for aggregated tree depth
            let agg_path_indices: Vec<Boolean> = ledger_index_bits
                .iter()
                .take(aggregated_tree_depth)
                .cloned()
                .collect();

            // === PHASE 2: Removed ledger index range checks ===
            // Phase 2: Rely on verifier-provided public indices (already range-checked by verifier)

            // Allocate aggregation siblings from witness
            let agg_siblings_alloc: Vec<AllocatedNum<F>> = witness
                .agg_siblings
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    AllocatedNum::alloc(file_cs.namespace(|| format!("agg_sibling_{}", i)), || {
                        Ok(*s)
                    })
                })
                .collect::<Result<_, _>>()?;

            // Verify that rc is in the aggregated tree at the public ledger index
            let computed_agg_root = verify_aggregation_path_gated(
                file_cs.namespace(|| "verify_ledger_membership"),
                &rc, // Verify rc (not just root) is in the ledger
                &agg_siblings_alloc,
                &agg_path_indices,
                aggregated_tree_depth,
            )?;

            // Verify aggregated root matches public input (gated by gate_for_slot)
            // Constraint: gate_for_slot * (computed_agg_root - public_root) = 0
            file_cs.enforce(
                || "aggregated_root_matches_gated",
                |lc| lc + &gate_for_slot.lc(CS::one(), F::ONE),
                |lc| lc + computed_agg_root.get_variable() - root.get_variable(),
                |lc| lc,
            );
        } else {
            // Single-file case: computed root should match public root directly (gated by gate_for_slot)
            file_cs.enforce(
                || "single_file_root_matches_gated",
                |lc| lc + &gate_for_slot.lc(CS::one(), F::ONE),
                |lc| lc + computed_file_root.get_variable() - root.get_variable(),
                |lc| lc,
            );
        }

        // 6. Update state with this file's leaf
        #[cfg(debug_assertions)]
        {
            if let (Some(state_val), Some(leaf_val)) =
                (current_state.get_value(), leaf_alloc.get_value())
            {
                debug!(
                    "Circuit state update file {}: H_state({:?}, {:?})",
                    file_idx, state_val, leaf_val
                );
            }
        }

        // Conditionally update state based on gate_for_slot with domain separation
        let updated_state = poseidon_hash_tagged_gadget(
            file_cs.namespace(|| "state_update"),
            domain_tags::state_update(),
            &current_state,
            &leaf_alloc,
        )?;

        // Gate the state update: if gate_for_slot, use updated_state; otherwise, keep current_state
        current_state = conditional_select(
            file_cs.namespace(|| "gate_state_update"),
            &gate_for_slot,
            &current_state, // if_false: when not active, keep current state
            &updated_state, // if_true: when active, use updated state
        )?;

        // Expose the challenged leaf as public output (gated by gate_for_slot)
        // Allocate a canonical zero for dummy slots
        let zero = AllocatedNum::alloc(file_cs.namespace(|| "zero"), || Ok(F::ZERO))?;

        // Select: leaf_pub = gate_for_slot ? leaf_alloc : zero
        let leaf_pub = conditional_select(
            file_cs.namespace(|| "public_leaf_select"),
            &gate_for_slot,
            &zero,       // if_false: when not active, output zero
            &leaf_alloc, // if_true: when active, output the actual leaf
        )?;

        public_leaf_values.push(leaf_pub);

        #[cfg(debug_assertions)]
        {
            if let Some(new_state) = current_state.get_value() {
                debug!("  = {:?}", new_state);
            }
        }
    } // End of file loop

    // Security comes from public depth binding per slot

    // Verifier provides public indices and ensures they are valid
    // Circuit trusts verifier-provided indices (no ordering constraints)

    // Security comes from public depth binding and rc membership in ledger

    // Create fresh output variables with equality constraints
    // This ensures Nova properly threads state across recursive steps
    let root_out = AllocatedNum::alloc(cs.namespace(|| "root_out"), || {
        root.get_value().ok_or(SynthesisError::AssignmentMissing)
    })?;

    // Carry forward all ledger indices
    let mut ledger_indices_out = Vec::new();
    for (i, idx) in ledger_indices_public.iter().enumerate() {
        let idx_out =
            AllocatedNum::alloc(cs.namespace(|| format!("ledger_index_out_{}", i)), || {
                idx.get_value().ok_or(SynthesisError::AssignmentMissing)
            })?;

        ledger_indices_out.push(idx_out);
    }

    // Carry forward all depths
    let mut depths_out = Vec::new();
    for (i, depth) in depths_public.iter().enumerate() {
        let depth_out = AllocatedNum::alloc(cs.namespace(|| format!("depth_out_{}", i)), || {
            depth.get_value().ok_or(SynthesisError::AssignmentMissing)
        })?;

        depths_out.push(depth_out);
    }

    // Carry forward all seeds
    let mut seeds_out = Vec::new();
    for (i, seed) in seeds_public.iter().enumerate() {
        let seed_out = AllocatedNum::alloc(cs.namespace(|| format!("seed_out_{}", i)), || {
            seed.get_value().ok_or(SynthesisError::AssignmentMissing)
        })?;

        seeds_out.push(seed_out);
    }

    // Build output vector: [root_out, current_state, ledger_indices..., depths..., seeds..., leaves...]
    let mut outputs = vec![root_out, current_state];
    outputs.extend(ledger_indices_out);
    outputs.extend(depths_out);
    outputs.extend(seeds_out);
    outputs.extend(public_leaf_values);

    Ok(outputs)
}
