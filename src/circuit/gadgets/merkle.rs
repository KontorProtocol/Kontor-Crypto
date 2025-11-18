//! Merkle path verification gadgets for circuits.
//!
//! This module provides gated Merkle path verification for both file trees
//! and aggregation trees within the Nova circuit.

use ff::PrimeField;
use ff::PrimeFieldBits;
use nova_snark::frontend::{
    gadgets::{boolean::Boolean, num::AllocatedNum},
    ConstraintSystem, SynthesisError,
};

use super::hash::{conditional_select, poseidon_hash_tagged_gadget};
use crate::commitment::domain_tags;

/// Generic Merkle path verification with gating support for uniform circuit structure.
/// This unified function handles both file tree and aggregation tree verification.
///
/// # Arguments
/// * `namespace_prefix` - Prefix for constraint namespaces ("merkle" or "agg_merkle")
/// * `is_active_flags` - Optional flags for gating (None creates always-active flags)
/// * `max_depth` - Maximum depth to process for uniform circuit structure
pub fn verify_gated_merkle_path<F: PrimeField + PrimeFieldBits, CS: ConstraintSystem<F>>(
    mut cs: CS,
    leaf: &AllocatedNum<F>,
    siblings: &[AllocatedNum<F>],
    path_indices: &[Boolean],
    is_active_flags: Option<&[Boolean]>,
    max_depth: usize,
    namespace_prefix: &str,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let mut current_hash = leaf.clone();

    // Process exactly max_depth levels for uniform structure
    for i in 0..max_depth {
        let mut step_cs = cs.namespace(|| format!("{}_step_{}", namespace_prefix, i));

        // Get the activity flag for this level
        // If is_active_flags is None, all levels are active (for aggregation)
        // If is_active_flags is Some, use the provided flags (for file trees)
        let is_active = if let Some(flags) = is_active_flags {
            // File tree case: use provided gating flags with fallback
            flags.get(i).cloned().unwrap_or(Boolean::constant(false))
        } else {
            // Aggregation tree case: all levels within depth are active
            Boolean::constant(i < max_depth)
        };

        // Get sibling and path bit (use dummy values if needed)
        let sibling = if i < siblings.len() {
            siblings[i].clone()
        } else {
            // Allocate dummy sibling for padding
            AllocatedNum::alloc(step_cs.namespace(|| "dummy_sibling"), || Ok(F::ZERO))?
        };

        let path_bit = if i < path_indices.len() {
            path_indices[i].clone()
        } else {
            // Dummy path bit
            Boolean::constant(false)
        };

        // Compute hash for this level
        let left = conditional_select(
            step_cs.namespace(|| "select_left"),
            &path_bit,
            &current_hash,
            &sibling,
        )?;
        let right = conditional_select(
            step_cs.namespace(|| "select_right"),
            &path_bit,
            &sibling,
            &current_hash,
        )?;

        // Use domain-separated hashing for Merkle nodes
        let level_hash = poseidon_hash_tagged_gadget(
            step_cs.namespace(|| "hash_nodes"),
            domain_tags::node(),
            &left,
            &right,
        )?;

        // Conditionally update current_hash based on is_active
        // If active: current_hash = level_hash (update with new hash)
        // If inactive: current_hash = current_hash (keep unchanged)
        current_hash = conditional_select(
            step_cs.namespace(|| "select_output"),
            &is_active,
            &current_hash, // if_false: when inactive, keep current
            &level_hash,   // if_true: when active, use new hash
        )?;
    }

    Ok(current_hash)
}

/// File tree Merkle path verification with gating support.
/// This is a wrapper around the generic verification function.
pub fn verify_merkle_path_gated<F: PrimeField + PrimeFieldBits, CS: ConstraintSystem<F>>(
    cs: CS,
    leaf: &AllocatedNum<F>,
    siblings: &[AllocatedNum<F>],
    path_indices: &[Boolean],
    is_active_flags: Option<&[Boolean]>,
    max_depth: usize,
) -> Result<AllocatedNum<F>, SynthesisError> {
    verify_gated_merkle_path(
        cs,
        leaf,
        siblings,
        path_indices,
        is_active_flags,
        max_depth,
        "merkle",
    )
}

/// Aggregation tree Merkle path verification with uniform structure.
/// This is a wrapper around the generic verification function.
pub fn verify_aggregation_path_gated<F: PrimeField + PrimeFieldBits, CS: ConstraintSystem<F>>(
    cs: CS,
    leaf: &AllocatedNum<F>,
    siblings: &[AllocatedNum<F>],
    path_indices: &[Boolean],
    depth: usize,
) -> Result<AllocatedNum<F>, SynthesisError> {
    verify_gated_merkle_path(
        cs,
        leaf,
        siblings,
        path_indices,
        None, // No gating flags - all levels within depth are active
        depth,
        "agg_merkle",
    )
}
