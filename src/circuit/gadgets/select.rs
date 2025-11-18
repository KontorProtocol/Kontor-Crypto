//! Conditional selection gadget for circuit operations.
//!
//! This module provides conditional selection utilities for choosing between values in circuits.

use ff::PrimeField;
use nova_snark::frontend::{
    gadgets::{boolean::Boolean, num::AllocatedNum},
    ConstraintSystem, SynthesisError,
};

/// Conditionally selects between two AllocatedNums based on a Boolean condition.
/// If condition is false, returns `if_false`. If condition is true, returns `if_true`.
pub fn conditional_select<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    condition: &Boolean,
    if_false: &AllocatedNum<F>,
    if_true: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let result = AllocatedNum::alloc(cs.namespace(|| "conditional_select_result"), || {
        if condition.get_value().unwrap_or(false) {
            if_true.get_value().ok_or(SynthesisError::AssignmentMissing)
        } else {
            if_false
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)
        }
    })?;

    // Enforce: result = if_false + condition * (if_true - if_false)
    // Rearranging: result - if_false = condition * (if_true - if_false)
    cs.enforce(
        || "conditional_select_constraint",
        |lc| lc + &condition.lc(CS::one(), F::ONE),
        |lc| lc + if_true.get_variable() - if_false.get_variable(),
        |lc| lc + result.get_variable() - if_false.get_variable(),
    );

    Ok(result)
}
