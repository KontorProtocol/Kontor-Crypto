//! Hash gadgets for circuit operations.
//!
//! This module contains Poseidon hash implementations and conditional selection logic
//! used within the Nova circuit.

use ff::PrimeField;
use ff::PrimeFieldBits;
use generic_array::typenum::U2;
use nova_snark::frontend::{
    gadgets::{
        boolean::Boolean,
        num::AllocatedNum,
        poseidon::{
            Elt, IOPattern, Simplex, Sponge, SpongeAPI, SpongeCircuit, SpongeOp, SpongeTrait,
            Strength,
        },
    },
    ConstraintSystem, SynthesisError,
};
use once_cell::sync::Lazy;

/// Cached IO pattern for circuit Poseidon hashing
static CIRCUIT_IO_PATTERN: Lazy<IOPattern> =
    Lazy::new(|| IOPattern(vec![SpongeOp::Absorb(2), SpongeOp::Squeeze(1)]));

/// Domain-separated Poseidon hash gadget for in-circuit use
/// Uses cached IO pattern for performance
pub fn poseidon_hash_tagged_gadget<F: PrimeField + PrimeFieldBits, CS: ConstraintSystem<F>>(
    mut cs: CS,
    tag: F, // Should be a constant
    x: &AllocatedNum<F>,
    y: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let poseidon_constants = Sponge::<F, U2>::api_constants(Strength::Standard);
    let io_pattern = &*CIRCUIT_IO_PATTERN;

    // First hash tag with x
    let h1 = {
        let mut hash_ns = cs.namespace(|| "hash_tag_x");
        let mut sponge = SpongeCircuit::new_with_constants(&poseidon_constants, Simplex);
        let tag_alloc = AllocatedNum::alloc(hash_ns.namespace(|| "tag"), || Ok(tag))?;
        // Constrain tag to be the expected constant
        hash_ns.enforce(
            || "tag_is_constant",
            |lc| lc + tag_alloc.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + (tag, CS::one()),
        );
        let elts = [Elt::Allocated(tag_alloc), Elt::Allocated(x.clone())];
        sponge.start(io_pattern.to_owned(), None, &mut hash_ns);
        SpongeAPI::absorb(&mut sponge, 2, &elts, &mut hash_ns);
        let output = SpongeAPI::squeeze(&mut sponge, 1, &mut hash_ns);
        sponge
            .finish(&mut hash_ns)
            .map_err(|_| SynthesisError::Unsatisfiable)?;
        Elt::ensure_allocated(&output[0], &mut hash_ns, true)?
    };

    // Then hash h1 with y
    let result = {
        let mut hash_ns = cs.namespace(|| "hash_h1_y");
        let mut sponge = SpongeCircuit::new_with_constants(&poseidon_constants, Simplex);
        let elts = [Elt::Allocated(h1), Elt::Allocated(y.clone())];
        sponge.start(io_pattern.to_owned(), None, &mut hash_ns);
        SpongeAPI::absorb(&mut sponge, 2, &elts, &mut hash_ns);
        let output = SpongeAPI::squeeze(&mut sponge, 1, &mut hash_ns);
        sponge
            .finish(&mut hash_ns)
            .map_err(|_| SynthesisError::Unsatisfiable)?;
        Elt::ensure_allocated(&output[0], &mut hash_ns, true)?
    };

    Ok(result)
}

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
