//! Poseidon hash gadgets for circuit operations.
//!
//! This module contains domain-separated Poseidon hash implementations for use within circuits.

use ff::PrimeField;
use ff::PrimeFieldBits;
use generic_array::typenum::U2;
use nova_snark::frontend::{
    gadgets::{
        num::AllocatedNum,
        poseidon::{
            Elt, IOPattern, Simplex, Sponge, SpongeAPI, SpongeCircuit, SpongeOp, SpongeTrait,
            Strength,
        },
    },
    ConstraintSystem, SynthesisError,
};
use once_cell::sync::Lazy;

/// Cached IO pattern for 3-input circuit Poseidon hashing
static CIRCUIT_IO_PATTERN_3: Lazy<IOPattern> =
    Lazy::new(|| IOPattern(vec![SpongeOp::Absorb(3), SpongeOp::Squeeze(1)]));

/// Domain-separated Poseidon hash gadget for in-circuit use
/// Optimized to use a single 3-input hash operation
pub fn poseidon_hash_tagged_gadget<F: PrimeField + PrimeFieldBits, CS: ConstraintSystem<F>>(
    mut cs: CS,
    tag: F, // Should be a constant
    x: &AllocatedNum<F>,
    y: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let poseidon_constants = Sponge::<F, U2>::api_constants(Strength::Standard);
    let io_pattern = &*CIRCUIT_IO_PATTERN_3;

    let mut hash_ns = cs.namespace(|| "hash_tag_x_y");
    let mut sponge = SpongeCircuit::new_with_constants(&poseidon_constants, Simplex);

    // Allocate tag as a constant
    let tag_alloc = AllocatedNum::alloc(hash_ns.namespace(|| "tag"), || Ok(tag))?;
    // Constrain tag to be the expected constant
    hash_ns.enforce(
        || "tag_is_constant",
        |lc| lc + tag_alloc.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + (tag, CS::one()),
    );

    // Hash all three inputs in one operation
    let elts = [
        Elt::Allocated(tag_alloc),
        Elt::Allocated(x.clone()),
        Elt::Allocated(y.clone()),
    ];
    sponge.start(io_pattern.to_owned(), None, &mut hash_ns);
    SpongeAPI::absorb(&mut sponge, 3, &elts, &mut hash_ns);
    let output = SpongeAPI::squeeze(&mut sponge, 1, &mut hash_ns);
    sponge
        .finish(&mut hash_ns)
        .map_err(|_| SynthesisError::Unsatisfiable)?;
    let result = Elt::ensure_allocated(&output[0], &mut hash_ns, true)?;

    Ok(result)
}
