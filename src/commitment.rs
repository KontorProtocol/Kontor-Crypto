//! Shared commitment calculation logic for API and circuit.
//!
//! This module ensures that commitment calculations are identical between
//! the external API and the internal circuit constraints, preventing
//! divergence bugs.

use crate::FieldElement;
use generic_array::typenum::U2;
use nova_snark::frontend::gadgets::poseidon::{
    IOPattern, PoseidonConstants, Simplex, Sponge, SpongeAPI, SpongeOp, SpongeTrait, Strength,
};
use once_cell::sync::Lazy;

/// Cached Poseidon constants for performance
static POSEIDON_CONSTANTS: Lazy<PoseidonConstants<FieldElement, U2>> =
    Lazy::new(|| Sponge::<FieldElement, U2>::api_constants(Strength::Standard));

/// Cached IO pattern for 2-input, 1-output Poseidon hashing
static IO_PATTERN: Lazy<IOPattern> =
    Lazy::new(|| IOPattern(vec![SpongeOp::Absorb(2), SpongeOp::Squeeze(1)]));

/// Domain separation tag values
/// These are distinct integers used to prevent hash collisions across different contexts
mod tag_values {
    pub const LEAF: u64 = 1;
    pub const NODE: u64 = 2;
    pub const CHALLENGE: u64 = 6;
    pub const STATE_UPDATE: u64 = 7;
    pub const ROOT_COMMITMENT: u64 = 8;
    pub const CHALLENGE_PER_FILE: u64 = 9;
    pub const CHALLENGE_ID: u64 = 10;
}

/// Domain separation tags for different Poseidon hash contexts
pub mod domain_tags {
    use super::tag_values;
    use ff::PrimeField;

    /// Tag for hashing leaf data in Merkle trees
    pub fn leaf<F: PrimeField>() -> F {
        F::from(tag_values::LEAF)
    }

    /// Tag for hashing internal Merkle tree nodes
    pub fn node<F: PrimeField>() -> F {
        F::from(tag_values::NODE)
    }

    /// Tag for challenge derivation
    pub fn challenge<F: PrimeField>() -> F {
        F::from(tag_values::CHALLENGE)
    }

    /// Tag for state updates
    pub fn state_update<F: PrimeField>() -> F {
        F::from(tag_values::STATE_UPDATE)
    }

    /// Tag for root commitment (rc = Poseidon(root, depth))
    pub fn root_commitment<F: PrimeField>() -> F {
        F::from(tag_values::ROOT_COMMITMENT)
    }

    /// Tag for per-file challenge derivation (combines challenge with file index)
    pub fn challenge_per_file<F: PrimeField>() -> F {
        F::from(tag_values::CHALLENGE_PER_FILE)
    }

    /// Tag for challenge ID derivation
    pub fn challenge_id<F: PrimeField>() -> F {
        F::from(tag_values::CHALLENGE_ID)
    }
}

/// Core Poseidon hash function for two field elements.
/// This is the single implementation used everywhere in the system.
/// Uses cached Poseidon constants for performance.
pub fn poseidon_hash2(left: FieldElement, right: FieldElement) -> FieldElement {
    let mut sponge = Sponge::<FieldElement, U2>::new_with_constants(&POSEIDON_CONSTANTS, Simplex);
    let mut acc = ();
    sponge.start(IO_PATTERN.clone(), None, &mut acc);
    SpongeAPI::absorb(&mut sponge, 2, &[left, right], &mut acc);
    let output = SpongeAPI::squeeze(&mut sponge, 1, &mut acc);
    sponge
        .finish(&mut acc)
        .expect("Poseidon sponge finish should not fail");

    output[0]
}

/// Domain-separated Poseidon hash with 3 inputs (tag + 2 data elements)
pub fn poseidon_hash_tagged(tag: FieldElement, x: FieldElement, y: FieldElement) -> FieldElement {
    // First hash tag with x, then hash result with y for consistent 2-arity
    let h1 = poseidon_hash2(tag, x);
    poseidon_hash2(h1, y)
}

/// Calculate the root commitment (rc) for a file.
/// rc = Poseidon(TAG_RC, root, depth)
///
/// This creates a unique commitment that binds both the root and depth,
/// preventing depth spoofing attacks.
pub fn calculate_root_commitment(root: FieldElement, depth: FieldElement) -> FieldElement {
    poseidon_hash_tagged(domain_tags::root_commitment(), root, depth)
}

/// Update state in the hash chain: state_new = Poseidon(TAG_STATE, state_old, leaf)
///
/// This creates a cryptographic chain linking proof steps together,
/// preventing replay and reordering attacks.
pub fn evolve_state(current_state: FieldElement, leaf: FieldElement) -> FieldElement {
    poseidon_hash_tagged(domain_tags::state_update(), current_state, leaf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FieldElement;

    #[test]
    fn test_domain_separation() {
        // Test that different domain tags produce different outputs for the same inputs
        let x = FieldElement::from(42u64);
        let y = FieldElement::from(123u64);

        // Hash with different tags
        let h_leaf = poseidon_hash_tagged(domain_tags::leaf(), x, y);
        let h_node = poseidon_hash_tagged(domain_tags::node(), x, y);
        let h_root_commitment = poseidon_hash_tagged(domain_tags::root_commitment(), x, y);
        let h_challenge = poseidon_hash_tagged(domain_tags::challenge(), x, y);
        let h_state = poseidon_hash_tagged(domain_tags::state_update(), x, y);

        // All should be different
        assert_ne!(h_leaf, h_node, "leaf and node hashes should differ");
        assert_ne!(
            h_leaf, h_root_commitment,
            "leaf and root_commitment hashes should differ"
        );
        assert_ne!(
            h_leaf, h_challenge,
            "leaf and challenge hashes should differ"
        );
        assert_ne!(h_leaf, h_state, "leaf and state hashes should differ");
        assert_ne!(
            h_node, h_root_commitment,
            "node and root_commitment hashes should differ"
        );
        assert_ne!(
            h_node, h_challenge,
            "node and challenge hashes should differ"
        );
        assert_ne!(h_node, h_state, "node and state hashes should differ");
        assert_ne!(
            h_root_commitment, h_challenge,
            "root_commitment and challenge hashes should differ"
        );
        assert_ne!(
            h_root_commitment, h_state,
            "root_commitment and state hashes should differ"
        );
        assert_ne!(
            h_challenge, h_state,
            "challenge and state hashes should differ"
        );

        // Test rc commitment calculation
        let root = FieldElement::from(1u64);
        let depth = FieldElement::from(10u64);

        let rc_commitment = calculate_root_commitment(root, depth);

        // Should be deterministic
        let rc_commitment2 = calculate_root_commitment(root, depth);
        assert_eq!(
            rc_commitment, rc_commitment2,
            "RC commitment should be deterministic"
        );
    }
}
