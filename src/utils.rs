//! Stateless helper functions for the Kontor PoR library

use crate::api::FieldElement;
use crate::commitment::{domain_tags, poseidon_hash_tagged};
use ff::PrimeField;

/// Convert up to 31 little-endian bytes into a field element using the
/// canonical byte representation expected by `ff::PrimeField::from_repr`.
///
/// This helper centralizes our endianness assumption and is covered by tests.
/// If upstream representation changes, tests will fail here.
pub fn bytes31_to_field_le<F: PrimeField>(bytes31: &[u8]) -> F {
    debug_assert!(bytes31.len() <= 31);
    let mut repr = <F as PrimeField>::Repr::default();
    let buf = repr.as_mut();
    // Copy provided bytes into the least-significant positions (little-endian)
    buf[..bytes31.len()].copy_from_slice(bytes31);
    F::from_repr(repr).expect("31-byte chunks should always fit in the field")
}

/// Convert a field element to its first 31 little-endian bytes.
/// This is the inverse of `bytes31_to_field_le` for 31-byte inputs.
pub fn field_to_bytes31_le<F: PrimeField>(element: &F) -> [u8; 31] {
    let repr = element.to_repr();
    let bytes = repr.as_ref();
    let mut out = [0u8; 31];
    out.copy_from_slice(&bytes[..31]);
    out
}

/// Utility function to derive a leaf index from a hash value using least-significant bits.
/// This extracts the first `depth` bits from the hash in little-endian order.
pub fn derive_index_from_bits<F: ff::PrimeField>(hash: F, depth: usize) -> usize {
    if depth == 0 {
        return 0;
    }

    let repr = hash.to_repr();
    let bytes = repr.as_ref();
    let mut idx: usize = 0;
    let mut bits_taken = 0;
    let mut byte_i = 0;
    let mut bit_i = 0;

    while bits_taken < depth {
        let b = *bytes.get(byte_i).unwrap_or(&0);
        let bit = (b >> bit_i) & 1;
        idx |= (bit as usize) << bits_taken;
        bits_taken += 1;
        bit_i += 1;
        if bit_i == 8 {
            bit_i = 0;
            byte_i += 1;
        }
    }

    idx
}

/// Convert a field element (representing a leaf) back to its 31-byte little-endian representation.
/// Wrapper maintained for compatibility; uses `field_to_bytes31_le` internally.
pub fn leaf_to_bytes31<F: ff::PrimeField>(leaf: &F) -> [u8; 31] {
    field_to_bytes31_le(leaf)
}

/// Derive an unbiased index in [0, leaf_count) from a field element by
/// rejection sampling. Falls back to rehashing with Poseidon and a counter
/// under the challenge domain tag to obtain new samples when needed.
///
/// For power-of-two `leaf_count`, this reduces to extracting the low bits.
///
/// # Security
///
/// Includes a maximum iteration limit to prevent theoretical infinite loops,
/// though cryptographically this should never occur with a sound hash function.
pub fn derive_index_unbiased(hash: FieldElement, leaf_count: usize) -> usize {
    assert!(leaf_count > 0, "leaf_count must be positive");

    // Fast path: power of two → exact bit-extraction
    if leaf_count.is_power_of_two() {
        let depth = leaf_count.trailing_zeros() as usize;
        return derive_index_from_bits(hash, depth);
    }

    const MAX_REJECTION_SAMPLES: u64 = 1000;
    let bound = leaf_count.next_power_of_two();
    let bits_needed = bound.trailing_zeros() as usize;

    let mut sample = hash;
    let mut counter: u64 = 0;

    while counter < MAX_REJECTION_SAMPLES {
        let candidate = derive_index_from_bits(sample, bits_needed);
        if candidate < leaf_count {
            return candidate;
        }
        counter += 1;
        let ctr_fe = FieldElement::from(counter);
        sample = poseidon_hash_tagged(domain_tags::challenge(), sample, ctr_fe);
    }

    // Fallback: if rejection sampling fails (cryptographically should never happen),
    // use modulo as last resort
    let final_candidate = derive_index_from_bits(sample, bits_needed);
    final_candidate % leaf_count
}

/// Single place for challenge → leaf index derivation logic.
/// This eliminates duplication between prove and verify functions.
///
/// # Arguments
/// * `file_idx` - Index of the file being challenged (0 for single-file)
/// * `file_depth` - Depth of the file's Merkle tree
/// * `seed` - Deterministic seed for challenge generation
/// * `local_state` - Current state in the hash chain
/// * `is_multi_file` - Whether this is a multi-file proof (affects domain separation)
///
/// # Returns
/// The derived leaf index for this file
pub fn derive_leaf_index_for_file(
    file_idx: usize,
    file_depth: usize,
    seed: FieldElement,
    local_state: FieldElement,
    is_multi_file: bool,
) -> usize {
    let ch = poseidon_hash_tagged(domain_tags::challenge(), seed, local_state);
    let per_file = if is_multi_file {
        poseidon_hash_tagged(
            domain_tags::challenge_per_file(),
            ch,
            FieldElement::from(file_idx as u64),
        )
    } else {
        ch
    };

    derive_index_unbiased(per_file, 1usize << file_depth)
}
