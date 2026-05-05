//! Merkle tree implementation for the Kontor PoR system.
//!
//! This module re-exports core Merkle primitives and provides thin wrappers
//! that convert `CoreError` to `KontorPoRError`.

use nova_snark::provider::PallasEngine;
use nova_snark::traits::Engine;

use super::KontorPoRError;

/// A type alias for the scalar field of the Pallas curve.
pub type F = <PallasEngine as Engine>::Scalar;

pub use kontor_crypto_core::merkle::{
    hash_leaf_data, hash_node, verify_merkle_proof_in_place, CircuitMerkleProof, MerkleTree,
};

/// Hashes two field elements using Poseidon (used in tests/primitives_merkle.rs).
pub fn poseidon_hash_pair(left: F, right: F) -> F {
    crate::poseidon::poseidon_hash2(left, right)
}

/// Converts a slice of raw bytes (max 31 bytes) into a single field element for use as a Merkle tree leaf.
pub fn get_leaf_hash(data: &[u8]) -> Result<F, KontorPoRError> {
    Ok(kontor_crypto_core::merkle::get_leaf_hash(data)?)
}

/// Builds a Poseidon-based Merkle tree from a slice of pre-computed leaves.
pub fn build_tree_from_leaves(leaves: &[F]) -> Result<MerkleTree, KontorPoRError> {
    Ok(kontor_crypto_core::merkle::build_tree_from_leaves(leaves)?)
}

/// Builds a Poseidon-based Merkle tree from the given data chunks.
pub fn build_tree(data_chunks: &[Vec<u8>]) -> Result<(MerkleTree, F), KontorPoRError> {
    Ok(kontor_crypto_core::merkle::build_tree(data_chunks)?)
}

/// Generates a `CircuitMerkleProof` for the leaf at `leaf_index` and pads it to `depth`.
pub fn get_padded_proof_for_leaf(
    tree: &MerkleTree,
    leaf_index: usize,
    depth: usize,
) -> Result<CircuitMerkleProof, KontorPoRError> {
    Ok(kontor_crypto_core::merkle::get_padded_proof_for_leaf(
        tree, leaf_index, depth,
    )?)
}
