//! Merkle tree implementation for the Kontor PoR system.
//!
//! This module provides functions for building and verifying Poseidon-based Merkle trees.
//! It includes helpers for hashing data into field elements (`get_leaf_hash`), constructing
//! the tree (`build_tree`), and generating proofs of inclusion (`get_padded_proof_for_leaf`).

use nova_snark::provider::PallasEngine;
use nova_snark::traits::Engine;
use ff::Field;
use serde::{Deserialize, Serialize};

use super::KontorPoRError;
use crate::commitment::domain_tags;
use crate::commitment::poseidon_hash_tagged;
use crate::config;
use crate::utils::bytes31_to_field_le;

/// A type alias for the scalar field of the Pallas curve.
pub type F = <PallasEngine as Engine>::Scalar;

/// Hashes two field elements using Poseidon.
/// This is now a wrapper around the centralized implementation in commitment.rs.
pub fn poseidon_hash_pair(left: F, right: F) -> F {
    crate::commitment::poseidon_hash2(left, right)
}

/// Domain-separated hash for Merkle tree nodes
pub fn hash_node(left: F, right: F) -> F {
    poseidon_hash_tagged(domain_tags::node(), left, right)
}

/// Domain-separated hash for leaf data
pub fn hash_leaf_data(left: F, right: F) -> F {
    poseidon_hash_tagged(domain_tags::leaf(), left, right)
}

/// Converts a slice of raw bytes (max 31 bytes) into a single field element for use as a Merkle tree leaf.
///
/// **SECURITY CRITICAL**: This function enforces that `data.len() <= 31 bytes`. This ensures each
/// Merkle leaf directly encodes the actual retrievable data rather than a hash of the data.
/// This prevents the "hash-only attack" where provers store only commitments instead of actual data.
///
/// The process:
/// 1. Validates that data.len() <= CHUNK_SIZE_BYTES (31 bytes)
/// 2. Directly encodes the bytes as a field element using little-endian byte order
/// 3. Returns the field element WITHOUT hashing (the leaf IS the data)
///
/// This approach ensures Proof of Retrievability: to prove knowledge of a leaf, the prover
/// must possess the actual 31 bytes of data, not just a hash.
///
/// # Errors
///
/// Returns `InvalidInput` error if data exceeds 31 bytes (security violation).
pub fn get_leaf_hash(data: &[u8]) -> Result<F, KontorPoRError> {
    // Enforce maximum leaf size
    // Each Merkle leaf must directly encode retrievable data (not a hash of data).
    if data.len() > config::CHUNK_SIZE_BYTES {
        return Err(KontorPoRError::InvalidInput(format!(
            "Data chunk too large for secure PoR: {} bytes (max {}). \
             Larger chunks would be hashed, allowing provers to store only hashes \
             instead of retrievable data. Use 31-byte symbols from erasure encoding.",
            data.len(),
            config::CHUNK_SIZE_BYTES
        )));
    }

    // Handle empty data
    if data.is_empty() {
        return Ok(F::ZERO);
    }

    let element = bytes31_to_field_le::<F>(data);
    Ok(element)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
/// A Merkle tree implementation with layers stored from leaves (layer 0) to root.
///
/// The tree stores all layers explicitly, where:
/// - `layers[0]` contains the leaf nodes
/// - `layers[layers.len() - 1]` contains the root (single element)
///
/// Each internal layer contains the hash of pairs from the layer below.
pub struct MerkleTree {
    /// The layers of the tree, with layer 0 being the leaves and the last layer being the root.
    /// Each layer contains the hash values at that level of the tree.
    pub layers: Vec<Vec<F>>,
}

impl MerkleTree {
    /// Returns the root of the tree.
    pub fn root(&self) -> F {
        self.layers
            .last()
            .and_then(|layer| layer.first())
            .copied()
            .unwrap_or(F::ZERO) // Default to zero if tree is malformed
    }
}

/// Builds a Poseidon-based Merkle tree from a slice of pre-computed leaves.
/// This is the generic, core logic for tree construction.
pub fn build_tree_from_leaves(leaves: &[F]) -> Result<MerkleTree, KontorPoRError> {
    if leaves.is_empty() {
        return Ok(MerkleTree {
            layers: vec![vec![F::ZERO]],
        });
    }

    let mut layers = vec![leaves.to_vec()];

    // Build the tree bottom-up
    while layers
        .last()
        .ok_or_else(|| KontorPoRError::MerkleTree("build_tree_from_leaves: Tree layers should never be empty - internal error in tree construction".to_string()))?
        .len()
        > 1
    {
        let current_layer = layers.last().ok_or_else(|| {
            KontorPoRError::MerkleTree("build_tree_from_leaves: Tree layers should never be empty during layer construction - internal error".to_string())
        })?;
        let mut next_layer = Vec::new();

        // Process pairs of nodes
        for pair in current_layer.chunks(2) {
            if pair.len() == 2 {
                next_layer.push(hash_node(pair[0], pair[1]));
            } else {
                // Odd number of nodes - duplicate the last one by hashing it with itself
                next_layer.push(hash_node(pair[0], pair[0]));
            }
        }
        layers.push(next_layer);
    }

    Ok(MerkleTree { layers })
}

/// Builds a Poseidon-based Merkle tree from the given data chunks.
/// This function serves as a wrapper around the generic `build_tree_from_leaves`
/// by first converting the data chunks into leaves.
pub fn build_tree(data_chunks: &[Vec<u8>]) -> Result<(MerkleTree, F), KontorPoRError> {
    if data_chunks.is_empty() {
        let leaf = F::ZERO;
        let tree = MerkleTree {
            layers: vec![vec![leaf]],
        };
        return Ok((tree, leaf));
    }

    // Convert data chunks to field elements (leaves)
    let leaves: Vec<F> = data_chunks
        .iter()
        .map(|chunk| get_leaf_hash(chunk))
        .collect::<Result<Vec<_>, _>>()?;

    // Build the tree using the generic, core logic
    let tree = build_tree_from_leaves(&leaves)?;
    let root = tree.root();

    Ok((tree, root))
}

/// A helper struct to hold the witness components for a Merkle proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
/// A Merkle proof that can be used in a circuit to verify inclusion of a leaf.
///
/// Contains all the necessary information to verify that a leaf is included
/// in a Merkle tree with a given root.
pub struct CircuitMerkleProof {
    /// The leaf value being proven for inclusion.
    pub leaf: F,
    /// The sibling hashes needed to reconstruct the path from leaf to root.
    /// Length should equal the tree depth.
    pub siblings: Vec<F>,
    /// Boolean indicators for the path from leaf to root.
    /// `true` means the current node is on the right (so the sibling is on the left).
    /// `false` means the current node is on the left (so the sibling is on the right).
    pub path_indices: Vec<bool>,
}

/// Generates a `CircuitMerkleProof` for the leaf at `leaf_index` and pads it
/// to the specified `depth`.
///
/// Returns an error if the leaf index is out of bounds.
pub fn get_padded_proof_for_leaf(
    tree: &MerkleTree,
    leaf_index: usize,
    depth: usize,
) -> Result<CircuitMerkleProof, KontorPoRError> {
    let leaf = tree
        .layers
        .first()
        .and_then(|layer| layer.get(leaf_index))
        .copied()
        .ok_or_else(|| KontorPoRError::IndexOutOfBounds {
            index: leaf_index,
            length: tree.layers.first().map(|l| l.len()).unwrap_or(0),
        })?;
    let mut siblings = Vec::new();
    let mut path_indices = Vec::new();

    let mut current_index = leaf_index;

    // Walk up the tree from leaf to root
    for level in 0..tree.layers.len() - 1 {
        let current_layer = &tree.layers[level];
        let is_right_node = current_index % 2 == 1;

        let sibling_index = if is_right_node {
            current_index - 1
        } else {
            current_index + 1
        };

        // Get the sibling, or duplicate current node if no sibling exists
        let sibling = current_layer
            .get(sibling_index)
            .copied()
            .unwrap_or(current_layer[current_index]);

        siblings.push(sibling);
        path_indices.push(is_right_node);

        // Move to parent index
        current_index /= 2;
    }

    // Pad the proof to the required depth
    while siblings.len() < depth {
        siblings.push(F::ZERO);
        path_indices.push(false);
    }

    // Truncate if somehow we have too many (shouldn't happen with correct usage)
    siblings.truncate(depth);
    path_indices.truncate(depth);

    Ok(CircuitMerkleProof {
        leaf,
        siblings,
        path_indices,
    })
}

/// Verifies a `CircuitMerkleProof` against a given root.
/// This is a non-circuit implementation for direct verification.
pub fn verify_merkle_proof_in_place(root: F, proof: &CircuitMerkleProof) -> bool {
    let mut current_hash = proof.leaf;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        let path_bit = proof.path_indices.get(i).copied().unwrap_or(false);
        if path_bit {
            // Sibling is on the left
            current_hash = hash_node(*sibling, current_hash);
        } else {
            // Sibling is on the right
            current_hash = hash_node(current_hash, *sibling);
        }
    }
    current_hash == root
}
