//! Merkle tree construction for Kontor PoR (Poseidon, domain-tagged).

use crate::config;
use crate::error::{CoreError, Result};
use crate::poseidon::domain_tags;
use crate::poseidon::poseidon_hash_tagged;
use crate::utils::bytes31_to_field_le;
use ff::Field;
use serde::{Deserialize, Serialize};

use crate::poseidon::FieldElement;

/// Hashes two field elements for internal nodes (domain-separated).
pub fn hash_node(left: FieldElement, right: FieldElement) -> FieldElement {
    poseidon_hash_tagged(domain_tags::node(), left, right)
}

/// Hashes two field elements for leaf data (domain-separated).
pub fn hash_leaf_data(left: FieldElement, right: FieldElement) -> FieldElement {
    poseidon_hash_tagged(domain_tags::leaf(), left, right)
}

/// Converts up to 31 bytes into a leaf field element (little-endian).
pub fn get_leaf_hash(data: &[u8]) -> Result<FieldElement> {
    if data.len() > config::CHUNK_SIZE_BYTES {
        return Err(CoreError::InvalidInput(format!(
            "Data chunk too large for PoR: {} bytes (max {})",
            data.len(),
            config::CHUNK_SIZE_BYTES
        )));
    }
    if data.is_empty() {
        return Ok(FieldElement::ZERO);
    }
    Ok(bytes31_to_field_le::<FieldElement>(data))
}

/// Merkle tree with layers from leaves (layer 0) to root.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MerkleTree {
    pub layers: Vec<Vec<FieldElement>>,
}

impl MerkleTree {
    pub fn root(&self) -> FieldElement {
        self.layers
            .last()
            .and_then(|layer| layer.first())
            .copied()
            .unwrap_or(FieldElement::ZERO)
    }
}

/// Builds a Merkle tree from pre-computed leaves.
pub fn build_tree_from_leaves(leaves: &[FieldElement]) -> Result<MerkleTree> {
    if leaves.is_empty() {
        return Ok(MerkleTree {
            layers: vec![vec![FieldElement::ZERO]],
        });
    }
    let mut layers = vec![leaves.to_vec()];
    while layers
        .last()
        .ok_or_else(|| CoreError::MerkleTree("build_tree_from_leaves: empty layers".to_string()))?
        .len()
        > 1
    {
        let current_layer = layers.last().ok_or_else(|| {
            CoreError::MerkleTree("build_tree_from_leaves: empty during construction".to_string())
        })?;
        let mut next_layer = Vec::new();
        for pair in current_layer.chunks(2) {
            if pair.len() == 2 {
                next_layer.push(hash_node(pair[0], pair[1]));
            } else {
                next_layer.push(hash_node(pair[0], pair[0]));
            }
        }
        layers.push(next_layer);
    }
    Ok(MerkleTree { layers })
}

/// Builds a Merkle tree from data chunks (each ≤ 31 bytes).
pub fn build_tree(data_chunks: &[Vec<u8>]) -> Result<(MerkleTree, FieldElement)> {
    if data_chunks.is_empty() {
        let leaf = FieldElement::ZERO;
        return Ok((
            MerkleTree {
                layers: vec![vec![leaf]],
            },
            leaf,
        ));
    }
    let leaves: Vec<FieldElement> = data_chunks
        .iter()
        .map(|chunk| get_leaf_hash(chunk))
        .collect::<Result<Vec<_>>>()?;
    let tree = build_tree_from_leaves(&leaves)?;
    let root = tree.root();
    Ok((tree, root))
}

/// Merkle proof for circuit verification (leaf, siblings, path indices).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitMerkleProof {
    pub leaf: FieldElement,
    pub siblings: Vec<FieldElement>,
    pub path_indices: Vec<bool>,
}

/// Generates a padded Merkle proof for the leaf at `leaf_index` to `depth`.
pub fn get_padded_proof_for_leaf(
    tree: &MerkleTree,
    leaf_index: usize,
    depth: usize,
) -> Result<CircuitMerkleProof> {
    let num_leaves = tree.layers.first().map(|l| l.len()).unwrap_or(0);
    let leaf = tree
        .layers
        .first()
        .and_then(|layer| layer.get(leaf_index))
        .copied()
        .ok_or(CoreError::IndexOutOfBounds {
            index: leaf_index,
            length: num_leaves,
        })?;
    let mut siblings = Vec::new();
    let mut path_indices = Vec::new();
    let mut current_index = leaf_index;
    for level in 0..tree.layers.len().saturating_sub(1) {
        let current_layer = &tree.layers[level];
        let is_right_node = current_index % 2 == 1;
        let sibling_index = if is_right_node {
            current_index - 1
        } else {
            current_index + 1
        };
        let sibling = current_layer
            .get(sibling_index)
            .copied()
            .unwrap_or(current_layer[current_index]);
        siblings.push(sibling);
        path_indices.push(is_right_node);
        current_index /= 2;
    }
    while siblings.len() < depth {
        siblings.push(FieldElement::ZERO);
        path_indices.push(false);
    }
    siblings.truncate(depth);
    path_indices.truncate(depth);
    Ok(CircuitMerkleProof {
        leaf,
        siblings,
        path_indices,
    })
}

/// Verifies a Merkle proof against a root (non-circuit).
pub fn verify_merkle_proof_in_place(root: FieldElement, proof: &CircuitMerkleProof) -> bool {
    let mut current_hash = proof.leaf;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        let path_bit = proof.path_indices.get(i).copied().unwrap_or(false);
        if path_bit {
            current_hash = hash_node(*sibling, current_hash);
        } else {
            current_hash = hash_node(current_hash, *sibling);
        }
    }
    current_hash == root
}
