//! File ledger for aggregated Merkle tree management.
//!
//! This module defines the `FileLedger`, which manages the aggregated Merkle tree
//! of file root commitments (rc values). It provides functionality for adding files,
//! persisting the ledger, and generating aggregation proofs.
//!
//! ## Canonical Index Ordering
//!
//! **INVARIANT**: Canonical file indices are determined by lexicographic ordering
//! of file identifiers in the `BTreeMap`. This ensures deterministic, stable indices:
//! - Index 0 = first file in lexicographic order
//! - Index i = i-th file in sorted key order
//! - Indices remain stable as long as files aren't removed
//!
//! The aggregated tree is built from rc values in this same key order, ensuring
//! that `get_canonical_index_for_rc()` returns the correct tree position.

use crate::merkle::{build_tree_from_leaves, get_padded_proof_for_leaf, MerkleTree, F};
use crate::KontorPoRError;
use ff::Field;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Entry for a single file in the ledger, combining all file information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// The Merkle root of this file
    pub root: F,
    /// The depth of this file's Merkle tree
    pub depth: usize,
    /// The root commitment (rc = H(TAG_RC, root, depth))
    pub rc: F,
}

/// Versioned wrapper for ledger serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerData {
    /// Format version for forward compatibility
    version: u16,
    /// The actual ledger data (unified file entries)
    files: BTreeMap<String, FileEntry>,
    /// Stored root for validation on load
    root: F,
    /// Historical roots retained for proof validation (keyed by block height).
    /// This is optional for backward compatibility with older serialized ledgers.
    #[serde(default)]
    historical_roots: BTreeMap<u64, [u8; 32]>,
}

/// The `FileLedger` manages the aggregated Merkle tree of all file roots.
/// It acts as the central, persistent state for the collection of files.
///
/// In Option 1, the ledger tree is built from rc values (root commitments)
/// where rc = Poseidon(TAG_RC, root, depth), not raw roots.
///
/// ## Historical Root Tracking
///
/// The ledger maintains a set of historical roots for proof validation.
/// When files are added/removed, the old root is preserved in `historical_roots`.
/// Verifiers check that a proof's `ledger_root` is in this set before accepting it.
/// This enables cross-block aggregation without proof regeneration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLedger {
    /// Unified map from file identifier to complete file information.
    /// BTreeMap ensures deterministic ordering for canonical ledger construction.
    pub files: BTreeMap<String, FileEntry>,
    /// The aggregated Merkle tree built from rc values (not raw roots).
    #[serde(skip)]
    pub tree: MerkleTree,
    /// Accepted historical roots for proof validation, keyed by block height.
    ///
    /// Proofs generated against a ledger root are valid as long as that root is either:
    /// - the current root, or
    /// - present in this map.
    ///
    /// Callers are expected to prune this map according to their consensus rules
    /// (typically a sliding window tied to block height).
    #[serde(default)]
    pub historical_roots: BTreeMap<u64, [u8; 32]>,
}

impl Default for FileLedger {
    fn default() -> Self {
        Self {
            files: BTreeMap::new(),
            tree: MerkleTree {
                layers: vec![vec![]],
            },
            historical_roots: BTreeMap::new(),
        }
    }
}

impl FileLedger {
    /// Creates a new, empty `FileLedger`.
    pub fn new() -> Self {
        Self::default()
    }

    // --- Historical Root Management ---

    /// Returns the current root of the aggregated Merkle tree.
    pub fn root(&self) -> F {
        self.tree.root()
    }

    /// Records the current root as a valid historical root at the given block height.
    ///
    /// Call this before modifying the ledger (e.g., before adding files) to preserve the
    /// old root for proof validation.
    ///
    /// Using a height-keyed map makes pruning unambiguous: old roots are invalidated by
    /// time (block height), not by the number of file additions.
    pub fn record_current_root(&mut self, block_height: u64) {
        use ff::PrimeField;
        let root = self.tree.root();
        let repr: [u8; 32] = root.to_repr().into();
        self.historical_roots.insert(block_height, repr);
    }

    /// Checks if a root is valid (either current or in historical set).
    /// Use this to validate `proof.ledger_root` before verification.
    pub fn is_valid_root(&self, root: F) -> bool {
        use ff::PrimeField;
        // Current root is always valid
        if root == self.tree.root() {
            return true;
        }
        // Check historical roots
        let repr: [u8; 32] = root.to_repr().into();
        self.historical_roots.values().any(|r| r == &repr)
    }

    /// Prunes historical roots strictly older than `min_block_height`.
    ///
    /// After this call, the retained set satisfies: `height >= min_block_height`.
    pub fn prune_historical_roots_older_than(&mut self, min_block_height: u64) {
        self.historical_roots
            .retain(|h, _root| *h >= min_block_height);
    }

    /// Keeps only the newest `max_entries` historical roots by block height.
    ///
    /// This is a size-based safeguard. Consensus rules should generally prune by height
    /// using `prune_historical_roots_older_than`.
    pub fn prune_historical_roots_keep_last(&mut self, max_entries: usize) {
        while self.historical_roots.len() > max_entries {
            if let Some((&oldest, _)) = self.historical_roots.iter().next() {
                self.historical_roots.remove(&oldest);
            } else {
                break;
            }
        }
    }

    /// Clears all historical roots.
    ///
    /// Use with caution: this invalidates proofs against old roots immediately.
    pub fn clear_historical_roots(&mut self) {
        self.historical_roots.clear();
    }

    /// Returns the number of historical roots being tracked.
    pub fn historical_root_count(&self) -> usize {
        self.historical_roots.len()
    }

    // --- File Management ---

    /// Adds a new file to the ledger and rebuilds the aggregated tree.
    ///
    /// # Arguments
    ///
    /// * `file_id` - A unique identifier for the file.
    /// * `file_root` - The Merkle root of the file to be added.
    /// * `file_depth` - The depth of the file's Merkle tree (for rc computation).
    pub fn add_file(
        &mut self,
        file_id: String,
        file_root: F,
        file_depth: usize,
    ) -> Result<(), KontorPoRError> {
        use crate::poseidon::calculate_root_commitment;

        let rc = calculate_root_commitment(file_root, F::from(file_depth as u64));
        let entry = FileEntry {
            root: file_root,
            depth: file_depth,
            rc,
        };

        self.files.insert(file_id, entry);
        self.rebuild_tree()
    }

    /// Rebuilds the aggregated Merkle tree from rc values (root commitments).
    /// The tree is built from rc = Poseidon(TAG_RC, root, depth) for each file,
    /// padded to the next power of two to ensure a fixed depth.
    fn rebuild_tree(&mut self) -> Result<(), KontorPoRError> {
        // Collect rc values in sorted key order (BTreeMap is deterministic)
        let rc_values: Vec<F> = self.files.values().map(|entry| entry.rc).collect();

        if rc_values.is_empty() {
            // An empty ledger has a tree with a single zero leaf.
            self.tree = build_tree_from_leaves(&[F::ZERO])?;
            return Ok(());
        }

        let padded_len = rc_values.len().next_power_of_two();
        let mut padded_rcs = rc_values;
        padded_rcs.resize(padded_len, F::ZERO); // Pad with neutral element

        self.tree = build_tree_from_leaves(&padded_rcs)?;
        Ok(())
    }

    /// Get the canonical ledger index for a specific rc value.
    /// This allows checking if a file with specific (root, depth) exists in the ledger.
    pub fn get_canonical_index_for_rc(&self, rc: F) -> Option<usize> {
        // Find position by file_id order (same as rebuild_tree) - BTreeMap iteration is deterministic
        self.files.values().position(|entry| entry.rc == rc)
    }

    /// Saves the `FileLedger` to the specified path using bincode serialization.
    pub fn save(&self, path: &Path) -> Result<(), KontorPoRError> {
        let data = LedgerData {
            version: crate::config::LEDGER_FORMAT_VERSION,
            files: self.files.clone(),
            root: self.tree.root(),
            historical_roots: self.historical_roots.clone(),
        };

        let encoded = bincode::serialize(&data).map_err(|e| {
            KontorPoRError::Serialization(format!("Failed to serialize ledger: {}", e))
        })?;

        if encoded.len() > crate::config::MAX_LEDGER_SIZE_BYTES {
            return Err(KontorPoRError::InvalidInput(format!(
                "Serialized ledger size {} bytes exceeds maximum {} bytes",
                encoded.len(),
                crate::config::MAX_LEDGER_SIZE_BYTES
            )));
        }

        fs::write(path, encoded).map_err(|e| {
            KontorPoRError::IO(format!(
                "Failed to write ledger to {}: {}",
                path.display(),
                e
            ))
        })
    }

    /// Loads a `FileLedger` from the specified path with validation.
    pub fn load(path: &Path) -> Result<Self, KontorPoRError> {
        let encoded = fs::read(path).map_err(|e| {
            KontorPoRError::IO(format!(
                "Failed to read ledger from {}: {}",
                path.display(),
                e
            ))
        })?;

        if encoded.len() > crate::config::MAX_LEDGER_SIZE_BYTES {
            return Err(KontorPoRError::InvalidInput(format!(
                "Ledger file size {} bytes exceeds maximum {} bytes",
                encoded.len(),
                crate::config::MAX_LEDGER_SIZE_BYTES
            )));
        }

        let data: LedgerData = bincode::deserialize(&encoded).map_err(|e| {
            KontorPoRError::Serialization(format!("Failed to deserialize ledger: {}", e))
        })?;

        if data.version != crate::config::LEDGER_FORMAT_VERSION {
            return Err(KontorPoRError::InvalidInput(format!(
                "Ledger format version {} is not compatible with current version {}",
                data.version,
                crate::config::LEDGER_FORMAT_VERSION
            )));
        }

        let mut ledger = FileLedger {
            files: data.files,
            tree: MerkleTree::default(),
            historical_roots: data.historical_roots,
        };
        ledger.rebuild_tree()?;

        if ledger.tree.root() != data.root {
            return Err(KontorPoRError::LedgerValidation {
                reason: "computed root does not match stored root".to_string(),
            });
        }

        Ok(ledger)
    }

    /// Returns the depth of the aggregated Merkle tree.
    pub fn depth(&self) -> usize {
        self.tree.layers.len().saturating_sub(1)
    }

    /// Looks up a file by its ID and returns its canonical index and leaf value (rc).
    /// The index is its lexicographical rank among all file IDs in the ledger.
    pub fn lookup(&self, file_id: &str) -> Option<(usize, F)> {
        if let Some(entry) = self.files.get(file_id) {
            // The index is the position in the BTreeMap's sorted keys. O(n) but simple.
            self.files
                .keys()
                .position(|k| k == file_id)
                .map(|index| (index, entry.rc))
        } else {
            None
        }
    }

    /// Returns the Merkle proof of inclusion for a given file ID in the aggregated tree.
    pub fn get_aggregation_proof(
        &self,
        file_id: &str,
    ) -> Option<crate::merkle::CircuitMerkleProof> {
        // Use the efficient cached lookup
        let (index, _rc) = self.lookup(file_id)?;

        let depth = self.depth();
        get_padded_proof_for_leaf(&self.tree, index, depth).ok()
    }
}
