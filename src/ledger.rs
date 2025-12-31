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
use crate::poseidon::calculate_root_commitment;
use crate::KontorPoRError;
use ff::Field;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Trait for types that can be added to a [`FileLedger`].
///
/// This trait decouples the ledger from any specific file metadata type,
/// allowing any type that provides the required information to be used.
pub trait FileDescriptor {
    /// Returns the unique identifier for this file.
    fn file_id(&self) -> &str;
    /// Returns the Merkle root of this file's tree.
    fn root(&self) -> F;
    /// Returns the depth of this file's Merkle tree.
    fn depth(&self) -> usize;
}

/// Entry for a single file in the ledger, combining all file information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLedgerEntry {
    /// The Merkle root of this file
    pub root: F,
    /// The depth of this file's Merkle tree
    pub depth: usize,
    /// The root commitment (rc = H(TAG_RC, root, depth))
    pub rc: F,
}

impl<T: FileDescriptor> From<&T> for FileLedgerEntry {
    fn from(entry: &T) -> Self {
        let rc = calculate_root_commitment(entry.root(), F::from(entry.depth() as u64));
        FileLedgerEntry {
            root: entry.root(),
            depth: entry.depth(),
            rc,
        }
    }
}

/// Versioned wrapper for ledger serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerData {
    /// Format version for forward compatibility
    version: u16,
    /// The actual ledger data (unified file entries)
    files: BTreeMap<String, FileLedgerEntry>,
    /// Stored root for validation on load
    root: F,
    #[serde(default)]
    historical_roots: Vec<[u8; 32]>,
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
/// When files are added, the pre-modification root is appended to `historical_roots`.
/// Verifiers check that a proof's `ledger_root` is in this set before accepting it.
/// This enables cross-block aggregation without proof regeneration.
///
/// Use [`Self::set_historical_roots`] to replace the historical roots when needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLedger {
    /// Unified map from file identifier to complete file information.
    /// BTreeMap ensures deterministic ordering for canonical ledger construction.
    pub files: BTreeMap<String, FileLedgerEntry>,
    /// The aggregated Merkle tree built from rc values (not raw roots).
    #[serde(skip)]
    pub tree: MerkleTree,
    /// Accepted historical roots for proof validation.
    ///
    /// Proofs generated against a ledger root are valid as long as that root is either:
    /// - the current root, or
    /// - present in this list.
    ///
    /// Use [`Self::set_historical_roots`] to replace this list.
    #[serde(default)]
    pub historical_roots: Vec<[u8; 32]>,
}

impl Default for FileLedger {
    fn default() -> Self {
        Self {
            files: BTreeMap::new(),
            tree: MerkleTree {
                layers: vec![vec![]],
            },
            historical_roots: Vec::new(),
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

    /// Records the current root as a valid historical root.
    ///
    /// Call this before modifying the ledger (e.g., before adding files) to preserve the
    /// old root for proof validation.
    pub fn record_current_root(&mut self) {
        use ff::PrimeField;
        let root = self.tree.root();
        let repr: [u8; 32] = root.to_repr().into();
        self.historical_roots.push(repr);
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
        self.historical_roots.iter().any(|r| r == &repr)
    }

    /// Sets the historical roots to the given list.
    ///
    /// This replaces any existing historical roots with the provided values.
    pub fn set_historical_roots(&mut self, roots: Vec<[u8; 32]>) {
        self.historical_roots = roots;
    }

    // --- File Management ---

    /// Adds a new file to the ledger and rebuilds the aggregated tree.
    ///
    /// On success, the new root is recorded in [`Self::historical_roots`],
    /// ensuring every valid ledger state is tracked for proof validation.
    ///
    /// # Arguments
    ///
    /// * `entry` - Any type that implements [`FileDescriptor`], providing
    ///   the file's ID, root, and depth.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use kontor_crypto::api::prepare_file;
    /// use kontor_crypto::FileLedger;
    ///
    /// let (prepared, metadata) = prepare_file(b"hello", "test.dat").unwrap();
    /// let mut ledger = FileLedger::new();
    /// ledger.add_file(&metadata).unwrap();
    /// ```
    pub fn add_file(&mut self, entry: &impl FileDescriptor) -> Result<(), KontorPoRError> {
        // Insert the new file
        self.files
            .insert(entry.file_id().to_string(), FileLedgerEntry::from(entry));

        // Rebuild tree
        self.rebuild_tree()?;

        // Record the new root as a historical root (every valid state is tracked)
        self.record_current_root();

        Ok(())
    }

    /// Adds multiple files to the ledger in a single batch, rebuilding the tree only once.
    ///
    /// This method is intended for bulk initialization or reconstruction of the ledger
    /// (e.g., syncing from a database). It does **not** record historical roots automatically.
    /// Clients should manage historical roots externally and use [`Self::set_historical_roots`]
    /// after reconstruction.
    ///
    /// For incremental additions that track state transitions, use [`Self::add_file`] instead.
    ///
    /// # Arguments
    ///
    /// * `files` - An iterator of references to types that implement [`FileDescriptor`].
    ///
    /// # Duplicate Handling
    ///
    /// If a file with the same `file_id` already exists in the ledger or appears
    /// multiple times in the batch, the last entry wins.
    ///
    pub fn add_files<'a, T: FileDescriptor + 'a>(
        &mut self,
        files: impl IntoIterator<Item = &'a T>,
    ) -> Result<(), KontorPoRError> {
        for entry in files {
            self.files
                .insert(entry.file_id().to_string(), FileLedgerEntry::from(entry));
        }

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
