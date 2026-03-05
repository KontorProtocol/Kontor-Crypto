//! File ledger for aggregated Merkle tree management.
//!
//! This module defines the `FileLedger`, which manages the aggregated Merkle tree
//! of file root commitments (rc values). It provides functionality for adding files,
//! persisting the ledger, and generating aggregation proofs.
//!
//! ## Canonical Index Ordering
//!
//! **INVARIANT**: Canonical file indices are explicit, stable, append-only ledger indices.
//! A file's index does not change when new files are added.
//!
//! The aggregated tree is built from rc values ordered by `ledger_index`, padded with zeros
//! for any missing slots. This keeps verifier-side index derivation deterministic.

use crate::merkle::{build_tree_from_leaves, get_padded_proof_for_leaf, MerkleTree, F};
use crate::poseidon::calculate_root_commitment;
use crate::KontorPoRError;
use bincode::Options;
use ff::Field;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
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
    /// Returns this file's stable ledger index if known.
    ///
    /// Implementations that do not supply an index use append-only assignment.
    fn ledger_index(&self) -> Option<usize> {
        None
    }
}

/// Retention policy for historical roots used during proof validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoricalRootPolicy {
    /// Keep all historical roots.
    Unlimited,
    /// Keep at most `n` historical roots, pruning oldest entries first.
    MaxRoots(usize),
}

impl Default for HistoricalRootPolicy {
    fn default() -> Self {
        HistoricalRootPolicy::MaxRoots(crate::config::DEFAULT_MAX_HISTORICAL_ROOTS)
    }
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

/// Entry with explicit stable ledger index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedFileLedgerEntry {
    /// Stable append-only ledger index for this file.
    pub ledger_index: usize,
    /// File commitment data.
    pub entry: FileLedgerEntry,
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
    files: BTreeMap<String, IndexedFileLedgerEntry>,
    /// Stored root for validation on load
    root: F,
    #[serde(default)]
    historical_roots: Vec<[u8; 32]>,
    #[serde(default)]
    historical_root_policy: HistoricalRootPolicy,
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
/// When files are added, the post-update root is appended to `historical_roots`.
/// Verifiers check that a proof's `ledger_root` is in this set before accepting it.
/// This enables cross-block aggregation without proof regeneration.
///
/// Use [`Self::set_historical_roots`] to replace the historical roots when needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLedger {
    /// Unified map from file identifier to complete file information.
    /// BTreeMap ensures deterministic ordering for canonical ledger construction.
    pub files: BTreeMap<String, IndexedFileLedgerEntry>,
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
    /// Historical-root retention policy.
    #[serde(default)]
    pub historical_root_policy: HistoricalRootPolicy,
    /// Runtime cache: ledger index -> file_id, used for O(1) uniqueness checks.
    #[serde(skip)]
    index_to_file_id: HashMap<usize, String>,
    /// Runtime cache: next append-only ledger index.
    #[serde(skip)]
    next_ledger_index: usize,
}

impl Default for FileLedger {
    fn default() -> Self {
        Self {
            files: BTreeMap::new(),
            tree: MerkleTree {
                layers: vec![vec![]],
            },
            historical_roots: Vec::new(),
            historical_root_policy: HistoricalRootPolicy::default(),
            index_to_file_id: HashMap::new(),
            next_ledger_index: 0,
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
    /// The ledger uses this to retain roots that were previously current so that verifiers can
    /// accept proofs generated against older ledger states (cross-block aggregation).
    pub fn record_current_root(&mut self) {
        use ff::PrimeField;
        let root = self.tree.root();
        let repr: [u8; 32] = root.to_repr().into();
        self.historical_roots.push(repr);
        self.prune_historical_roots();
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
        self.prune_historical_roots();
    }

    /// Returns the configured historical-root retention policy.
    pub fn historical_root_policy(&self) -> HistoricalRootPolicy {
        self.historical_root_policy
    }

    /// Sets the historical-root retention policy.
    pub fn set_historical_root_policy(&mut self, policy: HistoricalRootPolicy) {
        self.historical_root_policy = policy;
        self.prune_historical_roots();
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
    /// // Deterministic nonce ensures unique file_id (e.g., user_id + timestamp)
    /// let nonce = b"user_123_1704067200";
    /// let (prepared, metadata) = prepare_file(b"hello", "test.dat", nonce).unwrap();
    /// let mut ledger = FileLedger::new();
    /// ledger.add_file(&metadata).unwrap();
    /// ```
    pub fn add_file(&mut self, entry: &impl FileDescriptor) -> Result<(), KontorPoRError> {
        self.ensure_runtime_index_cache_initialized()?;

        let file_id = entry.file_id().to_string();
        let resolved_index = self.resolve_ledger_index(&file_id, entry.ledger_index())?;

        if let Some(owner) = self.index_to_file_id.get(&resolved_index) {
            if owner != &file_id {
                return Err(KontorPoRError::InvalidInput(format!(
                    "Ledger index {} already assigned to file '{}'",
                    resolved_index, owner
                )));
            }
        }

        self.files.insert(
            file_id.clone(),
            IndexedFileLedgerEntry {
                ledger_index: resolved_index,
                entry: FileLedgerEntry::from(entry),
            },
        );
        self.index_to_file_id.insert(resolved_index, file_id);
        self.next_ledger_index = self.next_ledger_index.max(resolved_index.saturating_add(1));

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
        self.ensure_runtime_index_cache_initialized()?;

        for entry in files {
            let file_id = entry.file_id().to_string();
            let resolved_index = self.resolve_ledger_index(&file_id, entry.ledger_index())?;

            if let Some(owner) = self.index_to_file_id.get(&resolved_index) {
                if owner != &file_id {
                    return Err(KontorPoRError::InvalidInput(format!(
                        "Ledger index {} already assigned to file '{}'",
                        resolved_index, owner
                    )));
                }
            }

            self.files.insert(
                file_id.clone(),
                IndexedFileLedgerEntry {
                    ledger_index: resolved_index,
                    entry: FileLedgerEntry::from(entry),
                },
            );
            self.index_to_file_id.insert(resolved_index, file_id);
            self.next_ledger_index = self.next_ledger_index.max(resolved_index.saturating_add(1));
        }

        self.rebuild_tree()
    }

    /// Rebuilds the aggregated Merkle tree from rc values (root commitments).
    /// The tree is built from rc = Poseidon(TAG_RC, root, depth) for each file,
    /// padded to the next power of two to ensure a fixed depth.
    fn rebuild_tree(&mut self) -> Result<(), KontorPoRError> {
        if self.files.is_empty() {
            // An empty ledger has a tree with a single zero leaf.
            self.tree = build_tree_from_leaves(&[F::ZERO])?;
            return Ok(());
        }

        let max_index = self
            .files
            .values()
            .map(|entry| entry.ledger_index)
            .max()
            .ok_or_else(|| KontorPoRError::LedgerValidation {
                reason: "Failed to determine max ledger index".to_string(),
            })?;
        let leaf_count = max_index
            .checked_add(1)
            .ok_or_else(|| KontorPoRError::InvalidInput("Ledger index overflow".to_string()))?;
        let mut rc_values = vec![F::ZERO; leaf_count];
        for indexed in self.files.values() {
            rc_values[indexed.ledger_index] = indexed.entry.rc;
        }

        let padded_len = rc_values.len().next_power_of_two();
        let mut padded_rcs = rc_values;
        padded_rcs.resize(padded_len, F::ZERO); // Pad with neutral element

        self.tree = build_tree_from_leaves(&padded_rcs)?;
        Ok(())
    }

    fn resolve_ledger_index(
        &self,
        file_id: &str,
        requested_index: Option<usize>,
    ) -> Result<usize, KontorPoRError> {
        if let Some(existing) = self.files.get(file_id) {
            if let Some(idx) = requested_index {
                if idx != existing.ledger_index {
                    return Err(KontorPoRError::InvalidInput(format!(
                        "File '{}' already has ledger index {}, got conflicting index {}",
                        file_id, existing.ledger_index, idx
                    )));
                }
            }
            return Ok(existing.ledger_index);
        }

        Ok(requested_index.unwrap_or(self.next_ledger_index))
    }

    fn ensure_runtime_index_cache_initialized(&mut self) -> Result<(), KontorPoRError> {
        if self.files.is_empty() {
            self.index_to_file_id.clear();
            self.next_ledger_index = 0;
            return Ok(());
        }

        if self.index_to_file_id.len() == self.files.len() && self.next_ledger_index > 0 {
            return Ok(());
        }

        self.rebuild_runtime_index_cache()
    }

    fn rebuild_runtime_index_cache(&mut self) -> Result<(), KontorPoRError> {
        self.index_to_file_id.clear();
        let mut next = 0usize;
        for (file_id, entry) in &self.files {
            if let Some(existing_owner) = self
                .index_to_file_id
                .insert(entry.ledger_index, file_id.clone())
            {
                return Err(KontorPoRError::LedgerValidation {
                    reason: format!(
                        "Duplicate ledger_index {} for files '{}' and '{}'",
                        entry.ledger_index, existing_owner, file_id
                    ),
                });
            }
            next = next.max(entry.ledger_index.saturating_add(1));
        }
        self.next_ledger_index = next;
        Ok(())
    }

    /// Returns the next append-only ledger index that will be assigned.
    pub fn next_ledger_index(&self) -> usize {
        self.next_ledger_index
    }

    /// Get the canonical ledger index for a specific rc value.
    /// This allows checking if a file with specific (root, depth) exists in the ledger.
    pub fn get_canonical_index_for_rc(&self, rc: F) -> Option<usize> {
        self.files
            .values()
            .find(|entry| entry.entry.rc == rc)
            .map(|entry| entry.ledger_index)
    }

    /// Saves the `FileLedger` to the specified path using bincode serialization.
    pub fn save(&self, path: &Path) -> Result<(), KontorPoRError> {
        let data = LedgerData {
            version: crate::config::LEDGER_FORMAT_VERSION,
            files: self.files.clone(),
            root: self.tree.root(),
            historical_roots: self.historical_roots.clone(),
            historical_root_policy: self.historical_root_policy,
        };

        // Pin ledger wire encoding to fixed-width ints + LE endianness so the
        // save/load format stays stable even if bincode defaults change.
        let options = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian();
        let encoded = options.serialize(&data).map_err(|e| {
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

        // Match save() encoding and reject trailing bytes to harden file parsing.
        //
        // `with_limit` is a safety guard against allocation DoS via attacker-controlled
        // container lengths inside the bincode payload.
        let options = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian()
            .with_limit(crate::config::MAX_LEDGER_SIZE_BYTES as u64)
            .reject_trailing_bytes();
        let data: LedgerData = options.deserialize(&encoded).map_err(|e| {
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
            historical_root_policy: data.historical_root_policy,
            index_to_file_id: HashMap::new(),
            next_ledger_index: 0,
        };
        ledger.rebuild_runtime_index_cache()?;
        ledger.rebuild_tree()?;
        ledger.prune_historical_roots();

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
    /// The index is its stable append-only ledger index.
    pub fn lookup(&self, file_id: &str) -> Option<(usize, F)> {
        self.files
            .get(file_id)
            .map(|entry| (entry.ledger_index, entry.entry.rc))
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

    fn prune_historical_roots(&mut self) {
        match self.historical_root_policy {
            HistoricalRootPolicy::Unlimited => {}
            HistoricalRootPolicy::MaxRoots(max_roots) => {
                if self.historical_roots.len() > max_roots {
                    let drop_count = self.historical_roots.len() - max_roots;
                    self.historical_roots.drain(0..drop_count);
                }
            }
        }
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn regression_ledger_load_rejects_oversized_historical_roots_len() {
        use ff::PrimeField;
        use tempfile::NamedTempFile;

        // Build a valid encoded LedgerData first...
        let root = F::from(123u64);
        let data = LedgerData {
            version: crate::config::LEDGER_FORMAT_VERSION,
            files: BTreeMap::new(),
            root,
            historical_roots: vec![],
            historical_root_policy: HistoricalRootPolicy::Unlimited,
        };

        let options = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian();
        let mut encoded = options.serialize(&data).expect("serialize LedgerData");

        // ...then corrupt the `historical_roots` vec length (u64 under fixint encoding).
        // We find it by locating the serialized root bytes and patching the next 8 bytes.
        let root_repr: [u8; 32] = root.to_repr().into();
        let root_pos = encoded
            .windows(root_repr.len())
            .position(|w| w == root_repr)
            .expect("serialized root bytes should appear in LedgerData encoding");
        let len_pos = root_pos + root_repr.len();
        encoded[len_pos..len_pos + 8].copy_from_slice(&u64::MAX.to_le_bytes());

        let tmp = NamedTempFile::new().expect("tempfile");
        std::fs::write(tmp.path(), &encoded).expect("write tampered ledger bytes");

        let err = FileLedger::load(tmp.path()).expect_err("must reject oversized vec length");
        match err {
            KontorPoRError::Serialization(_) => {}
            other => panic!("unexpected error variant: {other:?}"),
        }
    }
}
