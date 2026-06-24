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

use crate::merkle::{build_tree_from_leaves, get_padded_proof_for_leaf, hash_node, MerkleTree, F};
use crate::poseidon::calculate_root_commitment;
use crate::KontorPoRError;
use bincode::Options;
use ff::Field;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

/// Max allowed gap between the highest `ledger_index` and the number of files.
///
/// This prevents adversarial or corrupted inputs (e.g. during `load`) from forcing the
/// ledger to allocate a vector sized to an arbitrarily large index while holding only
/// a small number of files.
const MAX_LEDGER_INDEX_SPARSITY_GAP: usize = 1024;

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
    /// Implementations supplying persisted/reconstructed data must return `Some(index)`.
    /// Fresh files appended via [`FileLedger::add_file`] must return `None`.
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
    historical_root_depths: BTreeMap<[u8; 32], usize>,
    #[serde(default)]
    historical_root_policy: HistoricalRootPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyLedgerDataV2 {
    version: u16,
    files: BTreeMap<String, IndexedFileLedgerEntry>,
    root: F,
    #[serde(default)]
    historical_roots: Vec<[u8; 32]>,
    #[serde(default)]
    historical_root_policy: HistoricalRootPolicy,
}

fn load_legacy_ledger_data_v2(encoded: &[u8]) -> Result<LedgerData, KontorPoRError> {
    let options = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(crate::config::MAX_LEDGER_SIZE_BYTES as u64)
        .reject_trailing_bytes();
    let data: LegacyLedgerDataV2 = options.deserialize(encoded).map_err(|e| {
        KontorPoRError::Serialization(format!("Failed to deserialize legacy v2 ledger: {}", e))
    })?;

    if data.version != crate::config::LEGACY_LEDGER_FORMAT_VERSION_V2 {
        return Err(KontorPoRError::InvalidInput(format!(
            "Ledger format version {} is not compatible with current version {}",
            data.version,
            crate::config::LEDGER_FORMAT_VERSION
        )));
    }

    Ok(LedgerData {
        version: crate::config::LEDGER_FORMAT_VERSION,
        files: data.files,
        root: data.root,
        historical_roots: data.historical_roots,
        historical_root_depths: BTreeMap::new(),
        historical_root_policy: data.historical_root_policy,
    })
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
    /// Known depth for each accepted historical root.
    ///
    /// This is intentionally private: callers may still inspect and replace the
    /// root list, but verification only treats a historical root as shape-bound
    /// when its depth was recorded by the ledger or supplied through
    /// [`Self::set_historical_roots_with_depths`].
    #[serde(default)]
    historical_root_depths: BTreeMap<[u8; 32], usize>,
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
            historical_root_depths: BTreeMap::new(),
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
        let depth = self.depth();
        self.historical_root_depths.insert(repr, depth);
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

    /// Returns the exact accepted aggregation depth for `root`, when known.
    ///
    /// Current roots are always bound to the current ledger depth. Historical
    /// roots are accepted here only when their depth was recorded alongside the
    /// root; root-only historical entries still satisfy [`Self::is_valid_root`]
    /// for compatibility, but cannot pass multi-file proof verification.
    pub fn accepted_root_depth(&self, root: F) -> Option<usize> {
        use ff::PrimeField;
        if root == self.tree.root() {
            return Some(self.depth());
        }
        let repr: [u8; 32] = root.to_repr().into();
        if self.historical_roots.iter().any(|r| r == &repr) {
            return self.historical_root_depths.get(&repr).copied();
        }
        None
    }

    /// Sets the historical roots to the given list.
    ///
    /// This replaces any existing historical roots with the provided values.
    pub fn set_historical_roots(&mut self, roots: Vec<[u8; 32]>) {
        self.historical_roots = roots;
        self.prune_historical_roots();
    }

    /// Replaces historical roots with explicit root-depth pairs.
    ///
    /// Use this when reconstructing a verifier ledger from external storage:
    /// multi-file proof verification needs both the accepted root and the
    /// aggregation depth that produced it.
    pub fn set_historical_roots_with_depths(&mut self, roots: Vec<([u8; 32], usize)>) {
        self.historical_roots = roots.iter().map(|(root, _depth)| *root).collect();
        self.historical_root_depths = roots.into_iter().collect();
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
    /// [`Self::add_file`] is append-only: it only accepts fresh files and assigns the
    /// next stable ledger index internally. Persisted/reconstructed entries must use
    /// [`Self::add_files`] and provide explicit indices via [`FileDescriptor::ledger_index`].
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
        if entry.ledger_index().is_some() {
            return Err(KontorPoRError::InvalidInput(format!(
                "add_file does not accept explicit ledger_index for file '{}'; use add_files for reconstruction",
                file_id
            )));
        }
        if self.files.contains_key(&file_id) {
            return Err(KontorPoRError::InvalidInput(format!(
                "File '{}' already exists in ledger; file_id is immutable",
                file_id
            )));
        }
        let resolved_index = self.next_ledger_index;

        if let Some(owner) = self.index_to_file_id.get(&resolved_index) {
            if owner != &file_id {
                return Err(KontorPoRError::InvalidInput(format!(
                    "Ledger index {} already assigned to file '{}'",
                    resolved_index, owner
                )));
            }
        }

        let previous_entry = self.files.get(&file_id).cloned();
        let previous_owner = self.index_to_file_id.get(&resolved_index).cloned();
        let previous_next = self.next_ledger_index;

        self.files.insert(
            file_id.clone(),
            IndexedFileLedgerEntry {
                ledger_index: resolved_index,
                entry: FileLedgerEntry::from(entry),
            },
        );
        self.index_to_file_id.insert(resolved_index, file_id);
        self.next_ledger_index = self.next_ledger_index.max(resolved_index.saturating_add(1));

        // Rebuild tree (roll back state on error so tree/caches remain consistent).
        if let Err(err) = self.rebuild_tree() {
            match previous_entry {
                Some(old) => {
                    self.files.insert(entry.file_id().to_string(), old);
                }
                None => {
                    self.files.remove(entry.file_id());
                }
            }
            match previous_owner {
                Some(owner) => {
                    self.index_to_file_id.insert(resolved_index, owner);
                }
                None => {
                    self.index_to_file_id.remove(&resolved_index);
                }
            }
            self.next_ledger_index = previous_next;
            return Err(err);
        }

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
    /// [`Self::add_files`] is the persisted/reconstruction path. Every entry must carry
    /// an explicit stable index via [`FileDescriptor::ledger_index`].
    ///
    /// Duplicate `file_id`s are rejected, both against existing ledger contents and within
    /// the batch itself, since `file_id` is immutable.
    ///
    pub fn add_files<'a, T: FileDescriptor + 'a>(
        &mut self,
        files: impl IntoIterator<Item = &'a T>,
    ) -> Result<(), KontorPoRError> {
        self.ensure_runtime_index_cache_initialized()?;

        // Phase 1: validate + compute indices without mutating self.
        let mut planned: BTreeMap<String, IndexedFileLedgerEntry> = BTreeMap::new();
        let mut planned_indices: HashMap<usize, String> = HashMap::new();
        let mut next_index = self.next_ledger_index;

        for entry in files {
            let file_id = entry.file_id().to_string();
            let idx = entry.ledger_index().ok_or_else(|| {
                KontorPoRError::InvalidInput(format!(
                    "add_files requires explicit ledger_index for file '{}'",
                    file_id
                ))
            })?;

            if self.files.contains_key(&file_id) {
                return Err(KontorPoRError::InvalidInput(format!(
                    "File '{}' already exists in ledger; file_id is immutable",
                    file_id
                )));
            }

            if planned.contains_key(&file_id) {
                return Err(KontorPoRError::InvalidInput(format!(
                    "Duplicate file '{}' provided in add_files batch",
                    file_id
                )));
            }

            if let Some(owner) = self.index_to_file_id.get(&idx) {
                return Err(KontorPoRError::InvalidInput(format!(
                    "Ledger index {} already assigned to file '{}'",
                    idx, owner
                )));
            }
            if let Some(owner) = planned_indices.get(&idx) {
                return Err(KontorPoRError::InvalidInput(format!(
                    "Ledger index {} already assigned to file '{}' in batch",
                    idx, owner
                )));
            }

            planned.insert(
                file_id.clone(),
                IndexedFileLedgerEntry {
                    ledger_index: idx,
                    entry: FileLedgerEntry::from(entry),
                },
            );
            planned_indices.insert(idx, file_id);
            next_index = next_index.max(idx.saturating_add(1));
        }

        // Phase 2: apply mutations with rollback on rebuild failure.
        let previous_next = self.next_ledger_index;
        let mut previous_files: Vec<(String, Option<IndexedFileLedgerEntry>)> = Vec::new();
        let mut previous_owners: Vec<(usize, Option<String>)> = Vec::new();

        for (file_id, entry) in planned.iter() {
            previous_files.push((file_id.clone(), self.files.get(file_id).cloned()));
            previous_owners.push((
                entry.ledger_index,
                self.index_to_file_id.get(&entry.ledger_index).cloned(),
            ));
        }

        for (file_id, entry) in planned.into_iter() {
            self.files.insert(file_id, entry);
        }
        for (idx, owner) in planned_indices.into_iter() {
            self.index_to_file_id.insert(idx, owner);
        }
        self.next_ledger_index = next_index;

        if let Err(err) = self.rebuild_tree() {
            for (file_id, prior) in previous_files {
                match prior {
                    Some(old) => {
                        self.files.insert(file_id, old);
                    }
                    None => {
                        self.files.remove(&file_id);
                    }
                }
            }
            for (idx, prior) in previous_owners {
                match prior {
                    Some(owner) => {
                        self.index_to_file_id.insert(idx, owner);
                    }
                    None => {
                        self.index_to_file_id.remove(&idx);
                    }
                }
            }
            self.next_ledger_index = previous_next;
            return Err(err);
        }

        Ok(())
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

        let files_len = self.files.len();
        if leaf_count > files_len.saturating_add(MAX_LEDGER_INDEX_SPARSITY_GAP) {
            return Err(KontorPoRError::InvalidInput(format!(
                "Ledger indices too sparse: max_index={} implies leaf_count={} for only {} files",
                max_index, leaf_count, files_len
            )));
        }

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

    fn rebuild_missing_historical_root_depths(&mut self) -> Result<(), KontorPoRError> {
        let wanted: HashSet<[u8; 32]> = self.historical_roots.iter().copied().collect();
        if wanted.is_empty()
            || wanted
                .iter()
                .all(|root| self.historical_root_depths.contains_key(root))
        {
            self.retain_historical_root_depths();
            return Ok(());
        }

        let mut by_index: Vec<(usize, F)> = self
            .files
            .values()
            .map(|entry| (entry.ledger_index, entry.entry.rc))
            .collect();
        by_index.sort_by_key(|(idx, _rc)| *idx);

        let mut prefix = Vec::new();
        for (expected_idx, (idx, rc)) in by_index.iter().copied().enumerate() {
            if idx != expected_idx {
                break;
            }
            prefix.push((rc, idx));
            let root = aggregate_root(&prefix)?;
            if wanted.contains(&root) {
                let depth = prefix.len().next_power_of_two().trailing_zeros() as usize;
                self.historical_root_depths.insert(root, depth);
            }
        }

        self.retain_historical_root_depths();
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
            historical_root_depths: self.historical_root_depths.clone(),
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
        let data = match options.deserialize::<LedgerData>(&encoded) {
            Ok(data) if data.version == crate::config::LEDGER_FORMAT_VERSION => data,
            Ok(data) => load_legacy_ledger_data_v2(&encoded).map_err(|legacy_err| {
                KontorPoRError::InvalidInput(format!(
                    "Ledger format version {} is not compatible with current version {}; legacy load failed: {}",
                    data.version,
                    crate::config::LEDGER_FORMAT_VERSION,
                    legacy_err
                ))
            })?,
            Err(current_err) => load_legacy_ledger_data_v2(&encoded).map_err(|legacy_err| {
                KontorPoRError::Serialization(format!(
                    "Failed to deserialize ledger: {}; legacy v2 load failed: {}",
                    current_err, legacy_err
                ))
            })?,
        };

        let mut ledger = FileLedger {
            files: data.files,
            tree: MerkleTree::default(),
            historical_roots: data.historical_roots,
            historical_root_depths: data.historical_root_depths,
            historical_root_policy: data.historical_root_policy,
            index_to_file_id: HashMap::new(),
            next_ledger_index: 0,
        };
        ledger.rebuild_runtime_index_cache()?;
        ledger.rebuild_tree()?;
        ledger.rebuild_missing_historical_root_depths()?;
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

    /// Looks up a file by its ID and returns its stable ledger index and leaf value (rc).
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
        self.retain_historical_root_depths();
    }

    fn retain_historical_root_depths(&mut self) {
        let retained: HashSet<[u8; 32]> = self.historical_roots.iter().copied().collect();
        self.historical_root_depths
            .retain(|root, _depth| retained.contains(root));
    }
}

/// Compute the aggregated ledger root from each file's `(rc, ledger_index)` slot,
/// statelessly — no live [`FileLedger`] required.
///
/// Mirrors [`FileLedger`]'s internal `rebuild_tree`: each `rc` is placed at its stable
/// append-only slot, gaps are zero-filled, and the leaf vector is padded to a power of
/// two. The result is byte-identical to [`FileLedger::root`] over the same files, so a
/// contract holding its files (with their slots) in its own storage can compute the
/// current ledger root itself and feed it to [`crate::api::verify_stateless`] as a
/// valid root. The returned root is the 32-byte little-endian field repr (matching
/// [`FileLedger::historical_roots`]).
///
/// Errors if two files claim the same slot, or if the slots are too sparse (same guard
/// as the live ledger: the implied leaf count may exceed the file count by at most
/// `MAX_LEDGER_INDEX_SPARSITY_GAP`).
pub fn aggregate_root(files: &[(F, usize)]) -> Result<[u8; 32], KontorPoRError> {
    use ff::PrimeField;

    if files.is_empty() {
        // An empty ledger has a tree with a single zero leaf (see `rebuild_tree`).
        let tree = build_tree_from_leaves(&[F::ZERO])?;
        return Ok(tree.root().to_repr().into());
    }

    let max_index = files.iter().map(|(_, idx)| *idx).max().unwrap_or(0);
    let leaf_count = max_index
        .checked_add(1)
        .ok_or_else(|| KontorPoRError::InvalidInput("Ledger index overflow".to_string()))?;

    if leaf_count > files.len().saturating_add(MAX_LEDGER_INDEX_SPARSITY_GAP) {
        return Err(KontorPoRError::InvalidInput(format!(
            "Ledger indices too sparse: max_index={} implies leaf_count={} for only {} files",
            max_index,
            leaf_count,
            files.len()
        )));
    }

    let mut rc_values = vec![F::ZERO; leaf_count];
    let mut seen = HashSet::with_capacity(files.len());
    for (rc, idx) in files {
        if !seen.insert(*idx) {
            return Err(KontorPoRError::InvalidInput(format!(
                "Duplicate ledger_index {idx} in aggregate_root input"
            )));
        }
        rc_values[*idx] = *rc;
    }

    let padded_len = rc_values.len().next_power_of_two();
    rc_values.resize(padded_len, F::ZERO);

    let tree = build_tree_from_leaves(&rc_values)?;
    Ok(tree.root().to_repr().into())
}

/// Convenience over [`aggregate_root`] that takes each file's `(root, depth,
/// ledger_index)` and computes the `rc = calculate_root_commitment(root, depth)`
/// internally. `files` may be in any order; each carries its own stable slot.
pub fn aggregate_root_from_files(files: &[(F, usize, usize)]) -> Result<[u8; 32], KontorPoRError> {
    let rc_slots: Vec<(F, usize)> = files
        .iter()
        .map(|(root, depth, idx)| {
            (
                calculate_root_commitment(*root, F::from(*depth as u64)),
                *idx,
            )
        })
        .collect();
    aggregate_root(&rc_slots)
}

/// Zero-subtree roots by height: `Z[0] = 0` (a zero leaf), `Z[h] = node(Z[h-1], Z[h-1])`.
/// These fill the empty right portion of the aggregated tree, matching the zero-fill +
/// power-of-two padding that [`aggregate_root`] feeds to `build_tree_from_leaves`.
fn zero_subtree_roots(max_height: usize) -> Vec<F> {
    let mut z = Vec::with_capacity(max_height + 1);
    z.push(F::ZERO);
    for h in 1..=max_height {
        let prev = z[h - 1];
        z.push(hash_node(prev, prev));
    }
    z
}

/// Append-only incremental accumulator for the aggregated ledger root.
///
/// Maintains the O(log n) Merkle "mountain peaks" of the contiguous, append-only file
/// slots, so adding a file is one `O(log n)` fold instead of an `O(n)` tree rebuild.
/// [`Self::root`] is **byte-identical** to [`aggregate_root`] over the same contiguous
/// slots `0..count` (see the `frontier_*` equivalence tests), so a contract can persist
/// just `(count, peaks)` and update the ledger root incrementally each block rather than
/// recomputing the whole tree.
///
/// Only the append-only case is supported — slots assigned `0, 1, 2, …` with no gaps.
/// Interior removal / zero-fill is intentionally out of scope (it would invalidate the
/// right-edge peaks); a removal workload would need a full rebuild or a richer structure.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LedgerFrontier {
    count: u64,
    /// Perfect-subtree roots, lowest height first — exactly one per set bit of `count`.
    peaks: Vec<F>,
}

impl LedgerFrontier {
    /// An empty frontier (no files), whose [`Self::root`] matches `aggregate_root(&[])`.
    pub fn new() -> Self {
        Self {
            count: 0,
            peaks: Vec::new(),
        }
    }

    /// Reconstruct from persisted state (e.g. a contract reading its own storage).
    /// Errors unless `peaks.len()` equals the number of set bits in `count`, the
    /// structural invariant of the mountain-peak representation.
    pub fn from_parts(count: u64, peaks: Vec<F>) -> Result<Self, KontorPoRError> {
        if peaks.len() != count.count_ones() as usize {
            return Err(KontorPoRError::InvalidInput(format!(
                "LedgerFrontier: got {} peaks for count {} (expected {} set bits)",
                peaks.len(),
                count,
                count.count_ones()
            )));
        }
        Ok(Self { count, peaks })
    }

    /// Number of appended files (== next slot to be assigned).
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Perfect-subtree peaks, lowest height first — persist these alongside `count`.
    pub fn peaks(&self) -> &[F] {
        &self.peaks
    }

    /// Append a file by its precomputed root-commitment `rc` at the next slot. O(log n).
    pub fn append_rc(&mut self, rc: F) {
        // Binary-increment carry: the trailing run of set bits in `count` are the low
        // peaks that merge with the new leaf. Each existing peak is the LEFT sibling and
        // the carry the RIGHT — matching `build_tree_from_leaves`'s low-index-left order.
        let mut carry = rc;
        let mut h = 0;
        while (self.count >> h) & 1 == 1 {
            let left = self.peaks.remove(0);
            carry = hash_node(left, carry);
            h += 1;
        }
        self.peaks.insert(0, carry);
        self.count += 1;
    }

    /// Append a file by its `(root, depth)`, computing `rc` as [`aggregate_root_from_files`]
    /// does, then folding it in via [`Self::append_rc`].
    pub fn append(&mut self, root: F, depth: usize) {
        self.append_rc(calculate_root_commitment(root, F::from(depth as u64)));
    }

    /// Current aggregated ledger root — byte-identical to [`aggregate_root`] over slots
    /// `0..count`. Returned as the 32-byte little-endian field repr (matching
    /// [`FileLedger::historical_roots`]).
    pub fn root(&self) -> [u8; 32] {
        use ff::PrimeField;

        if self.count == 0 {
            // Empty ledger: a single zero leaf (mirrors `aggregate_root`/`rebuild_tree`).
            return F::ZERO.to_repr().into();
        }

        // Root height D = ceil(log2(count)) = bit-length(count - 1); D = 0 for count == 1.
        let d = (u64::BITS - (self.count - 1).leading_zeros()) as usize;
        let z = zero_subtree_roots(d);

        // Fold peaks low-to-high. `acc` is the root of the accumulated right-hand region
        // at height `acc_h`; lift it with zero-subtrees to the current height before
        // combining the next peak (a fully-filled subtree to its left).
        let mut acc: Option<F> = None;
        let mut acc_h = 0usize;
        let mut peaks = self.peaks.iter();
        for h in 0..=d {
            if let Some(a) = acc.as_mut() {
                while acc_h < h {
                    *a = hash_node(*a, z[acc_h]);
                    acc_h += 1;
                }
            }
            if (self.count >> h) & 1 == 1 {
                let p = *peaks.next().expect("peak count matches set bits of count");
                match acc {
                    None => {
                        acc = Some(p);
                        acc_h = h;
                    }
                    Some(a) => {
                        acc = Some(hash_node(p, a));
                        acc_h = h + 1;
                    }
                }
            }
        }
        acc.expect("count >= 1 yields a root").to_repr().into()
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
            historical_root_depths: BTreeMap::new(),
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
