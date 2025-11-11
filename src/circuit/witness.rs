//! Circuit witness data structures and constructors.
//!
//! This module defines the witness types and ensures proper padding and structure
//! for Nova's folding requirements.

use ff::PrimeField;

/// Witness data for a single file's proof.
/// Padding is determined by actual_depth == 0
#[derive(Clone, Debug)]
pub struct FileProofWitness<F: PrimeField> {
    /// The leaf value being proven
    pub leaf: F,
    /// The siblings in the file's Merkle tree (padded to file_tree_depth)
    pub file_siblings: Vec<F>,
    /// The root of this file's Merkle tree
    pub file_root: F,
    /// The actual depth of this file's tree (for gating)
    pub actual_depth: usize,
    /// The siblings in the aggregation tree (if multi-file)
    pub agg_siblings: Vec<F>,
    /// The file's index in the ledger (for aggregation proof verification)
    pub ledger_index: usize,
}

/// A structured witness for the circuit that enforces correct padding and structure.
///
/// This struct acts as a "gatekeeper" to ensure that witness data is always properly
/// formed before reaching the circuit. It can only be constructed through controlled
/// factory functions, making it impossible to accidentally pass malformed witness data.
///
/// ## Invariants
///
/// - Contains exactly `next_power_of_two(num_files)` witnesses (real files + padding)
/// - Real file witnesses come first, followed by padding witnesses
/// - All padding witnesses have `actual_depth: 0` (Phase 3: no is_real field)
/// - The structure is guaranteed to be uniform for Nova's folding requirements
#[derive(Debug, Clone)]
pub struct CircuitWitness<F: PrimeField> {
    /// The witnesses, guaranteed to be exactly next_power_of_two(num_files) in length
    pub witnesses: Vec<FileProofWitness<F>>,
    /// The number of real (non-padding) files in this witness
    pub(crate) num_real_files: usize,
}

impl<F: PrimeField> CircuitWitness<F> {
    /// Create a new circuit witness with the given witnesses and real file count
    pub fn new(witnesses: Vec<FileProofWitness<F>>, num_real_files: usize) -> Self {
        Self {
            witnesses,
            num_real_files,
        }
    }

    /// Get the witnesses for use in the circuit
    pub fn witnesses(&self) -> &[FileProofWitness<F>] {
        &self.witnesses
    }

    /// Get the number of real files (for validation)
    pub(crate) fn num_real_files(&self) -> usize {
        self.num_real_files
    }
}
