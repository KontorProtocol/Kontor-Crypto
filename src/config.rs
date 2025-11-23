//! Centralized configuration for the Kontor PoR system.
//!
//! This module contains constants and default parameters used throughout the
//! application to ensure consistency and ease of modification.

use ff::Field;

/// Maximum practical number of files to prove at once
pub const PRACTICAL_MAX_FILES: usize = 1024;

/// Maximum number of challenges per file (prevents DoS via resource exhaustion)
pub const MAX_NUM_CHALLENGES: usize = 10_000;

// --- Circuit and Proof Parameters ---

/// The base arity of the primary `PorCircuit` (fixed fields only).
/// Layout: `[aggregated_root, state_in, ledger_index_0, ..., actual_depth_0, ..., seed_0, ..., leaf_0, ...]`.
/// Total arity = BASE_CIRCUIT_ARITY + ledger_indices + depths + seeds + leaves
pub const BASE_CIRCUIT_ARITY: usize = 2;

/// Compute the full circuit arity for a given number of files per step.
/// arity = fixed_fields + ledger_indices + depths + seeds + leaves
#[inline]
pub fn circuit_arity(files_per_step: usize) -> usize {
    BASE_CIRCUIT_ARITY + files_per_step + files_per_step + files_per_step + files_per_step
}

/// Public input/output layout helper to centralize index management.
///
/// This prevents bugs from manually managing indices in multiple places.
/// Layout: [fixed_fields, ledger_indices, depths, seeds, leaf_outputs]
#[derive(Debug, Clone)]
pub struct PublicIOLayout {
    pub files_per_step: usize,
}

impl PublicIOLayout {
    /// Number of fixed public input fields
    pub const FIXED: usize = BASE_CIRCUIT_ARITY; // 2

    /// Create new layout helper
    pub fn new(files_per_step: usize) -> Self {
        Self { files_per_step }
    }

    /// Total arity: fixed + ledger indices + depths + seeds + leaf outputs
    pub fn arity(&self) -> usize {
        Self::FIXED + 4 * self.files_per_step
    }

    /// Helper: compute the start index of a per-file section
    /// Section 0 = ledger_indices, 1 = depths, 2 = seeds, 3 = leaves
    fn section_start(&self, section: usize) -> usize {
        Self::FIXED + section * self.files_per_step
    }

    // --- Fixed field indices ---

    /// Index of aggregated_root field
    pub fn idx_agg_root(&self) -> usize {
        0
    }

    /// Index of state_in field
    pub fn idx_state_in(&self) -> usize {
        1
    }

    // --- Ledger indices section ---

    /// Index of ledger_index_i field
    pub fn idx_ledger(&self, i: usize) -> usize {
        self.section_start(0) + i
    }

    /// Range of all ledger indices
    pub fn ledger_indices_range(&self) -> std::ops::Range<usize> {
        self.section_start(0)..self.section_start(1)
    }

    // --- Depth section ---

    /// Index of actual_depth_i field
    pub fn idx_depth(&self, i: usize) -> usize {
        self.section_start(1) + i
    }

    /// Range of all depth fields
    pub fn depths_range(&self) -> std::ops::Range<usize> {
        self.section_start(1)..self.section_start(2)
    }

    // --- Seed section ---

    /// Index of seed_i field
    pub fn idx_seed(&self, i: usize) -> usize {
        self.section_start(2) + i
    }

    /// Range of all seed fields
    pub fn seeds_range(&self) -> std::ops::Range<usize> {
        self.section_start(2)..self.section_start(3)
    }

    // --- Leaf output section ---

    /// Index of leaf_i output field
    pub fn idx_leaf(&self, i: usize) -> usize {
        self.section_start(3) + i
    }

    /// Range of all leaf outputs
    pub fn leaf_outputs_range(&self) -> std::ops::Range<usize> {
        self.section_start(3)..self.section_start(4)
    }

    /// Build the initial z0_primary vector for proving/verification
    /// Layout: [aggregated_root, state_in, ledger_indices..., depths..., seeds..., leaves...]
    pub fn build_z0_primary(
        &self,
        aggregated_root: crate::api::FieldElement,
        ledger_indices: &[usize],
        depths: &[usize],
        seeds: &[crate::api::FieldElement],
    ) -> Vec<crate::api::FieldElement> {
        use crate::api::FieldElement;

        let mut z0_primary = Vec::with_capacity(self.arity());

        // Fixed fields
        z0_primary.push(aggregated_root); // [0]
        z0_primary.push(FieldElement::ZERO); // [1] state_in

        // Ledger indices
        for &idx in ledger_indices.iter() {
            z0_primary.push(FieldElement::from(idx as u64));
        }
        // Pad ledger indices if needed
        while z0_primary.len() < Self::FIXED + self.files_per_step {
            z0_primary.push(FieldElement::ZERO);
        }

        // Depths
        for &depth in depths.iter() {
            z0_primary.push(FieldElement::from(depth as u64));
        }
        // Pad depths if needed
        while z0_primary.len() < Self::FIXED + self.files_per_step + self.files_per_step {
            z0_primary.push(FieldElement::ZERO);
        }

        // Seeds
        for &seed in seeds.iter() {
            z0_primary.push(seed);
        }
        // Pad seeds if needed
        while z0_primary.len()
            < Self::FIXED + self.files_per_step + self.files_per_step + self.files_per_step
        {
            z0_primary.push(FieldElement::ZERO);
        }

        // Leaf outputs (initially zero, filled by circuit)
        for _ in 0..self.files_per_step {
            z0_primary.push(FieldElement::ZERO);
        }

        z0_primary
    }
}

/// The default tree depth used for testing and default circuit instances.
pub const DEFAULT_TEST_TREE_DEPTH: usize = 3;

/// Derive the exact circuit shape from public inputs.
/// Returns (files_per_step, file_tree_depth) tuple.
///
/// # Arguments
/// * `num_files` - The actual number of files being challenged
/// * `max_depth` - The maximum Merkle tree depth among challenged files
///
/// # Returns
/// * `files_per_step` - Next power of two of num_files (min 1)
/// * `file_tree_depth` - The maximum depth (unchanged)
#[inline]
pub fn derive_shape(num_files: usize, max_depth: usize) -> (usize, usize) {
    let files_per_step = num_files.next_power_of_two().max(1);
    // Minimum depth of 1 is required for circuit structure (can't have depth 0 Merkle tree)
    let file_tree_depth = max_depth.max(1);
    (files_per_step, file_tree_depth)
}

// --- Hashing and Merkle Tree Parameters ---

/// The size of chunks/symbols (in bytes) for proof-of-retrievability.
/// This value is set to 31 to ensure that the resulting integer fits safely within
/// the scalar field of the Pallas curve, which has a 255-bit modulus.
/// This is the fundamental unit: chunk = symbol = shard = leaf = 31 bytes.
pub const CHUNK_SIZE_BYTES: usize = 31;

// --- Reed-Solomon Multi-Codeword Parameters ---

/// Data symbols per RS codeword (GF(2^8) constraint: total ≤ 255)
pub const DATA_SYMBOLS_PER_CODEWORD: usize = 231;

/// Parity symbols per codeword (10% overhead)
pub const PARITY_SYMBOLS_PER_CODEWORD: usize = 24;

/// Total symbols per codeword (data + parity)
pub const TOTAL_SYMBOLS_PER_CODEWORD: usize = 255;

// --- Erasure Coding Parameters ---

/// The default number of data shards for erasure coding.
/// This determines how many pieces the original data is split into.
pub const DEFAULT_ERASURE_DATA_SHARDS: usize = 10;

/// The default number of parity shards for erasure coding.
/// This determines how many additional redundancy pieces are generated.
/// The system can tolerate losing up to this many shards.
pub const DEFAULT_ERASURE_PARITY_SHARDS: usize = 1;

// --- Ledger I/O Constants ---

/// Maximum size for serialized ledger files (100 MB)
pub const MAX_LEDGER_SIZE_BYTES: usize = 100 * 1024 * 1024;

/// Current ledger format version
pub const LEDGER_FORMAT_VERSION: u16 = 1;

// --- Test-related Constants ---

/// A fixed random seed used in tests to ensure deterministic behavior.
pub const TEST_RANDOM_SEED: u64 = 42;

// --- Economic Constants ---

/// Default Bitcoin transaction fee assumption for cost analysis (in USD)
pub const BTC_TX_FEE_USD_DEFAULT: f64 = 0.50;

/// Average proof size for single-file proofs (in bytes, approximate)
pub const SINGLE_PROOF_SIZE_BYTES: usize = 10240; // ~10 KB

/// Blocks per hour (Bitcoin averages ~6 blocks/hour)
pub const BLOCKS_PER_HOUR: usize = 6;

/// Blocks per day
pub const BLOCKS_PER_DAY: usize = BLOCKS_PER_HOUR * 24; // 144

/// Challenge window spacing for realistic simulation (blocks between challenges)
pub const CHALLENGE_SPACING_BLOCKS: u64 = 50;

// --- Circuit Cost Constants (from protocol spec) ---

/// Circuit cost multiplier: C_IVC = CIRCUIT_COST_PER_DEPTH × depth
/// From protocol spec § Appendix, Parameter Selection table
pub const CIRCUIT_COST_PER_DEPTH: usize = 100;
