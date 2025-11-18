//! Test fixtures and scenario configuration.
//!
//! This module provides the TestConfig struct for declarative test setup
//! and the TestSetup struct containing all components needed for a test.

#![allow(dead_code)]

use kontor_crypto::{
    api::{
        prepare_file, tree_depth_from_metadata, Challenge, FieldElement, FileMetadata, PorParams,
        PreparedFile,
    },
    config::{self, CHUNK_SIZE_BYTES},
    ledger::FileLedger,
    params,
};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use std::collections::BTreeMap;

// Circuit test support
use bellpepper_core::{num::AllocatedNum, ConstraintSystem};
use ff::PrimeField;
use kontor_crypto::circuit::FileProofWitness;

// Arecibo type aliases for circuit tests
use arecibo::{
    provider::{ipa_pc, PallasEngine, VestaEngine},
    spartan::snark::RelaxedR1CSSNARK,
    traits::{circuit::TrivialCircuit, Engine},
};

pub type E1 = PallasEngine;
pub type E2 = VestaEngine;
pub type EE1 = ipa_pc::EvaluationEngine<E1>;
pub type EE2 = ipa_pc::EvaluationEngine<E2>;
pub type S1 = RelaxedR1CSSNARK<E1, EE1>;
pub type S2 = RelaxedR1CSSNARK<E2, EE2>;
pub type F1 = <E1 as Engine>::Scalar;
pub type F2 = <E2 as Engine>::Scalar;
pub type C2 = TrivialCircuit<F2>;

/// Specification for a test file.
#[derive(Debug, Clone)]
pub struct FileSpec {
    /// Size of the raw file data in bytes
    pub size: usize,
    /// Optional seed for deterministic data generation (defaults to size)
    pub seed: Option<u64>,
}

impl FileSpec {
    /// Creates a FileSpec from a size with default seed
    pub fn from_size(size: usize) -> Self {
        Self { size, seed: None }
    }

    /// Creates a FileSpec with a specific seed
    pub fn with_seed(size: usize, seed: u64) -> Self {
        Self {
            size,
            seed: Some(seed),
        }
    }

    /// Creates a file spec targeting a specific tree depth
    /// With the new multi-codeword RS scheme, tree depth is determined by:
    /// data size -> 31-byte chunks -> RS encoding (10% overhead) -> Merkle tree leaves
    pub fn for_depth(target_depth: usize) -> Self {
        let size = if target_depth == 0 {
            // Very small for depth 0
            CHUNK_SIZE_BYTES / 2
        } else {
            // Calculate size to achieve target depth after RS encoding and padding
            // num_leaves = 2^depth
            // After RS: symbols = ceil(size/31) * (255/231) ≈ size/31 * 1.104
            // After power-of-2 padding: padded_symbols = 2^depth
            // So: size ≈ 2^depth * 31 / 1.104 ≈ 2^depth * 28
            let num_leaves = 1 << target_depth;
            (num_leaves * 28).max(CHUNK_SIZE_BYTES)
        };
        Self::from_size(size)
    }
}

/// Complete test scenario configuration.
#[derive(Debug, Clone)]
pub struct TestConfig {
    /// Specifications for files to create
    pub file_specs: Vec<FileSpec>,
    /// Number of challenges per file
    pub challenges_per_file: usize,
    /// Base seed for challenge generation
    pub seed: u64,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            // Use minimal file size that still creates a meaningful tree (depth 1)
            file_specs: vec![FileSpec::from_size(CHUNK_SIZE_BYTES + 1)],
            challenges_per_file: 1,
            seed: 42,
        }
    }
}

impl TestConfig {
    /// Creates a config for testing with minimal data (depth 0)
    pub fn minimal() -> Self {
        Self {
            file_specs: vec![FileSpec::from_size(CHUNK_SIZE_BYTES / 2)],
            ..Default::default()
        }
    }

    /// Creates a config with a specific number of challenges, using minimal data
    pub fn with_challenges(challenges_per_file: usize) -> Self {
        Self {
            challenges_per_file,
            ..Default::default()
        }
    }

    /// Creates a config with a specific seed, using minimal data
    pub fn with_seed(seed: u64) -> Self {
        Self {
            seed,
            ..Default::default()
        }
    }

    /// Creates a config for testing specific tree depths efficiently
    pub fn for_depth(target_depth: usize) -> Self {
        Self {
            file_specs: vec![FileSpec::for_depth(target_depth)],
            ..Default::default()
        }
    }

    /// Creates a config for testing multiple files with minimal data
    pub fn multi_file(num_files: usize) -> Self {
        Self {
            file_specs: (0..num_files)
                .map(|i| FileSpec::with_seed(CHUNK_SIZE_BYTES / 2, 1000 + i as u64))
                .collect(),
            ..Default::default()
        }
    }
}

/// Complete test setup ready for assertions.
#[derive(Clone)]
pub struct TestSetup {
    /// Generated parameters for the proof system
    pub params: PorParams,
    /// Optional ledger for multi-file proofs
    pub ledger: Option<FileLedger>,
    /// Map of file hashes to prepared files
    pub files: BTreeMap<String, PreparedFile>,
    /// File metadata in order
    pub metadatas: Vec<FileMetadata>,
    /// Generated challenges
    pub challenges: Vec<Challenge>,
}

impl TestSetup {
    /// Convenience method to get file references for the prove API
    pub fn file_refs(&self) -> BTreeMap<String, &PreparedFile> {
        self.files.iter().map(|(k, v)| (k.clone(), v)).collect()
    }

    /// Convenience method to get ledger reference
    pub fn ledger_ref(&self) -> Option<&FileLedger> {
        self.ledger.as_ref()
    }
}

/// Creates a complete test scenario from configuration.
pub fn setup_test_scenario(config: &TestConfig) -> Result<TestSetup, kontor_crypto::KontorPoRError> {
    // 1. Create files from specs
    let mut files = BTreeMap::new();
    let mut metadatas = Vec::new();
    // With unified API, always create a ledger (even for single files)
    let mut ledger = Some(FileLedger::new());

    for (i, file_spec) in config.file_specs.iter().enumerate() {
        // Generate deterministic test data
        let seed_value = file_spec.seed.unwrap_or(file_spec.size as u64 + i as u64);
        let mut rng = StdRng::seed_from_u64(seed_value);
        let mut data = vec![0u8; file_spec.size];
        rng.fill_bytes(&mut data);

        // Prepare the file
        let (prepared, metadata) = prepare_file(&data, &format!("test_file_{}.dat", i))?;

        // Add to ledger if multi-file
        if let Some(ref mut ledger) = ledger {
            ledger.add_file(
                metadata.file_id.clone(),
                metadata.root,
                kontor_crypto::api::tree_depth_from_metadata(&metadata),
            )?;
        }

        files.insert(metadata.file_id.clone(), prepared);
        metadatas.push(metadata);
    }

    // 2. Generate parameters (using cache for performance)
    let max_file_depth = metadatas
        .iter()
        .map(tree_depth_from_metadata)
        .max()
        .unwrap_or(0);

    // 3. Create challenges
    let challenges: Vec<Challenge> = metadatas
        .iter()
        .map(|metadata| {
            Challenge::new_test(
                metadata.clone(),
                1000, // block_height
                config.challenges_per_file,
                FieldElement::from(config.seed),
            )
        })
        .collect();

    // Generate parameters after we know the number of challenges
    let agg_depth = ledger
        .as_ref()
        .map(|l| l.tree.layers.len() - 1)
        .unwrap_or(0);
    let (files_per_step, file_tree_depth) = config::derive_shape(challenges.len(), max_file_depth);
    let params = params::load_or_generate_params(files_per_step, file_tree_depth, agg_depth)
        .expect("Failed to load or generate parameters");

    Ok(TestSetup {
        params,
        ledger,
        files,
        metadatas,
        challenges,
    })
}

// Re-export some helper functions from the old test_utils for compatibility
// These will be used during the migration process

/// Creates deterministic test data of the specified size.
pub fn create_test_data(size: usize, seed: Option<u64>) -> Vec<u8> {
    let seed_value = seed.unwrap_or(size as u64);
    let mut rng = StdRng::seed_from_u64(seed_value);
    let mut data = vec![0u8; size];
    rng.fill_bytes(&mut data);
    data
}

/// Creates allocated public inputs (z0) for circuit testing.
/// This centralizes the repetitive pattern of allocating z0 vectors.
/// Phase 3: Updated for new public I/O schema [agg_root, state_in, seed, ledger_indices..., depths..., leaves...]
pub fn create_circuit_public_inputs<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    agg_root: F,
    state_in: F,
    seed: F,
    ledger_indices: &[usize],
    depths: &[usize],
    leaf_values: &[F],
) -> Vec<AllocatedNum<F>> {
    let mut z = Vec::new();

    // Fixed public inputs (now only 2: agg_root and state_in)
    z.push(AllocatedNum::alloc(cs.namespace(|| "agg_root"), || Ok(agg_root)).unwrap());
    z.push(AllocatedNum::alloc(cs.namespace(|| "state_in"), || Ok(state_in)).unwrap());

    // Ledger indices
    for (i, &ledger_idx) in ledger_indices.iter().enumerate() {
        z.push(
            AllocatedNum::alloc(cs.namespace(|| format!("ledger_idx_{}", i)), || {
                Ok(F::from(ledger_idx as u64))
            })
            .unwrap(),
        );
    }

    // Depths
    for (i, &depth) in depths.iter().enumerate() {
        z.push(
            AllocatedNum::alloc(cs.namespace(|| format!("depth_{}", i)), || {
                Ok(F::from(depth as u64))
            })
            .unwrap(),
        );
    }

    // Seeds (per-file, same seed for all files in this helper for backward compat)
    for i in 0..ledger_indices.len() {
        z.push(AllocatedNum::alloc(cs.namespace(|| format!("seed_{}", i)), || Ok(seed)).unwrap());
    }

    // Leaf values
    for (i, &leaf_val) in leaf_values.iter().enumerate() {
        z.push(
            AllocatedNum::alloc(cs.namespace(|| format!("leaf_{}", i)), || Ok(leaf_val)).unwrap(),
        );
    }

    z
}

/// DEPRECATED: Meta commitments are no longer used in Phase 3 circuit.
/// Security now comes from public depth binding per slot.
/// This function is kept only for legacy tests that haven't been updated yet.
pub fn create_files_meta_commitment(
    _file_metadatas: &[&FileMetadata],
    _files_per_step: usize,
) -> Result<FieldElement, kontor_crypto::KontorPoRError> {
    // Return a dummy value since meta commitments are no longer used
    Ok(FieldElement::from(42u64))
}

/// Creates a FileProofWitness with standard defaults.
/// This reduces boilerplate in circuit tests.
pub fn create_witness<F: PrimeField>(
    leaf: F,
    file_root: F,
    actual_depth: usize,
    file_tree_depth: usize,
    ledger_index: usize,
    agg_depth: usize,
    _is_real: bool, // Phase 3: Ignored (padding determined by actual_depth == 0)
) -> FileProofWitness<F> {
    FileProofWitness {
        leaf,
        file_siblings: vec![F::ZERO; file_tree_depth],
        file_root,
        actual_depth,
        agg_siblings: vec![F::ZERO; agg_depth],
        ledger_index,
    }
}

/// Creates a FileProofWitness with custom siblings.
/// For tests that need specific sibling values.
pub fn create_witness_with_siblings<F: PrimeField>(
    leaf: F,
    file_siblings: Vec<F>,
    file_root: F,
    actual_depth: usize,
    agg_siblings: Vec<F>,
    ledger_index: usize,
    _is_real: bool, // Phase 3: Ignored (padding determined by actual_depth == 0)
) -> FileProofWitness<F> {
    FileProofWitness {
        leaf,
        file_siblings,
        file_root,
        actual_depth,
        agg_siblings,
        ledger_index,
    }
}

/// Creates a padding witness (actual_depth = 0).
pub fn create_padding_witness<F: PrimeField>(
    file_tree_depth: usize,
    agg_depth: usize,
) -> FileProofWitness<F> {
    create_witness(F::ZERO, F::ZERO, 0, file_tree_depth, 0, agg_depth, false)
}

/// Creates a FileLedger with the given file metadatas.
/// This centralizes the common pattern of building ledgers in tests.
pub fn create_ledger_from_metadatas(metadatas: &[&FileMetadata]) -> FileLedger {
    let mut ledger = FileLedger::new();
    for metadata in metadatas {
        let depth = tree_depth_from_metadata(metadata);
        ledger
            .add_file(metadata.file_id.clone(), metadata.root, depth)
            .expect("Failed to add file to ledger");
    }
    ledger
}

/// Creates N test files with deterministic seeds and returns (prepared_files, metadatas).
/// This reduces boilerplate for multi-file test setups.
pub fn create_test_files(
    count: usize,
    base_size: usize,
    base_seed: u64,
) -> (BTreeMap<String, PreparedFile>, Vec<FileMetadata>) {
    let mut files = BTreeMap::new();
    let mut metadatas = Vec::new();

    for i in 0..count {
        let size = base_size + i * 10; // Vary sizes slightly
        let seed = base_seed + i as u64;
        let data = create_test_data(size, Some(seed));

        let (prepared, metadata) =
            prepare_file(&data, "test_file.dat").expect("Failed to prepare test file");

        files.insert(metadata.file_id.clone(), prepared);
        metadatas.push(metadata);
    }

    (files, metadatas)
}

// =============================================================================
// Ledger Creation Helpers
// =============================================================================

/// Create a FileLedger containing a single file.
/// This is a test helper to reduce boilerplate when creating ledgers.
pub fn create_single_file_ledger(metadata: &FileMetadata) -> FileLedger {
    let mut ledger = FileLedger::new();
    ledger
        .add_file(
            metadata.file_id.clone(),
            metadata.root,
            tree_depth_from_metadata(metadata),
        )
        .expect("Failed to add file to test ledger");
    ledger
}

/// Create a FileLedger containing multiple files.
/// This is a test helper to reduce boilerplate when creating ledgers.
pub fn create_multi_file_ledger(metadatas: &[&FileMetadata]) -> FileLedger {
    let mut ledger = FileLedger::new();
    for metadata in metadatas {
        ledger
            .add_file(
                metadata.file_id.clone(),
                metadata.root,
                tree_depth_from_metadata(metadata),
            )
            .expect("Failed to add file to test ledger");
    }
    ledger
}
