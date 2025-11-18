//! Parameter caching and management for dynamic circuit shapes.
//!
//! This module provides in-memory caching for Nova parameters,
//! allowing efficient reuse of expensive parameter generation within a session.
//! Parameters are uniquely determined by (files_per_step, file_tree_depth, aggregated_tree_depth).

use crate::{api::PorParams, circuit::PorCircuit, ledger::FileLedger, KontorPoRError, Result};
use nova_snark::{
    nova::{CompressedSNARK, PublicParams},
    provider::{ipa_pc, PallasEngine, VestaEngine},
    spartan::snark::RelaxedR1CSSNARK,
    traits::{snark::RelaxedR1CSSNARKTrait, Engine},
};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{debug, info};

// Type aliases for readability
type E1 = PallasEngine;
type E2 = VestaEngine;
type EE1 = ipa_pc::EvaluationEngine<E1>;
type EE2 = ipa_pc::EvaluationEngine<E2>;
type S1 = RelaxedR1CSSNARK<E1, EE1>;
type S2 = RelaxedR1CSSNARK<E2, EE2>;
type F1 = <E1 as Engine>::Scalar;
// Nova 0.41.0 uses a single circuit type C instead of C1/C2
type C = PorCircuit<F1>;

/// Cache key for storing parameters. Parameters depend on the complete circuit shape.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ParamKey {
    files_per_step: usize,
    file_tree_depth: usize,
    aggregated_tree_depth: usize,
}

/// Maximum number of parameter sets to cache in memory.
/// Prevents unbounded memory growth from many unique circuit shapes.
const MAX_CACHE_SIZE: usize = 50;

/// In-memory cache for storing generated parameters.
/// This avoids redundant parameter generation for frequently used shapes.
/// Limited to MAX_CACHE_SIZE entries with LRU eviction.
static MEMORY_CACHE: Lazy<Mutex<HashMap<ParamKey, PorParams>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Generate new parameters for the given shape.
fn generate_params_for_shape(
    files_per_step: usize,
    file_tree_depth: usize,
    aggregated_tree_depth: usize,
) -> Result<PorParams> {
    use crate::api::generate_circuit_witness;
    use crate::api::{Challenge, FieldElement, FileMetadata};
    use ff::Field;

    info!(
        "Generating new parameters for shape {}x{} with agg_depth={}",
        files_per_step, file_tree_depth, aggregated_tree_depth
    );

    // Create dummy challenges for parameter generation
    let dummy_challenges = (0..files_per_step)
        .map(|i| {
            let metadata = FileMetadata {
                root: FieldElement::ZERO,
                file_id: format!("dummy{}", i),
                padded_len: if i == 0 {
                    1 << file_tree_depth // First file at max depth
                } else {
                    1 // Other files at minimal depth for diversity
                },
                original_size: 0,
                filename: format!("dummy{}.dat", i),
            };
            Challenge::new(
                metadata,
                0,
                1,
                FieldElement::ZERO,
                String::from("test_prover"),
            )
        })
        .collect::<Vec<_>>();

    let dummy_challenges_refs: Vec<&Challenge> = dummy_challenges.iter().collect();

    // Create dummy ledger for parameter generation
    let mut dummy_ledger = FileLedger::new();
    for challenge in &dummy_challenges {
        let file_depth = if challenge.file_metadata.padded_len > 0 {
            challenge.file_metadata.padded_len.trailing_zeros() as usize
        } else {
            0
        };
        dummy_ledger
            .add_file(
                challenge.file_metadata.file_id.clone(),
                challenge.file_metadata.root,
                file_depth,
            )
            .expect("Dummy ledger operations should never fail during parameter generation");
    }

    // Generate witness using the canonical function
    // For parameter generation, ledger indices don't matter (all zeros)
    let dummy_ledger_indices = vec![0usize; files_per_step];
    let (circuit_witness, _) = generate_circuit_witness(
        &dummy_challenges_refs,
        None,          // No actual files for parameter generation
        &dummy_ledger, // Dummy ledger for parameter generation
        file_tree_depth,
        file_tree_depth, // For exact shape, max_supported = actual
        FieldElement::ZERO,
        aggregated_tree_depth,
        0,                     // step 0 for param gen
        &dummy_ledger_indices, // Dummy indices for param generation
    )?;

    // Create the circuit with the generated witness
    let circuit_primary = C::new(
        files_per_step,
        file_tree_depth,
        aggregated_tree_depth,
        Some(circuit_witness.witnesses().to_vec()),
    );

    // Generate public params
    let pp = PublicParams::<E1, E2, C>::setup(
        &circuit_primary,
        &*S1::ck_floor(),
        &*S2::ck_floor(),
    )
    .map_err(|e| {
        KontorPoRError::Snark(format!("Failed to setup public params: {:?}", e))
    })?;

    // Generate compressed SNARK keys
    let (pk, vk) = CompressedSNARK::setup(&pp).map_err(|e| {
        KontorPoRError::Snark(format!("Failed to setup compressed SNARK keys: {:?}", e))
    })?;

    Ok(PorParams {
        pp: Arc::new(pp),  // Wrap in Arc for efficient sharing
        keys: crate::api::KeyPair {
            pk: Arc::new(pk),  // Wrap in Arc
            vk: Arc::new(vk),  // Wrap in Arc
        },
        file_tree_depth,
        max_supported_depth: file_tree_depth,
        aggregated_tree_depth,
    })
}

/// Load or generate parameters for the given shape.
/// This is the main entry point for getting parameters.
///
/// # Arguments
/// * `files_per_step` - Number of file slots in the circuit (power of 2)
/// * `file_tree_depth` - Maximum Merkle tree depth for files
/// * `aggregated_tree_depth` - Depth of the aggregation tree (0 for single-file)
///
/// # Returns
/// Parameters configured for the exact shape, either from cache or newly generated.
pub fn load_or_generate_params(
    files_per_step: usize,
    file_tree_depth: usize,
    aggregated_tree_depth: usize,
) -> Result<PorParams> {
    let key = ParamKey {
        files_per_step,
        file_tree_depth,
        aggregated_tree_depth,
    };

    // Check memory cache first
    {
        let cache = MEMORY_CACHE
            .lock()
            .expect("Parameter cache mutex should not be poisoned");
        if let Some(params) = cache.get(&key) {
            debug!("Using memory-cached parameters for {:?}", key);
            return Ok(params.clone());
        }
    }

    // Generate new parameters
    let params = generate_params_for_shape(files_per_step, file_tree_depth, aggregated_tree_depth)?;

    // Store in memory cache with size limit
    {
        let mut cache = MEMORY_CACHE
            .lock()
            .expect("Parameter cache mutex should not be poisoned");

        // Simple eviction: if at max size, remove an arbitrary entry
        if cache.len() >= MAX_CACHE_SIZE {
            if let Some(old_key) = cache.keys().next().cloned() {
                cache.remove(&old_key);
                info!("Evicted parameter cache entry to stay under limit");
            }
        }

        cache.insert(key, params.clone());
    }

    Ok(params)
}

/// Clear the in-memory cache. Useful for testing or memory management.
pub fn clear_memory_cache() {
    let mut cache = MEMORY_CACHE
        .lock()
        .expect("Parameter cache mutex should not be poisoned");
    cache.clear();
    debug!("Memory cache cleared");
}

/// Get the current memory cache size.
pub fn memory_cache_size() -> usize {
    let cache = MEMORY_CACHE
        .lock()
        .expect("Parameter cache mutex should not be poisoned");
    cache.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key() {
        let key1 = ParamKey {
            files_per_step: 4,
            file_tree_depth: 10,
            aggregated_tree_depth: 2,
        };

        let key2 = ParamKey {
            files_per_step: 4,
            file_tree_depth: 10,
            aggregated_tree_depth: 2,
        };

        let key3 = ParamKey {
            files_per_step: 8,
            file_tree_depth: 10,
            aggregated_tree_depth: 2,
        };

        let key4 = ParamKey {
            files_per_step: 4,
            file_tree_depth: 10,
            aggregated_tree_depth: 3,
        };

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key1, key4);
    }
}
