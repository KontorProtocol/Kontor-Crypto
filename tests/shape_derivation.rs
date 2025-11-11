//! Tests for dynamic shape derivation and parameter caching

use ff::Field;
use kontor_crypto::{
    api::{Challenge, FieldElement, FileMetadata},
    config, params,
};

#[test]
fn test_derive_shape_basic() {
    // Test basic shape derivation
    assert_eq!(config::derive_shape(1, 5), (1, 5));
    assert_eq!(config::derive_shape(2, 10), (2, 10));
    assert_eq!(config::derive_shape(3, 8), (4, 8)); // 3 -> next_power_of_two = 4
    assert_eq!(config::derive_shape(5, 12), (8, 12)); // 5 -> next_power_of_two = 8
    assert_eq!(config::derive_shape(0, 0), (1, 1)); // Edge case: 0 files -> 1, min depth 1
}

#[test]
fn test_derive_shape_powers_of_two() {
    // Test that powers of two remain unchanged
    for i in 0..10 {
        let num_files = 1 << i; // 1, 2, 4, 8, 16, ...
        let depth = 10;
        assert_eq!(config::derive_shape(num_files, depth), (num_files, depth));
    }
}

#[test]
fn test_param_cache_consistency() {
    // Test that loading params twice gives the same result
    let files_per_step = 4;
    let file_tree_depth = 10;
    let aggregated_tree_depth = 2;

    // Clear cache to start fresh
    params::clear_memory_cache();

    // First load
    let params1 =
        params::load_or_generate_params(files_per_step, file_tree_depth, aggregated_tree_depth)
            .expect("Failed to load params");

    // Second load should come from cache
    let params2 =
        params::load_or_generate_params(files_per_step, file_tree_depth, aggregated_tree_depth)
            .expect("Failed to load params");

    // They should have the same shape parameters
    assert_eq!(params1.file_tree_depth, params2.file_tree_depth);
    assert_eq!(params1.max_supported_depth, params2.max_supported_depth);
    assert_eq!(params1.aggregated_tree_depth, params2.aggregated_tree_depth);

    // Cache should have at least 1 entry (might have more if other tests ran in parallel)
    assert!(params::memory_cache_size() >= 1);
}

#[test]
fn test_param_cache_different_shapes() {
    // Test that different shapes get different params
    params::clear_memory_cache();

    // Load params for shape 1
    let _params1 = params::load_or_generate_params(2, 5, 0).expect("Failed to load params 1");

    // Load params for shape 2
    let _params2 = params::load_or_generate_params(4, 8, 0).expect("Failed to load params 2");

    // Cache should have at least 2 entries (might have more if other tests ran in parallel)
    assert!(params::memory_cache_size() >= 2);
}

#[test]
fn test_shape_from_challenges() {
    // Create some test challenges with different file depths
    let metadata1 = FileMetadata {
        root: FieldElement::ZERO,
        file_id: "file1".to_string(),
        padded_len: 16, // depth 4 (2^4 = 16)
        original_size: 100,
        filename: "file1.dat".to_string(),
    };

    let metadata2 = FileMetadata {
        root: FieldElement::ZERO,
        file_id: "file2".to_string(),
        padded_len: 64, // depth 6 (2^6 = 64)
        original_size: 200,
        filename: "file2.dat".to_string(),
    };

    let metadata3 = FileMetadata {
        root: FieldElement::ZERO,
        file_id: "file3".to_string(),
        padded_len: 8, // depth 3 (2^3 = 8)
        original_size: 50,
        filename: "file3.dat".to_string(),
    };

    let challenges = [
        Challenge::new_test(metadata1, 1000, 1, FieldElement::ZERO),
        Challenge::new_test(metadata2, 1000, 1, FieldElement::ZERO),
        Challenge::new_test(metadata3, 1000, 1, FieldElement::ZERO),
    ];

    // Calculate max depth from challenges
    let max_depth = challenges
        .iter()
        .map(|c| kontor_crypto::api::tree_depth_from_metadata(&c.file_metadata))
        .max()
        .unwrap();

    assert_eq!(max_depth, 6); // max(4, 6, 3) = 6

    // Derive shape
    let (files_per_step, file_tree_depth) = config::derive_shape(challenges.len(), max_depth);

    assert_eq!(files_per_step, 4); // next_power_of_two(3) = 4
    assert_eq!(file_tree_depth, 6); // max depth unchanged
}

#[test]
fn test_edge_cases() {
    // Test with 0 files (should default to 1)
    let (files, depth) = config::derive_shape(0, 10);
    assert_eq!(files, 1);
    assert_eq!(depth, 10);

    // Test with large numbers
    let (files, depth) = config::derive_shape(100, 20);
    assert_eq!(files, 128); // next_power_of_two(100) = 128
    assert_eq!(depth, 20);

    // Test with exactly power of 2
    let (files, depth) = config::derive_shape(64, 15);
    assert_eq!(files, 64);
    assert_eq!(depth, 15);
}
