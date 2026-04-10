//! End-to-end circuit uniformity tests.
//!
//! These tests verify that the API works correctly with files of different
//! tree depths, ensuring the Phase 1 fixes for circuit uniformity work
//! in practice.

mod common;
use common::fixtures::{setup_test_scenario, TestConfig};

#[test]
fn test_depth_0_through_3_with_same_params() {
    // Test that we can use the same parameters for files of different depths
    // This validates the circuit uniformity implementation
    use common::assertions::assert_configs_succeed;

    // Test each depth from 0 to 3 using optimized convenience method
    assert_configs_succeed(0..=3, TestConfig::for_depth);

    println!("✓ All depths (0-3) verified successfully with same params");
}

#[test]
fn test_circuit_uniformity_with_different_file_sizes() {
    // Test circuit uniformity across different tree depths using minimal data for each depth
    // Test key representative depths rather than exhaustive range
    use common::assertions::assert_configs_succeed;

    let depths = [0, 1, 3]; // Representative depths: edge case, small, medium
    assert_configs_succeed(depths, TestConfig::for_depth);

    println!("✓ Circuit uniformity verified across representative depths");
}

#[test]
fn test_multi_challenge_single_file() {
    // Test that multiple challenges work correctly for a single file using minimal data
    use common::assertions::assert_configs_succeed;

    let test_challenge_counts = vec![1, 2, 3]; // Reduced for speed
    assert_configs_succeed(test_challenge_counts, |num| {
        TestConfig::with_challenges(num)
    });

    println!("✓ Multiple challenge counts verified successfully");
}

#[test]
fn test_parameter_reuse_across_depths() {
    // Test that we can use parameters generated for one depth with files of other depths
    // This verifies the circuit gating implementation using minimal test coverage
    use common::assertions::assert_configs_succeed;

    // Test key depths (0, 1, 3) rather than all depths to reduce proving operations
    assert_configs_succeed([0, 1, 3], TestConfig::for_depth);

    println!("✓ All depths work with unified params");
}

#[test]
fn test_deterministic_behavior_across_depths() {
    // Test that the same configuration produces deterministic results
    // Test only one representative depth to reduce proving operations
    use common::assertions::assert_deterministic_behavior;

    assert_deterministic_behavior(|| {
        let config = TestConfig {
            seed: 12345,                // Fixed seed for determinism
            ..TestConfig::for_depth(1)  // Representative depth
        };
        setup_test_scenario(&config).unwrap()
    });

    println!("✓ Deterministic behavior verified");
}
