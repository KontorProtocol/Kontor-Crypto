//! Single-file proof end-to-end tests.

mod common;
use common::{
    assertions::assert_prove_and_verify_succeeds,
    fixtures::{setup_test_scenario, TestConfig},
};

#[test]
fn test_basic_single_file_proof() {
    // Test the most basic case: single file with default settings
    let setup = setup_test_scenario(&TestConfig::default()).unwrap();
    assert_prove_and_verify_succeeds(setup);
}

#[test]
fn test_single_file_multiple_challenges() {
    // Test single file with multiple challenges per file
    let setup = setup_test_scenario(&TestConfig::with_challenges(3)).unwrap();
    assert_prove_and_verify_succeeds(setup);
}

#[test]
fn test_single_file_different_sizes() {
    // Test files that result in different tree depths using minimal data
    // Focus on tree depth boundaries rather than arbitrary large sizes
    use common::assertions::assert_configs_succeed;

    assert_configs_succeed(0..=3, TestConfig::for_depth);
    println!("✓ All depths (0-3) verified with minimal data");
}

#[test]
fn test_single_file_tiny() {
    // Test with very small file (should result in depth 0)
    let setup = setup_test_scenario(&TestConfig::minimal()).unwrap();
    assert_prove_and_verify_succeeds(setup);
}

#[test]
fn test_single_file_deterministic() {
    // Test that same configuration produces identical results using minimal data
    use common::assertions::assert_deterministic_behavior;

    assert_deterministic_behavior(|| {
        let config = TestConfig {
            seed: 12345, // Fixed seed for determinism
            ..Default::default()
        };
        setup_test_scenario(&config).unwrap()
    });
}

#[test]
fn test_full_workflow_single_file() {
    // Test the complete workflow: file preparation -> proof -> verification
    let setup = setup_test_scenario(&TestConfig::with_challenges(2)).unwrap();

    // Verify all components are properly initialized
    assert_eq!(setup.files.len(), 1);
    assert_eq!(setup.metadatas.len(), 1);
    assert_eq!(setup.challenges.len(), 1);
    assert_eq!(setup.challenges[0].num_challenges, 2);
    assert!(setup.ledger.is_some()); // With unified API, ledger is always created

    // Full workflow should succeed
    assert_prove_and_verify_succeeds(setup);

    println!("✓ Full single-file workflow completed successfully");
}

#[test]
fn test_different_challenge_counts() {
    // Test various challenge counts work correctly using minimal data
    use common::assertions::assert_configs_succeed;

    let challenge_counts = vec![1, 2, 3]; // Focus on essential coverage

    assert_configs_succeed(challenge_counts.clone(), |count| {
        TestConfig::with_challenges(count)
    });

    for count in challenge_counts {
        println!("✓ {} challenges verified successfully", count);
    }
}
