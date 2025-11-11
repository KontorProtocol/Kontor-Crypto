//! Regression tests for previously fixed bugs.
//!
//! These tests ensure we don't reintroduce issues that have been resolved.
//! Each test documents the specific bug it prevents.

mod common;
use common::{
    assertions::assert_prove_and_verify_succeeds,
    fixtures::{setup_test_scenario, FileSpec, TestConfig},
};

#[test]
fn regression_depth_zero_special_case() {
    // Regression test for the depth=0 branching bug that caused InvalidSumcheckProof errors.
    //
    // Background: The circuit previously had a special case for depth=0 that returned early,
    // creating different R1CS constraint structures for different depths.
    // This broke Nova's requirement for uniform circuits.
    //
    // Note: With multi-codeword architecture, minimum depth is now 8 (1 codeword = 255 symbols).
    // This test now verifies multi-file proofs work with minimal depth.

    println!("Testing minimal depth regression (circuit uniformity)");

    // Test multi-file with minimal sizes
    let config = TestConfig::multi_file(2);

    let setup = setup_test_scenario(&config).unwrap();

    // Verify we got small files (depth 8 is minimum with multi-codeword)
    for (i, metadata) in setup.metadatas.iter().enumerate() {
        let depth = metadata.padded_len.trailing_zeros() as usize;
        println!(
            "File {}: padded_len={}, depth={}",
            i, metadata.padded_len, depth
        );
        assert!(
            depth >= 8,
            "File {} should have depth >= 8 with multi-codeword architecture",
            i
        );
    }

    // This would have failed before the circuit uniformity fix
    assert_prove_and_verify_succeeds(setup);

    println!("✓ Multi-file proof works with minimal depth (circuit uniformity bug fixed)");
}

#[test]
fn regression_circuit_uniformity_across_depths() {
    // Regression test for circuit structure uniformity across different tree depths.
    // This was the core issue fixed in Phase 1.
    //
    // Background: Previously, circuits for files of different depths had different
    // constraint structures, violating Nova's uniformity requirements.

    println!("Testing circuit uniformity regression");

    // Test multiple depths - all should work with the same underlying circuit structure
    for depth_target in 0..=3 {
        let config = TestConfig {
            file_specs: vec![FileSpec::for_depth(depth_target)],
            seed: depth_target as u64 * 100,
            ..Default::default()
        };

        let setup = setup_test_scenario(&config).unwrap();
        let actual_depth = setup.metadatas[0].padded_len.trailing_zeros() as usize;

        // This would have failed for certain depths before the uniformity fix
        assert_prove_and_verify_succeeds(setup);

        println!(
            "✓ Target depth {} (actual {}) works with uniform circuit",
            depth_target, actual_depth
        );
    }

    println!("✓ Circuit uniformity across depths verified (Phase 1 fix confirmed)");
}

#[test]
fn regression_deterministic_btreemap_ordering() {
    // Regression test for the HashMap -> BTreeMap fix for deterministic ordering.
    //
    // Background: Previously used HashMap which caused non-deterministic ordering
    // of files in multi-file proofs, leading to inconsistent behavior.

    println!("Testing BTreeMap deterministic ordering regression");

    // Create minimal multi-file setup to test ordering
    let config = TestConfig::multi_file(2);

    // Run the same multi-file test multiple times
    let setup1 = setup_test_scenario(&config).unwrap();
    let setup2 = setup_test_scenario(&config).unwrap();

    // File ordering should be deterministic (BTreeMap sorts by key)
    let files1: Vec<_> = setup1.files.keys().collect();
    let files2: Vec<_> = setup2.files.keys().collect();
    assert_eq!(
        files1, files2,
        "BTreeMap should provide deterministic ordering"
    );

    println!("✓ Deterministic BTreeMap ordering verified (HashMap bug fixed)");
}

#[test]
fn regression_multi_file_proof_functionality() {
    // Separate test to verify multi-file proving works (split from ordering test for speed)
    let setup = setup_test_scenario(&TestConfig::multi_file(2)).unwrap();

    // Verify it's actually a multi-file setup
    assert_eq!(setup.files.len(), 2);
    assert!(setup.ledger.is_some());

    // Should be able to prove and verify
    assert_prove_and_verify_succeeds(setup);

    println!("✓ Multi-file proof functionality verified");
}

#[test]
fn regression_parameter_generation_consistency() {
    // Regression test for parameter generation consistency.
    //
    // Background: Ensures that parameter generation produces consistent results
    // and doesn't vary unexpectedly between runs.

    println!("Testing parameter generation consistency");

    let config = TestConfig {
        seed: 99999, // Fixed seed
        ..Default::default()
    };

    // Generate the same setup multiple times
    let setup1 = setup_test_scenario(&config).unwrap();
    let setup2 = setup_test_scenario(&config).unwrap();

    // Should produce identical metadata
    assert_eq!(setup1.metadatas[0].root, setup2.metadatas[0].root);
    assert_eq!(setup1.metadatas[0].file_id, setup2.metadatas[0].file_id);
    assert_eq!(
        setup1.metadatas[0].total_symbols(),
        setup2.metadatas[0].total_symbols()
    );

    // Both should work
    assert_prove_and_verify_succeeds(setup1);
    assert_prove_and_verify_succeeds(setup2);

    println!("✓ Parameter generation consistency verified");
}

#[test]
fn regression_erasure_coding_edge_cases() {
    // Regression test for edge cases in erasure coding that previously caused issues.
    //
    // Background: Ensures that various erasure coding configurations work correctly
    // and don't cause unexpected failures.

    println!("Testing erasure coding edge cases");

    let edge_case_configs = vec![
        // Single byte file
        (1, "single byte"),
        // Small file
        (50, "small file"),
        // Medium file
        (1024, "medium file"),
    ];

    for (file_size, description) in edge_case_configs {
        let config = TestConfig {
            file_specs: vec![FileSpec::from_size(file_size)],
            ..Default::default()
        };

        let setup = setup_test_scenario(&config).unwrap();
        assert_prove_and_verify_succeeds(setup);

        println!("✓ Erasure coding edge case '{}' works", description);
    }

    println!("✓ Erasure coding edge cases verified");
}
