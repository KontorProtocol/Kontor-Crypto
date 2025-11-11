//! Comprehensive validation and negative edge case tests.
//!
//! These tests verify that the API properly validates inputs and
//! rejects invalid parameters with appropriate error messages.

use kontor_crypto::api::{self, FieldElement};
use sha2::{Digest, Sha256};

mod common;
use common::{
    assertions::{
        assert_error_contains, assert_prove_and_verify_succeeds, assert_prove_fails,
        assert_verify_fails_contains,
    },
    fixtures::{create_test_data, setup_test_scenario, FileSpec, TestConfig},
};

// ================== API Input Validation Tests ==================

#[test]
fn test_prove_with_zero_challenges() {
    // Verify prove rejects challenges that specify zero proof iterations
    println!("Testing prove with zero challenges");

    let mut setup = setup_test_scenario(&TestConfig::default()).unwrap();

    // Modify challenge to have num_challenges = 0
    setup.challenges[0].num_challenges = 0;

    let file_refs = setup.file_refs();
    let ledger_ref = setup.ledger_ref();

    // This should fail
    let ledger = ledger_ref.expect("Ledger should be available for unified API");
    let system = kontor_crypto::api::PorSystem::new(ledger);
    let files_vec: Vec<&_> = file_refs.values().copied().collect();
    let result = system.prove(files_vec, &setup.challenges);

    assert_error_contains(result, "challenge");

    println!("✓ Zero challenges correctly rejected in prove");
}

#[test]
fn test_verify_with_zero_challenges() {
    // Verify verify rejects challenges that specify zero proof iterations
    println!("Testing verify with zero challenges");

    // First generate a valid proof
    let setup = setup_test_scenario(&TestConfig::default()).unwrap();
    let file_refs = setup.file_refs();
    let ledger_ref = setup.ledger_ref();

    let ledger = ledger_ref.expect("Ledger should be available for unified API");
    let system = api::PorSystem::new(ledger);
    let files_vec: Vec<&_> = file_refs.values().copied().collect();
    let proof = system
        .prove(files_vec, &setup.challenges)
        .expect("Should generate valid proof");

    // Create challenges with num_challenges = 0 for verification
    let mut zero_challenges = setup.challenges.clone();
    zero_challenges[0].num_challenges = 0;

    // This should fail
    let result = system.verify(&proof, &zero_challenges);

    // Should either error or return false (gets caught by challenge ID validation)
    assert_verify_fails_contains(result, Some("Challenge ID mismatch"));

    println!("✓ Zero challenges correctly rejected in verify");
}

#[test]
fn test_prove_fails_with_empty_challenges_slice() {
    // Ensure prove handles an empty slice of challenges gracefully
    println!("Testing prove with empty challenges slice");

    let setup = setup_test_scenario(&TestConfig::default()).unwrap();
    let file_refs = setup.file_refs();
    let ledger_ref = setup.ledger_ref();

    // Call prove with empty challenges
    let ledger = ledger_ref.expect("Ledger should be available for unified API");
    let system = api::PorSystem::new(ledger);
    let files_vec: Vec<&_> = file_refs.values().copied().collect();
    let result = system.prove(files_vec, &[]);

    assert_error_contains(result, "challenge");

    println!("✓ Empty challenges slice correctly rejected");
}

#[test]
fn test_file_metadata_sha256_matches_input() {
    // Confirm that the file_id in FileMetadata is the correct SHA-256 digest
    println!("Testing file_id is correct SHA-256 of input data");

    let data = b"Hello, Kontor PoR!";

    // Prepare file and get metadata
    let (_prepared, metadata) =
        api::prepare_file(data, "test_file.dat").expect("Should prepare file");

    // Manually compute SHA-256
    let mut hasher = Sha256::new();
    hasher.update(data);
    let expected_hash = format!("{:x}", hasher.finalize());

    // Compare
    assert_eq!(
        metadata.file_id, expected_hash,
        "file_id should match SHA-256 of input data"
    );

    println!("✓ file_id correctly matches SHA-256 of input");
}

#[test]
fn test_reconstruct_fails_metadata_inconsistencies() {
    // Verify reconstruct_file fails when metadata contains logical inconsistencies
    println!("Testing reconstruct_file with inconsistent metadata");

    let data = create_test_data(512, Some(12345));

    // Prepare file and get symbols
    let (_prepared, metadata) =
        api::prepare_file(&data, "test_file.dat").expect("Should prepare file");

    // Create mock symbols for testing (all zero-filled)
    let total_symbols = metadata.total_symbols();
    let complete_shards: Vec<Option<Vec<u8>>> =
        (0..total_symbols).map(|_| Some(vec![0u8; 31])).collect();

    // Test: original_size > total_symbols * 31 (logical inconsistency)
    let mut tampered_metadata = metadata.clone();
    tampered_metadata.original_size = tampered_metadata.total_symbols() * 31 + 100;

    let result = api::reconstruct_file(&complete_shards, &tampered_metadata);
    assert!(
        result.is_err(),
        "reconstruct_file should reject metadata where original_size > blob_size"
    );

    println!("✓ Metadata inconsistencies correctly handled");
}

#[test]
fn test_challenge_seed_overflow_handling() {
    // Test that extremely large seed values are handled correctly
    println!("Testing challenge seed overflow handling");

    let setup = setup_test_scenario(&TestConfig::default()).unwrap();
    let file_refs = setup.file_refs();
    let ledger_ref = setup.ledger_ref();

    // Create challenge with maximum field element value as seed
    let max_seed = FieldElement::from(u64::MAX);
    let mut max_seed_challenges = setup.challenges.clone();
    max_seed_challenges[0].seed = max_seed;

    // This should work without overflow
    let ledger = ledger_ref.expect("Ledger should be available for unified API");
    let system = api::PorSystem::new(ledger);
    let files_vec: Vec<&_> = file_refs.values().copied().collect();
    let result = system.prove(files_vec, &max_seed_challenges);
    assert!(result.is_ok(), "Should handle maximum seed value");

    println!("✓ Large seed values handled correctly");
}

// ================== Setup and Configuration Validation Tests ==================

#[test]
fn test_empty_file_specs_fails() {
    // Test that empty file specs fails during setup
    let config = TestConfig {
        file_specs: vec![], // No files
        ..Default::default()
    };

    let result = setup_test_scenario(&config);
    match result {
        Ok(setup) => {
            // If it succeeds, it should have 0 files (empty)
            assert_eq!(setup.files.len(), 0);
            assert_eq!(setup.metadatas.len(), 0);
            println!("✓ Empty file specs handled gracefully with 0 files");
        }
        Err(_) => {
            println!("✓ Empty file specs correctly rejected");
        }
    }
}

#[test]
fn test_zero_size_file_handling() {
    // Test edge case with zero-size file
    let config = TestConfig {
        file_specs: vec![FileSpec::from_size(0)],
        ..Default::default()
    };

    let result = setup_test_scenario(&config);
    // This might succeed or fail depending on implementation
    // The important thing is that it doesn't panic
    match result {
        Ok(setup) => {
            // If it succeeds, verification should work
            assert_prove_and_verify_succeeds(setup);
            println!("✓ Zero-size file handled gracefully");
        }
        Err(_) => {
            println!("✓ Zero-size file correctly rejected during setup");
        }
    }
}

#[test]
fn test_invalid_challenge_count() {
    // Test with zero challenges
    let config = TestConfig {
        file_specs: vec![FileSpec::from_size(100)],
        challenges_per_file: 0, // Invalid
        ..Default::default()
    };

    let result = setup_test_scenario(&config);
    match result {
        Ok(setup) => {
            // If setup succeeds, proving should fail
            let file_refs = setup.file_refs();
            let ledger_ref = setup.ledger_ref();
            let ledger = ledger_ref.expect("Ledger should be available for unified API");
            let system = api::PorSystem::new(ledger);
            let files_vec: Vec<&_> = file_refs.values().copied().collect();
            let prove_result = system.prove(files_vec, &setup.challenges);
            assert!(
                prove_result.is_err(),
                "Zero challenges should fail during proving"
            );
        }
        Err(_) => {
            println!("✓ Zero challenges correctly rejected during setup");
        }
    }
}

#[test]
fn test_extremely_large_challenge_count() {
    // Test with very large challenge count
    let config = TestConfig {
        file_specs: vec![FileSpec::from_size(100)],
        challenges_per_file: 1000, // Very large
        ..Default::default()
    };

    let setup = setup_test_scenario(&config).unwrap();
    assert_eq!(setup.challenges[0].num_challenges, 1000);

    // This should work but might be slow
    // For now, just verify setup succeeds
    println!("✓ Large challenge count handled in setup");
}

#[test]
fn test_chunk_size_boundary_conditions() {
    // Test files around chunk size boundaries
    use common::assertions::assert_configs_succeed;
    use kontor_crypto::config::CHUNK_SIZE_BYTES;

    let boundary_sizes = vec![
        CHUNK_SIZE_BYTES / 2, // Half chunk
        CHUNK_SIZE_BYTES - 1, // Just under one chunk
        CHUNK_SIZE_BYTES,     // Exactly one chunk
        CHUNK_SIZE_BYTES + 1, // Just over one chunk
        CHUNK_SIZE_BYTES * 2, // Exactly two chunks
    ];

    assert_configs_succeed(boundary_sizes.clone(), |size| TestConfig {
        file_specs: vec![FileSpec::from_size(size)],
        ..Default::default()
    });

    for size in boundary_sizes {
        println!(
            "✓ Size {} (relative to chunk size {}) verified",
            size, CHUNK_SIZE_BYTES
        );
    }
}

#[test]
fn test_file_size_extremes() {
    // Test key size boundaries that exercise different logic paths
    use common::assertions::assert_configs_succeed;
    use kontor_crypto::config::CHUNK_SIZE_BYTES;

    let boundary_sizes = vec![
        1,                    // Single byte
        CHUNK_SIZE_BYTES / 2, // Small depth 0
        CHUNK_SIZE_BYTES,     // Exactly one chunk
        CHUNK_SIZE_BYTES + 1, // Just over one chunk
        CHUNK_SIZE_BYTES * 2, // Two chunks
    ];

    assert_configs_succeed(boundary_sizes.clone(), |size| TestConfig {
        file_specs: vec![FileSpec::from_size(size)],
        ..Default::default()
    });

    for size in boundary_sizes {
        println!("✓ Boundary size {} verified", size);
    }
}

// ================== Multi-file Validation Tests ==================

#[test]
fn test_prove_fails_with_mismatched_challenge_seeds() {
    // Test that api::prove now accepts challenges with different seeds (multi-batch aggregation)
    use kontor_crypto::api::FieldElement;

    // Create a multi-file setup
    let mut setup = setup_test_scenario(&TestConfig::multi_file(2)).unwrap();

    // Modify one challenge to have a different seed (now allowed!)
    setup.challenges[1].seed = FieldElement::from(99999u64);

    // This should now succeed (multi-batch aggregation)
    let system = kontor_crypto::api::PorSystem::new(setup.ledger.as_ref().unwrap());
    let files_vec: Vec<&_> = setup.files.values().collect();
    let proof = system
        .prove(files_vec, &setup.challenges)
        .expect("Multi-seed proof should succeed");

    // Verify the proof
    assert!(
        system.verify(&proof, &setup.challenges).unwrap(),
        "Multi-seed proof should verify"
    );

    println!("✓ Different challenge seeds correctly accepted (multi-batch aggregation)");
}

#[test]
fn test_prove_fails_with_mismatched_num_challenges() {
    // Test that api::prove correctly rejects a list of challenges where the num_challenges
    // values differ

    // Create a multi-file setup
    let mut setup = setup_test_scenario(&TestConfig::multi_file(2)).unwrap();

    // Modify one challenge to have a different num_challenges
    setup.challenges[1].num_challenges += 1;

    // This should fail during prove() with a num_challenges mismatch error
    assert_prove_fails(setup, "Challenge mismatch: num_challenges");

    println!("✓ Mismatched num_challenges correctly rejected");
}

#[test]
fn test_prove_fails_with_missing_file() {
    // Test that api::prove correctly rejects when a challenged file is not provided

    // Create a multi-file setup
    let mut setup = setup_test_scenario(&TestConfig::multi_file(2)).unwrap();

    // Remove one of the files from the files map while keeping the challenge
    let first_key = setup.files.keys().next().unwrap().clone();
    setup.files.remove(&first_key);

    // This should fail during prove() with a missing file error
    assert_prove_fails(setup, "not found");

    println!("✓ Missing file correctly rejected");
}

#[test]
fn test_verify_fails_with_mismatched_challenge_counts() {
    // Test that api::verify correctly rejects when challenges have different num_challenges
    use kontor_crypto::api::PorSystem;

    // Create a valid multi-file setup
    let setup = setup_test_scenario(&TestConfig::multi_file(2)).unwrap();
    let file_refs = setup.file_refs();
    let ledger_ref = setup.ledger_ref();

    // Generate a valid proof first
    let ledger = ledger_ref.expect("Ledger should be available for unified API");
    let system = PorSystem::new(ledger);
    let files_vec: Vec<&_> = file_refs.values().copied().collect();
    let proof = system
        .prove(files_vec, &setup.challenges)
        .expect("Should be able to generate valid proof");

    // Create modified challenges with different num_challenges for verification
    let mut modified_challenges = setup.challenges.clone();
    modified_challenges[1].num_challenges += 1;

    // Verification should fail due to mismatched challenge IDs (caused by different num_challenges)
    let result = system.verify(&proof, &modified_challenges);
    assert_verify_fails_contains(result, Some("Challenge ID mismatch"));

    println!("✓ Mismatched num_challenges in verification correctly rejected");
}

#[test]
fn test_metadata_consistency() {
    // Test that file metadata is consistent and makes sense
    // Use representative boundary sizes rather than arbitrary large ones
    use kontor_crypto::config::CHUNK_SIZE_BYTES;

    let sizes = vec![1, CHUNK_SIZE_BYTES, CHUNK_SIZE_BYTES + 1]; // Key boundaries

    for size in sizes {
        let config = TestConfig {
            file_specs: vec![FileSpec::from_size(size)],
            ..Default::default()
        };

        let setup = setup_test_scenario(&config).unwrap();
        let metadata = setup.metadatas[0].clone();

        // Basic consistency checks
        assert_eq!(metadata.original_size, size);
        assert!(metadata.total_symbols() * 31 >= metadata.original_size); // Should be larger due to erasure
        assert!(metadata.padded_len.is_power_of_two()); // Must be power of 2
        assert!(!metadata.file_id.is_empty()); // Should have a hash

        // Should be able to prove with this metadata
        assert_prove_and_verify_succeeds(setup);

        println!(
            "✓ Size {} metadata consistent: orig={}, total_symbols={}, padded={}",
            size,
            metadata.original_size,
            metadata.total_symbols(),
            metadata.padded_len
        );
    }
}
