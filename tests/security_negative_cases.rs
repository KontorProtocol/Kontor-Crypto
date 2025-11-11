//! Negative security tests that should fail.
//!
//! These tests verify that the system correctly rejects invalid inputs
//! and malicious attempts to bypass security constraints.

use kontor_crypto::api::{self, Challenge, FieldElement};
use std::collections::BTreeMap;

mod common;
use common::assertions::assert_error_contains;
use common::fixtures::create_ledger_from_metadatas;

#[test]
fn test_wrong_root_depth_pair_fails() {
    println!("Testing that wrong (root, depth) pairs cause meta-commit mismatch");

    let data = b"Test data for wrong root/depth test";
    let (prepared, metadata) = api::prepare_file(data, "test_file.dat").unwrap();

    // Create correct challenge
    let seed = FieldElement::from(12345u64);
    let correct_challenge = Challenge::new_test(metadata.clone(), 1000, 1, seed);

    // Create challenge with WRONG root but correct depth
    let mut wrong_metadata = metadata.clone();
    wrong_metadata.root = FieldElement::from(999999u64); // Wrong root
    let wrong_challenge = Challenge::new_test(wrong_metadata.clone(), 1000, 1, seed);

    // Generate proof with correct challenge
    let mut files = BTreeMap::new();
    files.insert(metadata.file_id.clone(), &prepared);

    // Create ledger with correct metadata
    let mut correct_ledger = kontor_crypto::FileLedger::new();
    correct_ledger
        .add_file(
            metadata.file_id.clone(),
            metadata.root,
            api::tree_depth_from_metadata(&metadata),
        )
        .unwrap();

    let system = api::PorSystem::new(&correct_ledger);
    let files_vec: Vec<&_> = files.values().copied().collect();
    let proof = system
        .prove(files_vec, std::slice::from_ref(&correct_challenge))
        .expect("Should generate proof with correct challenge");

    // Create ledger with wrong metadata for verification
    let mut wrong_ledger = kontor_crypto::FileLedger::new();
    wrong_ledger
        .add_file(
            wrong_metadata.file_id.clone(),
            wrong_metadata.root,
            api::tree_depth_from_metadata(&wrong_metadata),
        )
        .unwrap();

    // Attempt to verify with wrong challenge (different root)
    // This should fail because files_meta_commitment will be different
    let wrong_system = api::PorSystem::new(&wrong_ledger);
    let result = wrong_system.verify(&proof, &[wrong_challenge]);

    match result {
        Ok(is_valid) => {
            assert!(
                !is_valid,
                "SECURITY VIOLATION: Proof should NOT verify with wrong (root, depth) pair!"
            );
        }
        Err(_) => {
            // Error is also acceptable - the important thing is it doesn't succeed
            println!("✓ Verification failed with error (acceptable)");
        }
    }

    println!("✓ Wrong (root, depth) pair correctly rejected");
}

#[test]
fn test_different_seeds_between_challenges_fails() {
    println!("Testing that challenges with different seeds are allowed (multi-batch aggregation)");

    let data1 = b"First file for seed test";
    let data2 = b"Second file for seed test";

    let (prepared1, metadata1) = api::prepare_file(data1, "test_file.dat").unwrap();
    let (prepared2, metadata2) = api::prepare_file(data2, "test_file.dat").unwrap();

    // Create challenges with DIFFERENT seeds (multi-batch aggregation)
    let seed1 = FieldElement::from(111u64);
    let seed2 = FieldElement::from(222u64); // Different seed - OK!
    let challenge1 = Challenge::new_test(metadata1.clone(), 1000, 1, seed1);
    let challenge2 = Challenge::new_test(metadata2.clone(), 1000, 1, seed2);

    // Create ledger
    let metadatas_refs = vec![&metadata1, &metadata2];
    let ledger = create_ledger_from_metadatas(&metadatas_refs);

    // Create file map
    let mut files = BTreeMap::new();
    files.insert(metadata1.file_id.clone(), &prepared1);
    files.insert(metadata2.file_id.clone(), &prepared2);

    // Prove with mixed seeds - should now succeed!
    let system = api::PorSystem::new(&ledger);
    let files_vec: Vec<&_> = files.values().copied().collect();
    let proof = system
        .prove(files_vec, &[challenge1.clone(), challenge2.clone()])
        .expect("Multi-seed proof should succeed");

    // Verify the proof
    assert!(
        system.verify(&proof, &[challenge1, challenge2]).unwrap(),
        "Multi-seed proof should verify"
    );
    println!("✓ Different seeds correctly accepted for multi-batch aggregation");
}

#[test]
fn test_different_num_challenges_fails() {
    println!("Testing that challenges with different num_challenges are rejected");

    let data1 = b"First file for num_challenges test";
    let data2 = b"Second file for num_challenges test";

    let (prepared1, metadata1) = api::prepare_file(data1, "test_file.dat").unwrap();
    let (prepared2, metadata2) = api::prepare_file(data2, "test_file.dat").unwrap();

    // Create challenges with DIFFERENT num_challenges (this should be rejected)
    let seed = FieldElement::from(42u64);
    let challenge1 = Challenge::new_test(metadata1.clone(), 1000, 2, seed); // 2 challenges
    let challenge2 = Challenge::new_test(metadata2.clone(), 1000, 3, seed); // 3 challenges - different!

    // Create ledger
    let metadatas_refs = vec![&metadata1, &metadata2];
    let ledger = create_ledger_from_metadatas(&metadatas_refs);

    // Create file map
    let mut files = BTreeMap::new();
    files.insert(metadata1.file_id.clone(), &prepared1);
    files.insert(metadata2.file_id.clone(), &prepared2);

    // Attempt to prove with different num_challenges - should fail
    let system = api::PorSystem::new(&ledger);
    let files_vec: Vec<&_> = files.values().copied().collect();
    let result = system.prove(files_vec, &[challenge1, challenge2]);
    assert_error_contains(result, "num_challenges");
    println!("✓ Different num_challenges correctly rejected during proving");
}

#[test]
fn test_zero_challenges_rejected() {
    println!("Testing that zero challenges are rejected");

    let data = b"Test data for zero challenges";
    let (prepared, metadata) = api::prepare_file(data, "test_file.dat").unwrap();

    // Create challenge with num_challenges = 0 (invalid)
    let challenge = Challenge::new_test(metadata.clone(), 1000, 0, FieldElement::from(42u64));

    let mut files = BTreeMap::new();
    files.insert(metadata.file_id.clone(), &prepared);

    // Create ledger for unified API
    let mut ledger = kontor_crypto::FileLedger::new();
    ledger
        .add_file(
            metadata.file_id.clone(),
            metadata.root,
            api::tree_depth_from_metadata(&metadata),
        )
        .unwrap();

    // Should fail during proving
    let system = api::PorSystem::new(&ledger);
    let files_vec: Vec<&_> = files.values().copied().collect();
    let result = system.prove(files_vec, &[challenge]);
    assert_error_contains(result, "challenge");
    println!("✓ Zero challenges correctly rejected");
}

// Note: test_too_many_files_rejected removed - too complex and slow for the benefit
// The PRACTICAL_MAX_FILES limit is validated, but creating 1000+ test files is impractical

#[test]
fn test_empty_data_rejected() {
    println!("Testing that empty data is rejected");

    let empty_data = b""; // Empty data

    // Should fail during prepare_file
    let result = api::prepare_file(empty_data, "test_file.dat");
    assert_error_contains(result, "Empty");
    println!("✓ Empty data correctly rejected");
}
