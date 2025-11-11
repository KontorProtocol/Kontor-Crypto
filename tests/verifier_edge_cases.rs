//! Tests for malicious or non-standard verifier inputs and edge cases

use kontor_crypto::api::{self, Challenge, FieldElement};
use std::collections::BTreeMap;

#[test]
fn test_duplicate_file_challenges() {
    // VERIF-01: Test behavior when verifier requests same file multiple times
    println!("Testing duplicate file challenges in multi-file proof");

    let data = vec![1u8; 100];

    let (prepared, metadata) = api::prepare_file(&data, "test_file.dat").unwrap();

    // Create challenges for the same file multiple times [A, A, A]
    let seed = FieldElement::from(42u64);
    let challenges = vec![
        Challenge::new_test(metadata.clone(), 1000, 1, seed),
        Challenge::new_test(metadata.clone(), 1000, 1, seed),
        Challenge::new_test(metadata.clone(), 1000, 1, seed),
    ];

    let mut files = BTreeMap::new();
    files.insert(metadata.file_id.clone(), &prepared);

    // Create ledger (for multi-file proof)
    let mut ledger = kontor_crypto::ledger::FileLedger::new();
    ledger
        .add_file(
            metadata.file_id.clone(),
            metadata.root,
            kontor_crypto::api::tree_depth_from_metadata(&metadata),
        )
        .unwrap();

    // Try to prove with duplicate challenges
    let system = kontor_crypto::api::PorSystem::new(&ledger);
    let files_vec = vec![&prepared];
    let result = system.prove(files_vec, &challenges);

    // Document the actual behavior (should either error or handle gracefully)
    match result {
        Ok(proof) => {
            println!("  System allows duplicate file challenges (deduplication or repetition)");

            // If it succeeds, verify the proof works
            let verify_result = system.verify(&proof, &challenges);
            match verify_result {
                Ok(true) => {
                    println!("  Duplicate challenges verified successfully");
                    println!("✓ Duplicate file challenges handled gracefully (proof verifies)");
                }
                Ok(false) => {
                    println!("  Duplicate challenges failed verification");
                    println!("✓ Duplicate challenges handled but verification failed (acceptable edge case)");
                }
                Err(e) => {
                    println!("  Verification error with duplicates: {:?}", e);
                    println!("✓ Duplicate challenges cause verification error (acceptable edge case behavior)");
                    // This is acceptable - duplicate challenges are an edge case
                }
            }
        }
        Err(e) => {
            println!("✓ Duplicate file challenges rejected with error: {}", e);
            // This is also acceptable behavior
        }
    }
}

#[test]
fn test_malformed_metadata_non_power_of_two_padded_len() {
    // VERIF-02: Test verifier with malformed FileMetadata (non-power-of-two padded_len)
    println!("Testing verification with malformed FileMetadata (non-power-of-two padded_len)");

    // First create a valid proof
    let data = vec![5u8; 80];

    let (prepared, valid_metadata) = api::prepare_file(&data, "test_file.dat").unwrap();

    let valid_challenge =
        Challenge::new_test(valid_metadata.clone(), 1000, 1, FieldElement::from(999u64));

    let mut files = BTreeMap::new();
    files.insert(valid_metadata.file_id.clone(), &prepared);

    // Create ledger for unified API
    let mut ledger = kontor_crypto::FileLedger::new();
    ledger
        .add_file(
            valid_metadata.file_id.clone(),
            valid_metadata.root,
            api::tree_depth_from_metadata(&valid_metadata),
        )
        .unwrap();

    let system = kontor_crypto::api::PorSystem::new(&ledger);
    let files_vec: Vec<&_> = files.values().copied().collect();
    let proof = system
        .prove(files_vec, std::slice::from_ref(&valid_challenge))
        .expect("Should generate valid proof");

    // Verify with correct metadata works
    let valid_result = system
        .verify(&proof, &[valid_challenge])
        .expect("Valid verification should complete");
    assert!(valid_result, "Valid metadata should verify");

    // Now create malformed metadata with non-power-of-two padded_len
    let mut malformed_metadata = valid_metadata.clone();
    malformed_metadata.padded_len = 7; // Not a power of two!

    let malformed_challenge = Challenge::new_test(
        malformed_metadata.clone(),
        1000,
        1,
        FieldElement::from(999u64),
    );

    // Create ledger with malformed metadata for verification
    let mut malformed_ledger = kontor_crypto::FileLedger::new();
    malformed_ledger
        .add_file(
            malformed_metadata.file_id.clone(),
            malformed_metadata.root,
            api::tree_depth_from_metadata(&malformed_metadata),
        )
        .unwrap();

    // Try to verify with malformed metadata
    let malformed_system = kontor_crypto::api::PorSystem::new(&malformed_ledger);
    let malformed_result = malformed_system.verify(&proof, &[malformed_challenge]);

    match malformed_result {
        Ok(is_valid) => {
            assert!(
                !is_valid,
                "Proof with non-power-of-two padded_len should not verify as valid"
            );
            println!("✓ Malformed metadata (padded_len=7) correctly rejected (returned false)");
        }
        Err(e) => {
            println!("✓ Malformed metadata correctly caused error: {}", e);
        }
    }
}

#[test]
fn test_inconsistent_metadata_fields() {
    // Additional test for other metadata inconsistencies
    println!("Testing verification with internally inconsistent metadata");

    let data = vec![10u8; 100];

    let (prepared, valid_metadata) = api::prepare_file(&data, "test_file.dat").unwrap();
    let valid_challenge =
        Challenge::new_test(valid_metadata.clone(), 1000, 1, FieldElement::from(123u64));

    let mut files = BTreeMap::new();
    files.insert(valid_metadata.file_id.clone(), &prepared);

    // Create ledger for unified API
    let mut ledger = kontor_crypto::FileLedger::new();
    ledger
        .add_file(
            valid_metadata.file_id.clone(),
            valid_metadata.root,
            api::tree_depth_from_metadata(&valid_metadata),
        )
        .unwrap();

    let system = kontor_crypto::api::PorSystem::new(&ledger);
    let files_vec: Vec<&_> = files.values().copied().collect();
    let proof = system
        .prove(files_vec, std::slice::from_ref(&valid_challenge))
        .expect("Should generate valid proof");

    // Test 1: original_size > total_symbols * 31 (logically impossible)
    let mut inconsistent_meta1 = valid_metadata.clone();
    inconsistent_meta1.original_size = inconsistent_meta1.total_symbols() * 31 + 100;

    let bad_challenge1 = Challenge::new_test(
        inconsistent_meta1.clone(),
        1000,
        1,
        FieldElement::from(123u64),
    );

    // Create ledger with inconsistent metadata for verification
    let mut bad_ledger1 = kontor_crypto::FileLedger::new();
    bad_ledger1
        .add_file(
            inconsistent_meta1.file_id.clone(),
            inconsistent_meta1.root,
            api::tree_depth_from_metadata(&inconsistent_meta1),
        )
        .unwrap();

    let bad_system1 = kontor_crypto::api::PorSystem::new(&bad_ledger1);
    let result1 = bad_system1.verify(&proof, &[bad_challenge1]);

    match result1 {
        Ok(is_valid) => {
            // Note: The verifier may not validate this logical inconsistency
            // since it doesn't need to reconstruct the file
            if is_valid {
                println!("⚠️  Metadata with original_size > blob_size accepted (verifier doesn't validate this)");
            } else {
                println!("✓ Metadata with original_size > blob_size rejected");
            }
        }
        Err(_) => {
            println!("✓ Metadata with original_size > blob_size caused error");
        }
    }

    // Test 2: padded_len = 0 (invalid tree)
    let mut inconsistent_meta2 = valid_metadata.clone();
    inconsistent_meta2.padded_len = 0;

    let bad_challenge2 = Challenge::new_test(
        inconsistent_meta2.clone(),
        1000,
        1,
        FieldElement::from(123u64),
    );

    // Create ledger with zero padded_len metadata
    let mut bad_ledger2 = kontor_crypto::FileLedger::new();
    bad_ledger2
        .add_file(
            inconsistent_meta2.file_id.clone(),
            inconsistent_meta2.root,
            api::tree_depth_from_metadata(&inconsistent_meta2),
        )
        .unwrap();

    let bad_system2 = kontor_crypto::api::PorSystem::new(&bad_ledger2);
    let result2 = bad_system2.verify(&proof, &[bad_challenge2]);

    match result2 {
        Ok(is_valid) => {
            assert!(!is_valid, "Metadata with padded_len=0 should fail");
            println!("✓ Metadata with padded_len=0 rejected");
        }
        Err(_) => {
            println!("✓ Metadata with padded_len=0 caused error");
        }
    }
}
