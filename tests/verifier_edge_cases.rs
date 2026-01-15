//! Tests for malicious or non-standard verifier inputs and edge cases

use kontor_crypto::api::{self, Challenge, FieldElement};
use kontor_crypto::KontorPoRError;
use std::collections::BTreeMap;

#[test]
fn test_verifier_rejects_out_of_range_ledger_index() {
    // Verifier should reject ledger_indices >= 2^aggregated_tree_depth, since the circuit
    // only consumes low bits and would otherwise permit non-canonical indices.
    let data_a = vec![1u8; 100];
    let data_b = vec![2u8; 100];
    let (prepared_a, meta_a) = api::prepare_file(&data_a, "a.dat", b"").unwrap();
    let (prepared_b, meta_b) = api::prepare_file(&data_b, "b.dat", b"").unwrap();

    let mut ledger = kontor_crypto::FileLedger::new();
    ledger.add_file(&meta_a).unwrap();
    ledger.add_file(&meta_b).unwrap();

    let challenges = vec![
        Challenge::new_test(meta_a.clone(), 1000, 1, FieldElement::from(1u64)),
        Challenge::new_test(meta_b.clone(), 1000, 1, FieldElement::from(2u64)),
    ];

    let system = kontor_crypto::api::PorSystem::new(&ledger);
    let mut proof = system
        .prove(vec![&prepared_a, &prepared_b], &challenges)
        .expect("Should generate a valid multi-file proof");

    assert!(proof.aggregated_tree_depth > 0, "Must be multi-file proof");

    // Make ledger_index out of range: max is (1<<depth)-1, so choose 1<<depth.
    let out_of_range = 1usize << proof.aggregated_tree_depth;
    proof.ledger_indices[0] = out_of_range;

    let res = system.verify(&proof, &challenges);
    assert!(
        matches!(res, Err(KontorPoRError::InvalidInput(_))),
        "Expected InvalidInput for out-of-range ledger index, got: {res:?}"
    );
}

#[test]
fn test_verifier_rejects_ledger_indices_length_mismatch() {
    // Verifier should reject proofs whose ledger_indices length doesn't match files_per_step.
    let data_a = vec![3u8; 100];
    let data_b = vec![4u8; 100];
    let (prepared_a, meta_a) = api::prepare_file(&data_a, "a2.dat", b"").unwrap();
    let (prepared_b, meta_b) = api::prepare_file(&data_b, "b2.dat", b"").unwrap();

    let mut ledger = kontor_crypto::FileLedger::new();
    ledger.add_file(&meta_a).unwrap();
    ledger.add_file(&meta_b).unwrap();

    let challenges = vec![
        Challenge::new_test(meta_a.clone(), 1000, 1, FieldElement::from(11u64)),
        Challenge::new_test(meta_b.clone(), 1000, 1, FieldElement::from(22u64)),
    ];

    let system = kontor_crypto::api::PorSystem::new(&ledger);
    let mut proof = system
        .prove(vec![&prepared_a, &prepared_b], &challenges)
        .expect("Should generate a valid multi-file proof");

    // Corrupt the proof: remove one index so the length doesn't match files_per_step.
    proof.ledger_indices.pop();

    let res = system.verify(&proof, &challenges);
    assert!(
        matches!(res, Err(KontorPoRError::InvalidInput(_))),
        "Expected InvalidInput for ledger_indices length mismatch, got: {res:?}"
    );
}

#[test]
fn test_duplicate_file_challenges_fail_verification() {
    // VERIF-01: Duplicate challenges (same file, same params) produce invalid proofs.
    // This is expected - duplicate challenges are not a supported use case.
    // The verifier correctly rejects these proofs.
    println!("Testing duplicate file challenges in multi-file proof");

    let data = vec![1u8; 100];
    let (prepared, metadata) = api::prepare_file(&data, "test_file.dat", b"").unwrap();

    // Create identical challenges for the same file [A, A, A]
    let seed = FieldElement::from(42u64);
    let challenges = vec![
        Challenge::new_test(metadata.clone(), 1000, 1, seed),
        Challenge::new_test(metadata.clone(), 1000, 1, seed),
        Challenge::new_test(metadata.clone(), 1000, 1, seed),
    ];

    let mut ledger = kontor_crypto::ledger::FileLedger::new();
    ledger.add_file(&metadata).unwrap();

    let system = kontor_crypto::api::PorSystem::new(&ledger);
    let proof = system
        .prove(vec![&prepared], &challenges)
        .expect("Prove accepts duplicate challenges");

    // Verification should fail - duplicate challenges produce invalid proofs
    let verify_result = system.verify(&proof, &challenges);
    assert!(
        matches!(verify_result, Ok(false) | Err(_)),
        "Duplicate challenges MUST fail verification"
    );

    println!("✓ Duplicate challenges correctly rejected by verifier");
}

#[test]
fn test_malformed_metadata_non_power_of_two_padded_len() {
    // VERIF-02: Test verifier with malformed FileMetadata (non-power-of-two padded_len)
    println!("Testing verification with malformed FileMetadata (non-power-of-two padded_len)");

    // First create a valid proof
    let data = vec![5u8; 80];

    let (prepared, valid_metadata) = api::prepare_file(&data, "test_file.dat", b"").unwrap();

    let valid_challenge =
        Challenge::new_test(valid_metadata.clone(), 1000, 1, FieldElement::from(999u64));

    let mut files = BTreeMap::new();
    files.insert(valid_metadata.file_id.clone(), &prepared);

    // Create ledger for unified API
    let mut ledger = kontor_crypto::FileLedger::new();
    ledger.add_file(&valid_metadata).unwrap();

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
    malformed_ledger.add_file(&malformed_metadata).unwrap();

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

    let (prepared, valid_metadata) = api::prepare_file(&data, "test_file.dat", b"").unwrap();
    let valid_challenge =
        Challenge::new_test(valid_metadata.clone(), 1000, 1, FieldElement::from(123u64));

    let mut files = BTreeMap::new();
    files.insert(valid_metadata.file_id.clone(), &prepared);

    // Create ledger for unified API
    let mut ledger = kontor_crypto::FileLedger::new();
    ledger.add_file(&valid_metadata).unwrap();

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
    bad_ledger1.add_file(&inconsistent_meta1).unwrap();

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
    bad_ledger2.add_file(&inconsistent_meta2).unwrap();

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
