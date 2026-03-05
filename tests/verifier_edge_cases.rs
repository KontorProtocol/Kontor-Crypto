//! Tests for malicious or non-standard verifier inputs and edge cases

use kontor_crypto::api::{self, Challenge, FieldElement};
use kontor_crypto::KontorPoRError;
use rand::RngCore;
use std::collections::BTreeMap;

fn random_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

#[test]
fn test_verifier_rejects_out_of_range_ledger_index() {
    // Verifier should reject proofs when derived ledger indices don't fit the claimed
    // aggregated tree depth.
    let data_a = vec![1u8; 100];
    let data_b = vec![2u8; 100];
    let data_c = vec![3u8; 100];
    let (prepared_a, meta_a) = api::prepare_file(&data_a, "a.dat", &random_nonce()).unwrap();
    let (prepared_b, meta_b) = api::prepare_file(&data_b, "b.dat", &random_nonce()).unwrap();
    let (prepared_c, meta_c) = api::prepare_file(&data_c, "c.dat", &random_nonce()).unwrap();

    let mut ledger = kontor_crypto::FileLedger::new();
    ledger.add_file(&meta_a).unwrap();
    ledger.add_file(&meta_b).unwrap();
    ledger.add_file(&meta_c).unwrap();

    let challenges = vec![
        Challenge::new_test(meta_a.clone(), 1000, 1, FieldElement::from(1u64)),
        Challenge::new_test(meta_b.clone(), 1000, 1, FieldElement::from(2u64)),
        Challenge::new_test(meta_c.clone(), 1000, 1, FieldElement::from(3u64)),
    ];

    let system = kontor_crypto::api::PorSystem::new(&ledger);
    let mut proof = system
        .prove(vec![&prepared_a, &prepared_b, &prepared_c], &challenges)
        .expect("Should generate a valid multi-file proof");

    assert!(
        proof.aggregated_tree_depth > 1,
        "Must have at least depth 2 for 3-file proof"
    );

    // Shrink claimed depth so derived index 2 no longer fits range [0, 1].
    proof.aggregated_tree_depth -= 1;

    let res = system.verify(&proof, &challenges);
    assert!(
        matches!(res, Err(KontorPoRError::InvalidInput(_))),
        "Expected InvalidInput for out-of-range derived ledger index, got: {res:?}"
    );
}

#[test]
fn test_verifier_rejects_ledger_indices_length_mismatch() {
    // Verifier should reject multi-file proofs with aggregated_tree_depth = 0.
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

    proof.aggregated_tree_depth = 0;

    let res = system.verify(&proof, &challenges);
    assert!(
        matches!(res, Err(KontorPoRError::InvalidInput(_))),
        "Expected InvalidInput for zero aggregated_tree_depth on multi-file proof, got: {res:?}"
    );
}

#[test]
fn test_duplicate_file_challenges_fail_verification() {
    // VERIF-01: Duplicate challenges must be rejected during prove() to avoid
    // wasting prover resources on unsupported/ambiguous statements.
    println!("Testing duplicate file challenges are rejected by prove()");

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
    let prove_result = system.prove(vec![&prepared], &challenges);
    assert!(
        matches!(prove_result, Err(KontorPoRError::InvalidInput(_))),
        "Duplicate challenges MUST be rejected by prove()"
    );

    println!("✓ Duplicate challenges correctly rejected by prove()");
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

    assert!(
        matches!(result1, Err(KontorPoRError::InvalidInput(_))),
        "Metadata with inconsistent original_size must be rejected"
    );
    println!("✓ Metadata with original_size inconsistency rejected");

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
