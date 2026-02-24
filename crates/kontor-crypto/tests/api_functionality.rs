//! Comprehensive tests for Kontor PoR API functionality
//!
//! This module tests the core features of the Kontor PoR API:
//! - ChallengeID determinism and collision resistance
//! - Proof serialization round-trips
//! - Batch seed validation
//! - PorSystem interface

use kontor_crypto::{
    api::{Challenge, FieldElement, PorSystem, Proof},
    FileLedger,
};
use std::collections::HashSet;

#[test]
fn test_challenge_id_determinism() {
    println!("Testing ChallengeID deterministic derivation");

    let data = b"Test data for challenge ID determinism";
    let (_, metadata) = kontor_crypto::api::prepare_file(data, "test.dat", b"").unwrap();

    // Same challenge should produce same ID
    let challenge1 = Challenge::new_test(metadata.clone(), 1000, 5, FieldElement::from(42u64));
    let challenge2 = Challenge::new_test(metadata.clone(), 1000, 5, FieldElement::from(42u64));

    assert_eq!(
        challenge1.id(),
        challenge2.id(),
        "Identical challenges should have identical IDs"
    );

    // Different block heights should produce different IDs
    let challenge_diff_height =
        Challenge::new_test(metadata.clone(), 1001, 5, FieldElement::from(42u64));
    assert_ne!(
        challenge1.id(),
        challenge_diff_height.id(),
        "Different block heights should produce different IDs"
    );

    // Different seeds should produce different IDs
    let challenge_diff_seed =
        Challenge::new_test(metadata.clone(), 1000, 5, FieldElement::from(43u64));
    assert_ne!(
        challenge1.id(),
        challenge_diff_seed.id(),
        "Different seeds should produce different IDs"
    );

    // Different num_challenges should produce different IDs
    let challenge_diff_num =
        Challenge::new_test(metadata.clone(), 1000, 6, FieldElement::from(42u64));
    assert_ne!(
        challenge1.id(),
        challenge_diff_num.id(),
        "Different num_challenges should produce different IDs"
    );

    println!("  ✓ ChallengeID determinism verified");
}

#[test]
fn test_challenge_id_collision_resistance() {
    println!("Testing ChallengeID collision resistance across different files");

    // Create two different files
    let data1 = b"First test file for collision resistance testing";
    let data2 = b"Second test file with different content entirely";

    let (_, metadata1) = kontor_crypto::api::prepare_file(data1, "file1.dat", b"").unwrap();
    let (_, metadata2) = kontor_crypto::api::prepare_file(data2, "file2.dat", b"").unwrap();

    // Same parameters, different files
    let challenge1 = Challenge::new_test(metadata1, 1000, 5, FieldElement::from(42u64));
    let challenge2 = Challenge::new_test(metadata2, 1000, 5, FieldElement::from(42u64));

    assert_ne!(
        challenge1.id(),
        challenge2.id(),
        "Different files should produce different challenge IDs"
    );

    // Collect challenge IDs to check for collisions
    let mut ids = HashSet::new();
    for i in 0..100 {
        let data = format!("Test file content {}", i);
        let (_, metadata) =
            kontor_crypto::api::prepare_file(data.as_bytes(), &format!("file{}.dat", i), b"")
                .unwrap();
        let challenge =
            Challenge::new_test(metadata, 1000 + i as u64, 3, FieldElement::from(i as u64));
        let id = challenge.id();

        assert!(
            !ids.contains(&id),
            "Challenge ID collision detected at iteration {}",
            i
        );
        ids.insert(id);
    }

    println!("  ✓ No collisions found in {} challenge IDs", ids.len());
}

#[test]
fn test_proof_serialization_roundtrip() {
    println!("Testing proof serialization round-trip");

    let data = b"Test data for proof serialization testing with sufficient length";
    let (prepared, metadata) =
        kontor_crypto::api::prepare_file(data, "serialize_test.dat", b"").unwrap();

    // Create ledger
    let mut ledger = FileLedger::new();
    ledger.add_file(&metadata).unwrap();

    let system = PorSystem::new(&ledger);

    // Create challenge and generate proof
    let challenge = Challenge::new_test(metadata.clone(), 1000, 2, FieldElement::from(123u64));
    let proof = system
        .prove(vec![&prepared], std::slice::from_ref(&challenge))
        .unwrap();

    // Test serialization
    let serialized = proof.to_bytes().unwrap();
    println!("  ✓ Serialized proof: {} bytes", serialized.len());

    // Test deserialization
    let deserialized = Proof::from_bytes(&serialized).unwrap();
    println!("  ✓ Deserialized proof successfully");

    // Verify the deserialized proof works
    let is_valid = system.verify(&deserialized, &[challenge]).unwrap();
    assert!(is_valid, "Deserialized proof should verify successfully");

    // Test that challenge IDs are preserved
    assert_eq!(
        proof.challenge_ids, deserialized.challenge_ids,
        "Challenge IDs should be preserved through serialization"
    );

    println!("  ✓ Proof serialization round-trip successful");
}

#[test]
fn test_proof_serialization_format_validation() {
    println!("Testing proof serialization format validation");

    // Test invalid magic bytes
    let bad_magic = b"XXXX\x01\x00\x04\x00\x00\x00test";
    let result = Proof::from_bytes(bad_magic);
    assert!(result.is_err(), "Should reject invalid magic bytes");

    // Test unsupported version
    let bad_version = b"NPOR\x99\x00\x04\x00\x00\x00test";
    let result = Proof::from_bytes(bad_version);
    assert!(result.is_err(), "Should reject unsupported version");

    // Test truncated data
    let truncated = b"NPOR\x01\x00";
    let result = Proof::from_bytes(truncated);
    assert!(result.is_err(), "Should reject truncated data");

    println!("  ✓ Format validation working correctly");
}

#[test]
fn test_batch_seed_validation() {
    println!("Testing batch seed validation in prove/verify");

    let data1 = b"First file for batch seed testing";
    let data2 = b"Second file for batch seed testing";

    let (prepared1, metadata1) =
        kontor_crypto::api::prepare_file(data1, "batch1.dat", b"").unwrap();
    let (prepared2, metadata2) =
        kontor_crypto::api::prepare_file(data2, "batch2.dat", b"").unwrap();

    // Create ledger
    let mut ledger = FileLedger::new();
    ledger.add_file(&metadata1).unwrap();
    ledger.add_file(&metadata2).unwrap();

    let system = PorSystem::new(&ledger);

    // Test uniform seeds (should work)
    let uniform_seed = FieldElement::from(555u64);
    let challenge1_uniform = Challenge::new_test(metadata1.clone(), 1000, 2, uniform_seed);
    let challenge2_uniform = Challenge::new_test(metadata2.clone(), 1000, 2, uniform_seed);

    let files = vec![&prepared1, &prepared2];
    let uniform_challenges = vec![challenge1_uniform.clone(), challenge2_uniform.clone()];

    let proof = system.prove(files.clone(), &uniform_challenges).unwrap();
    let is_valid = system.verify(&proof, &uniform_challenges).unwrap();
    assert!(is_valid, "Proof with uniform seeds should verify");

    // Test non-uniform seeds (multi-batch aggregation)
    let challenge1_diff =
        Challenge::new_test(metadata1.clone(), 1000, 2, FieldElement::from(555u64));
    let challenge2_diff =
        Challenge::new_test(metadata2.clone(), 1000, 2, FieldElement::from(556u64)); // Different seed

    let mixed_challenges = vec![challenge1_diff.clone(), challenge2_diff.clone()];
    let proof = system
        .prove(files, &mixed_challenges)
        .expect("Multi-seed proof should succeed");

    // Verify the proof with different seeds
    let is_valid = system.verify(&proof, &mixed_challenges).unwrap();
    assert!(
        is_valid,
        "Proof with different seeds should verify (multi-batch aggregation)"
    );
    println!("  ✓ Non-uniform seeds correctly accepted (multi-batch aggregation enabled)");
}

#[test]
fn test_porsystem_challenge_id_matching() {
    println!("Testing PorSystem challenge ID matching in verify");

    let data = b"Test data for challenge ID matching";
    let (prepared, metadata) =
        kontor_crypto::api::prepare_file(data, "id_match_test.dat", b"").unwrap();

    // Create ledger
    let mut ledger = FileLedger::new();
    ledger.add_file(&metadata).unwrap();

    let system = PorSystem::new(&ledger);

    // Create challenge and proof
    let challenge = Challenge::new_test(metadata.clone(), 1000, 2, FieldElement::from(777u64));
    let proof = system
        .prove(vec![&prepared], std::slice::from_ref(&challenge))
        .unwrap();

    // Verify with correct challenge should work
    let is_valid = system
        .verify(&proof, std::slice::from_ref(&challenge))
        .unwrap();
    assert!(is_valid, "Proof should verify with correct challenge");

    // Create a different challenge (different seed) and try to verify
    let different_challenge =
        Challenge::new_test(metadata.clone(), 1000, 2, FieldElement::from(778u64));
    let result = system.verify(&proof, &[different_challenge]);

    match result {
        Err(kontor_crypto::KontorPoRError::InvalidInput(msg)) => {
            assert!(
                msg.contains("Challenge ID mismatch"),
                "Should report challenge ID mismatch"
            );
            println!("  ✓ Challenge ID mismatch correctly detected");
        }
        _ => panic!("Expected InvalidInput error for mismatched challenge IDs"),
    }
}

#[test]
fn test_porsystem_file_not_found() {
    println!("Testing PorSystem error handling for missing files");

    let data = b"Test data for file not found testing";
    let (prepared, metadata) =
        kontor_crypto::api::prepare_file(data, "missing_test.dat", b"").unwrap();

    // Create ledger without adding the file
    let ledger = FileLedger::new();
    let system = PorSystem::new(&ledger);

    // Create challenge for a file not in the ledger
    let challenge = Challenge::new_test(metadata.clone(), 1000, 2, FieldElement::from(999u64));

    // This should fail because the file is not in the ledger
    let result = system.prove(vec![&prepared], &[challenge]);

    match result {
        Err(kontor_crypto::KontorPoRError::FileNotInLedger { file_id }) => {
            assert_eq!(
                file_id, metadata.file_id,
                "Should report correct missing file hash"
            );
            println!("  ✓ Missing file correctly detected");
        }
        _ => panic!("Expected FileNotInLedger error for missing file"),
    }
}

#[test]
fn test_porsystem_prepare_file() {
    println!("Testing PorSystem::prepare_file method");

    let ledger = FileLedger::new();
    let system = PorSystem::new(&ledger);

    let data = b"Test data for PorSystem prepare_file method testing";

    // Test successful preparation
    let result = system.prepare_file(data, "porsystem_test.dat", b"");
    assert!(
        result.is_ok(),
        "PorSystem::prepare_file should succeed with valid inputs"
    );

    let (prepared, metadata) = result.unwrap();

    // Verify the results are correct
    assert_eq!(
        metadata.filename, "porsystem_test.dat",
        "Filename should be stored correctly"
    );
    assert_eq!(
        metadata.original_size,
        data.len(),
        "Original size should match input"
    );
    assert_eq!(
        prepared.file_id, metadata.file_id,
        "PreparedFile and FileMetadata should have matching file_id"
    );
    assert_eq!(
        prepared.root, metadata.root,
        "PreparedFile and FileMetadata should have matching root"
    );

    // Test empty data rejection
    let empty_result = system.prepare_file(&[], "empty.dat", b"");
    match empty_result {
        Err(kontor_crypto::KontorPoRError::EmptyData { operation }) => {
            assert_eq!(operation, "prepare_file", "Should report correct operation");
            println!("  ✓ Empty data correctly rejected");
        }
        _ => panic!("Expected EmptyData error for empty input"),
    }

    println!("  ✓ PorSystem::prepare_file method working correctly");
}

#[test]
fn test_porsystem_vs_free_function_equivalence() {
    println!("Testing equivalence between PorSystem methods and free functions");

    let data = b"Test data for API equivalence testing";

    // Test prepare_file equivalence
    let (prepared_free, metadata_free) =
        kontor_crypto::api::prepare_file(data, "free_func.dat", b"").unwrap();

    let ledger = FileLedger::new();
    let system = PorSystem::new(&ledger);
    let (prepared_system, metadata_system) =
        system.prepare_file(data, "system_method.dat", b"").unwrap();

    // Results should be equivalent (except for filename)
    assert_eq!(
        prepared_free.file_id, prepared_system.file_id,
        "File hashes should be identical"
    );
    assert_eq!(
        prepared_free.root, prepared_system.root,
        "Roots should be identical"
    );
    assert_eq!(
        metadata_free.root, metadata_system.root,
        "Metadata roots should be identical"
    );
    assert_eq!(
        metadata_free.original_size, metadata_system.original_size,
        "Original sizes should be identical"
    );
    assert_eq!(
        metadata_free.total_symbols(),
        metadata_system.total_symbols(),
        "Total symbols should be identical"
    );

    println!("  ✓ Free function and PorSystem method produce equivalent results");
}
