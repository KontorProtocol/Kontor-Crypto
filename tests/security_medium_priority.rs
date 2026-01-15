//! Security tests for medium-priority issues
//!
//! This module contains tests for:
//! 1. Endianness sanity check (already fixed, but verifying)
//! 2. Strictly increasing ledger indices
//! 3. Meta-commitment binding
//! 4. Multi-file challenge separation
//! 5. Single-file vs multi-file equivalence

use ff::PrimeField;
use kontor_crypto::{
    api::{self, Challenge, FieldElement, PorSystem},
    merkle,
    poseidon::{domain_tags, poseidon_hash_tagged},
    FileLedger,
};
use std::collections::BTreeMap;

mod common;
use common::{
    create_multi_file_ledger, create_single_file_ledger,
    fixtures::{create_test_data, setup_test_scenario, TestConfig},
};

#[test]
fn test_endianness_sanity_after_fix() {
    // Test that after the endianness fix, small byte values map to small field elements
    println!("Testing endianness sanity after fix...");

    // Test single byte [0x01] maps to field element 1
    let one_byte = vec![0x01];
    let hash_one = merkle::get_leaf_hash(&one_byte).unwrap();
    assert_eq!(
        hash_one,
        FieldElement::from(1u64),
        "Single byte 0x01 should map to field element 1"
    );

    // Test incrementing bytes map to incrementing field elements
    for i in 0u8..10 {
        let byte_data = vec![i];
        let hash = merkle::get_leaf_hash(&byte_data).unwrap();
        assert_eq!(
            hash,
            FieldElement::from(i as u64),
            "Byte {} should map to field element {}",
            i,
            i
        );
    }

    // Test round-trip: field element -> bytes -> field element
    let field_val = FieldElement::from(42u64);
    let field_bytes = field_val.to_repr();
    let mut test_bytes = vec![0u8; 8];
    test_bytes.copy_from_slice(&field_bytes[..8]);
    let hash = merkle::get_leaf_hash(&test_bytes).unwrap();
    assert_eq!(
        hash, field_val,
        "Round-trip through bytes should preserve field element value"
    );

    println!("✓ Endianness is correctly implemented");
}

#[test]
fn test_meta_commitment_binding() {
    // Test that changing a single (root, depth) pair invalidates the proof
    println!("Testing meta-commitment binding...");

    // Setup multi-file scenario
    let setup = setup_test_scenario(&TestConfig::multi_file(2)).unwrap();
    let ledger = setup.ledger.as_ref().unwrap();
    let file_refs = setup.file_refs();

    // Generate a valid proof
    let system = PorSystem::new(ledger);
    let files_vec: Vec<&_> = file_refs.values().copied().collect();
    let proof = system
        .prove(files_vec, &setup.challenges)
        .expect("Should generate valid proof");

    // Verify it works normally
    assert!(
        system
            .verify(&proof, &setup.challenges)
            .expect("Verification should complete"),
        "Original proof should verify"
    );

    // Now create a modified challenge with different root (simulating tampering)
    let mut tampered_challenges = setup.challenges.clone();
    let mut tampered_metadata = tampered_challenges[0].file_metadata.clone();
    tampered_metadata.root = FieldElement::from(999999u64); // Different root
    tampered_challenges[0] = Challenge::new_test(
        tampered_metadata.clone(),
        tampered_challenges[0].block_height,
        tampered_challenges[0].num_challenges,
        tampered_challenges[0].seed,
    );

    // Create ledger with tampered metadata for verification
    let metadatas_refs: Vec<&_> = vec![&tampered_metadata, &setup.challenges[1].file_metadata];
    let tampered_ledger = create_multi_file_ledger(&metadatas_refs);

    // Verification should fail due to meta-commitment mismatch
    let tampered_system = api::PorSystem::new(&tampered_ledger);
    let result = tampered_system.verify(&proof, &tampered_challenges);

    // The verification should either error or return false
    match result {
        Ok(false) => {
            println!("✓ Meta-commitment correctly rejected tampered root");
        }
        Err(_) => {
            println!("✓ Meta-commitment validation caused verification error");
        }
        Ok(true) => {
            panic!("Meta-commitment should prevent verification with tampered root!");
        }
    }
}

#[test]
fn test_multi_file_challenge_separation() {
    // Test that challenges for different files produce different indices
    // even with same seed and state
    println!("Testing multi-file challenge separation...");

    let seed = FieldElement::from(42u64);
    let state = FieldElement::from(100u64);

    // Compute challenge base
    let challenge_base = poseidon_hash_tagged(domain_tags::challenge(), seed, state);

    // Test the new domain-separated approach
    let challenge_file_0 = poseidon_hash_tagged(
        domain_tags::challenge_per_file(),
        challenge_base,
        FieldElement::from(0u64),
    );

    let challenge_file_1 = poseidon_hash_tagged(
        domain_tags::challenge_per_file(),
        challenge_base,
        FieldElement::from(1u64),
    );

    assert_ne!(
        challenge_file_0, challenge_file_1,
        "Challenges for different files must differ"
    );

    // Verify they're not linearly related (old approach was base + file_idx)
    let linear_diff = challenge_file_1 - challenge_file_0;
    assert_ne!(
        linear_diff,
        FieldElement::from(1u64),
        "Challenges should not have linear relationship"
    );

    // Test multiple files
    let mut challenges = Vec::new();
    for i in 0..5 {
        let challenge = poseidon_hash_tagged(
            domain_tags::challenge_per_file(),
            challenge_base,
            FieldElement::from(i as u64),
        );
        challenges.push(challenge);
    }

    // All should be unique
    for i in 0..challenges.len() {
        for j in (i + 1)..challenges.len() {
            assert_ne!(
                challenges[i], challenges[j],
                "All file challenges must be unique"
            );
        }
    }

    println!("✓ Multi-file challenges are properly separated");
}

#[test]
fn test_single_vs_multi_file_equivalence() {
    // Test that the same file proved alone vs in a batch produces valid proofs
    println!("Testing single-file vs multi-file equivalence...");

    // Create test data
    let data = create_test_data(100, Some(42));
    let (prepared, metadata) =
        api::prepare_file(&data, "test_file.dat", b"").expect("Failed to prepare file");

    let challenge = Challenge::new_test(metadata.clone(), 1000, 3, FieldElement::from(123u64));

    // Test 1: Single-file proof
    let mut single_files = BTreeMap::new();
    single_files.insert(metadata.file_id.clone(), &prepared);

    // Create ledger for single-file proof
    let single_ledger = create_single_file_ledger(&metadata);

    let single_system = api::PorSystem::new(&single_ledger);
    let single_files_vec: Vec<&_> = single_files.values().copied().collect();
    let single_proof = single_system
        .prove(single_files_vec, std::slice::from_ref(&challenge))
        .expect("Should generate single-file proof");

    // Verify single-file proof
    assert!(
        single_system
            .verify(&single_proof, std::slice::from_ref(&challenge))
            .expect("Single-file verification should complete"),
        "Single-file proof should verify"
    );

    // Test 2: Same file in multi-file context with padding
    // Create a second dummy file for the batch
    let data2 = create_test_data(50, Some(99));
    let (prepared2, metadata2) =
        api::prepare_file(&data2, "test_file.dat", b"").expect("Failed to prepare file 2");

    let challenge2 = Challenge::new_test(metadata2.clone(), 1000, 3, FieldElement::from(123u64));

    // Create ledger with both files
    let mut ledger = FileLedger::new();
    ledger.add_file(&metadata).unwrap();
    ledger.add_file(&metadata2).unwrap();

    let mut multi_files = BTreeMap::new();
    multi_files.insert(metadata.file_id.clone(), &prepared);
    multi_files.insert(metadata2.file_id.clone(), &prepared2);

    let multi_system = api::PorSystem::new(&ledger);
    let multi_files_vec: Vec<&_> = multi_files.values().copied().collect();
    let multi_proof = multi_system
        .prove(multi_files_vec, &[challenge.clone(), challenge2.clone()])
        .expect("Should generate multi-file proof");

    // Verify multi-file proof
    assert!(
        multi_system
            .verify(&multi_proof, &[challenge, challenge2])
            .expect("Multi-file verification should complete"),
        "Multi-file proof should verify"
    );

    println!("✓ Single-file and multi-file proofs both work correctly");
}

#[test]
fn test_gating_uniformity() {
    // Test that proofs for files of different depths use the same parameters
    println!("Testing gating uniformity across different file depths...");

    // Create files targeting different depths
    // With multi-codeword: need larger files for depth variation
    // Small file for depth 8 (1 codeword)
    let data_small = create_test_data(1_000, Some(1));
    let (prepared_small, metadata_small) =
        api::prepare_file(&data_small, "test_file.dat", b"").expect("Failed to prepare small file");

    // Larger file for depth ~12 (multiple codewords)
    let data_large = create_test_data(50_000, Some(2));
    let (prepared_large, metadata_large) =
        api::prepare_file(&data_large, "test_file.dat", b"").expect("Failed to prepare large file");

    let depth_small = kontor_crypto::api::tree_depth_from_metadata(&metadata_small);
    let depth_large = kontor_crypto::api::tree_depth_from_metadata(&metadata_large);

    // Depths should be different
    assert_ne!(
        depth_small, depth_large,
        "Test files should have different depths"
    );

    println!(
        "  Small file depth: {}, Large file depth: {}",
        depth_small, depth_large
    );

    // Create challenges
    let challenge_small =
        Challenge::new_test(metadata_small.clone(), 1000, 2, FieldElement::from(456u64));
    let challenge_large =
        Challenge::new_test(metadata_large.clone(), 1000, 2, FieldElement::from(456u64));

    // Create ledger with both files
    let mut ledger = FileLedger::new();
    ledger.add_file(&metadata_small).unwrap();
    ledger.add_file(&metadata_large).unwrap();

    let mut files = BTreeMap::new();
    files.insert(metadata_small.file_id.clone(), &prepared_small);
    files.insert(metadata_large.file_id.clone(), &prepared_large);

    // Generate and verify proof with mixed depths
    let system = api::PorSystem::new(&ledger);
    let files_vec: Vec<&_> = files.values().copied().collect();
    let proof = system
        .prove(
            files_vec,
            &[challenge_small.clone(), challenge_large.clone()],
        )
        .expect("Should generate proof with mixed depths");

    assert!(
        system
            .verify(&proof, &[challenge_small, challenge_large])
            .expect("Verification should complete"),
        "Proof with mixed depths should verify"
    );

    println!("✓ Gating allows uniform parameters across different depths");
}
