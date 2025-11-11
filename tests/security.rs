//! Security tests for the Proof-of-Retrievability system.
//!
//! These tests verify that the system correctly enforces security properties:
//! - Valid proofs are accepted
//! - Invalid/malicious proofs are rejected
//! - The system is resistant to common attacks

mod common;
use common::{
    assertions::assert_prove_and_verify_succeeds,
    fixtures::{setup_test_scenario, FileSpec, TestConfig},
};

#[test]
fn test_valid_proofs_are_accepted() {
    // Test that legitimate proofs for valid files are accepted using minimal data
    let setup = setup_test_scenario(&TestConfig::with_challenges(2)).unwrap();

    // This should work - valid file, valid proof
    assert_prove_and_verify_succeeds(setup);

    println!("✓ Valid proof accepted as expected");
}

#[test]
fn test_deterministic_challenge_calculation() {
    // Test that the same seed produces the same challenge sequence using minimal data
    let config = TestConfig {
        challenges_per_file: 2,
        seed: 12345, // Fixed seed
        ..Default::default()
    };

    // Create two identical setups
    let setup1 = setup_test_scenario(&config).unwrap();
    let setup2 = setup_test_scenario(&config).unwrap();

    // Should have identical challenge parameters
    assert_eq!(setup1.challenges.len(), setup2.challenges.len());
    assert_eq!(setup1.challenges[0].seed, setup2.challenges[0].seed);
    assert_eq!(
        setup1.challenges[0].num_challenges,
        setup2.challenges[0].num_challenges
    );

    // Both should produce valid proofs
    assert_prove_and_verify_succeeds(setup1);
    assert_prove_and_verify_succeeds(setup2);

    println!("✓ Deterministic challenge calculation verified");
}

#[test]
fn test_different_seeds_produce_different_challenges() {
    // Test that different seeds produce different challenges (prevents replay attacks) using minimal data
    let config1 = TestConfig {
        seed: 11111,
        ..Default::default()
    };
    let config2 = TestConfig {
        seed: 22222,
        ..Default::default()
    };

    let setup1 = setup_test_scenario(&config1).unwrap();
    let setup2 = setup_test_scenario(&config2).unwrap();

    // Different seeds should produce different challenge seeds
    assert_ne!(setup1.challenges[0].seed, setup2.challenges[0].seed);

    // But both should still be valid
    assert_prove_and_verify_succeeds(setup1);
    assert_prove_and_verify_succeeds(setup2);

    println!("✓ Different seeds produce different but valid challenges");
}

#[test]
fn test_multiple_challenge_security() {
    // Test that multiple challenges increase security without breaking functionality
    let challenge_counts = vec![1, 2, 3]; // Reduced for performance while maintaining coverage

    for challenge_count in challenge_counts {
        let setup = setup_test_scenario(&TestConfig::with_challenges(challenge_count)).unwrap();

        // Verify the challenge setup is correct
        assert_eq!(setup.challenges.len(), 1); // One file
        assert_eq!(setup.challenges[0].num_challenges, challenge_count);

        // Should be able to prove and verify
        assert_prove_and_verify_succeeds(setup);

        println!("✓ {} challenges verified successfully", challenge_count);
    }
}

#[test]
fn test_file_integrity_through_hashing() {
    // Test that different files produce different hashes/roots (prevents file substitution)
    let file_specs = [
        FileSpec::with_seed(100, 1111),
        FileSpec::with_seed(100, 2222), // Same size, different content
        FileSpec::with_seed(101, 1111), // Different size, same seed
    ];

    let mut roots = Vec::new();
    let mut file_ides = Vec::new();

    for (i, file_spec) in file_specs.iter().enumerate() {
        let config = TestConfig {
            file_specs: vec![file_spec.clone()],
            seed: i as u64,
            ..Default::default()
        };

        let setup = setup_test_scenario(&config).unwrap();

        // Extract data before consuming setup
        roots.push(setup.metadatas[0].root);
        file_ides.push(setup.metadatas[0].file_id.clone());

        // Each should produce a valid proof
        assert_prove_and_verify_succeeds(setup);
    }

    // All roots should be different
    for i in 0..roots.len() {
        for j in i + 1..roots.len() {
            assert_ne!(
                roots[i], roots[j],
                "Files {} and {} should have different roots",
                i, j
            );
            assert_ne!(
                file_ides[i], file_ides[j],
                "Files {} and {} should have different hashes",
                i, j
            );
        }
    }

    println!("✓ File integrity verified - different files produce different hashes");
}

#[test]
fn test_erasure_coding_security() {
    // Test that the fixed Reed-Solomon encoding doesn't compromise security
    // The system now uses fixed parameters: 231 data + 24 parity symbols per codeword

    let config = TestConfig {
        challenges_per_file: 2,
        ..Default::default()
    };

    let setup = setup_test_scenario(&config).unwrap();

    // Should be able to prove and verify securely
    assert_prove_and_verify_succeeds(setup);

    println!("✓ Fixed RS encoding (231+24) maintains security");
}

#[test]
fn test_proof_replay_with_different_files_is_rejected() {
    // Critical security test: Verify that the challenged_roots_commitment correctly prevents
    // a "proof replay" attack, where a prover tries to use a valid proof for files {A, B}
    // to answer a verifier's challenge for files {A, C}.
    use kontor_crypto::api::PorSystem;
    use std::collections::BTreeMap;

    println!("Testing proof replay attack prevention");

    // Create a setup with 3 files so we can test {A,B} vs {A,C} scenario
    let config = TestConfig::multi_file(3);
    let setup = setup_test_scenario(&config).unwrap();

    // Extract components we need
    let _params = &setup.params;
    let ledger = setup.ledger.as_ref().unwrap();
    let metadatas = &setup.metadatas;
    let all_files = setup.files;

    // Verify we have 3 files
    assert_eq!(metadatas.len(), 3, "Setup should have exactly 3 files");

    // Create challenges for files A and B (indices 0 and 1)
    let seed = kontor_crypto::api::FieldElement::from(42u64);
    let challenges_ab = vec![
        kontor_crypto::api::Challenge::new_test(metadatas[0].clone(), 1000, 1, seed),
        kontor_crypto::api::Challenge::new_test(metadatas[1].clone(), 1000, 1, seed),
    ];

    // Create file map for files A and B only
    let mut files_ab = BTreeMap::new();
    files_ab.insert(
        metadatas[0].file_id.clone(),
        all_files.get(&metadatas[0].file_id).unwrap(),
    );
    files_ab.insert(
        metadatas[1].file_id.clone(),
        all_files.get(&metadatas[1].file_id).unwrap(),
    );

    // Generate a valid proof for {A, B}
    let system = PorSystem::new(ledger);
    let files_ab_vec: Vec<&_> = files_ab.values().copied().collect();
    let proof_for_ab = system
        .prove(files_ab_vec, &challenges_ab)
        .expect("Should be able to generate valid proof for files A and B");

    println!("✓ Generated valid proof for files A and B");

    // Now create challenges for files A and C (indices 0 and 2) - this is the attack
    let challenges_ac = vec![
        kontor_crypto::api::Challenge::new_test(metadatas[0].clone(), 1000, 1, seed),
        kontor_crypto::api::Challenge::new_test(metadatas[2].clone(), 1000, 1, seed), // Different file!
    ];

    // Attempt to verify the proof generated for {A, B} against challenges for {A, C}
    // This should fail because the challenged_roots_commitment will not match
    // We need to test the underlying cryptographic security, not just API validation
    let verification_result = kontor_crypto::api::verify_raw(&challenges_ac, &proof_for_ab, ledger)
        .expect("Verification should complete without error");

    // The verification should return false, indicating the proof is invalid for these challenges
    assert!(!verification_result,
        "Proof for files A,B should NOT verify against challenges for files A,C - this prevents proof replay attacks!");

    println!("✓ Proof replay attack correctly rejected - challenged_roots_commitment working as intended");

    // Sanity check: Verify that the original proof still works for the original challenges
    let original_verification = system
        .verify(&proof_for_ab, &challenges_ab)
        .expect("Original verification should complete");
    assert!(
        original_verification,
        "Original proof should still verify against original challenges"
    );

    println!("✓ Original proof still verifies against original challenges");
}

#[test]
fn test_tampered_proof_bytes_rejected() {
    // Verify that a bit-flipped or corrupted proof object fails verification gracefully
    println!("Testing tampered proof detection");

    // Generate a valid proof
    let setup = setup_test_scenario(&TestConfig::default()).unwrap();
    let file_refs = setup.file_refs();
    let ledger_ref = setup.ledger_ref();

    let ledger = ledger_ref.expect("Ledger should be available for unified API");
    let system = kontor_crypto::api::PorSystem::new(ledger);

    // Convert BTreeMap to Vec for PorSystem API
    let files_vec: Vec<&_> = file_refs.values().copied().collect();
    let proof = system
        .prove(files_vec, &setup.challenges)
        .expect("Should generate valid proof");

    // Serialize the proof to bytes using the stable API
    let proof_bytes = proof.to_bytes().expect("Should serialize proof");

    // Tamper with the proof bytes - flip a bit in the middle
    let mut tampered_bytes = proof_bytes.clone();
    if tampered_bytes.len() > 100 {
        tampered_bytes[100] ^= 0x01; // Flip one bit
    } else if !tampered_bytes.is_empty() {
        tampered_bytes[0] ^= 0x01; // Flip first bit if proof is small
    }

    // Try to deserialize the tampered bytes
    use kontor_crypto::api::Proof;
    match Proof::from_bytes(&tampered_bytes) {
        Ok(tampered_proof) => {
            // If deserialization succeeds, the proof should fail verification
            let result = system.verify(&tampered_proof, &setup.challenges);

            match result {
                Ok(is_valid) => {
                    assert!(!is_valid, "Tampered proof should not verify as valid");
                    println!("✓ Tampered proof correctly rejected (returned false)");
                }
                Err(_) => {
                    println!("✓ Tampered proof correctly rejected (verification error)");
                }
            }
        }
        Err(_) => {
            println!("✓ Tampered proof bytes failed deserialization (expected behavior)");
        }
    }
}
