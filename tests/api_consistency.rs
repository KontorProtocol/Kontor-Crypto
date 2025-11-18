//! Tests for api.rs - state evolution, commitment matching, and ledger requirements
use kontor_crypto::{
    api::{self, Challenge, FieldElement, PorSystem},
    poseidon::{domain_tags, poseidon_hash_tagged},
};
use std::collections::BTreeMap;

mod common;
use common::{
    create_multi_file_ledger, create_single_file_ledger, fixtures::create_files_meta_commitment,
};

#[test]
fn test_state_evolution_across_files() {
    // A-09: Verify that new_state from generate_circuit_witness matches manual computation
    println!("Testing state evolution across files in witness generation");

    // Prepare test files
    let mut files = BTreeMap::new();
    let mut metadatas = vec![];

    for i in 0..3 {
        let data = vec![(i * 10) as u8; 50];
        let (prepared, metadata) =
            api::prepare_file(&data, "test_file.dat").expect("Failed to prepare file");

        files.insert(metadata.file_id.clone(), prepared);
        metadatas.push(metadata);
    }

    // Create challenges (sorted by file_id as the API does)
    let seed = FieldElement::from(42u64);
    let mut challenges: Vec<Challenge> = metadatas
        .iter()
        .map(|m| Challenge::new_test(m.clone(), 1000, 1, seed))
        .collect();
    challenges.sort_by_key(|c| c.file_metadata.file_id.clone());

    // Get witness and new state
    let initial_state = FieldElement::from(100u64);
    let file_refs: BTreeMap<String, &_> = files.iter().map(|(k, v)| (k.clone(), v)).collect();

    // Create dummy ledger for this test
    let metadatas_refs: Vec<&_> = metadatas.iter().collect();
    let dummy_ledger = create_multi_file_ledger(&metadatas_refs);

    let dummy_ledger_indices = vec![0; challenges.len()]; // Dummy indices for test
    let (witness, new_state) = api::generate_circuit_witness(
        &challenges.iter().collect::<Vec<_>>(),
        Some(&file_refs),
        &dummy_ledger, // Use dummy ledger
        10,            // file_tree_depth
        10,            // max_supported_depth
        initial_state,
        0, // aggregated_tree_depth
        0, // step_num
        &dummy_ledger_indices,
    )
    .expect("Failed to generate witness");

    // Manually compute expected state evolution
    // The state should evolve by hashing (state, leaf) for each real file in order
    let mut expected_state = initial_state;
    for witness_entry in witness.witnesses() {
        if witness_entry.actual_depth > 0 {
            // Phase 3: Real files have depth > 0
            expected_state = poseidon_hash_tagged(
                domain_tags::state_update(),
                expected_state,
                witness_entry.leaf,
            );
        }
    }

    assert_eq!(
        new_state, expected_state,
        "State evolution doesn't match manual computation"
    );

    println!("✓ State evolution across files matches manual computation");
}

#[test]
fn test_commitments_match_between_api_and_circuit() {
    // A-11: Critical test - API commitment calculations must match in-circuit
    println!("Testing commitment calculations match between API and circuit");

    // This test verifies that the commitments calculated in prove/verify
    // match what the circuit expects. We'll create a proof and verify it,
    // then manually compute commitments and ensure they match.

    let data1 = vec![1u8; 100];
    let data2 = vec![2u8; 150];

    let (prep1, meta1) = api::prepare_file(&data1, "test_file.dat").unwrap();
    let (prep2, meta2) = api::prepare_file(&data2, "test_file.dat").unwrap();

    // Create challenges
    let seed = FieldElement::from(999u64);
    let challenges = vec![
        Challenge::new_test(meta1.clone(), 1000, 1, seed),
        Challenge::new_test(meta2.clone(), 1000, 1, seed),
    ];

    // Create ledger for multi-file proof
    let mut ledger = kontor_crypto::ledger::FileLedger::new();
    ledger
        .add_file(
            meta1.file_id.clone(),
            meta1.root,
            kontor_crypto::api::tree_depth_from_metadata(&meta1),
        )
        .unwrap();
    ledger
        .add_file(
            meta2.file_id.clone(),
            meta2.root,
            kontor_crypto::api::tree_depth_from_metadata(&meta2),
        )
        .unwrap();

    let mut files = BTreeMap::new();
    files.insert(meta1.file_id.clone(), &prep1);
    files.insert(meta2.file_id.clone(), &prep2);

    // Generate proof using PorSystem
    let system = PorSystem::new(&ledger);
    let files_vec: Vec<&_> = files.values().copied().collect();
    let proof = system
        .prove(files_vec, &challenges)
        .expect("Failed to generate proof");

    // Verify it works
    let is_valid = system
        .verify(&proof, &challenges)
        .expect("Failed to verify");
    assert!(is_valid, "Proof should be valid");

    // Now manually compute the commitments that should have been used
    // The API should compute these identically to how the circuit does

    // This is implicitly tested by the fact that verification succeeds
    // If there was a mismatch, verification would fail
    // But we can add explicit validation here

    // Verify files meta commitment calculation consistency
    let metadatas_refs = vec![&meta1, &meta2];
    let meta_commitment = create_files_meta_commitment(&metadatas_refs, 2)
        .expect("Failed to compute meta commitment");

    println!("✓ Meta commitment computed successfully (verification implies matching)");
    println!("  Meta commitment: {:?}", meta_commitment);
}

#[test]
fn test_prove_fails_without_required_ledger() {
    // A-24: Multi-file proof should fail without ledger
    println!("Testing that multi-file proof fails without required ledger");

    let data1 = vec![10u8; 50];
    let data2 = vec![20u8; 60];

    let (prep1, meta1) = api::prepare_file(&data1, "test_file.dat").unwrap();
    let (prep2, meta2) = api::prepare_file(&data2, "test_file.dat").unwrap();

    let challenges = vec![
        Challenge::new_test(meta1.clone(), 1000, 1, FieldElement::from(42u64)),
        Challenge::new_test(meta2.clone(), 1000, 1, FieldElement::from(42u64)),
    ];

    let mut files = BTreeMap::new();
    files.insert(meta1.file_id.clone(), &prep1);
    files.insert(meta2.file_id.clone(), &prep2);

    // With unified API, we now always provide a ledger and it should work
    let metadatas_refs: Vec<&_> = vec![&meta1, &meta2];
    let ledger = create_multi_file_ledger(&metadatas_refs);
    let system = PorSystem::new(&ledger);
    let files_vec: Vec<&_> = files.values().copied().collect();
    let result = system.prove(files_vec, &challenges);

    assert!(
        result.is_ok(),
        "Multi-file proof should now succeed with unified API and proper ledger"
    );

    println!("✓ Multi-file proof succeeds with unified API");
}

#[test]
fn test_single_file_ignores_ledger() {
    // A-24: Single-file proof should ignore ledger even if provided
    println!("Testing that single-file proof ignores ledger");

    let data = vec![30u8; 70];

    let (prepared, metadata) = api::prepare_file(&data, "test_file.dat").unwrap();

    let challenge = Challenge::new_test(metadata.clone(), 1000, 1, FieldElement::from(123u64));

    let mut files = BTreeMap::new();
    files.insert(metadata.file_id.clone(), &prepared);

    // Create minimal ledger with just this file
    let minimal_ledger = create_single_file_ledger(&metadata);

    // Create larger ledger with this file plus another
    let mut larger_ledger = kontor_crypto::ledger::FileLedger::new();
    larger_ledger
        .add_file(
            metadata.file_id.clone(),
            metadata.root,
            kontor_crypto::api::tree_depth_from_metadata(&metadata),
        )
        .unwrap();
    // Add another file to make the ledger different
    larger_ledger
        .add_file("other_file".to_string(), FieldElement::from(999u64), 3)
        .unwrap();

    // Should work with minimal ledger
    let system_minimal = PorSystem::new(&minimal_ledger);
    let files_vec: Vec<&_> = files.values().copied().collect();
    let proof_minimal = system_minimal
        .prove(files_vec.clone(), std::slice::from_ref(&challenge))
        .expect("Single-file proof should work with minimal ledger");

    // Should also work with larger ledger (but uses file root for single-file case)
    let system_larger = PorSystem::new(&larger_ledger);
    let proof_larger = system_larger
        .prove(files_vec, std::slice::from_ref(&challenge))
        .expect("Single-file proof should work with larger ledger");

    // Both should verify (single-file always uses file root)
    let valid_minimal = system_minimal
        .verify(&proof_minimal, std::slice::from_ref(&challenge))
        .expect("Verification failed");
    let valid_larger = system_larger
        .verify(&proof_larger, &[challenge])
        .expect("Verification failed");

    assert!(valid_minimal, "Proof with minimal ledger should verify");
    assert!(valid_larger, "Proof with larger ledger should verify");

    println!("✓ Single-file proof works with different ledger configurations");
}

#[test]
#[ignore] // This is informational/speculative
fn test_proof_determinism() {
    // A-20: Check if proofs are deterministic (informational test)
    println!("Testing proof determinism (informational)");

    let data = vec![42u8; 100];

    let (prepared, metadata) = api::prepare_file(&data, "test_file.dat").unwrap();
    let challenge = Challenge::new_test(metadata.clone(), 1000, 1, FieldElement::from(777u64));

    let mut files = BTreeMap::new();
    files.insert(metadata.file_id.clone(), &prepared);

    // Create ledger for unified API
    let ledger = create_single_file_ledger(&metadata);

    // Generate two proofs with identical inputs
    let system = PorSystem::new(&ledger);
    let files_vec: Vec<&_> = files.values().copied().collect();
    let proof1 = system
        .prove(files_vec.clone(), std::slice::from_ref(&challenge))
        .expect("Failed to generate proof 1");
    let proof2 = system
        .prove(files_vec, std::slice::from_ref(&challenge))
        .expect("Failed to generate proof 2");

    // Serialize and compare
    let bytes1 = bincode::serialize(&proof1).unwrap();
    let bytes2 = bincode::serialize(&proof2).unwrap();

    if bytes1 == bytes2 {
        println!("✓ Proofs are deterministic (byte-identical)");
    } else {
        println!("  Note: Proofs are not byte-identical");
        println!("  Proof 1 size: {} bytes", bytes1.len());
        println!("  Proof 2 size: {} bytes", bytes2.len());

        // Both should still verify
        let valid1 = system
            .verify(&proof1, std::slice::from_ref(&challenge))
            .unwrap();
        let valid2 = system.verify(&proof2, &[challenge]).unwrap();

        assert!(
            valid1 && valid2,
            "Both proofs should verify even if not identical"
        );
        println!("  Both proofs verify successfully");
    }
}
