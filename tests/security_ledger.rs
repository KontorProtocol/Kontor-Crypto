//! Security tests for the FileLedger component.

use kontor_crypto::api::{self, FieldElement, FileMetadata};
use std::collections::BTreeMap;

mod common;
use common::fixtures::{create_test_data, setup_test_scenario, TestConfig};
use kontor_crypto::KontorPoRError;

fn historical_root_total(ledger: &kontor_crypto::ledger::FileLedger) -> usize {
    ledger.historical_roots.len()
}

/// Helper to create a synthetic FileMetadata for testing.
fn synthetic_metadata(file_id: &str, root: FieldElement, depth: usize) -> FileMetadata {
    FileMetadata {
        root,
        file_id: file_id.to_string(),
        padded_len: 1 << depth, // 2^depth
        original_size: 100,
        filename: "synthetic.dat".to_string(),
    }
}

// =============================================================================
// HISTORICAL LEDGER: FULL LIFECYCLE TEST
// =============================================================================
//
// This test demonstrates the complete lifecycle of historical root tracking
// and explains WHY it is essential for the Kontor PoR system.
//
// PROBLEM STATEMENT:
// ------------------
// In a blockchain context, files are added to the ledger over time across
// multiple blocks. When a prover generates a proof, it commits to the current
// ledger root (the Merkle root of all file root commitments). But what happens
// when more files are added in subsequent blocks?
//
// Without historical root tracking:
// - A proof generated at block N commits to ledger_root_N
// - At block N+1, new files are added, creating ledger_root_N+1
// - The verifier only knows ledger_root_N+1 (the current state)
// - The proof fails because ledger_root_N != ledger_root_N+1
// - All proofs would need to be regenerated every time the ledger changes!
//
// With historical root tracking:
// - When files are added at block N+1, ledger_root_N is recorded as historical
// - The proof's ledger_root_N is checked against both current AND historical roots
// - The proof remains valid as long as ledger_root_N is in the historical set
// - Proofs can survive across multiple block updates without regeneration
//
// This is CRITICAL for practical PoR systems where:
// - Files are continuously added by different users
// - Proofs may be aggregated and verified at different times
// - Regenerating all proofs on every ledger update would be prohibitively expensive

#[test]
fn test_historical_ledger_full_lifecycle() {
    println!("=== HISTORICAL LEDGER: FULL LIFECYCLE DEMONSTRATION ===\n");

    // =========================================================================
    // BLOCK 1000: Initial state - Alice adds her files
    // =========================================================================
    println!("BLOCK 1000: Alice adds two files to the ledger");

    let alice_data_1 = create_test_data(100, Some(1001));
    let alice_data_2 = create_test_data(100, Some(1002));
    let (alice_prepared_1, alice_meta_1) =
        api::prepare_file(&alice_data_1, "alice_doc1.pdf").unwrap();
    let (alice_prepared_2, alice_meta_2) =
        api::prepare_file(&alice_data_2, "alice_doc2.pdf").unwrap();

    let mut ledger = kontor_crypto::ledger::FileLedger::new();
    ledger.add_file(&alice_meta_1).unwrap();
    ledger.add_file(&alice_meta_2).unwrap();

    let root_block_1000 = ledger.root();
    println!("  Ledger root after block 1000: {:?}", root_block_1000);
    println!("  Files in ledger: {}", ledger.files.len());
    println!(
        "  Historical roots recorded: {}\n",
        historical_root_total(&ledger)
    );

    // =========================================================================
    // BLOCK 1000: Alice generates a MULTI-FILE proof for BOTH her files
    // =========================================================================
    // NOTE: Single-file proofs (k=1) use the file's own Merkle root directly,
    // NOT the ledger root. They survive ledger updates WITHOUT historical roots.
    //
    // Multi-file proofs (k>1) commit to the LEDGER root and include indices
    // showing where each file sits in the aggregated tree. THESE require
    // historical root tracking to verify after the ledger changes.
    println!("BLOCK 1000: Alice generates a MULTI-FILE proof for both her files");

    let challenge_1 =
        api::Challenge::new_test(alice_meta_1.clone(), 1000, 1, FieldElement::from(12345u64));
    let challenge_2 =
        api::Challenge::new_test(alice_meta_2.clone(), 1000, 1, FieldElement::from(67890u64));
    let challenges = vec![challenge_1.clone(), challenge_2.clone()];

    let system_1000 = api::PorSystem::new(&ledger);
    let multi_file_proof = system_1000
        .prove(vec![&alice_prepared_1, &alice_prepared_2], &challenges)
        .expect("Alice should generate a valid multi-file proof");

    println!(
        "  Multi-file proof commits to ledger_root: {:?}",
        multi_file_proof.ledger_root
    );
    println!("  This is the AGGREGATED root of all files in the ledger");
    println!(
        "  Proof verifies against current ledger: {}\n",
        system_1000.verify(&multi_file_proof, &challenges).unwrap()
    );

    // =========================================================================
    // BLOCK 1001: Bob adds his file - ledger root CHANGES
    // =========================================================================
    println!("BLOCK 1001: Bob adds a file to the ledger");

    let bob_data = create_test_data(100, Some(2001));
    let (_bob_prepared, bob_meta) = api::prepare_file(&bob_data, "bob_contract.pdf").unwrap();

    // CRITICAL: add_file atomically records the OLD root before adding the new file
    ledger.add_file(&bob_meta).unwrap();

    let root_block_1001 = ledger.root();
    println!("  Ledger root after block 1001: {:?}", root_block_1001);
    println!("  Files in ledger: {}", ledger.files.len());
    println!(
        "  Historical roots recorded: {}",
        historical_root_total(&ledger)
    );

    // Verify the roots are different
    assert_ne!(
        root_block_1000, root_block_1001,
        "Ledger root must change when a file is added"
    );
    println!(
        "  Root changed: {} -> {} (different: ✓)\n",
        &format!("{:?}", root_block_1000)[0..20],
        &format!("{:?}", root_block_1001)[0..20]
    );

    // =========================================================================
    // THE CRITICAL TEST: Can Alice's old multi-file proof still verify?
    // =========================================================================
    println!("BLOCK 1001: Verifier checks Alice's multi-file proof from block 1000");
    println!(
        "  Proof's ledger_root (from block 1000): {:?}",
        multi_file_proof.ledger_root
    );
    println!(
        "  Current ledger root (block 1001):      {:?}",
        root_block_1001
    );
    println!("  These are DIFFERENT - the proof was generated against a stale root!");

    // Create a new system with the updated ledger
    let system_1001 = api::PorSystem::new(&ledger);

    // THIS IS WHERE HISTORICAL ROOTS MATTER:
    // The proof's ledger_root (from block 1000) != current root (from block 1001)
    // But verification should STILL succeed because:
    // 1. The old root was recorded as historical when Bob's file was added
    // 2. The verifier checks is_valid_root() which includes historical roots
    // 3. The SNARK proves the proof is valid for the claimed root

    println!(
        "\n  Is old root in historical set? {}",
        ledger.is_valid_root(root_block_1000)
    );

    let verification_result = system_1001
        .verify(&multi_file_proof, &challenges)
        .expect("Verification should complete without error");

    println!(
        "  VERIFICATION RESULT: {}",
        if verification_result {
            "✓ VALID"
        } else {
            "✗ INVALID"
        }
    );

    assert!(
        verification_result,
        "Alice's multi-file proof from block 1000 MUST verify against block 1001 ledger"
    );

    // =========================================================================
    // NEGATIVE TEST: What happens WITHOUT historical root tracking?
    // =========================================================================
    println!("\n--- NEGATIVE TEST: Simulating a ledger without historical roots ---");

    // Create a copy of the ledger and clear its historical roots
    let mut ledger_no_history = ledger.clone();
    ledger_no_history.historical_roots.clear();

    println!(
        "  Historical roots cleared: count = {}",
        historical_root_total(&ledger_no_history)
    );
    println!(
        "  Is old root (block 1000) valid now? {}",
        ledger_no_history.is_valid_root(root_block_1000)
    );

    let system_no_history = api::PorSystem::new(&ledger_no_history);
    let no_history_result = system_no_history.verify(&multi_file_proof, &challenges);

    println!("  Verification result: {:?}", no_history_result);

    assert!(
        no_history_result.is_err(),
        "WITHOUT historical roots, Alice's multi-file proof MUST fail verification"
    );
    println!("\n✓ Historical ledger lifecycle test PASSED\n");
}

#[test]
fn test_proofs_against_any_intermediate_state_remain_valid() {
    // This test verifies that proofs generated at ANY point within a block
    // remain valid after subsequent operations, because all intermediate
    // states are preserved in the historical roots.
    println!("=== INTERMEDIATE STATE PROOF VALIDATION TEST ===\n");

    // Create files for the test
    let data_1 = create_test_data(100, Some(1));
    let data_2 = create_test_data(100, Some(2));
    let data_3 = create_test_data(100, Some(3));
    let data_4 = create_test_data(100, Some(4));

    let (prepared_1, meta_1) = api::prepare_file(&data_1, "file_1.dat").unwrap();
    let (prepared_2, meta_2) = api::prepare_file(&data_2, "file_2.dat").unwrap();
    let (prepared_3, meta_3) = api::prepare_file(&data_3, "file_3.dat").unwrap();
    let (_prepared_4, meta_4) = api::prepare_file(&data_4, "file_4.dat").unwrap();

    let mut ledger = kontor_crypto::ledger::FileLedger::new();

    // =========================================================================
    // Block 1000: Add files one by one, generate proofs at each step
    // =========================================================================
    println!("BLOCK 1000: Adding files and generating proofs at each step\n");

    // Add file_1
    ledger.add_file(&meta_1).unwrap();
    let root_after_1 = ledger.root();
    println!(
        "  After file_1: root = {:?}",
        &format!("{:?}", root_after_1)[0..20]
    );

    // Add file_2 - generate a multi-file proof at this state
    ledger.add_file(&meta_2).unwrap();
    let root_after_2 = ledger.root();
    println!(
        "  After file_2: root = {:?}",
        &format!("{:?}", root_after_2)[0..20]
    );

    let challenge_1 = api::Challenge::new_test(meta_1.clone(), 1000, 1, FieldElement::from(111u64));
    let challenge_2 = api::Challenge::new_test(meta_2.clone(), 1000, 1, FieldElement::from(222u64));

    let system_2 = api::PorSystem::new(&ledger);
    let proof_at_state_2 = system_2
        .prove(
            vec![&prepared_1, &prepared_2],
            &[challenge_1.clone(), challenge_2.clone()],
        )
        .expect("Should generate proof at state 2");
    println!(
        "  Generated proof_at_state_2 against root: {:?}",
        &format!("{:?}", proof_at_state_2.ledger_root)[0..20]
    );

    // Add file_3 - generate another proof at this state
    ledger.add_file(&meta_3).unwrap();
    let root_after_3 = ledger.root();
    println!(
        "  After file_3: root = {:?}",
        &format!("{:?}", root_after_3)[0..20]
    );

    let challenge_3 = api::Challenge::new_test(meta_3.clone(), 1000, 1, FieldElement::from(333u64));

    let system_3 = api::PorSystem::new(&ledger);
    let proof_at_state_3 = system_3
        .prove(
            vec![&prepared_1, &prepared_2, &prepared_3],
            &[
                challenge_1.clone(),
                challenge_2.clone(),
                challenge_3.clone(),
            ],
        )
        .expect("Should generate proof at state 3");
    println!(
        "  Generated proof_at_state_3 against root: {:?}",
        &format!("{:?}", proof_at_state_3.ledger_root)[0..20]
    );

    // =========================================================================
    // Block 1001: Add another file, changing the ledger state
    // =========================================================================
    println!("\nBLOCK 1001: Adding file_4\n");

    ledger.add_file(&meta_4).unwrap();
    let root_after_4 = ledger.root();
    println!(
        "  After file_4: root = {:?}",
        &format!("{:?}", root_after_4)[0..20]
    );

    // Verify all roots are different
    assert_ne!(root_after_2, root_after_3);
    assert_ne!(root_after_3, root_after_4);

    // =========================================================================
    // Verify ALL historical roots are preserved
    // =========================================================================
    println!("Checking historical roots are preserved:");
    println!(
        "  Total historical roots: {}",
        historical_root_total(&ledger)
    );

    // root_after_1 should be valid (recorded when file_2 was added in block 1000)
    assert!(
        ledger.is_valid_root(root_after_1),
        "root_after_1 should be in historical roots"
    );
    println!("  ✓ root_after_1 is valid");

    // root_after_2 should be valid (recorded when file_3 was added in block 1000)
    assert!(
        ledger.is_valid_root(root_after_2),
        "root_after_2 should be in historical roots"
    );
    println!("  ✓ root_after_2 is valid");

    // root_after_3 should be valid (recorded when file_4 was added in block 1001)
    assert!(
        ledger.is_valid_root(root_after_3),
        "root_after_3 should be in historical roots"
    );
    println!("  ✓ root_after_3 is valid");

    // root_after_4 is the current root
    assert!(
        ledger.is_valid_root(root_after_4),
        "root_after_4 (current) should be valid"
    );
    println!("  ✓ root_after_4 (current) is valid");

    // =========================================================================
    // Verify ALL proofs generated at intermediate states still validate
    // =========================================================================
    println!("\nVerifying proofs against intermediate states:");

    let final_system = api::PorSystem::new(&ledger);

    // Proof generated at state 2 (when only file_1, file_2 existed)
    let result_2 = final_system
        .verify(
            &proof_at_state_2,
            &[challenge_1.clone(), challenge_2.clone()],
        )
        .expect("Verification should complete");
    assert!(
        result_2,
        "Proof at state 2 should still be valid after ledger changed"
    );
    println!("  ✓ proof_at_state_2 validates (generated when ledger had 2 files)");

    // Proof generated at state 3 (when file_1, file_2, file_3 existed)
    let result_3 = final_system
        .verify(
            &proof_at_state_3,
            &[
                challenge_1.clone(),
                challenge_2.clone(),
                challenge_3.clone(),
            ],
        )
        .expect("Verification should complete");
    assert!(
        result_3,
        "Proof at state 3 should still be valid after ledger changed"
    );
    println!("  ✓ proof_at_state_3 validates (generated when ledger had 3 files)");

    println!("\n=== ALL INTERMEDIATE STATE PROOFS VALIDATED SUCCESSFULLY ===\n");
}

#[test]
fn test_single_file_proof_survives_ledger_update() {
    // Single-file proofs (k=1) use the file's Merkle root directly as the
    // aggregated root, NOT the ledger root. So they remain valid even when
    // the ledger changes.
    println!("Testing that single-file proofs survive ledger updates");

    // 1. Set up an initial multi-file scenario with 2 files (A and B)
    let setup = setup_test_scenario(&TestConfig::multi_file(2)).unwrap();
    let original_ledger = setup.ledger.as_ref().unwrap().clone();

    // 2. Generate a SINGLE-FILE proof for just file A
    let challenge_a = setup.challenges[0].clone();
    let file_a_hash = &challenge_a.file_metadata.file_id;
    let file_a_ref = setup.files.get(file_a_hash).unwrap();
    let mut files_for_proof = BTreeMap::new();
    files_for_proof.insert(file_a_hash.clone(), file_a_ref);

    let system = kontor_crypto::api::PorSystem::new(&original_ledger);
    let files_vec: Vec<&_> = files_for_proof.values().copied().collect();
    let proof_for_a = system
        .prove(files_vec, std::slice::from_ref(&challenge_a))
        .expect("Should generate a valid single-file proof for file A");

    // Sanity check: the proof should be valid against the original ledger
    assert!(
        system
            .verify(&proof_for_a, std::slice::from_ref(&challenge_a))
            .expect("Verification should succeed"),
        "Single-file proof should be valid against the original ledger"
    );

    // 3. Update the ledger by adding a third file (C)
    let mut updated_ledger = original_ledger.clone();
    let data_c = create_test_data(100, Some(999));
    let (_, metadata_c) = api::prepare_file(&data_c, "test_file.dat").unwrap();

    updated_ledger.add_file(&metadata_c).unwrap();

    assert_ne!(
        original_ledger.tree.root(),
        updated_ledger.tree.root(),
        "Ledger root should change after adding a file"
    );

    // 4. Single-file proof should STILL be valid against updated ledger
    // because single-file mode uses the file's root directly, not the ledger root
    let updated_system = api::PorSystem::new(&updated_ledger);
    let verification_result = updated_system
        .verify(&proof_for_a, &[challenge_a])
        .expect("Verification should complete");

    assert!(
        verification_result,
        "Single-file proof should remain valid (uses file root, not ledger root)"
    );

    println!("✓ Single-file proof correctly survives ledger update");
}

#[test]
fn test_multi_file_proof_valid_with_historical_root() {
    // Multi-file proofs include ledger_root and ledger_indices.
    // The proof remains valid as long as the root is in the historical set.
    // No ledger snapshot needed - the proof carries its own indices.
    println!("Testing multi-file proof valid with historical root");

    // 1. Set up multi-file scenario with 2 files
    let setup = setup_test_scenario(&TestConfig::multi_file(2)).unwrap();
    let original_ledger = setup.ledger.as_ref().unwrap().clone();

    // 2. Generate a MULTI-FILE proof for both files
    let system = kontor_crypto::api::PorSystem::new(&original_ledger);
    let files_vec: Vec<&_> = setup.files.values().collect();
    let challenges: Vec<_> = setup.challenges.clone();

    let multi_proof = system
        .prove(files_vec, &challenges)
        .expect("Should generate multi-file proof");

    // Sanity check: proof valid against original ledger
    assert!(
        system
            .verify(&multi_proof, &challenges)
            .expect("Should verify"),
        "Multi-file proof should be valid against original ledger"
    );

    // 3. Create updated ledger with historical root recorded
    let mut updated_ledger = original_ledger.clone();
    updated_ledger.record_current_root(); // Record original root as historical

    println!("Original root recorded as historical");
    println!(
        "Historical root count: {}",
        historical_root_total(&updated_ledger)
    );

    // Add a third file (this changes the current root)
    // Note: add_file automatically records historical
    let data_c = create_test_data(100, Some(999));
    let (_, metadata_c) = api::prepare_file(&data_c, "test_file.dat").unwrap();
    updated_ledger.add_file(&metadata_c).unwrap();

    println!("Added new file, current root changed");
    println!("Proof ledger_root: {:?}", multi_proof.ledger_root);
    println!("Updated ledger root: {:?}", updated_ledger.root());

    // 4. Verify using updated ledger - should work because:
    //    - proof.ledger_root is in historical_roots (automatically recorded by add_file)
    //    - proof includes ledger_indices from proof generation time
    //    - SNARK proves indices are correct for claimed root
    let updated_system = api::PorSystem::new(&updated_ledger);
    let result = updated_system.verify(&multi_proof, &challenges);

    assert!(
        result.expect("Should complete verification"),
        "Multi-file proof should be valid with historical root (proof carries its own indices)"
    );

    println!("✓ Multi-file proof correctly validates with historical root");
}

#[test]
fn test_multi_file_proof_fails_without_historical_root() {
    // If we don't have the historical root tracked, multi-file proof fails
    println!("Testing multi-file proof fails without historical root");

    // 1. Set up multi-file scenario
    let setup = setup_test_scenario(&TestConfig::multi_file(2)).unwrap();
    let original_ledger = setup.ledger.as_ref().unwrap().clone();

    // 2. Generate multi-file proof
    let system = kontor_crypto::api::PorSystem::new(&original_ledger);
    let files_vec: Vec<&_> = setup.files.values().collect();
    let challenges: Vec<_> = setup.challenges.clone();

    let multi_proof = system
        .prove(files_vec, &challenges)
        .expect("Should generate multi-file proof");

    // 3. Create a NEW ledger and add a file
    let mut new_ledger = original_ledger.clone();

    // Add a file to change the root (this will record the old root as historical)
    let data_c = create_test_data(100, Some(999));
    let (_, metadata_c) = api::prepare_file(&data_c, "test_file.dat").unwrap();
    new_ledger.add_file(&metadata_c).unwrap();

    // Clear historical roots to simulate not tracking history properly
    new_ledger.historical_roots.clear();

    // 4. Verify should FAIL because old root not in historical_roots
    let new_system = api::PorSystem::new(&new_ledger);
    let result = new_system.verify(&multi_proof, &challenges);

    assert!(
        result.is_err(),
        "Multi-file proof should fail when old root is NOT in historical_roots"
    );

    // Check it's the right error
    let err = result.unwrap_err();
    let err_msg = format!("{}", err);
    assert!(
        err_msg.contains("Invalid ledger root"),
        "Error should mention invalid ledger root, got: {}",
        err_msg
    );

    println!("✓ Multi-file proof correctly rejected when historical root not recorded");
}

#[test]
fn test_ledger_save_load_roundtrip() {
    // Ensure a ledger can be serialized to disk and deserialized back into an identical object
    println!("Testing ledger save/load roundtrip");

    // Create a ledger with several files
    let mut ledger = kontor_crypto::ledger::FileLedger::new();

    // Add multiple files
    for i in 0..5 {
        let metadata = synthetic_metadata(
            &format!("file_{}", i),
            FieldElement::from(i as u64 * 100),
            3,
        );
        ledger.add_file(&metadata).unwrap();
    }

    // Store the original root for comparison
    let original_root = ledger.tree.root();
    let original_file_count = ledger.files.len();

    // Save to a temporary file
    let temp_path = std::env::temp_dir().join("test_ledger.bin");
    ledger.save(&temp_path).expect("Should save ledger");

    // Load it back
    let loaded_ledger =
        kontor_crypto::ledger::FileLedger::load(&temp_path).expect("Should load ledger");

    // Clean up temp file
    std::fs::remove_file(&temp_path).ok();

    // Assert they are identical
    assert_eq!(
        loaded_ledger.tree.root(),
        original_root,
        "Loaded ledger should have same root"
    );
    assert_eq!(
        loaded_ledger.files.len(),
        original_file_count,
        "Loaded ledger should have same number of files"
    );

    // Check that all files are present
    for i in 0..5 {
        let file_id = format!("file_{}", i);
        assert!(
            loaded_ledger.files.contains_key(&file_id),
            "File {} should be present in loaded ledger",
            i
        );
    }

    println!("✓ Ledger save/load roundtrip successful");
}

#[test]
fn test_ledger_tamper_detected_on_load() {
    // Verify that FileLedger::load rejects a ledger file that has been tampered with
    println!("Testing tampered ledger detection");

    // Create and save a valid ledger
    let mut ledger = kontor_crypto::ledger::FileLedger::new();
    ledger
        .add_file(&synthetic_metadata("file1", FieldElement::from(100u64), 3))
        .unwrap();
    ledger
        .add_file(&synthetic_metadata("file2", FieldElement::from(200u64), 3))
        .unwrap();

    let temp_path = std::env::temp_dir().join("test_tampered_ledger.bin");
    ledger.save(&temp_path).expect("Should save ledger");

    // Read the file and tamper with it
    let mut ledger_bytes = std::fs::read(&temp_path).expect("Should read ledger file");

    // Flip a bit in the middle of the file
    if ledger_bytes.len() > 10 {
        ledger_bytes[10] ^= 0x01;
    }

    // Write the tampered bytes back
    std::fs::write(&temp_path, ledger_bytes).expect("Should write tampered file");

    // Try to load the tampered ledger
    let result = kontor_crypto::ledger::FileLedger::load(&temp_path);

    // Clean up temp file
    std::fs::remove_file(&temp_path).ok();

    // Should fail to load or fail validation
    assert!(result.is_err(), "Tampered ledger should fail to load");

    println!("✓ Tampered ledger correctly rejected");
}

#[test]
fn test_get_aggregation_proof_missing_returns_none() {
    // Ensure get_aggregation_proof returns None for a file not in the ledger
    println!("Testing get_aggregation_proof for missing file");

    // Create a ledger with a few files
    let mut ledger = kontor_crypto::ledger::FileLedger::new();
    ledger
        .add_file(&synthetic_metadata("file1", FieldElement::from(100u64), 3))
        .unwrap();
    ledger
        .add_file(&synthetic_metadata("file2", FieldElement::from(200u64), 3))
        .unwrap();
    ledger
        .add_file(&synthetic_metadata("file3", FieldElement::from(300u64), 3))
        .unwrap();

    // Try to get proof for a non-existent file
    let result = ledger.get_aggregation_proof("nonexistent_file");

    assert!(
        result.is_none(),
        "get_aggregation_proof should return None for missing file"
    );

    // Verify that existing files do return Some
    let existing_proof = ledger.get_aggregation_proof("file1");
    assert!(
        existing_proof.is_some(),
        "get_aggregation_proof should return Some for existing file"
    );

    println!("✓ get_aggregation_proof correctly handles missing files");
}

#[test]
fn test_ledger_file_ordering_consistency() {
    // Test that ledger maintains consistent ordering of files
    println!("Testing ledger file ordering consistency");

    // Create a ledger and add files in a specific order
    let mut ledger = kontor_crypto::ledger::FileLedger::new();

    let files = [
        (
            "zebra".to_string(),
            kontor_crypto::api::FieldElement::from(1u64),
        ),
        (
            "apple".to_string(),
            kontor_crypto::api::FieldElement::from(2u64),
        ),
        (
            "mango".to_string(),
            kontor_crypto::api::FieldElement::from(3u64),
        ),
        (
            "banana".to_string(),
            kontor_crypto::api::FieldElement::from(4u64),
        ),
    ];

    for (hash, root) in files.iter() {
        ledger
            .add_file(&synthetic_metadata(hash, *root, 3))
            .unwrap();
    }

    // Get the keys in sorted order (BTreeMap should maintain this)
    let sorted_keys: Vec<_> = ledger.files.keys().cloned().collect();

    // Verify alphabetical ordering
    assert_eq!(sorted_keys[0], "apple");
    assert_eq!(sorted_keys[1], "banana");
    assert_eq!(sorted_keys[2], "mango");
    assert_eq!(sorted_keys[3], "zebra");

    println!("✓ Ledger maintains consistent file ordering");
}

#[test]
fn test_ledger_duplicate_file_updates_entry() {
    // Test that adding the same file_id again updates the existing entry.
    // This is the expected behavior: the ledger uses BTreeMap::insert which
    // silently overwrites. This allows file metadata to be updated (e.g., if
    // the file content changes and gets a new root).
    println!("Testing duplicate file updates in ledger");

    let mut ledger = kontor_crypto::ledger::FileLedger::new();

    // Add a file
    let file_id = "duplicate_test";
    let root1 = FieldElement::from(100u64);

    let result1 = ledger.add_file(&synthetic_metadata(file_id, root1, 3));
    assert!(result1.is_ok(), "First add should succeed");

    let original_root = ledger.files.get(file_id).unwrap().root;
    assert_eq!(original_root, root1, "Initial root should be root1");

    // Add the same file again with a different root - this should UPDATE
    let root2 = kontor_crypto::api::FieldElement::from(200u64);
    let result2 = ledger.add_file(&synthetic_metadata(file_id, root2, 3));

    assert!(result2.is_ok(), "Second add should succeed (update)");
    assert_eq!(
        ledger.files.get(file_id).unwrap().root,
        root2,
        "Root MUST be updated to new value - ledger uses insert semantics"
    );

    // Verify only one file exists (not two)
    assert_eq!(
        ledger.files.len(),
        1,
        "Should still have exactly one file entry"
    );

    println!("✓ Duplicate file correctly updates existing entry");
}

// ===========================================
// Security Tests for add_files()
// ===========================================

#[test]
fn test_batch_add_produces_identical_cryptographic_commitments() {
    // SECURITY: Batch add must produce identical root commitments (rc) as individual adds.
    // If rc values differ, proofs would fail or be forgeable.
    println!("Testing that batch add produces identical cryptographic commitments");

    let files_data = vec![
        synthetic_metadata("file_alpha", FieldElement::from(100u64), 3),
        synthetic_metadata("file_beta", FieldElement::from(200u64), 5),
        synthetic_metadata("file_gamma", FieldElement::from(300u64), 4),
    ];

    // Method 1: Individual adds
    let mut ledger_individual = kontor_crypto::ledger::FileLedger::new();
    for metadata in files_data.iter() {
        ledger_individual.add_file(metadata).unwrap();
    }

    // Method 2: Batch add
    let mut ledger_batch = kontor_crypto::ledger::FileLedger::new();
    ledger_batch.add_files(&files_data).unwrap();

    // Verify cryptographic equivalence
    assert_eq!(
        ledger_individual.tree.root(),
        ledger_batch.tree.root(),
        "SECURITY VIOLATION: Aggregated roots must be identical"
    );

    // Verify each file's rc (root commitment) is identical
    for file_id in ["file_alpha", "file_beta", "file_gamma"] {
        let rc_individual = ledger_individual.files.get(file_id).unwrap().rc;
        let rc_batch = ledger_batch.files.get(file_id).unwrap().rc;
        assert_eq!(
            rc_individual, rc_batch,
            "SECURITY VIOLATION: RC for {} must be identical",
            file_id
        );
    }

    println!("✓ Batch add produces identical cryptographic commitments");
}

#[test]
fn test_batch_add_proof_generation_and_verification() {
    // SECURITY: Proofs generated against a batch-added ledger must verify correctly.
    // This tests the full cryptographic pipeline with batch add.
    println!("Testing proof generation and verification with batch-added ledger");

    // Prepare real files
    let data_1 = create_test_data(100, Some(1));
    let data_2 = create_test_data(150, Some(2));

    let (prepared_1, metadata_1) = api::prepare_file(&data_1, "file1.dat").unwrap();
    let (_prepared_2, metadata_2) = api::prepare_file(&data_2, "file2.dat").unwrap();

    // Use batch add to create ledger
    let mut ledger = kontor_crypto::ledger::FileLedger::new();
    ledger.add_files([&metadata_1, &metadata_2]).unwrap();

    // Generate a proof for file 1
    let challenge = api::Challenge::new(
        metadata_1.clone(),
        1000,
        2,
        api::FieldElement::from(42u64),
        String::from("test_prover"),
    );

    let system = api::PorSystem::new(&ledger);
    let proof = system
        .prove(vec![&prepared_1], std::slice::from_ref(&challenge))
        .expect("Proof generation should succeed with batch-added ledger");

    // Verify the proof
    let is_valid = system
        .verify(&proof, std::slice::from_ref(&challenge))
        .expect("Verification should complete");

    assert!(
        is_valid,
        "SECURITY VIOLATION: Proof must verify against batch-added ledger"
    );

    println!("✓ Proofs correctly verify against batch-added ledger");
}

#[test]
fn test_batch_add_multi_file_proof_verification() {
    // SECURITY: Multi-file proofs must work correctly with batch-added ledgers.
    println!("Testing multi-file proof with batch-added ledger");

    // Prepare multiple files
    let mut prepared_files = Vec::new();
    let mut metadatas = Vec::new();

    for i in 0..3 {
        let data = create_test_data(80 + i * 20, Some(i as u64));
        let (prepared, metadata) = api::prepare_file(&data, &format!("file{}.dat", i)).unwrap();
        prepared_files.push(prepared);
        metadatas.push(metadata);
    }

    // Batch add all files to ledger
    let mut ledger = kontor_crypto::ledger::FileLedger::new();
    ledger.add_files(&metadatas).unwrap();

    // Create challenges for all files
    let challenges: Vec<_> = metadatas
        .iter()
        .enumerate()
        .map(|(i, m)| {
            api::Challenge::new(
                m.clone(),
                1000,
                2,
                api::FieldElement::from((i + 100) as u64),
                String::from("test_prover"),
            )
        })
        .collect();

    // Generate multi-file proof
    let system = api::PorSystem::new(&ledger);
    let files_refs: Vec<_> = prepared_files.iter().collect();
    let proof = system
        .prove(files_refs, &challenges)
        .expect("Multi-file proof should succeed with batch-added ledger");

    // Verify the proof
    let is_valid = system
        .verify(&proof, &challenges)
        .expect("Verification should complete");

    assert!(
        is_valid,
        "SECURITY VIOLATION: Multi-file proof must verify against batch-added ledger"
    );

    println!("✓ Multi-file proofs correctly verify against batch-added ledger");
}

#[test]
fn test_batch_add_save_load_roundtrip() {
    // SECURITY: Batch-added ledgers must serialize and deserialize correctly.
    // A corrupted save/load could lead to proof failures or security issues.
    println!("Testing save/load roundtrip with batch-added ledger");

    let mut ledger = kontor_crypto::ledger::FileLedger::new();

    // Batch add files
    let files: Vec<_> = (0..10)
        .map(|i| {
            synthetic_metadata(
                &format!("file_{}", i),
                api::FieldElement::from(i as u64 * 100 + 42),
                (i % 5) + 1,
            )
        })
        .collect();

    ledger.add_files(&files).unwrap();
    let original_root = ledger.tree.root();
    let original_count = ledger.files.len();

    // Save and reload
    let temp_path = std::env::temp_dir().join("test_batch_ledger_security.bin");
    ledger
        .save(&temp_path)
        .expect("Should save batch-added ledger");

    let loaded = kontor_crypto::ledger::FileLedger::load(&temp_path).expect("Should load ledger");
    std::fs::remove_file(&temp_path).ok();

    // Verify cryptographic integrity
    assert_eq!(
        loaded.tree.root(),
        original_root,
        "SECURITY VIOLATION: Loaded root must match original"
    );
    assert_eq!(loaded.files.len(), original_count);

    // Verify each file's rc is preserved
    for (file_id, entry) in &ledger.files {
        let loaded_entry = loaded.files.get(file_id).expect("File should exist");
        assert_eq!(
            entry.rc, loaded_entry.rc,
            "SECURITY VIOLATION: RC must be preserved for {}",
            file_id
        );
    }

    println!("✓ Batch-added ledger save/load preserves cryptographic integrity");
}

#[test]
fn test_batch_add_canonical_ordering_security() {
    // SECURITY: Canonical ordering must be deterministic regardless of batch order.
    // Non-deterministic ordering could lead to proof failures or index confusion attacks.
    println!("Testing canonical ordering security with batch add");

    // Same files in different batch orders
    let files_order1 = vec![
        synthetic_metadata("zebra", api::FieldElement::from(1u64), 3),
        synthetic_metadata("apple", api::FieldElement::from(2u64), 3),
        synthetic_metadata("mango", api::FieldElement::from(3u64), 3),
    ];

    let files_order2 = vec![
        synthetic_metadata("mango", api::FieldElement::from(3u64), 3),
        synthetic_metadata("zebra", api::FieldElement::from(1u64), 3),
        synthetic_metadata("apple", api::FieldElement::from(2u64), 3),
    ];

    let mut ledger1 = kontor_crypto::ledger::FileLedger::new();
    ledger1.add_files(&files_order1).unwrap();

    let mut ledger2 = kontor_crypto::ledger::FileLedger::new();
    ledger2.add_files(&files_order2).unwrap();

    // Roots must be identical
    assert_eq!(
        ledger1.tree.root(),
        ledger2.tree.root(),
        "SECURITY VIOLATION: Different batch orders must produce same root"
    );

    // Canonical indices must be identical
    for file_id in ["apple", "mango", "zebra"] {
        let (idx1, rc1) = ledger1.lookup(file_id).unwrap();
        let (idx2, rc2) = ledger2.lookup(file_id).unwrap();
        assert_eq!(
            idx1, idx2,
            "SECURITY VIOLATION: Canonical index for {} must be identical",
            file_id
        );
        assert_eq!(
            rc1, rc2,
            "SECURITY VIOLATION: RC for {} must be identical",
            file_id
        );
    }

    // Verify expected canonical order (alphabetical)
    assert_eq!(ledger1.lookup("apple").unwrap().0, 0);
    assert_eq!(ledger1.lookup("mango").unwrap().0, 1);
    assert_eq!(ledger1.lookup("zebra").unwrap().0, 2);

    println!("✓ Batch add maintains deterministic canonical ordering");
}

#[test]
fn test_batch_add_aggregation_proof_integrity() {
    // SECURITY: Aggregation proofs from batch-added ledgers must be valid.
    // Invalid aggregation proofs could allow forged multi-file proofs.
    println!("Testing aggregation proof integrity with batch-added ledger");

    let mut ledger = kontor_crypto::ledger::FileLedger::new();

    // Batch add files
    let files = vec![
        synthetic_metadata("file_a", api::FieldElement::from(100u64), 3),
        synthetic_metadata("file_b", api::FieldElement::from(200u64), 4),
        synthetic_metadata("file_c", api::FieldElement::from(300u64), 5),
        synthetic_metadata("file_d", api::FieldElement::from(400u64), 3),
    ];
    ledger.add_files(&files).unwrap();

    // Get aggregation proof for each file and verify structure
    for file_id in ["file_a", "file_b", "file_c", "file_d"] {
        let proof = ledger
            .get_aggregation_proof(file_id)
            .expect("Should get aggregation proof");
        let (_, rc) = ledger.lookup(file_id).unwrap();

        // Verify the proof's leaf matches the file's rc
        assert_eq!(
            proof.leaf, rc,
            "SECURITY VIOLATION: Proof leaf must equal file's rc for {}",
            file_id
        );

        // Verify proof structure is consistent
        assert_eq!(
            proof.siblings.len(),
            proof.path_indices.len(),
            "Proof structure invalid for {}",
            file_id
        );
    }

    println!("✓ Aggregation proofs from batch-added ledger are valid");
}

#[test]
fn test_batch_add_ledger_root_changes_with_different_files() {
    // SECURITY: Adding different files must produce different aggregated roots.
    // If roots don't change, an attacker could substitute files.
    println!("Testing that different file batches produce different roots");

    let files_a = vec![
        synthetic_metadata("file_1", api::FieldElement::from(100u64), 3),
        synthetic_metadata("file_2", api::FieldElement::from(200u64), 3),
    ];

    let files_b = vec![
        synthetic_metadata("file_1", api::FieldElement::from(100u64), 3),
        synthetic_metadata("file_2", api::FieldElement::from(201u64), 3), // Different root!
    ];

    let files_c = vec![
        synthetic_metadata("file_1", api::FieldElement::from(100u64), 3),
        synthetic_metadata("file_2", api::FieldElement::from(200u64), 4), // Different depth!
    ];

    let mut ledger_a = kontor_crypto::ledger::FileLedger::new();
    ledger_a.add_files(&files_a).unwrap();

    let mut ledger_b = kontor_crypto::ledger::FileLedger::new();
    ledger_b.add_files(&files_b).unwrap();

    let mut ledger_c = kontor_crypto::ledger::FileLedger::new();
    ledger_c.add_files(&files_c).unwrap();

    // All roots must be different
    assert_ne!(
        ledger_a.tree.root(),
        ledger_b.tree.root(),
        "SECURITY VIOLATION: Different file roots must produce different aggregated roots"
    );

    assert_ne!(
        ledger_a.tree.root(),
        ledger_c.tree.root(),
        "SECURITY VIOLATION: Different file depths must produce different aggregated roots"
    );

    println!("✓ Different file batches correctly produce different roots");
}

#[test]
fn test_batch_add_rc_computation_consistency() {
    // SECURITY: Root commitment (rc) computation must be consistent between
    // batch add and individual add. rc = Poseidon(TAG_RC, root, depth)
    println!("Testing rc computation consistency in batch add");

    let metadata = synthetic_metadata("test_file", api::FieldElement::from(12345u64), 7);

    // Add via individual method
    let mut ledger_individual = kontor_crypto::ledger::FileLedger::new();
    ledger_individual.add_file(&metadata).unwrap();
    let rc_individual = ledger_individual.files.get("test_file").unwrap().rc;

    // Add via batch method
    let mut ledger_batch = kontor_crypto::ledger::FileLedger::new();
    ledger_batch.add_files([&metadata]).unwrap();
    let rc_batch = ledger_batch.files.get("test_file").unwrap().rc;

    assert_eq!(
        rc_individual, rc_batch,
        "SECURITY VIOLATION: RC computation must be identical between add_file and add_files"
    );

    // Verify rc is non-trivial (not zero or the root itself)
    assert_ne!(
        rc_individual,
        api::FieldElement::from(0u64),
        "RC should not be zero"
    );
    assert_ne!(
        rc_individual, metadata.root,
        "RC should not equal the raw root (domain separation)"
    );

    println!("✓ RC computation is consistent between individual and batch add");
}

#[test]
fn test_batch_add_with_real_files_proof_equivalence() {
    // SECURITY: End-to-end test that proofs generated with batch-added ledgers
    // are equivalent to those with individually-added ledgers.
    println!("Testing proof equivalence with real files (batch vs individual)");

    // Prepare real files
    let data_1 = create_test_data(100, Some(42));
    let data_2 = create_test_data(150, Some(43));

    let (prepared_1, metadata_1) = api::prepare_file(&data_1, "file1.dat").unwrap();
    let (_prepared_2, metadata_2) = api::prepare_file(&data_2, "file2.dat").unwrap();

    // Create ledger via individual adds
    let mut ledger_individual = kontor_crypto::ledger::FileLedger::new();
    ledger_individual.add_file(&metadata_1).unwrap();
    ledger_individual.add_file(&metadata_2).unwrap();

    // Create ledger via batch add
    let mut ledger_batch = kontor_crypto::ledger::FileLedger::new();
    ledger_batch.add_files([&metadata_1, &metadata_2]).unwrap();

    // Roots must be identical
    assert_eq!(
        ledger_individual.tree.root(),
        ledger_batch.tree.root(),
        "Ledger roots must be identical"
    );

    // Generate proofs with both ledgers
    let challenge = api::Challenge::new(
        metadata_1.clone(),
        1000,
        2,
        api::FieldElement::from(999u64),
        String::from("test_prover"),
    );

    let system_individual = api::PorSystem::new(&ledger_individual);
    let system_batch = api::PorSystem::new(&ledger_batch);

    let proof_individual = system_individual
        .prove(vec![&prepared_1], std::slice::from_ref(&challenge))
        .expect("Individual ledger proof should succeed");

    let proof_batch = system_batch
        .prove(vec![&prepared_1], std::slice::from_ref(&challenge))
        .expect("Batch ledger proof should succeed");

    // Both proofs should verify
    assert!(
        system_individual
            .verify(&proof_individual, std::slice::from_ref(&challenge))
            .unwrap(),
        "Individual ledger proof should verify"
    );

    assert!(
        system_batch
            .verify(&proof_batch, std::slice::from_ref(&challenge))
            .unwrap(),
        "Batch ledger proof should verify"
    );

    // Cross-verification: proof from one should verify with the other
    // (since ledgers are cryptographically identical)
    assert!(
        system_batch
            .verify(&proof_individual, std::slice::from_ref(&challenge))
            .unwrap(),
        "Individual proof should verify against batch ledger"
    );

    assert!(
        system_individual
            .verify(&proof_batch, std::slice::from_ref(&challenge))
            .unwrap(),
        "Batch proof should verify against individual ledger"
    );

    println!("✓ Proofs are equivalent between batch and individual ledger creation");
}

#[test]
fn test_batch_add_canonical_indices_match_individual_adds() {
    // SECURITY: The canonical index for each file must be identical whether
    // the ledger was built via batch add or individual adds.
    // Different indices would break proof verification.
    println!("Testing canonical index equivalence between batch and individual adds");

    // Create files with names that will sort in a specific order
    let files = vec![
        synthetic_metadata("delta", FieldElement::from(400u64), 3),
        synthetic_metadata("alpha", FieldElement::from(100u64), 4),
        synthetic_metadata("gamma", FieldElement::from(300u64), 5),
        synthetic_metadata("beta", FieldElement::from(200u64), 3),
    ];

    // Build ledger via individual adds (in random order)
    let mut ledger_individual = kontor_crypto::ledger::FileLedger::new();
    for metadata in files.iter() {
        ledger_individual.add_file(metadata).unwrap();
    }

    // Build ledger via batch add (same order)
    let mut ledger_batch = kontor_crypto::ledger::FileLedger::new();
    ledger_batch.add_files(&files).unwrap();

    // Verify canonical indices are identical
    let expected_order = ["alpha", "beta", "delta", "gamma"]; // Alphabetical

    for (expected_idx, file_id) in expected_order.iter().enumerate() {
        let (idx_individual, rc_individual) = ledger_individual
            .lookup(file_id)
            .unwrap_or_else(|| panic!("{} not found in individual ledger", file_id));
        let (idx_batch, rc_batch) = ledger_batch
            .lookup(file_id)
            .unwrap_or_else(|| panic!("{} not found in batch ledger", file_id));

        assert_eq!(
            idx_individual, expected_idx,
            "SECURITY VIOLATION: {} should be at index {} in individual ledger, got {}",
            file_id, expected_idx, idx_individual
        );
        assert_eq!(
            idx_batch, expected_idx,
            "SECURITY VIOLATION: {} should be at index {} in batch ledger, got {}",
            file_id, expected_idx, idx_batch
        );
        assert_eq!(
            idx_individual, idx_batch,
            "SECURITY VIOLATION: Canonical index for {} differs between batch ({}) and individual ({})",
            file_id, idx_batch, idx_individual
        );
        assert_eq!(
            rc_individual, rc_batch,
            "SECURITY VIOLATION: RC for {} differs between batch and individual",
            file_id
        );
    }

    // Also verify via get_canonical_index_for_rc
    for file_id in &expected_order {
        let rc = ledger_individual.files.get(*file_id).unwrap().rc;
        let idx_individual = ledger_individual.get_canonical_index_for_rc(rc);
        let idx_batch = ledger_batch.get_canonical_index_for_rc(rc);

        assert_eq!(
            idx_individual, idx_batch,
            "SECURITY VIOLATION: get_canonical_index_for_rc differs for {}",
            file_id
        );
    }

    println!("✓ Canonical indices are identical between batch and individual adds");
}

// =============================================================================
// Historical Root Recording Tests
// =============================================================================

#[test]
fn test_add_file_records_historical_root_on_non_empty_ledger() {
    // SECURITY: When adding a file to a non-empty ledger, the old root must be
    // recorded as a historical root to allow proofs against the old state to remain valid.
    println!("Testing that add_file records historical root on non-empty ledger");

    let mut ledger = kontor_crypto::ledger::FileLedger::new();

    // First file: ledger is empty, no historical root should be recorded
    let meta1 = synthetic_metadata("file_1", FieldElement::from(100u64), 3);
    ledger.add_file(&meta1).unwrap();

    assert_eq!(
        historical_root_total(&ledger),
        0,
        "First file should NOT record historical root (ledger was empty)"
    );

    let root_after_first = ledger.root();

    // Second file: ledger is non-empty, historical root SHOULD be recorded
    let meta2 = synthetic_metadata("file_2", FieldElement::from(200u64), 3);
    ledger.add_file(&meta2).unwrap();

    assert_eq!(
        historical_root_total(&ledger),
        1,
        "Second file should record exactly one historical root"
    );
    assert!(
        ledger.is_valid_root(root_after_first),
        "Root after first file should be valid as historical root"
    );

    let root_after_second = ledger.root();
    assert_ne!(
        root_after_first, root_after_second,
        "Root should change after adding second file"
    );

    // Third file: another historical root should be recorded
    let meta3 = synthetic_metadata("file_3", FieldElement::from(300u64), 3);
    ledger.add_file(&meta3).unwrap();

    assert_eq!(
        historical_root_total(&ledger),
        2,
        "Third file should result in two historical roots"
    );
    assert!(
        ledger.is_valid_root(root_after_first),
        "First historical root should still be valid"
    );
    assert!(
        ledger.is_valid_root(root_after_second),
        "Second historical root should be valid"
    );

    println!("✓ Historical roots correctly recorded on file additions");
}

#[test]
fn test_add_files_batch_records_single_historical_root() {
    // SECURITY: Batch add should record only ONE historical root entry,
    // not one per file. This is more efficient and semantically correct.
    println!("Testing that add_files records single historical root for batch");

    let mut ledger = kontor_crypto::ledger::FileLedger::new();

    // Add initial file
    let meta1 = synthetic_metadata("file_1", FieldElement::from(100u64), 3);
    ledger.add_file(&meta1).unwrap();
    let root_before_batch = ledger.root();

    assert_eq!(historical_root_total(&ledger), 0);

    // Batch add multiple files
    let batch = vec![
        synthetic_metadata("file_2", FieldElement::from(200u64), 3),
        synthetic_metadata("file_3", FieldElement::from(300u64), 3),
        synthetic_metadata("file_4", FieldElement::from(400u64), 3),
    ];
    ledger.add_files(&batch).unwrap();

    assert_eq!(
        historical_root_total(&ledger),
        1,
        "Batch add should record exactly ONE historical root, not one per file"
    );
    assert!(
        ledger.is_valid_root(root_before_batch),
        "Root before batch should be valid as historical root"
    );

    println!("✓ Batch add correctly records single historical root");
}

#[test]
fn test_historical_roots_accumulate_and_can_be_set() {
    // SECURITY: Historical roots accumulate with each file addition and
    // can be set/cleared with set_historical_roots.
    println!("Testing historical root accumulation and set_historical_roots");

    let mut ledger = kontor_crypto::ledger::FileLedger::new();

    // Add files
    ledger
        .add_file(&synthetic_metadata("file_1", FieldElement::from(100u64), 3))
        .unwrap();
    let root_1 = ledger.tree.root();

    ledger
        .add_file(&synthetic_metadata("file_2", FieldElement::from(200u64), 3))
        .unwrap();
    let root_2 = ledger.tree.root();

    ledger
        .add_file(&synthetic_metadata("file_3", FieldElement::from(300u64), 3))
        .unwrap();

    assert_eq!(historical_root_total(&ledger), 2);

    // All historical roots should be valid
    assert!(ledger.is_valid_root(root_1));
    assert!(ledger.is_valid_root(root_2));

    // Clear historical roots using set_historical_roots
    ledger.set_historical_roots(vec![]);

    assert_eq!(
        historical_root_total(&ledger),
        0,
        "Should have zero roots after clearing"
    );

    // Old roots should no longer be valid
    assert!(!ledger.is_valid_root(root_1));
    assert!(!ledger.is_valid_root(root_2));

    println!("✓ Historical roots correctly managed with set_historical_roots");
}

#[test]
fn test_historical_root_enables_old_proof_verification() {
    // SECURITY: The main purpose of historical roots is to allow proofs
    // generated against an old ledger state to remain valid.
    println!("Testing that historical roots enable old proof verification");

    // 1. Create ledger with 2 files
    let data1 = create_test_data(100, Some(1));
    let data2 = create_test_data(100, Some(2));
    let (prepared1, metadata1) = api::prepare_file(&data1, "file1.dat").unwrap();
    let (_prepared2, metadata2) = api::prepare_file(&data2, "file2.dat").unwrap();

    let mut ledger = kontor_crypto::ledger::FileLedger::new();
    ledger.add_file(&metadata1).unwrap();
    ledger.add_file(&metadata2).unwrap();

    // 2. Generate proof against current state
    let challenge = api::Challenge::new_test(metadata1.clone(), 1000, 1, FieldElement::from(42u64));
    let system = api::PorSystem::new(&ledger);
    let proof = system
        .prove(vec![&prepared1], std::slice::from_ref(&challenge))
        .expect("Should generate proof");

    // Verify proof works
    assert!(
        system
            .verify(&proof, std::slice::from_ref(&challenge))
            .unwrap(),
        "Proof should verify against current ledger"
    );

    // 3. Add a third file (this changes the current root but records old root as historical)
    let data3 = create_test_data(100, Some(3));
    let (_, metadata3) = api::prepare_file(&data3, "file3.dat").unwrap();
    ledger.add_file(&metadata3).unwrap();

    // 4. Verify the old proof still works because the old root is in historical_roots
    let updated_system = api::PorSystem::new(&ledger);
    let result = updated_system.verify(&proof, &[challenge]);

    assert!(
        result.expect("Verification should complete"),
        "Old proof should still verify because historical root is preserved"
    );

    println!("✓ Historical roots correctly enable old proof verification");
}

#[test]
fn test_is_valid_root_checks_current_and_historical() {
    // SECURITY: is_valid_root should return true for both current root
    // AND any root in the historical set.
    println!("Testing is_valid_root checks both current and historical roots");

    let mut ledger = kontor_crypto::ledger::FileLedger::new();

    // Add files and track roots
    ledger
        .add_file(&synthetic_metadata("file_1", FieldElement::from(100u64), 3))
        .unwrap();
    let root1 = ledger.root();

    ledger
        .add_file(&synthetic_metadata("file_2", FieldElement::from(200u64), 3))
        .unwrap();
    let root2 = ledger.root();

    ledger
        .add_file(&synthetic_metadata("file_3", FieldElement::from(300u64), 3))
        .unwrap();
    let root3 = ledger.root(); // Current root

    // Current root should be valid
    assert!(ledger.is_valid_root(root3), "Current root must be valid");

    // Historical roots should be valid
    assert!(
        ledger.is_valid_root(root1),
        "First historical root must be valid"
    );
    assert!(
        ledger.is_valid_root(root2),
        "Second historical root must be valid"
    );

    // Random root should NOT be valid
    let random_root = FieldElement::from(999999u64);
    assert!(
        !ledger.is_valid_root(random_root),
        "Random root must NOT be valid"
    );

    println!("✓ is_valid_root correctly validates current and historical roots");
}

#[test]
fn test_resetting_historical_roots_invalidates_old_multi_file_proof() {
    // POLICY: proofs against historical roots remain valid only while the root is retained.
    // Once pruned, verification must reject the proof with InvalidLedgerRoot.
    let data1 = create_test_data(100, Some(10));
    let data2 = create_test_data(100, Some(20));
    let data3 = create_test_data(100, Some(30));

    let (prepared1, meta1) = api::prepare_file(&data1, "p1.dat").unwrap();
    let (prepared2, meta2) = api::prepare_file(&data2, "p2.dat").unwrap();
    let (_prepared3, meta3) = api::prepare_file(&data3, "p3.dat").unwrap();

    let mut ledger = kontor_crypto::ledger::FileLedger::new();
    ledger.add_file(&meta1).unwrap();
    ledger.add_file(&meta2).unwrap();

    let challenges = vec![
        api::Challenge::new_test(meta1.clone(), 1000, 1, FieldElement::from(101u64)),
        api::Challenge::new_test(meta2.clone(), 1000, 1, FieldElement::from(202u64)),
    ];

    let system_1000 = api::PorSystem::new(&ledger);
    let proof = system_1000
        .prove(vec![&prepared1, &prepared2], &challenges)
        .expect("Should generate multi-file proof");

    // Add a third file in the next block.
    ledger.add_file(&meta3).unwrap();
    assert!(historical_root_total(&ledger) > 0);

    // Proof should verify while the old root is retained.
    {
        let system_1001 = api::PorSystem::new(&ledger);
        assert!(
            system_1001.verify(&proof, &challenges).unwrap(),
            "Proof should verify while historical root is retained"
        );
    }

    // Clear all historical roots.
    ledger.set_historical_roots(vec![]);
    assert_eq!(ledger.historical_roots.len(), 0);

    // Now verification must fail due to invalid ledger root.
    let system_post_prune = api::PorSystem::new(&ledger);
    let res = system_post_prune.verify(&proof, &challenges);
    assert!(
        matches!(res, Err(KontorPoRError::InvalidLedgerRoot { .. })),
        "Expected InvalidLedgerRoot after pruning, got: {res:?}"
    );
}

#[test]
fn test_clear_historical_roots_invalidates_old_proofs() {
    // SECURITY: Clearing historical roots should immediately invalidate
    // multi-file proofs against old ledger states.
    println!("Testing that clearing historical roots invalidates old proofs");

    // 1. Setup with 2 files
    let data1 = create_test_data(100, Some(1));
    let data2 = create_test_data(100, Some(2));
    let (prepared1, metadata1) = api::prepare_file(&data1, "file1.dat").unwrap();
    let (prepared2, metadata2) = api::prepare_file(&data2, "file2.dat").unwrap();

    let mut ledger = kontor_crypto::ledger::FileLedger::new();
    ledger.add_file(&metadata1).unwrap();
    ledger.add_file(&metadata2).unwrap();

    // 2. Generate multi-file proof (must have 2 challenges for 2 files)
    let challenges = [
        api::Challenge::new_test(metadata1.clone(), 1000, 1, FieldElement::from(42u64)),
        api::Challenge::new_test(metadata2.clone(), 1000, 1, FieldElement::from(43u64)),
    ];
    let system = api::PorSystem::new(&ledger);
    let proof = system
        .prove(vec![&prepared1, &prepared2], &challenges)
        .expect("Should generate multi-file proof");

    // 3. Add third file (records historical root)
    let data3 = create_test_data(100, Some(3));
    let (_, metadata3) = api::prepare_file(&data3, "file3.dat").unwrap();
    ledger.add_file(&metadata3).unwrap();

    // Proof should still work because historical root is preserved
    let system2 = api::PorSystem::new(&ledger);
    assert!(
        system2.verify(&proof, &challenges).unwrap(),
        "Proof should work with historical root"
    );

    // 4. Clear all historical roots
    ledger.historical_roots.clear();
    assert_eq!(historical_root_total(&ledger), 0);

    // 5. Multi-file proof should now FAIL because ledger_root is no longer valid
    let system3 = api::PorSystem::new(&ledger);
    let result = system3.verify(&proof, &challenges);

    assert!(
        matches!(result, Err(KontorPoRError::InvalidLedgerRoot { .. })),
        "Multi-file proof MUST fail after clearing historical roots, got: {:?}",
        result
    );

    println!("✓ Clearing historical roots correctly invalidates old multi-file proofs");
}

#[test]
fn test_set_historical_roots() {
    // Test that set_historical_roots replaces the historical roots.

    let mut ledger = kontor_crypto::ledger::FileLedger::new();

    // Add 10 files to create 9 historical roots
    for i in 0..10 {
        ledger
            .add_file(&synthetic_metadata(
                &format!("file_{}", i),
                FieldElement::from(i as u64 * 100),
                3,
            ))
            .unwrap();
    }

    assert_eq!(
        historical_root_total(&ledger),
        9,
        "Should have 9 historical roots (first add doesn't create one)"
    );

    // Keep only the last 3 roots by slicing
    let last_three: Vec<[u8; 32]> = ledger.historical_roots[6..9].to_vec();
    ledger.set_historical_roots(last_three);

    assert_eq!(
        ledger.historical_roots.len(),
        3,
        "Should have 3 roots after set"
    );
    assert_eq!(historical_root_total(&ledger), 3);
}

// =============================================================================
// Atomicity Tests for add_file / add_files
// =============================================================================
//
// These tests verify that the ledger operations maintain consistency:
// 1. Historical root recorded is exactly the pre-modification root
// 2. Historical root is only recorded on successful completion
// 3. State remains consistent after operations complete

#[test]
fn test_add_file_atomicity_records_correct_historical_root() {
    // ATOMICITY: The historical root recorded must be exactly the root
    // that existed BEFORE the modification, not some intermediate state.
    println!("Testing add_file records the correct historical root");

    let mut ledger = kontor_crypto::ledger::FileLedger::new();

    // Add first file (no historical root recorded for empty ledger)
    let meta1 = synthetic_metadata("file_1", FieldElement::from(100u64), 3);
    ledger.add_file(&meta1).unwrap();

    // Capture the root before adding second file
    let root_before_second = ledger.root();

    // Add second file
    let meta2 = synthetic_metadata("file_2", FieldElement::from(200u64), 3);
    ledger.add_file(&meta2).unwrap();

    // Verify exactly one historical root was recorded
    assert_eq!(ledger.historical_roots.len(), 1);

    // Verify the recorded root matches the pre-modification root exactly
    use ff::PrimeField;
    let recorded_root: [u8; 32] = ledger.historical_roots[0];
    let expected_root: [u8; 32] = root_before_second.to_repr().into();
    assert_eq!(
        recorded_root, expected_root,
        "ATOMICITY VIOLATION: Historical root must be the pre-modification root"
    );

    // Verify the root is valid
    assert!(
        ledger.is_valid_root(root_before_second),
        "Pre-modification root should be valid via is_valid_root"
    );

    println!("✓ add_file correctly records pre-modification root");
}

#[test]
fn test_add_files_atomicity_records_correct_historical_root() {
    // ATOMICITY: Batch add should record the root that existed before
    // ANY of the batch files were added.
    println!("Testing add_files records the correct historical root");

    let mut ledger = kontor_crypto::ledger::FileLedger::new();

    // Add initial file
    let meta1 = synthetic_metadata("file_1", FieldElement::from(100u64), 3);
    ledger.add_file(&meta1).unwrap();

    // Capture root before batch add
    let root_before_batch = ledger.root();

    // Batch add multiple files
    let batch = vec![
        synthetic_metadata("file_2", FieldElement::from(200u64), 3),
        synthetic_metadata("file_3", FieldElement::from(300u64), 4),
        synthetic_metadata("file_4", FieldElement::from(400u64), 5),
    ];
    ledger.add_files(&batch).unwrap();

    // Verify exactly one historical root was recorded (not one per file)
    assert_eq!(
        ledger.historical_roots.len(),
        1,
        "Batch add should record exactly ONE historical root"
    );

    // Verify the recorded root is the pre-batch root
    use ff::PrimeField;
    let recorded_root: [u8; 32] = ledger.historical_roots[0];
    let expected_root: [u8; 32] = root_before_batch.to_repr().into();
    assert_eq!(
        recorded_root, expected_root,
        "ATOMICITY VIOLATION: Historical root must be the root before batch started"
    );

    println!("✓ add_files correctly records single pre-batch root");
}

#[test]
fn test_add_file_atomicity_state_consistency_after_success() {
    // ATOMICITY: After successful add_file, all state components must be consistent:
    // - files map contains the new file
    // - tree root reflects all files
    // - historical_roots contains pre-modification root (if applicable)
    println!("Testing add_file state consistency after success");

    let mut ledger = kontor_crypto::ledger::FileLedger::new();

    // Add first file
    let meta1 = synthetic_metadata("file_1", FieldElement::from(100u64), 3);
    ledger.add_file(&meta1).unwrap();

    // State check after first file
    assert_eq!(ledger.files.len(), 1, "Should have 1 file");
    assert!(ledger.files.contains_key("file_1"), "file_1 should exist");
    assert_eq!(
        ledger.historical_roots.len(),
        0,
        "No historical root for first file"
    );

    let root_after_first = ledger.root();

    // Add second file
    let meta2 = synthetic_metadata("file_2", FieldElement::from(200u64), 3);
    ledger.add_file(&meta2).unwrap();

    // State check after second file
    assert_eq!(ledger.files.len(), 2, "Should have 2 files");
    assert!(ledger.files.contains_key("file_1"), "file_1 should exist");
    assert!(ledger.files.contains_key("file_2"), "file_2 should exist");
    assert_eq!(
        ledger.historical_roots.len(),
        1,
        "Should have 1 historical root"
    );

    // Tree root should have changed
    let root_after_second = ledger.root();
    assert_ne!(
        root_after_first, root_after_second,
        "Root must change after adding file"
    );

    // Historical root should be the old root
    assert!(
        ledger.is_valid_root(root_after_first),
        "Old root should be valid"
    );

    // Current root should also be valid
    assert!(
        ledger.is_valid_root(root_after_second),
        "Current root should be valid"
    );

    println!("✓ add_file maintains consistent state after success");
}

#[test]
fn test_add_files_atomicity_state_consistency_after_success() {
    // ATOMICITY: After successful add_files, all state components must be consistent.
    println!("Testing add_files state consistency after success");

    let mut ledger = kontor_crypto::ledger::FileLedger::new();

    // Add initial file
    let meta1 = synthetic_metadata("file_1", FieldElement::from(100u64), 3);
    ledger.add_file(&meta1).unwrap();
    let root_before_batch = ledger.root();

    // Batch add
    let batch = vec![
        synthetic_metadata("file_2", FieldElement::from(200u64), 3),
        synthetic_metadata("file_3", FieldElement::from(300u64), 3),
    ];
    ledger.add_files(&batch).unwrap();

    // State check
    assert_eq!(ledger.files.len(), 3, "Should have 3 files");
    assert!(ledger.files.contains_key("file_1"));
    assert!(ledger.files.contains_key("file_2"));
    assert!(ledger.files.contains_key("file_3"));

    // Historical root should be the pre-batch root
    assert_eq!(ledger.historical_roots.len(), 1);
    assert!(ledger.is_valid_root(root_before_batch));

    // Tree should reflect all files
    let final_root = ledger.root();
    assert_ne!(root_before_batch, final_root);
    assert!(ledger.is_valid_root(final_root));

    println!("✓ add_files maintains consistent state after success");
}

#[test]
fn test_empty_batch_is_noop_no_historical_root() {
    // ATOMICITY: Empty batch should be a complete no-op:
    // - No state changes
    // - No historical root recorded
    println!("Testing empty batch is a complete no-op");

    let mut ledger = kontor_crypto::ledger::FileLedger::new();

    // Add initial file
    let meta1 = synthetic_metadata("file_1", FieldElement::from(100u64), 3);
    ledger.add_file(&meta1).unwrap();

    let root_before = ledger.root();
    let files_before = ledger.files.len();
    let history_before = ledger.historical_roots.len();

    // Empty batch
    let empty: Vec<&api::FileMetadata> = vec![];
    ledger.add_files(empty).unwrap();

    // Verify complete no-op
    assert_eq!(ledger.root(), root_before, "Root should not change");
    assert_eq!(ledger.files.len(), files_before, "Files count unchanged");
    assert_eq!(
        ledger.historical_roots.len(),
        history_before,
        "Historical roots unchanged"
    );

    println!("✓ Empty batch is a complete no-op");
}

#[test]
fn test_atomicity_historical_root_order_matches_add_order() {
    // ATOMICITY: Historical roots should be recorded in the order files were added,
    // allowing reconstruction of ledger history.
    println!("Testing historical roots preserve temporal ordering");

    let mut ledger = kontor_crypto::ledger::FileLedger::new();

    // Track roots as we add files
    let mut expected_historical_roots = Vec::new();

    // Add files one by one, capturing the root before each addition
    for i in 0..5 {
        if i > 0 {
            // Capture root before adding (this will become historical)
            expected_historical_roots.push(ledger.root());
        }

        let meta = synthetic_metadata(
            &format!("file_{}", i),
            FieldElement::from(i as u64 * 100),
            3,
        );
        ledger.add_file(&meta).unwrap();
    }

    // Verify historical roots match expected order
    assert_eq!(
        ledger.historical_roots.len(),
        expected_historical_roots.len()
    );

    use ff::PrimeField;
    for (i, expected_root) in expected_historical_roots.iter().enumerate() {
        let expected_bytes: [u8; 32] = expected_root.to_repr().into();
        assert_eq!(
            ledger.historical_roots[i], expected_bytes,
            "Historical root {} should match pre-add root",
            i
        );
    }

    println!("✓ Historical roots preserve temporal ordering");
}
