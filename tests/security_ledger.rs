//! Security tests for the FileLedger component.

use kontor_crypto::api::{self};
use std::collections::BTreeMap;

mod common;
use common::fixtures::{create_test_data, setup_test_scenario, TestConfig};

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

    let depth_c = kontor_crypto::api::tree_depth_from_metadata(&metadata_c);
    updated_ledger
        .add_file(metadata_c.file_id, metadata_c.root, depth_c)
        .unwrap();

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
    updated_ledger.record_current_root(1_000); // Record original root as historical (height-keyed)

    println!("Original root recorded as historical");
    println!(
        "Historical root count: {}",
        updated_ledger.historical_root_count()
    );

    // Add a third file (this changes the current root)
    let data_c = create_test_data(100, Some(999));
    let (_, metadata_c) = api::prepare_file(&data_c, "test_file.dat").unwrap();
    let depth_c = kontor_crypto::api::tree_depth_from_metadata(&metadata_c);
    updated_ledger
        .add_file(metadata_c.file_id, metadata_c.root, depth_c)
        .unwrap();

    println!("Added new file, current root changed");
    println!("Proof ledger_root: {:?}", multi_proof.ledger_root);
    println!("Updated ledger root: {:?}", updated_ledger.root());

    // 4. Verify using updated ledger - should work because:
    //    - proof.ledger_root is in historical_roots
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
    // If we don't record the historical root, multi-file proof fails
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

    // 3. Create a NEW ledger (without historical root)
    let mut new_ledger = original_ledger.clone();
    // DO NOT call record_current_root() - this simulates not tracking history

    // Add a file to change the root
    let data_c = create_test_data(100, Some(999));
    let (_, metadata_c) = api::prepare_file(&data_c, "test_file.dat").unwrap();
    let depth_c = kontor_crypto::api::tree_depth_from_metadata(&metadata_c);
    new_ledger
        .add_file(metadata_c.file_id, metadata_c.root, depth_c)
        .unwrap();

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
        let file_id = format!("file_{}", i);
        let root = kontor_crypto::api::FieldElement::from(i as u64 * 100);
        ledger.add_file(file_id, root, 3).unwrap();
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
        .add_file(
            "file1".to_string(),
            kontor_crypto::api::FieldElement::from(100u64),
            3,
        )
        .unwrap();
    ledger
        .add_file(
            "file2".to_string(),
            kontor_crypto::api::FieldElement::from(200u64),
            3,
        )
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
        .add_file(
            "file1".to_string(),
            kontor_crypto::api::FieldElement::from(100u64),
            3,
        )
        .unwrap();
    ledger
        .add_file(
            "file2".to_string(),
            kontor_crypto::api::FieldElement::from(200u64),
            3,
        )
        .unwrap();
    ledger
        .add_file(
            "file3".to_string(),
            kontor_crypto::api::FieldElement::from(300u64),
            3,
        )
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

    let files = vec![
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

    for (hash, root) in &files {
        ledger.add_file(hash.clone(), *root, 3).unwrap();
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
    let file_id = "duplicate_test".to_string();
    let root1 = kontor_crypto::api::FieldElement::from(100u64);

    let result1 = ledger.add_file(file_id.clone(), root1, 3);
    assert!(result1.is_ok(), "First add should succeed");

    let original_root = ledger.files.get(&file_id).unwrap().root;
    assert_eq!(original_root, root1, "Initial root should be root1");

    // Add the same file again with a different root - this should UPDATE
    let root2 = kontor_crypto::api::FieldElement::from(200u64);
    let result2 = ledger.add_file(file_id.clone(), root2, 3);

    assert!(result2.is_ok(), "Second add should succeed (update)");
    assert_eq!(
        ledger.files.get(&file_id).unwrap().root,
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
