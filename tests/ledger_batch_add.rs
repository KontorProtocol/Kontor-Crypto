//! Tests for the FileLedger::add_files_batch() method.
//!
//! These tests verify that batch adding files to a ledger produces identical
//! results to individual adds, but with O(n) performance instead of O(n²).

use kontor_crypto::api::FieldElement;
use kontor_crypto::ledger::FileLedger;

/// Helper to create a test file tuple (file_id, root, depth)
fn test_file(id: &str, root_val: u64, depth: usize) -> (String, FieldElement, usize) {
    (id.to_string(), FieldElement::from(root_val), depth)
}

// ===========================================
// Basic Functionality Tests
// ===========================================

#[test]
fn test_batch_add_basic() {
    let mut ledger = FileLedger::new();

    let files = vec![
        test_file("file_a", 100, 3),
        test_file("file_b", 200, 4),
        test_file("file_c", 300, 5),
    ];

    ledger
        .add_files_batch(files)
        .expect("Batch add should succeed");

    assert_eq!(ledger.files.len(), 3, "Should have 3 files");
    assert!(ledger.files.contains_key("file_a"));
    assert!(ledger.files.contains_key("file_b"));
    assert!(ledger.files.contains_key("file_c"));
}

#[test]
fn test_batch_add_empty() {
    let mut ledger = FileLedger::new();

    // Add a file first
    ledger
        .add_file("existing".to_string(), FieldElement::from(1u64), 3)
        .unwrap();
    let root_before = ledger.tree.root();

    // Empty batch should succeed and not change anything
    let empty: Vec<(String, FieldElement, usize)> = vec![];
    ledger
        .add_files_batch(empty)
        .expect("Empty batch should succeed");

    assert_eq!(ledger.files.len(), 1, "Should still have 1 file");
    assert_eq!(ledger.tree.root(), root_before, "Root should not change");
}

#[test]
fn test_batch_add_single_file() {
    let mut ledger = FileLedger::new();

    let files = vec![test_file("only_file", 999, 5)];
    ledger
        .add_files_batch(files)
        .expect("Single file batch should succeed");

    assert_eq!(ledger.files.len(), 1);
    assert!(ledger.files.contains_key("only_file"));
    assert_eq!(
        ledger.files.get("only_file").unwrap().root,
        FieldElement::from(999u64)
    );
    assert_eq!(ledger.files.get("only_file").unwrap().depth, 5);
}

// ===========================================
// Equivalence Tests (batch vs individual adds)
// ===========================================

#[test]
fn test_batch_add_equivalent_to_individual_adds() {
    // Create files to add
    let files = vec![
        test_file("alpha", 100, 3),
        test_file("beta", 200, 4),
        test_file("gamma", 300, 5),
        test_file("delta", 400, 3),
    ];

    // Method 1: Individual adds
    let mut ledger_individual = FileLedger::new();
    for (file_id, root, depth) in files.clone() {
        ledger_individual.add_file(file_id, root, depth).unwrap();
    }

    // Method 2: Batch add
    let mut ledger_batch = FileLedger::new();
    ledger_batch.add_files_batch(files).unwrap();

    // Both should produce identical results
    assert_eq!(
        ledger_individual.tree.root(),
        ledger_batch.tree.root(),
        "Roots should be identical"
    );
    assert_eq!(
        ledger_individual.files.len(),
        ledger_batch.files.len(),
        "File counts should be identical"
    );

    // Verify all file entries match
    for (key, entry_individual) in &ledger_individual.files {
        let entry_batch = ledger_batch
            .files
            .get(key)
            .expect("File should exist in batch ledger");
        assert_eq!(
            entry_individual.root, entry_batch.root,
            "Roots should match for {}",
            key
        );
        assert_eq!(
            entry_individual.depth, entry_batch.depth,
            "Depths should match for {}",
            key
        );
        assert_eq!(
            entry_individual.rc, entry_batch.rc,
            "RC values should match for {}",
            key
        );
    }
}

#[test]
fn test_batch_add_order_independence() {
    // BTreeMap should produce same result regardless of insertion order
    let files_order1 = vec![
        test_file("zebra", 1, 3),
        test_file("apple", 2, 3),
        test_file("mango", 3, 3),
    ];

    let files_order2 = vec![
        test_file("apple", 2, 3),
        test_file("mango", 3, 3),
        test_file("zebra", 1, 3),
    ];

    let mut ledger1 = FileLedger::new();
    ledger1.add_files_batch(files_order1).unwrap();

    let mut ledger2 = FileLedger::new();
    ledger2.add_files_batch(files_order2).unwrap();

    assert_eq!(
        ledger1.tree.root(),
        ledger2.tree.root(),
        "Different insertion orders should produce same root due to BTreeMap sorting"
    );
}

// ===========================================
// Large Scale Tests
// ===========================================

#[test]
fn test_batch_add_large_batch() {
    let mut ledger = FileLedger::new();

    // Add 100 files in a batch
    let files: Vec<_> = (0..100)
        .map(|i| test_file(&format!("file_{:03}", i), i as u64 * 100, 5))
        .collect();

    ledger
        .add_files_batch(files)
        .expect("Large batch should succeed");

    assert_eq!(ledger.files.len(), 100, "Should have 100 files");

    // Verify a few random entries
    assert!(ledger.files.contains_key("file_000"));
    assert!(ledger.files.contains_key("file_050"));
    assert!(ledger.files.contains_key("file_099"));

    // Verify ordering is correct (BTreeMap sorts lexicographically)
    let keys: Vec<_> = ledger.files.keys().collect();
    assert_eq!(keys[0], "file_000");
    assert_eq!(keys[99], "file_099");
}

// ===========================================
// Duplicate Handling Tests
// ===========================================

#[test]
fn test_batch_add_with_duplicates_in_batch() {
    let mut ledger = FileLedger::new();

    // Batch contains duplicate file_id - last one should win
    let files = vec![
        test_file("dup_file", 100, 3),
        test_file("other_file", 200, 4),
        test_file("dup_file", 999, 5), // Same file_id, different root/depth
    ];

    ledger.add_files_batch(files).unwrap();

    assert_eq!(ledger.files.len(), 2, "Should have 2 unique files");

    // The last duplicate should win
    let dup_entry = ledger.files.get("dup_file").unwrap();
    assert_eq!(
        dup_entry.root,
        FieldElement::from(999u64),
        "Last duplicate root should be used"
    );
    assert_eq!(dup_entry.depth, 5, "Last duplicate depth should be used");
}

#[test]
fn test_batch_add_overwrites_existing_files() {
    let mut ledger = FileLedger::new();

    // Add initial file
    ledger
        .add_file("existing".to_string(), FieldElement::from(100u64), 3)
        .unwrap();
    assert_eq!(
        ledger.files.get("existing").unwrap().root,
        FieldElement::from(100u64)
    );

    // Batch add with same file_id
    let files = vec![
        test_file("existing", 999, 5), // Overwrite
        test_file("new_file", 200, 4),
    ];
    ledger.add_files_batch(files).unwrap();

    assert_eq!(ledger.files.len(), 2, "Should have 2 files");
    assert_eq!(
        ledger.files.get("existing").unwrap().root,
        FieldElement::from(999u64),
        "Existing file should be overwritten"
    );
    assert_eq!(ledger.files.get("existing").unwrap().depth, 5);
}

// ===========================================
// Mixed Usage Tests
// ===========================================

#[test]
fn test_batch_add_after_individual_adds() {
    let mut ledger = FileLedger::new();

    // Add files individually first
    ledger
        .add_file("individual_1".to_string(), FieldElement::from(100u64), 3)
        .unwrap();
    ledger
        .add_file("individual_2".to_string(), FieldElement::from(200u64), 4)
        .unwrap();

    // Then batch add more files
    let batch_files = vec![test_file("batch_1", 300, 5), test_file("batch_2", 400, 3)];
    ledger.add_files_batch(batch_files).unwrap();

    assert_eq!(ledger.files.len(), 4, "Should have 4 files total");
    assert!(ledger.files.contains_key("individual_1"));
    assert!(ledger.files.contains_key("individual_2"));
    assert!(ledger.files.contains_key("batch_1"));
    assert!(ledger.files.contains_key("batch_2"));
}

#[test]
fn test_individual_add_after_batch_add() {
    let mut ledger = FileLedger::new();

    // Batch add first
    let files = vec![test_file("batch_1", 100, 3), test_file("batch_2", 200, 4)];
    ledger.add_files_batch(files).unwrap();

    // Then add individually
    ledger
        .add_file("individual_1".to_string(), FieldElement::from(300u64), 5)
        .unwrap();

    assert_eq!(ledger.files.len(), 3, "Should have 3 files total");
}

// ===========================================
// Lookup and Proof Tests
// ===========================================

#[test]
fn test_lookup_after_batch_add() {
    let mut ledger = FileLedger::new();

    let files = vec![
        test_file("apple", 100, 3),
        test_file("banana", 200, 4),
        test_file("cherry", 300, 5),
    ];
    ledger.add_files_batch(files).unwrap();

    // Test lookup for each file
    let (idx_apple, rc_apple) = ledger.lookup("apple").expect("apple should be found");
    let (idx_banana, rc_banana) = ledger.lookup("banana").expect("banana should be found");
    let (idx_cherry, rc_cherry) = ledger.lookup("cherry").expect("cherry should be found");

    // Indices should be in sorted order
    assert_eq!(
        idx_apple, 0,
        "apple should be at index 0 (alphabetically first)"
    );
    assert_eq!(idx_banana, 1, "banana should be at index 1");
    assert_eq!(idx_cherry, 2, "cherry should be at index 2");

    // RC values should be non-zero (computed correctly)
    assert_ne!(rc_apple, FieldElement::from(0u64));
    assert_ne!(rc_banana, FieldElement::from(0u64));
    assert_ne!(rc_cherry, FieldElement::from(0u64));

    // Each RC should be different
    assert_ne!(rc_apple, rc_banana);
    assert_ne!(rc_banana, rc_cherry);

    // Lookup for non-existent file should return None
    assert!(ledger.lookup("nonexistent").is_none());
}

#[test]
fn test_aggregation_proof_after_batch_add() {
    let mut ledger = FileLedger::new();

    let files = vec![
        test_file("file_1", 100, 3),
        test_file("file_2", 200, 4),
        test_file("file_3", 300, 5),
        test_file("file_4", 400, 3),
    ];
    ledger.add_files_batch(files).unwrap();

    // Get aggregation proof for each file
    for file_id in &["file_1", "file_2", "file_3", "file_4"] {
        let proof = ledger.get_aggregation_proof(file_id);
        assert!(
            proof.is_some(),
            "Should get aggregation proof for {}",
            file_id
        );

        let proof = proof.unwrap();
        // Verify proof has correct structure
        assert!(!proof.siblings.is_empty() || ledger.depth() == 0);
        assert_eq!(proof.siblings.len(), proof.path_indices.len());
    }

    // Non-existent file should return None
    assert!(ledger.get_aggregation_proof("nonexistent").is_none());
}

#[test]
fn test_canonical_index_for_rc_after_batch_add() {
    let mut ledger = FileLedger::new();

    let files = vec![
        test_file("alpha", 100, 3),
        test_file("beta", 200, 4),
        test_file("gamma", 300, 5),
    ];
    ledger.add_files_batch(files).unwrap();

    // Get rc values and verify canonical indices
    let rc_alpha = ledger.files.get("alpha").unwrap().rc;
    let rc_beta = ledger.files.get("beta").unwrap().rc;
    let rc_gamma = ledger.files.get("gamma").unwrap().rc;

    assert_eq!(ledger.get_canonical_index_for_rc(rc_alpha), Some(0));
    assert_eq!(ledger.get_canonical_index_for_rc(rc_beta), Some(1));
    assert_eq!(ledger.get_canonical_index_for_rc(rc_gamma), Some(2));

    // Unknown rc should return None
    assert_eq!(
        ledger.get_canonical_index_for_rc(FieldElement::from(999999u64)),
        None
    );
}

// ===========================================
// Tree Depth Tests
// ===========================================

#[test]
fn test_batch_add_tree_depth() {
    let mut ledger = FileLedger::new();

    // 1 file -> depth 0 (single leaf, padded to 1)
    ledger.add_files_batch(vec![test_file("f1", 1, 3)]).unwrap();
    assert_eq!(ledger.depth(), 0, "1 file should have depth 0");

    // 2 files -> depth 1 (padded to 2)
    ledger.add_files_batch(vec![test_file("f2", 2, 3)]).unwrap();
    assert_eq!(ledger.depth(), 1, "2 files should have depth 1");

    // 3-4 files -> depth 2 (padded to 4)
    ledger.add_files_batch(vec![test_file("f3", 3, 3)]).unwrap();
    assert_eq!(
        ledger.depth(),
        2,
        "3 files should have depth 2 (padded to 4)"
    );

    ledger.add_files_batch(vec![test_file("f4", 4, 3)]).unwrap();
    assert_eq!(ledger.depth(), 2, "4 files should have depth 2");

    // 5 files -> depth 3 (padded to 8)
    ledger.add_files_batch(vec![test_file("f5", 5, 3)]).unwrap();
    assert_eq!(
        ledger.depth(),
        3,
        "5 files should have depth 3 (padded to 8)"
    );
}

// ===========================================
// Iterator Flexibility Tests
// ===========================================

#[test]
fn test_batch_add_accepts_different_iterators() {
    // Test with Vec
    let mut ledger1 = FileLedger::new();
    let vec_files = vec![test_file("a", 1, 3), test_file("b", 2, 3)];
    ledger1.add_files_batch(vec_files).unwrap();

    // Test with slice via into_iter on a vec
    let mut ledger2 = FileLedger::new();
    let files = vec![test_file("a", 1, 3), test_file("b", 2, 3)];
    ledger2.add_files_batch(files).unwrap();

    // Test with iterator adapter (map)
    let mut ledger3 = FileLedger::new();
    let ids = ["a", "b"];
    let mapped_files = ids
        .iter()
        .enumerate()
        .map(|(i, id)| test_file(id, (i + 1) as u64, 3));
    ledger3.add_files_batch(mapped_files).unwrap();

    // All should produce the same result
    assert_eq!(ledger1.tree.root(), ledger2.tree.root());
    assert_eq!(ledger2.tree.root(), ledger3.tree.root());
}

// ===========================================
// Equivalence with Large Dataset
// ===========================================

#[test]
fn test_batch_vs_individual_large_dataset() {
    // Test that batch and individual adds produce identical results for a larger dataset
    let file_count = 50;

    let files: Vec<_> = (0..file_count)
        .map(|i| test_file(&format!("file_{:03}", i), (i * 17 + 42) as u64, (i % 5) + 1))
        .collect();

    // Individual adds
    let mut ledger_individual = FileLedger::new();
    for (file_id, root, depth) in files.clone() {
        ledger_individual.add_file(file_id, root, depth).unwrap();
    }

    // Batch add
    let mut ledger_batch = FileLedger::new();
    ledger_batch.add_files_batch(files).unwrap();

    // Verify identical results
    assert_eq!(
        ledger_individual.tree.root(),
        ledger_batch.tree.root(),
        "Roots must be identical for {} files",
        file_count
    );
    assert_eq!(ledger_individual.files.len(), ledger_batch.files.len());
    assert_eq!(ledger_individual.depth(), ledger_batch.depth());

    // Verify each file's lookup returns same values
    for i in 0..file_count {
        let file_id = format!("file_{:03}", i);
        let lookup_individual = ledger_individual.lookup(&file_id);
        let lookup_batch = ledger_batch.lookup(&file_id);
        assert_eq!(
            lookup_individual, lookup_batch,
            "Lookup should match for {}",
            file_id
        );
    }
}
