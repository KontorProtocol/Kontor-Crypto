//! Tests for the FileLedger::add_files_batch() method.
//!
//! These tests verify that batch adding files to a ledger produces identical
//! cryptographic results to individual adds, with the benefit of rebuilding
//! the Merkle tree only once.

use kontor_crypto::api::{self, FieldElement, FileMetadata};
use kontor_crypto::ledger::FileLedger;

/// Helper to create a dummy FileMetadata for testing.
/// The depth is derived from padded_len (2^depth).
fn dummy_metadata(file_id: &str, root_val: u64, depth: usize) -> FileMetadata {
    FileMetadata {
        root: FieldElement::from(root_val),
        file_id: file_id.to_string(),
        padded_len: 1 << depth, // 2^depth
        original_size: 100,
        filename: format!("{}.dat", file_id),
    }
}

// ===========================================
// Basic Functionality Tests
// ===========================================

#[test]
fn test_batch_add_basic() {
    let mut ledger = FileLedger::new();

    let files = vec![
        dummy_metadata("file_a", 100, 3),
        dummy_metadata("file_b", 200, 4),
        dummy_metadata("file_c", 300, 5),
    ];

    ledger
        .add_files_batch(&files)
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
    let existing = dummy_metadata("existing", 1, 3);
    ledger.add_file(&existing).unwrap();
    let root_before = ledger.tree.root();

    // Empty batch should succeed and not change anything
    let empty: Vec<FileMetadata> = vec![];
    ledger
        .add_files_batch(&empty)
        .expect("Empty batch should succeed");

    assert_eq!(ledger.files.len(), 1, "Should still have 1 file");
    assert_eq!(ledger.tree.root(), root_before, "Root should not change");
}

#[test]
fn test_batch_add_single_file() {
    let mut ledger = FileLedger::new();

    let files = vec![dummy_metadata("only_file", 999, 5)];
    ledger
        .add_files_batch(&files)
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
    let files = vec![
        dummy_metadata("alpha", 100, 3),
        dummy_metadata("beta", 200, 4),
        dummy_metadata("gamma", 300, 5),
        dummy_metadata("delta", 400, 3),
    ];

    // Method 1: Individual adds
    let mut ledger_individual = FileLedger::new();
    for metadata in &files {
        ledger_individual.add_file(metadata).unwrap();
    }

    // Method 2: Batch add
    let mut ledger_batch = FileLedger::new();
    ledger_batch.add_files_batch(&files).unwrap();

    // Both should produce identical cryptographic results
    assert_eq!(
        ledger_individual.tree.root(),
        ledger_batch.tree.root(),
        "Aggregated roots must be identical"
    );
    assert_eq!(
        ledger_individual.files.len(),
        ledger_batch.files.len(),
        "File counts must be identical"
    );

    // Verify all file entries match exactly
    for (key, entry_individual) in &ledger_individual.files {
        let entry_batch = ledger_batch
            .files
            .get(key)
            .expect("File should exist in batch ledger");
        assert_eq!(entry_individual.root, entry_batch.root);
        assert_eq!(entry_individual.depth, entry_batch.depth);
        assert_eq!(
            entry_individual.rc, entry_batch.rc,
            "Root commitments must match for {}",
            key
        );
    }
}

#[test]
fn test_batch_add_order_independence() {
    // BTreeMap ensures deterministic ordering regardless of insertion order
    let files_order1 = vec![
        dummy_metadata("zebra", 1, 3),
        dummy_metadata("apple", 2, 3),
        dummy_metadata("mango", 3, 3),
    ];

    let files_order2 = vec![
        dummy_metadata("apple", 2, 3),
        dummy_metadata("mango", 3, 3),
        dummy_metadata("zebra", 1, 3),
    ];

    let mut ledger1 = FileLedger::new();
    ledger1.add_files_batch(&files_order1).unwrap();

    let mut ledger2 = FileLedger::new();
    ledger2.add_files_batch(&files_order2).unwrap();

    assert_eq!(
        ledger1.tree.root(),
        ledger2.tree.root(),
        "Different insertion orders must produce identical root (BTreeMap sorts by key)"
    );

    // Verify canonical indices are the same
    assert_eq!(ledger1.lookup("apple").unwrap().0, 0);
    assert_eq!(ledger1.lookup("mango").unwrap().0, 1);
    assert_eq!(ledger1.lookup("zebra").unwrap().0, 2);
}

// ===========================================
// Duplicate Handling Tests
// ===========================================

#[test]
fn test_batch_add_with_duplicates_in_batch() {
    let mut ledger = FileLedger::new();

    // Batch contains duplicate file_id - last one should win
    let files = vec![
        dummy_metadata("dup_file", 100, 3),
        dummy_metadata("other_file", 200, 4),
        dummy_metadata("dup_file", 999, 5), // Same file_id, different values
    ];

    ledger.add_files_batch(&files).unwrap();

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
    let existing = dummy_metadata("existing", 100, 3);
    ledger.add_file(&existing).unwrap();
    let original_root = ledger.tree.root();

    // Batch add with same file_id but different values
    let files = vec![
        dummy_metadata("existing", 999, 5), // Overwrite
        dummy_metadata("new_file", 200, 4),
    ];
    ledger.add_files_batch(&files).unwrap();

    assert_eq!(ledger.files.len(), 2);
    assert_eq!(
        ledger.files.get("existing").unwrap().root,
        FieldElement::from(999u64),
        "Existing file should be overwritten"
    );
    assert_ne!(
        ledger.tree.root(),
        original_root,
        "Root should change after overwrite"
    );
}

// ===========================================
// Mixed Usage Tests
// ===========================================

#[test]
fn test_batch_add_after_individual_adds() {
    let mut ledger = FileLedger::new();

    // Add files individually first
    ledger
        .add_file(&dummy_metadata("individual_1", 100, 3))
        .unwrap();
    ledger
        .add_file(&dummy_metadata("individual_2", 200, 4))
        .unwrap();

    // Then batch add more files
    let batch_files = vec![
        dummy_metadata("batch_1", 300, 5),
        dummy_metadata("batch_2", 400, 3),
    ];
    ledger.add_files_batch(&batch_files).unwrap();

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
    let files = vec![
        dummy_metadata("batch_1", 100, 3),
        dummy_metadata("batch_2", 200, 4),
    ];
    ledger.add_files_batch(&files).unwrap();

    // Then add individually
    ledger
        .add_file(&dummy_metadata("individual_1", 300, 5))
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
        dummy_metadata("apple", 100, 3),
        dummy_metadata("banana", 200, 4),
        dummy_metadata("cherry", 300, 5),
    ];
    ledger.add_files_batch(&files).unwrap();

    // Indices should be in lexicographic order
    let (idx_apple, rc_apple) = ledger.lookup("apple").expect("apple should be found");
    let (idx_banana, rc_banana) = ledger.lookup("banana").expect("banana should be found");
    let (idx_cherry, rc_cherry) = ledger.lookup("cherry").expect("cherry should be found");

    assert_eq!(idx_apple, 0, "apple should be at index 0");
    assert_eq!(idx_banana, 1, "banana should be at index 1");
    assert_eq!(idx_cherry, 2, "cherry should be at index 2");

    // RC values should be distinct and non-zero
    assert_ne!(rc_apple, FieldElement::from(0u64));
    assert_ne!(rc_apple, rc_banana);
    assert_ne!(rc_banana, rc_cherry);

    // Non-existent file should return None
    assert!(ledger.lookup("nonexistent").is_none());
}

#[test]
fn test_aggregation_proof_after_batch_add() {
    let mut ledger = FileLedger::new();

    let files = vec![
        dummy_metadata("file_1", 100, 3),
        dummy_metadata("file_2", 200, 4),
        dummy_metadata("file_3", 300, 5),
        dummy_metadata("file_4", 400, 3),
    ];
    ledger.add_files_batch(&files).unwrap();

    // Get aggregation proof for each file
    for file_id in ["file_1", "file_2", "file_3", "file_4"] {
        let proof = ledger
            .get_aggregation_proof(file_id)
            .unwrap_or_else(|| panic!("Should get aggregation proof for {}", file_id));

        // Verify proof structure
        assert_eq!(proof.siblings.len(), proof.path_indices.len());

        // Verify leaf matches the file's rc
        let (_, rc) = ledger.lookup(file_id).unwrap();
        assert_eq!(proof.leaf, rc, "Proof leaf should equal file's rc");
    }

    // Non-existent file should return None
    assert!(ledger.get_aggregation_proof("nonexistent").is_none());
}

// ===========================================
// Tree Depth Tests
// ===========================================

#[test]
fn test_batch_add_tree_depth_progression() {
    // Test that tree depth grows correctly with file count
    let test_cases = [
        (1, 0), // 1 file -> depth 0
        (2, 1), // 2 files -> depth 1
        (3, 2), // 3 files -> depth 2 (padded to 4)
        (4, 2), // 4 files -> depth 2
        (5, 3), // 5 files -> depth 3 (padded to 8)
        (8, 3), // 8 files -> depth 3
        (9, 4), // 9 files -> depth 4 (padded to 16)
    ];

    for (file_count, expected_depth) in test_cases {
        let mut ledger = FileLedger::new();
        let files: Vec<_> = (0..file_count)
            .map(|i| dummy_metadata(&format!("file_{}", i), i as u64, 3))
            .collect();

        ledger.add_files_batch(&files).unwrap();

        assert_eq!(
            ledger.depth(),
            expected_depth,
            "{} files should produce depth {}",
            file_count,
            expected_depth
        );
    }
}

// ===========================================
// Large Scale Tests
// ===========================================

#[test]
fn test_batch_add_large_batch() {
    let mut ledger = FileLedger::new();

    // Add 100 files in a batch
    let files: Vec<_> = (0..100)
        .map(|i| dummy_metadata(&format!("file_{:03}", i), i as u64 * 100, 5))
        .collect();

    ledger
        .add_files_batch(&files)
        .expect("Large batch should succeed");

    assert_eq!(ledger.files.len(), 100);

    // Verify ordering (BTreeMap sorts lexicographically)
    let keys: Vec<_> = ledger.files.keys().collect();
    assert_eq!(*keys[0], "file_000");
    assert_eq!(*keys[50], "file_050");
    assert_eq!(*keys[99], "file_099");
}

#[test]
fn test_batch_vs_individual_large_dataset() {
    let file_count = 50;

    let files: Vec<_> = (0..file_count)
        .map(|i| dummy_metadata(&format!("file_{:03}", i), (i * 17 + 42) as u64, (i % 5) + 1))
        .collect();

    // Individual adds
    let mut ledger_individual = FileLedger::new();
    for metadata in &files {
        ledger_individual.add_file(metadata).unwrap();
    }

    // Batch add
    let mut ledger_batch = FileLedger::new();
    ledger_batch.add_files_batch(&files).unwrap();

    // Verify identical results
    assert_eq!(ledger_individual.tree.root(), ledger_batch.tree.root());
    assert_eq!(ledger_individual.files.len(), ledger_batch.files.len());
    assert_eq!(ledger_individual.depth(), ledger_batch.depth());

    // Verify each file's lookup returns same values
    for i in 0..file_count {
        let file_id = format!("file_{:03}", i);
        assert_eq!(
            ledger_individual.lookup(&file_id),
            ledger_batch.lookup(&file_id)
        );
    }
}

// ===========================================
// Iterator Flexibility Tests
// ===========================================

#[test]
fn test_batch_add_with_iter() {
    #[allow(clippy::useless_vec)]
    let files = vec![
        dummy_metadata("a", 1, 3),
        dummy_metadata("b", 2, 3),
        dummy_metadata("c", 3, 3),
    ];

    // Using .iter() explicitly
    let mut ledger = FileLedger::new();
    ledger.add_files_batch(files.iter()).unwrap();

    assert_eq!(ledger.files.len(), 3);
}

#[test]
fn test_batch_add_with_filter() {
    #[allow(clippy::useless_vec)]
    let files = vec![
        dummy_metadata("small_1", 1, 2),
        dummy_metadata("large_1", 2, 5),
        dummy_metadata("small_2", 3, 2),
        dummy_metadata("large_2", 4, 6),
    ];

    // Filter to only add files with depth > 3
    let mut ledger = FileLedger::new();
    ledger
        .add_files_batch(files.iter().filter(|m| m.depth() > 3))
        .unwrap();

    assert_eq!(ledger.files.len(), 2);
    assert!(ledger.files.contains_key("large_1"));
    assert!(ledger.files.contains_key("large_2"));
    assert!(!ledger.files.contains_key("small_1"));
}

// ===========================================
// Real File Tests (using prepare_file)
// ===========================================

#[test]
fn test_batch_add_with_real_files() {
    // Prepare real files using the API
    let data1 = vec![1u8; 100];
    let data2 = vec![2u8; 150];
    let data3 = vec![3u8; 200];

    let (_, metadata1) = api::prepare_file(&data1, "file1.dat").unwrap();
    let (_, metadata2) = api::prepare_file(&data2, "file2.dat").unwrap();
    let (_, metadata3) = api::prepare_file(&data3, "file3.dat").unwrap();

    let metadatas = vec![metadata1.clone(), metadata2.clone(), metadata3.clone()];

    // Batch add
    let mut ledger_batch = FileLedger::new();
    ledger_batch.add_files_batch(&metadatas).unwrap();

    // Individual adds for comparison
    let mut ledger_individual = FileLedger::new();
    ledger_individual.add_file(&metadata1).unwrap();
    ledger_individual.add_file(&metadata2).unwrap();
    ledger_individual.add_file(&metadata3).unwrap();

    // Must produce identical results
    assert_eq!(ledger_batch.tree.root(), ledger_individual.tree.root());
    assert_eq!(ledger_batch.files.len(), 3);

    // Verify each file is correctly stored
    for metadata in &metadatas {
        let entry = ledger_batch.files.get(&metadata.file_id).unwrap();
        assert_eq!(entry.root, metadata.root);
        assert_eq!(entry.depth, metadata.depth());
    }
}
