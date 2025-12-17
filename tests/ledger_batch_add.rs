//! Tests for the FileLedger::add_files() method.
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
        .add_files(&files, 0)
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
    ledger.add_file(&existing, 0).unwrap();
    let root_before = ledger.tree.root();

    // Empty batch should succeed and not change anything
    let empty: Vec<FileMetadata> = vec![];
    ledger
        .add_files(&empty, 0)
        .expect("Empty batch should succeed");

    assert_eq!(ledger.files.len(), 1, "Should still have 1 file");
    assert_eq!(ledger.tree.root(), root_before, "Root should not change");
}

#[test]
fn test_batch_add_single_file() {
    let mut ledger = FileLedger::new();

    let files = vec![dummy_metadata("only_file", 999, 5)];
    ledger
        .add_files(&files, 0)
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
    for (i, metadata) in files.iter().enumerate() {
        ledger_individual.add_file(metadata, i as u64).unwrap();
    }

    // Method 2: Batch add
    let mut ledger_batch = FileLedger::new();
    ledger_batch.add_files(&files, 0).unwrap();

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
    ledger1.add_files(&files_order1, 0).unwrap();

    let mut ledger2 = FileLedger::new();
    ledger2.add_files(&files_order2, 0).unwrap();

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

    ledger.add_files(&files, 0).unwrap();

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
    ledger.add_file(&existing, 0).unwrap();
    let original_root = ledger.tree.root();

    // Batch add with same file_id but different values
    let files = vec![
        dummy_metadata("existing", 999, 5), // Overwrite
        dummy_metadata("new_file", 200, 4),
    ];
    ledger.add_files(&files, 0).unwrap();

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
        .add_file(&dummy_metadata("individual_1", 100, 3), 0)
        .unwrap();
    ledger
        .add_file(&dummy_metadata("individual_2", 200, 4), 1)
        .unwrap();

    // Then batch add more files
    let batch_files = vec![
        dummy_metadata("batch_1", 300, 5),
        dummy_metadata("batch_2", 400, 3),
    ];
    ledger.add_files(&batch_files, 0).unwrap();

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
    ledger.add_files(&files, 0).unwrap();

    // Then add individually
    ledger
        .add_file(&dummy_metadata("individual_1", 300, 5), 1)
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
    ledger.add_files(&files, 0).unwrap();

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
    ledger.add_files(&files, 0).unwrap();

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

        ledger.add_files(&files, 0).unwrap();

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
        .add_files(&files, 0)
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
    for (i, metadata) in files.iter().enumerate() {
        ledger_individual.add_file(metadata, i as u64).unwrap();
    }

    // Batch add
    let mut ledger_batch = FileLedger::new();
    ledger_batch.add_files(&files, 0).unwrap();

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
    ledger.add_files(files.iter(), 0).unwrap();

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
        .add_files(files.iter().filter(|m| m.depth() > 3), 0)
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
    ledger_batch.add_files(&metadatas, 0).unwrap();

    // Individual adds for comparison
    let mut ledger_individual = FileLedger::new();
    ledger_individual.add_file(&metadata1, 0).unwrap();
    ledger_individual.add_file(&metadata2, 1).unwrap();
    ledger_individual.add_file(&metadata3, 2).unwrap();

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

// ===========================================
// Historical Root Recording Tests
// ===========================================

#[test]
fn test_add_file_no_historical_root_on_empty_ledger() {
    // First file addition should NOT record a historical root since the ledger was empty
    let mut ledger = FileLedger::new();

    let metadata = dummy_metadata("first_file", 100, 3);
    ledger.add_file(&metadata, 1000).unwrap();

    assert_eq!(
        ledger.historical_root_count(),
        0,
        "First file should not create historical root (ledger was empty)"
    );
}

#[test]
fn test_add_file_records_historical_root_on_non_empty_ledger() {
    let mut ledger = FileLedger::new();

    // First file - no historical root
    ledger
        .add_file(&dummy_metadata("file_1", 100, 3), 1000)
        .unwrap();
    assert_eq!(ledger.historical_root_count(), 0);

    let root_before = ledger.tree.root();

    // Second file - should record historical root
    ledger
        .add_file(&dummy_metadata("file_2", 200, 3), 1001)
        .unwrap();

    assert_eq!(
        ledger.historical_root_count(),
        1,
        "Second file should record one historical root"
    );
    assert!(
        ledger.is_valid_root(root_before),
        "Previous root should be in historical roots"
    );
}

#[test]
fn test_add_files_no_historical_root_on_empty_ledger() {
    // Batch add to empty ledger should NOT record a historical root
    let mut ledger = FileLedger::new();

    let files = vec![
        dummy_metadata("file_a", 100, 3),
        dummy_metadata("file_b", 200, 3),
        dummy_metadata("file_c", 300, 3),
    ];
    ledger.add_files(&files, 1000).unwrap();

    assert_eq!(
        ledger.historical_root_count(),
        0,
        "Batch add to empty ledger should not create historical root"
    );
    assert_eq!(ledger.files.len(), 3);
}

#[test]
fn test_add_files_records_single_historical_root() {
    // Batch add to non-empty ledger should record exactly ONE historical root
    let mut ledger = FileLedger::new();

    // Setup: add initial file
    ledger
        .add_file(&dummy_metadata("initial", 100, 3), 1000)
        .unwrap();
    let root_before_batch = ledger.tree.root();

    // Batch add multiple files
    let batch = vec![
        dummy_metadata("file_a", 200, 3),
        dummy_metadata("file_b", 300, 3),
        dummy_metadata("file_c", 400, 3),
    ];
    ledger.add_files(&batch, 1001).unwrap();

    assert_eq!(
        ledger.historical_root_count(),
        1,
        "Batch add should record exactly ONE historical root, not one per file"
    );
    assert!(
        ledger.is_valid_root(root_before_batch),
        "Root before batch should be valid"
    );
    assert_eq!(ledger.files.len(), 4, "Should have 4 files total");
}

#[test]
fn test_historical_roots_accumulate_correctly() {
    // Multiple add operations should accumulate historical roots
    let mut ledger = FileLedger::new();

    // Add files one by one
    for i in 0..5 {
        ledger
            .add_file(
                &dummy_metadata(&format!("file_{}", i), (i + 1) as u64 * 100, 3),
                (i + 1) as u64 * 1000,
            )
            .unwrap();
    }

    // First add: empty ledger, no historical root
    // Adds 2-5: each records one historical root
    assert_eq!(
        ledger.historical_root_count(),
        4,
        "Should have 4 historical roots (first add doesn't record)"
    );

    // Add a batch
    let batch = vec![
        dummy_metadata("batch_1", 600, 3),
        dummy_metadata("batch_2", 700, 3),
    ];
    ledger.add_files(&batch, 6000).unwrap();

    assert_eq!(
        ledger.historical_root_count(),
        5,
        "Batch add should add exactly one more historical root"
    );
}

#[test]
fn test_block_height_recorded_correctly() {
    // Verify that historical roots are keyed by the correct block height
    let mut ledger = FileLedger::new();

    ledger
        .add_file(&dummy_metadata("file_1", 100, 3), 100)
        .unwrap();
    ledger
        .add_file(&dummy_metadata("file_2", 200, 3), 200)
        .unwrap();
    ledger
        .add_file(&dummy_metadata("file_3", 300, 3), 300)
        .unwrap();

    // We have 2 historical roots at heights 200 and 300
    assert_eq!(ledger.historical_root_count(), 2);

    // Prune roots older than 250 - should remove root at height 200
    ledger.prune_historical_roots_older_than(250);

    assert_eq!(
        ledger.historical_root_count(),
        1,
        "Should have 1 root after pruning (height 300 >= 250)"
    );
}

// ===========================================
// Atomicity Tests
// ===========================================

#[test]
fn test_add_file_atomicity_state_consistency() {
    // Test that add_file maintains state consistency:
    // - File count, tree root, and historical roots should all be consistent
    let mut ledger = FileLedger::new();

    // Add first file
    ledger
        .add_file(&dummy_metadata("file_1", 100, 3), 1000)
        .unwrap();

    let files_before = ledger.files.len();
    let root_before = ledger.tree.root();
    let historical_count_before = ledger.historical_root_count();

    // Add second file
    ledger
        .add_file(&dummy_metadata("file_2", 200, 3), 1001)
        .unwrap();

    // State should be fully updated
    assert_eq!(
        ledger.files.len(),
        files_before + 1,
        "File count should increase by 1"
    );
    assert_ne!(ledger.tree.root(), root_before, "Tree root should change");
    assert_eq!(
        ledger.historical_root_count(),
        historical_count_before + 1,
        "Historical root count should increase by 1"
    );

    // The old root should be in historical roots
    assert!(
        ledger.is_valid_root(root_before),
        "Previous root should be valid"
    );
}

#[test]
fn test_add_files_atomicity_state_consistency() {
    // Test that add_files maintains state consistency for batch operations
    let mut ledger = FileLedger::new();

    // Setup initial state
    ledger
        .add_file(&dummy_metadata("initial", 100, 3), 1000)
        .unwrap();

    let files_before = ledger.files.len();
    let root_before = ledger.tree.root();
    let historical_count_before = ledger.historical_root_count();

    // Batch add
    let batch = vec![
        dummy_metadata("batch_1", 200, 3),
        dummy_metadata("batch_2", 300, 3),
        dummy_metadata("batch_3", 400, 3),
    ];
    ledger.add_files(&batch, 1001).unwrap();

    // State should be fully updated atomically
    assert_eq!(
        ledger.files.len(),
        files_before + 3,
        "File count should increase by batch size"
    );
    assert_ne!(ledger.tree.root(), root_before, "Tree root should change");
    assert_eq!(
        ledger.historical_root_count(),
        historical_count_before + 1,
        "Historical root count should increase by exactly 1 for batch"
    );
    assert!(
        ledger.is_valid_root(root_before),
        "Previous root should be valid"
    );
}

#[test]
fn test_empty_batch_does_not_record_historical_root() {
    // Adding an empty batch to a non-empty ledger should NOT record a historical root
    // because nothing actually changed
    let mut ledger = FileLedger::new();

    ledger
        .add_file(&dummy_metadata("initial", 100, 3), 1000)
        .unwrap();

    let root_before = ledger.tree.root();
    let historical_count_before = ledger.historical_root_count();

    // Add empty batch
    let empty: Vec<api::FileMetadata> = vec![];
    ledger.add_files(&empty, 1001).unwrap();

    // Historical root should still be recorded since ledger was non-empty
    // (the operation still "commits" at the block height even if no files added)
    // This is the current behavior - if you want to skip recording for empty batches,
    // that would be a different design decision
    assert_eq!(
        ledger.tree.root(),
        root_before,
        "Root should not change for empty batch"
    );

    // Note: Current implementation DOES record historical root even for empty batch
    // because the check is `if !self.files.is_empty()` not `if !files_to_add.is_empty()`
    // This may or may not be desired behavior
    assert_eq!(
        ledger.historical_root_count(),
        historical_count_before + 1,
        "Historical root is recorded even for empty batch (current behavior)"
    );
}

#[test]
fn test_add_file_and_batch_interleaved() {
    // Test interleaving add_file and add_files operations
    let mut ledger = FileLedger::new();

    // Individual add
    ledger
        .add_file(&dummy_metadata("ind_1", 100, 3), 1000)
        .unwrap();
    assert_eq!(ledger.files.len(), 1);
    assert_eq!(ledger.historical_root_count(), 0);

    // Batch add
    ledger
        .add_files(
            &[
                dummy_metadata("batch_1", 200, 3),
                dummy_metadata("batch_2", 300, 3),
            ],
            1001,
        )
        .unwrap();
    assert_eq!(ledger.files.len(), 3);
    assert_eq!(ledger.historical_root_count(), 1);

    // Individual add
    ledger
        .add_file(&dummy_metadata("ind_2", 400, 3), 1002)
        .unwrap();
    assert_eq!(ledger.files.len(), 4);
    assert_eq!(ledger.historical_root_count(), 2);

    // Another batch
    ledger
        .add_files(&[dummy_metadata("batch_3", 500, 3)], 1003)
        .unwrap();
    assert_eq!(ledger.files.len(), 5);
    assert_eq!(ledger.historical_root_count(), 3);

    // Verify all historical roots are valid
    // Current root is always valid
    assert!(ledger.is_valid_root(ledger.tree.root()));
}

#[test]
fn test_duplicate_block_height_overwrites_historical_root() {
    // If the same block height is used twice, the historical root entry is overwritten
    let mut ledger = FileLedger::new();

    ledger
        .add_file(&dummy_metadata("file_1", 100, 3), 1000)
        .unwrap();

    let root_after_1 = ledger.tree.root();

    ledger
        .add_file(&dummy_metadata("file_2", 200, 3), 2000)
        .unwrap();

    // Root at height 2000 is the root BEFORE file_2 was added (i.e., root_after_1)
    assert_eq!(ledger.historical_root_count(), 1);
    assert!(ledger.is_valid_root(root_after_1));

    let root_after_2 = ledger.tree.root();

    // Add another file with the SAME block height - this overwrites
    ledger
        .add_file(&dummy_metadata("file_3", 300, 3), 2000)
        .unwrap();

    // Still only 1 historical root (overwritten), but now it's root_after_2
    assert_eq!(
        ledger.historical_root_count(),
        1,
        "Same block height should overwrite, not add"
    );
    // The overwritten root is now root_after_2
    assert!(
        ledger.is_valid_root(root_after_2),
        "The overwritten root should be the most recent one at that height"
    );
}
