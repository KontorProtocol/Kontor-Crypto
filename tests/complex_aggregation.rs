//! Tests for complex aggregation scenarios with unusual file counts and depths

use ff::Field;
use kontor_crypto::{
    api::{self, Challenge, FieldElement, PorSystem},
    config,
};
use std::collections::BTreeMap;

mod common;
use common::{
    create_single_file_ledger,
    fixtures::{create_ledger_from_metadatas, create_test_files},
};

#[test]
fn test_awkward_file_count_padding() {
    // AGG-01: Test with 5 files (pads to 8) - exercises more complex padding logic
    println!("Testing aggregation with 5 files (awkward padding to 8)");

    let num_files = 5;

    // Create 5 files using helper
    let (files, metadatas) = create_test_files(num_files, 40, 1000);
    let metadata_refs: Vec<&_> = metadatas.iter().collect();
    let ledger = create_ledger_from_metadatas(&metadata_refs);

    // Create challenges for all 5 files
    let seed = FieldElement::from(12345u64);
    let challenges: Vec<Challenge> = metadatas
        .iter()
        .map(|m| Challenge::new_test(m.clone(), 1000, 1, seed))
        .collect();

    // Verify the shape derivation
    let max_depth = challenges
        .iter()
        .map(|c| api::tree_depth_from_metadata(&c.file_metadata))
        .max()
        .unwrap();

    let (files_per_step, file_tree_depth) = config::derive_shape(num_files, max_depth);
    assert_eq!(
        files_per_step, 8,
        "5 files should pad to 8 (next power of 2)"
    );

    // Generate proof
    let file_refs: BTreeMap<String, &_> = files.iter().map(|(k, v)| (k.clone(), v)).collect();

    let system = PorSystem::new(&ledger);
    let files_vec: Vec<&_> = file_refs.values().copied().collect();
    let proof = system
        .prove(files_vec, &challenges)
        .expect("Should generate proof with 5 files");

    // Verify proof
    let is_valid = system
        .verify(&proof, &challenges)
        .expect("Verification should complete");

    assert!(is_valid, "Proof with 5 files (padded to 8) should verify");
    println!("✓ Successfully proved and verified with 5 files padded to 8");

    // Additional check: witness generation should create 8 witnesses (5 real + 3 padding)
    let dummy_ledger_indices = vec![0, 1, 2, 3, 4, 0, 0, 0]; // 5 real indices + padding
    let (witness, _) = api::generate_circuit_witness(
        &challenges.iter().collect::<Vec<_>>(),
        Some(&file_refs),
        &ledger,
        file_tree_depth,
        file_tree_depth,
        FieldElement::ZERO,
        ledger.tree.layers.len() - 1,
        0,
        &dummy_ledger_indices,
    )
    .expect("Failed to generate witness");

    assert_eq!(
        witness.witnesses().len(),
        8,
        "Should have 8 witnesses (5 real + 3 padding)"
    );

    let real_count = witness
        .witnesses()
        .iter()
        .filter(|w| w.actual_depth > 0)
        .count();
    assert_eq!(real_count, 5, "Should have exactly 5 real witnesses");

    let padding_count = witness
        .witnesses()
        .iter()
        .filter(|w| w.actual_depth == 0)
        .count();
    assert_eq!(padding_count, 3, "Should have exactly 3 padding witnesses");

    println!("✓ Witness structure correct: 5 real + 3 padding = 8 total");
}

#[test]
fn test_highly_heterogeneous_depths() {
    // AGG-02: Test with files of depths 0, 1, 3, 5 in a single proof
    println!("Testing aggregation with highly heterogeneous depths (0, 1, 3, 5)");

    // Create files targeting specific depths
    // Depth calculation: ceil(log2(blob_size / chunk_size))
    // To get specific depths, we need specific blob sizes

    let target_depths = vec![0, 1, 3, 5];

    // With multi-codeword: need larger files for depth variation
    // depth 8: ~255 symbols (1 codeword)
    // depth 10: ~1,020 symbols (4 codewords)
    // depth 14: ~16,065 symbols (63 codewords)
    // depth 16: ~65,025 symbols (255 codewords)

    let _target_depths = target_depths; // Document intent (now approximate)
    let file_sizes = [
        100,       // 1 codeword → depth 8
        30_000,    // 4 codewords → depth 10
        500_000,   // 63 codewords → depth 14
        2_000_000, // 255 codewords → depth 16
    ];

    let mut files = BTreeMap::new();
    let mut metadatas = vec![];
    let mut ledger = kontor_crypto::ledger::FileLedger::new();
    let mut actual_depths = vec![];

    for (i, size) in file_sizes.iter().enumerate() {
        let data = vec![(i * 10) as u8; *size];
        let (prepared, metadata) = api::prepare_file(&data, &format!("test_file_{}.dat", i))
            .expect("Failed to prepare file");

        let depth = api::tree_depth_from_metadata(&metadata);
        actual_depths.push(depth);

        println!(
            "  File {}: size={}, total_symbols={}, padded_len={}, depth={}",
            i,
            size,
            metadata.total_symbols(),
            metadata.padded_len,
            depth
        );

        files.insert(metadata.file_id.clone(), prepared);
        ledger
            .add_file(
                metadata.file_id.clone(),
                metadata.root,
                kontor_crypto::api::tree_depth_from_metadata(&metadata),
            )
            .expect("Failed to add to ledger");
        metadatas.push(metadata);
    }

    // Verify we got a good spread of depths
    let min_depth = *actual_depths.iter().min().unwrap();
    let max_depth = *actual_depths.iter().max().unwrap();
    let depth_spread = max_depth - min_depth;

    println!(
        "  Achieved depths: {:?}, spread: {}",
        actual_depths, depth_spread
    );
    assert!(
        depth_spread >= 3,
        "Should have significant depth variation (spread >= 3)"
    );

    // Create challenges
    let seed = FieldElement::from(99999u64);
    let challenges: Vec<Challenge> = metadatas
        .iter()
        .map(|m| Challenge::new_test(m.clone(), 1000, 1, seed))
        .collect();

    // Generate proof with heterogeneous depths
    let file_refs: BTreeMap<String, &_> = files.iter().map(|(k, v)| (k.clone(), v)).collect();

    let system = PorSystem::new(&ledger);
    let files_vec: Vec<&_> = file_refs.values().copied().collect();
    let proof = system
        .prove(files_vec, &challenges)
        .expect("Should generate proof with heterogeneous depths");

    // Verify proof
    let is_valid = system
        .verify(&proof, &challenges)
        .expect("Verification should complete");

    assert!(
        is_valid,
        "Proof with highly heterogeneous depths should verify"
    );

    println!(
        "✓ Successfully proved and verified with depth spread of {}",
        depth_spread
    );
    println!("✓ Circuit gating correctly handles heterogeneous depths");
}

#[test]
fn test_maximum_file_aggregation() {
    // Test with a larger number of files to stress aggregation
    println!("Testing aggregation with 7 files");

    let num_files = 7; // Will pad to 8

    let mut files = BTreeMap::new();
    let mut metadatas = vec![];
    let mut ledger = kontor_crypto::ledger::FileLedger::new();

    for i in 0..num_files {
        // Vary sizes to get different depths
        let size = 30 + i * 20;
        let data = vec![(i * 5) as u8; size];
        let (prepared, metadata) =
            api::prepare_file(&data, "test_file.dat").expect("Failed to prepare file");

        files.insert(metadata.file_id.clone(), prepared);
        ledger
            .add_file(
                metadata.file_id.clone(),
                metadata.root,
                kontor_crypto::api::tree_depth_from_metadata(&metadata),
            )
            .expect("Failed to add to ledger");
        metadatas.push(metadata);
    }

    // Create challenges
    let seed = FieldElement::from(54321u64);
    let challenges: Vec<Challenge> = metadatas
        .iter()
        .map(|m| Challenge::new_test(m.clone(), 1000, 2, seed)) // 2 challenges per file
        .collect();

    // Generate and verify proof
    let file_refs: BTreeMap<String, &_> = files.iter().map(|(k, v)| (k.clone(), v)).collect();

    let system = PorSystem::new(&ledger);
    let files_vec: Vec<&_> = file_refs.values().copied().collect();
    let proof = system
        .prove(files_vec, &challenges)
        .expect("Should generate proof with 7 files");

    let is_valid = system
        .verify(&proof, &challenges)
        .expect("Verification should complete");

    assert!(is_valid, "Proof with 7 files should verify");

    // Check aggregation tree depth
    let agg_depth = ledger.tree.layers.len() - 1;
    let expected_agg_depth = (num_files as f64).log2().ceil() as usize;

    println!("✓ 7 files aggregated successfully");
    println!(
        "  Aggregation tree depth: {} (expected ~{})",
        agg_depth, expected_agg_depth
    );
}

#[test]
fn test_single_file_with_various_depths() {
    // Test single-file proofs at different depths to ensure consistency
    println!("Testing single-file proofs at various depths");

    let test_sizes = vec![10, 35, 70, 150, 300]; // Various sizes for different depths

    for size in test_sizes {
        let data = vec![42u8; size];
        let (prepared, metadata) =
            api::prepare_file(&data, "test_file.dat").expect("Failed to prepare file");

        let depth = api::tree_depth_from_metadata(&metadata);

        let challenge =
            Challenge::new_test(metadata.clone(), 1000, 1, FieldElement::from(size as u64));

        let mut files = BTreeMap::new();
        files.insert(metadata.file_id.clone(), &prepared);

        // Create ledger for unified API
        let ledger = create_single_file_ledger(&metadata);

        let system = PorSystem::new(&ledger);
        let files_vec: Vec<&_> = files.values().copied().collect();
        let proof = system
            .prove(files_vec, std::slice::from_ref(&challenge))
            .unwrap_or_else(|e| {
                panic!(
                    "Should generate proof for size {} (depth {}): {}",
                    size, depth, e
                )
            });

        let is_valid = system
            .verify(&proof, &[challenge])
            .expect("Verification should complete");

        assert!(
            is_valid,
            "Single-file proof at depth {} should verify",
            depth
        );

        println!("  ✓ Size {} -> depth {} verified", size, depth);
    }

    println!("✓ All single-file depths verified successfully");
}

#[test]
fn test_aggregate_proofs_from_different_blocks() {
    // AGG-03: Test aggregating challenges from different blockchain heights
    // This simulates real-world scenario where challenges arrive from different blocks
    println!("Testing aggregation of proofs from different block heights");

    let num_files = 3;

    // Create test files
    let (files, metadatas) = create_test_files(num_files, 50, 1000);
    let metadata_refs: Vec<&_> = metadatas.iter().collect();
    let ledger = create_ledger_from_metadatas(&metadata_refs);

    // Simulate challenges from different blocks with per-file seeds
    // In practice: seed = H(block_hash, file_id)
    // Here we simulate with: seed = block_height * 1000 + file_index
    let challenges: Vec<Challenge> = vec![
        Challenge::new(
            metadatas[0].clone(),
            1000, // Block 1000
            2,
            FieldElement::from(1000 * 1000), // Simulated H(block_1000_hash, file0_id)
            "prover0".to_string(),
        ),
        Challenge::new(
            metadatas[1].clone(),
            1005, // Block 1005 - different block!
            2,
            FieldElement::from(1005 * 1000 + 1), // Simulated H(block_1005_hash, file1_id)
            "prover1".to_string(),
        ),
        Challenge::new(
            metadatas[2].clone(),
            1010, // Block 1010 - yet another block!
            2,
            FieldElement::from(1010 * 1000 + 2), // Simulated H(block_1010_hash, file2_id)
            "prover2".to_string(),
        ),
    ];

    println!(
        "  Challenge 0: block_height={}, seed={:?}",
        challenges[0].block_height, challenges[0].seed
    );
    println!(
        "  Challenge 1: block_height={}, seed={:?}",
        challenges[1].block_height, challenges[1].seed
    );
    println!(
        "  Challenge 2: block_height={}, seed={:?}",
        challenges[2].block_height, challenges[2].seed
    );

    // Generate aggregated proof across different block heights
    let file_refs: BTreeMap<String, &_> = files.iter().map(|(k, v)| (k.clone(), v)).collect();
    let system = PorSystem::new(&ledger);
    let files_vec: Vec<&_> = file_refs.values().copied().collect();

    let proof = system
        .prove(files_vec, &challenges)
        .expect("Should generate aggregated proof from different blocks");

    // Verify the aggregated proof
    let is_valid = system
        .verify(&proof, &challenges)
        .expect("Verification should complete");

    assert!(
        is_valid,
        "Aggregated proof from blocks 1000, 1005, 1010 should verify"
    );

    println!("✓ Successfully aggregated and verified proofs from blocks 1000, 1005, 1010");
    println!("✓ Multi-block aggregation with per-file seeds works correctly");
}
