//! Low-level Merkle tree primitive tests.
//!
//! These tests verify the core Merkle tree functionality independent
//! of the higher-level proof system.

use ff::Field;
use kontor_crypto::merkle::F;
use kontor_crypto::merkle::{
    build_tree, get_leaf_hash, get_padded_proof_for_leaf, hash_node, poseidon_hash_pair,
    verify_merkle_proof_in_place,
};

#[test]
fn test_poseidon_hash_pair_basic() {
    // Test basic hash functionality
    let a = F::from(123u64);
    let b = F::from(456u64);
    let hash1 = poseidon_hash_pair(a, b);
    let hash2 = poseidon_hash_pair(a, b);

    // Same inputs should produce same hash
    assert_eq!(hash1, hash2);

    // Different inputs should produce different hash
    let c = F::from(789u64);
    let hash3 = poseidon_hash_pair(a, c);
    assert_ne!(hash1, hash3);

    // Order matters
    let hash4 = poseidon_hash_pair(b, a);
    assert_ne!(hash1, hash4);
}

#[test]
fn test_poseidon_hash_pair_edge_cases() {
    // Test with zero values
    let zero = F::ZERO;
    let one = F::ONE;

    let hash_zero_zero = poseidon_hash_pair(zero, zero);
    let hash_zero_one = poseidon_hash_pair(zero, one);
    let hash_one_zero = poseidon_hash_pair(one, zero);

    // All should be different
    assert_ne!(hash_zero_zero, hash_zero_one);
    assert_ne!(hash_zero_zero, hash_one_zero);
    assert_ne!(hash_zero_one, hash_one_zero);
}

#[test]
fn test_get_leaf_hash_basic() {
    // Test leaf hash from different byte arrays
    let data1 = vec![1u8, 2, 3, 4];
    let data2 = vec![1u8, 2, 3, 4]; // same data
    let data3 = vec![1u8, 2, 3, 5]; // different data

    let hash1 = get_leaf_hash(&data1).unwrap();
    let hash2 = get_leaf_hash(&data2).unwrap();
    let hash3 = get_leaf_hash(&data3).unwrap();

    assert_eq!(hash1, hash2, "Same data should produce same hash");
    assert_ne!(hash1, hash3, "Different data should produce different hash");
}

#[test]
fn test_get_leaf_hash_edge_cases() {
    // Empty data
    let empty = vec![];
    let hash_empty = get_leaf_hash(&empty).unwrap();
    assert_eq!(hash_empty, F::ZERO, "Empty data should hash to zero");

    // Single byte
    let single = vec![42u8];
    let hash_single = get_leaf_hash(&single).unwrap();
    assert_ne!(hash_single, F::ZERO, "Single byte should not hash to zero");

    // Exactly 31 bytes (maximum allowed - at boundary)
    let data_31 = vec![1u8; 31];
    let hash_31 = get_leaf_hash(&data_31).unwrap();
    assert_ne!(hash_31, F::ZERO);

    // 32 bytes should FAIL (security enforcement - over the 31-byte limit)
    let data_32 = vec![1u8; 32];
    let result_32 = get_leaf_hash(&data_32);
    assert!(
        result_32.is_err(),
        "Data over 31 bytes should be rejected for PoR security"
    );
    assert!(result_32
        .unwrap_err()
        .to_string()
        .contains("Data chunk too large"));

    // Large data should also FAIL (security enforcement)
    let data_large = vec![2u8; 100];
    let result_large = get_leaf_hash(&data_large);
    assert!(
        result_large.is_err(),
        "Large data should be rejected for PoR security"
    );
}

#[test]
fn test_build_tree_single_leaf() {
    let data = vec![vec![1u8, 2, 3, 4]];
    let (tree, root) = build_tree(&data).expect("Failed to build tree for test");

    assert_eq!(tree.layers.len(), 1, "Single leaf tree should have 1 layer");
    assert_eq!(tree.layers[0].len(), 1, "Layer should have 1 element");
    assert_eq!(tree.root(), root, "Tree root should match returned root");

    let leaf_hash = get_leaf_hash(&data[0]).unwrap();
    assert_eq!(tree.layers[0][0], leaf_hash, "Leaf should be hash of data");
    assert_eq!(root, leaf_hash, "Root should equal leaf for single element");
}

#[test]
fn test_build_tree_two_leaves() {
    let data = vec![vec![1u8, 2, 3, 4], vec![5u8, 6, 7, 8]];
    let (tree, root) = build_tree(&data).expect("Failed to build tree for test");

    assert_eq!(tree.layers.len(), 2, "Two leaf tree should have 2 layers");
    assert_eq!(tree.layers[0].len(), 2, "First layer should have 2 leaves");
    assert_eq!(tree.layers[1].len(), 1, "Second layer should have 1 root");

    let leaf0 = get_leaf_hash(&data[0]).unwrap();
    let leaf1 = get_leaf_hash(&data[1]).unwrap();
    assert_eq!(tree.layers[0][0], leaf0);
    assert_eq!(tree.layers[0][1], leaf1);

    let expected_root = hash_node(leaf0, leaf1);
    assert_eq!(root, expected_root, "Root should be hash of two leaves");
}

#[test]
fn test_build_tree_power_of_two() {
    for size in [1, 2, 4, 8, 16].iter() {
        let data: Vec<Vec<u8>> = (0..*size).map(|i| vec![i as u8]).collect();

        let (tree, _root) = build_tree(&data).expect("Failed to build tree for test");

        // Calculate expected depth
        let expected_depth = if *size == 1 {
            1
        } else {
            (*size as f64).log2() as usize + 1
        };

        assert_eq!(
            tree.layers.len(),
            expected_depth,
            "Tree with {} leaves should have depth {}",
            size,
            expected_depth
        );
    }
}

#[test]
fn test_merkle_proof_single_leaf() {
    let data = vec![vec![1u8, 2, 3, 4]];
    let (tree, _root) = build_tree(&data).expect("Failed to build tree for test");

    let proof = get_padded_proof_for_leaf(&tree, 0, 0).expect("Failed to get proof for test");

    assert_eq!(
        proof.siblings.len(),
        0,
        "Single leaf should have no siblings"
    );
    assert_eq!(
        proof.path_indices.len(),
        0,
        "Single leaf should have no path indices"
    );
    assert_eq!(
        proof.leaf, tree.layers[0][0],
        "Proof leaf should match tree leaf"
    );
}

#[test]
fn test_merkle_proof_verification() {
    let data = vec![vec![1u8], vec![2u8], vec![3u8], vec![4u8]];
    let (tree, root) = build_tree(&data).expect("Failed to build tree for test");
    let tree_depth = 2; // 4 leaves -> depth 2

    // Test proof for each leaf
    for leaf_index in 0..4 {
        let proof = get_padded_proof_for_leaf(&tree, leaf_index, tree_depth)
            .expect("Failed to get proof for test");

        // Verify the proof manually
        let mut current = proof.leaf;
        for i in 0..tree_depth {
            let sibling = proof.siblings[i];
            let path_bit = proof.path_indices[i];

            current = if !path_bit {
                hash_node(current, sibling)
            } else {
                hash_node(sibling, current)
            };
        }

        assert_eq!(
            current, root,
            "Merkle proof verification failed for leaf {}",
            leaf_index
        );
    }
}

#[test]
fn test_merkle_proof_path_indices() {
    let data = vec![vec![1u8], vec![2u8], vec![3u8], vec![4u8]];
    let (tree, _root) = build_tree(&data).expect("Failed to build tree for test");
    let tree_depth = 2;

    // Leaf 0: path should be [false, false] (left, left)
    let proof0 =
        get_padded_proof_for_leaf(&tree, 0, tree_depth).expect("Failed to get proof for test");
    assert!(!proof0.path_indices[0]);
    assert!(!proof0.path_indices[1]);

    // Leaf 1: path should be [true, false] (right, left)
    let proof1 =
        get_padded_proof_for_leaf(&tree, 1, tree_depth).expect("Failed to get proof for test");
    assert!(proof1.path_indices[0]);
    assert!(!proof1.path_indices[1]);

    // Leaf 2: path should be [false, true] (left, right)
    let proof2 =
        get_padded_proof_for_leaf(&tree, 2, tree_depth).expect("Failed to get proof for test");
    assert!(!proof2.path_indices[0]);
    assert!(proof2.path_indices[1]);

    // Leaf 3: path should be [true, true] (right, right)
    let proof3 =
        get_padded_proof_for_leaf(&tree, 3, tree_depth).expect("Failed to get proof for test");
    assert!(proof3.path_indices[0]);
    assert!(proof3.path_indices[1]);
}

#[test]
fn test_path_direction_docstring_correctness() {
    // This test specifically verifies that the docstring for path_indices is correct.
    // It ensures that:
    // - `true` means the current node is on the right (so sibling is on the left)
    // - `false` means the current node is on the left (so sibling is on the right)

    let data = vec![vec![1u8], vec![2u8]]; // Simple 2-leaf tree
    let (tree, root) = build_tree(&data).expect("Failed to build tree for test");
    let tree_depth = 1; // 2 leaves -> depth 1

    // For a 2-leaf tree:
    //    root
    //   /    \
    //  l0    l1
    //
    // When we get proof for leaf 0 (left node):
    let proof0 = get_padded_proof_for_leaf(&tree, 0, tree_depth).expect("Should get proof");
    assert!(
        !proof0.path_indices[0],
        "Leaf 0 is on the left, so path_indices[0] should be false"
    );

    // When we get proof for leaf 1 (right node):
    let proof1 = get_padded_proof_for_leaf(&tree, 1, tree_depth).expect("Should get proof");
    assert!(
        proof1.path_indices[0],
        "Leaf 1 is on the right, so path_indices[0] should be true"
    );

    // Now verify that the verification logic interprets these correctly:
    // For leaf 0: path_indices[0] = false (current is left, sibling is right)
    // So we should hash: hash_node(current, sibling) = hash_node(leaf0, leaf1)
    let mut current0 = proof0.leaf;
    let sibling0 = proof0.siblings[0];
    let path_bit0 = proof0.path_indices[0];

    if path_bit0 {
        // According to docstring: current node is right, sibling is left
        current0 = hash_node(sibling0, current0);
    } else {
        // According to docstring: current node is left, sibling is right
        current0 = hash_node(current0, sibling0);
    }

    assert_eq!(
        current0, root,
        "Path direction interpretation should lead to correct root for left leaf"
    );

    // For leaf 1: path_indices[0] = true (current is right, sibling is left)
    // So we should hash: hash_node(sibling, current) = hash_node(leaf0, leaf1)
    let mut current1 = proof1.leaf;
    let sibling1 = proof1.siblings[0];
    let path_bit1 = proof1.path_indices[0];

    if path_bit1 {
        // According to docstring: current node is right, sibling is left
        current1 = hash_node(sibling1, current1);
    } else {
        // According to docstring: current node is left, sibling is right
        current1 = hash_node(current1, sibling1);
    }

    assert_eq!(
        current1, root,
        "Path direction interpretation should lead to correct root for right leaf"
    );

    // Most importantly: both should produce the same result as they represent the same root
    assert_eq!(
        current0, current1,
        "Both paths should lead to the same root"
    );
}

#[test]
fn test_empty_tree() {
    let data: Vec<Vec<u8>> = vec![];
    let (tree, root) = build_tree(&data).expect("Failed to build tree for test");

    assert_eq!(tree.layers.len(), 1, "Empty tree should have 1 layer");
    assert_eq!(tree.layers[0].len(), 1, "Empty tree should have 1 element");
    assert_eq!(root, F::ZERO, "Empty tree root should be zero");
}

#[test]
fn test_deterministic_hashing() {
    // Ensure hashing is deterministic across runs
    let data = vec![
        vec![1u8, 2, 3],
        vec![4u8, 5, 6],
        vec![7u8, 8, 9],
        vec![10u8, 11, 12],
    ];

    let (tree1, root1) = build_tree(&data).expect("Failed to build tree for test");
    let (tree2, root2) = build_tree(&data).expect("Failed to build tree for test");

    assert_eq!(root1, root2, "Same data should produce same root");
    assert_eq!(
        tree1.layers, tree2.layers,
        "Same data should produce same tree structure"
    );
}

#[test]
fn test_leaf_hash_handles_field_overflow() {
    // This test verifies that get_leaf_hash correctly handles input data that,
    // when interpreted as a number, exceeds the field modulus. The critical
    // property is that the behavior is DETERMINISTIC, not that it maps to any
    // specific value.

    // The modulus of the Pallas scalar field (from the 'ff' crate documentation)
    // r = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
    let modulus_bytes: [u8; 32] = [
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x22, 0x46, 0x98, 0xfc, 0x09, 0x4c, 0xf9, 0x1b, 0x99, 0x2d, 0x30, 0xed, 0x00, 0x00,
        0x00, 0x01,
    ];

    // Test 1: Verify deterministic behavior for values at/near the modulus
    // We pass this as a 31-byte chunk to get_leaf_hash, which internally pads it to 32 bytes.
    let hash_modulus_1 = get_leaf_hash(&modulus_bytes[1..]).unwrap();
    let hash_modulus_2 = get_leaf_hash(&modulus_bytes[1..]).unwrap();
    assert_eq!(
        hash_modulus_1, hash_modulus_2,
        "Hashing the same overflow value should be deterministic"
    );

    // Test 2: Values larger than the modulus should also be handled deterministically
    let mut larger_than_modulus = modulus_bytes;
    larger_than_modulus[31] = 0xFF; // Make it larger than the modulus
    let hash_large_1 = get_leaf_hash(&larger_than_modulus[1..]).unwrap();
    let hash_large_2 = get_leaf_hash(&larger_than_modulus[1..]).unwrap();
    assert_eq!(
        hash_large_1, hash_large_2,
        "Hashing values larger than modulus should be deterministic"
    );

    // Test 3: Different overflow values should produce different hashes
    // This confirms that the reduction is not simply mapping all overflow values to the same result
    assert_ne!(
        hash_modulus_1, hash_large_1,
        "Different overflow values should produce different hashes"
    );

    println!("✓ Leaf hash correctly handles field overflow condition deterministically");
}

#[test]
fn test_build_tree_three_leaves_and_verify() {
    // Verify correct tree construction for an odd number of leaves
    println!("Testing tree construction with 3 leaves");

    let data = vec![vec![1u8], vec![2u8], vec![3u8]];

    let (tree, root) = build_tree(&data).expect("Failed to build tree");

    // Get leaf hashes
    let leaf0 = get_leaf_hash(&data[0]).unwrap();
    let leaf1 = get_leaf_hash(&data[1]).unwrap();
    let leaf2 = get_leaf_hash(&data[2]).unwrap();

    // With 3 leaves, the tree may handle padding differently
    // Let's check what the actual structure is
    let num_layers = tree.layers.len();
    let num_leaves = tree.layers[0].len();

    println!(
        "Tree structure: {} layers, {} leaves in first layer",
        num_layers, num_leaves
    );

    // Verify the leaves are present
    assert!(tree.layers[0].len() >= 3, "Should have at least 3 leaves");
    assert_eq!(tree.layers[0][0], leaf0);
    assert_eq!(tree.layers[0][1], leaf1);
    assert_eq!(tree.layers[0][2], leaf2);

    // The tree should pad to the next power of 2 (4 leaves)
    // Calculate the expected tree depth for verification
    let expected_depth = if num_leaves == 3 {
        // If not padded to 4, depth would be ceil(log2(3)) = 2
        2
    } else if num_leaves == 4 {
        // If padded to 4, depth is log2(4) = 2
        2
    } else {
        panic!("Unexpected number of leaves: {}", num_leaves);
    };

    // Verify proofs for each of the 3 original leaves
    for leaf_index in 0..3 {
        let proof =
            get_padded_proof_for_leaf(&tree, leaf_index, expected_depth).expect("Should get proof");

        // Verify the proof
        let mut current = proof.leaf;
        for i in 0..expected_depth {
            let sibling = proof.siblings[i];
            let path_bit = proof.path_indices[i];

            current = if !path_bit {
                hash_node(current, sibling)
            } else {
                hash_node(sibling, current)
            };
        }

        assert_eq!(
            current, root,
            "Proof for leaf {} should verify to root",
            leaf_index
        );
    }

    println!("✓ Tree with 3 leaves constructed and verified correctly");
}

#[test]
fn test_get_padded_proof_for_leaf_out_of_bounds_errors() {
    // Ensure proof generation handles invalid leaf index correctly
    println!("Testing out-of-bounds leaf index handling");

    let data = vec![vec![1u8], vec![2u8], vec![3u8], vec![4u8]];

    let (tree, _root) = build_tree(&data).expect("Failed to build tree");
    let tree_depth = 2; // 4 leaves -> depth 2

    // Try to get proof for out-of-bounds index
    let _result = get_padded_proof_for_leaf(&tree, 4, tree_depth);

    // This should either return an error or panic
    // The current implementation might panic, so we'll use catch_unwind
    use std::panic;
    let result = panic::catch_unwind(|| get_padded_proof_for_leaf(&tree, 4, tree_depth));

    assert!(
        result.is_err() || result.unwrap().is_err(),
        "Out-of-bounds index should cause error or panic"
    );

    // Test with way out of bounds index
    let result = panic::catch_unwind(|| get_padded_proof_for_leaf(&tree, 100, tree_depth));

    assert!(
        result.is_err() || result.unwrap().is_err(),
        "Far out-of-bounds index should cause error or panic"
    );

    println!("✓ Out-of-bounds leaf index correctly handled");
}

#[test]
fn test_node_vs_leaf_hash_distinct() {
    // Explicitly verify that domain separation for Merkle nodes and leaves is effective
    println!("Testing domain separation between node and leaf hashing");

    // Choose two random field elements
    let a = F::from(123456u64);
    let b = F::from(789012u64);

    // Compute node hash (internal node in tree)
    let h_node = hash_node(a, b);

    // For leaf hash, we need to work with bytes
    // For leaf hash, use simple 31-byte data (max allowed)
    let leaf_data = vec![1u8, 2, 3, 4, 5]; // Simple small data
    let h_leaf = get_leaf_hash(&leaf_data).unwrap();

    // These should be different due to domain separation
    assert_ne!(
        h_node, h_leaf,
        "Node hash and leaf hash should be different due to domain separation"
    );

    // Also test with simple data
    let simple_data = vec![1u8, 2, 3, 4];
    let h_leaf_simple = get_leaf_hash(&simple_data).unwrap();

    // Hash the leaf hash with itself as if it were a node
    let h_node_of_leaf = hash_node(h_leaf_simple, h_leaf_simple);

    // These should also be different
    assert_ne!(
        h_leaf_simple, h_node_of_leaf,
        "Leaf hash should differ from node hash of same values"
    );

    println!("✓ Domain separation between node and leaf hashing verified");
}

#[test]
fn test_merkle_tree_with_many_leaves() {
    // Test tree construction with a larger number of leaves
    println!("Testing tree with many leaves");

    let num_leaves = 17; // Non-power-of-2 to test padding
    let data: Vec<Vec<u8>> = (0..num_leaves).map(|i| vec![i as u8]).collect();

    let (tree, root) = build_tree(&data).expect("Failed to build tree");

    // The tree should have 17 leaves (the implementation doesn't pad internally)
    assert_eq!(
        tree.layers[0].len(),
        num_leaves,
        "First layer should have {} leaves",
        num_leaves
    );

    // Calculate actual depth based on tree structure
    let actual_depth = tree.layers.len() - 1;
    println!(
        "Tree has {} layers, depth {}",
        tree.layers.len(),
        actual_depth
    );

    // For testing with padded proofs, we need the padded depth
    let padded_depth = (num_leaves as f64).log2().ceil() as usize;

    // Verify all original leaves can generate valid proofs
    for i in 0..num_leaves {
        let proof = get_padded_proof_for_leaf(&tree, i, padded_depth).expect("Should get proof");

        // Verify the proof
        let mut current = proof.leaf;
        for j in 0..padded_depth {
            let sibling = proof.siblings[j];
            let path_bit = proof.path_indices[j];

            current = if !path_bit {
                hash_node(current, sibling)
            } else {
                hash_node(sibling, current)
            };
        }

        assert_eq!(current, root, "Proof for leaf {} should verify", i);
    }

    println!("✓ Tree with {} leaves constructed and verified", num_leaves);
}

#[test]
fn test_merkle_proof_siblings_correctness() {
    // Test that merkle proof siblings are correct for known tree structure
    println!("Testing merkle proof sibling correctness");

    let data = vec![vec![1u8], vec![2u8], vec![3u8], vec![4u8]];

    let (tree, _root) = build_tree(&data).expect("Failed to build tree");

    // For a 4-leaf tree:
    //       root
    //      /    \
    //    n01    n23
    //   /  \   /  \
    //  l0  l1 l2  l3

    // Get proof for leaf 0
    let proof0 = get_padded_proof_for_leaf(&tree, 0, 2).expect("Should get proof");

    // Siblings for leaf 0 should be: [l1, n23]
    assert_eq!(
        proof0.siblings[0], tree.layers[0][1],
        "First sibling should be l1"
    );
    assert_eq!(
        proof0.siblings[1], tree.layers[1][1],
        "Second sibling should be n23"
    );

    // Get proof for leaf 3
    let proof3 = get_padded_proof_for_leaf(&tree, 3, 2).expect("Should get proof");

    // Siblings for leaf 3 should be: [l2, n01]
    assert_eq!(
        proof3.siblings[0], tree.layers[0][2],
        "First sibling should be l2"
    );
    assert_eq!(
        proof3.siblings[1], tree.layers[1][0],
        "Second sibling should be n01"
    );

    println!("✓ Merkle proof siblings verified correct");
}

#[test]
fn test_zero_depth_tree() {
    // Test edge case of depth-0 tree (single leaf)
    println!("Testing depth-0 tree");

    let data = vec![vec![42u8]];
    let (tree, root) = build_tree(&data).expect("Failed to build tree");

    assert_eq!(tree.layers.len(), 1, "Depth-0 tree should have 1 layer");
    assert_eq!(tree.layers[0].len(), 1, "Should have exactly 1 leaf");

    let leaf = get_leaf_hash(&data[0]).unwrap();
    assert_eq!(root, leaf, "Root should equal the single leaf");

    // Get proof for the single leaf with depth 0
    let proof = get_padded_proof_for_leaf(&tree, 0, 0).expect("Should get proof");

    assert_eq!(
        proof.siblings.len(),
        0,
        "Depth-0 proof should have no siblings"
    );
    assert_eq!(
        proof.path_indices.len(),
        0,
        "Depth-0 proof should have no path indices"
    );
    assert_eq!(proof.leaf, leaf, "Proof leaf should match");

    println!("✓ Depth-0 tree handled correctly");
}

#[test]
fn test_adversarial_sibling_swap() {
    // Swapping any sibling should cause verification to fail
    println!("Testing adversarial sibling swap detection");

    let data: Vec<Vec<u8>> = (0..8).map(|i| vec![i as u8]).collect();
    let (tree, root) = build_tree(&data).expect("Failed to build tree");
    let depth = 3; // 8 leaves = depth 3

    // Get a valid proof
    let mut proof = get_padded_proof_for_leaf(&tree, 3, depth).expect("Failed to get proof");

    // Verify original proof works
    assert!(
        verify_merkle_proof_in_place(root, &proof),
        "Original proof should verify"
    );

    // Swap each sibling one at a time
    for i in 0..proof.siblings.len() {
        let original = proof.siblings[i];

        // Swap with a different value
        proof.siblings[i] = F::from(999999u64);

        let should_fail = verify_merkle_proof_in_place(root, &proof);
        assert!(
            !should_fail,
            "Proof with tampered sibling at index {} should fail verification",
            i
        );

        // Restore original
        proof.siblings[i] = original;
    }

    println!("✓ Sibling tampering correctly detected");
}

#[test]
fn test_adversarial_path_bit_flip() {
    // Flipping any path bit should cause verification to fail
    println!("Testing adversarial path bit flip detection");

    let data: Vec<Vec<u8>> = (0..16).map(|i| vec![i as u8, (i * 2) as u8]).collect();
    let (tree, root) = build_tree(&data).expect("Failed to build tree");
    let depth = 4; // 16 leaves = depth 4

    // Test with multiple leaf positions
    for leaf_idx in [0, 5, 10, 15] {
        let mut proof =
            get_padded_proof_for_leaf(&tree, leaf_idx, depth).expect("Failed to get proof");

        // Verify original works
        assert!(
            verify_merkle_proof_in_place(root, &proof),
            "Original proof for leaf {} should verify",
            leaf_idx
        );

        // Flip each path bit
        for i in 0..proof.path_indices.len() {
            proof.path_indices[i] = !proof.path_indices[i];

            let should_fail = verify_merkle_proof_in_place(root, &proof);
            assert!(
                !should_fail,
                "Proof with flipped path bit {} for leaf {} should fail",
                i, leaf_idx
            );

            // Restore
            proof.path_indices[i] = !proof.path_indices[i];
        }
    }

    println!("✓ Path bit tampering correctly detected");
}
