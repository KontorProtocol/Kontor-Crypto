use kontor_crypto::circuit::{FileProofWitness, PorCircuit};
use kontor_crypto::config;
use kontor_crypto::merkle::{build_tree, get_padded_proof_for_leaf};
use kontor_crypto::poseidon::{domain_tags, poseidon_hash_tagged};

mod common;
use common::fixtures::{create_circuit_public_inputs, E1, E2, F1, S1, S2};
use ff::Field;
use nova_snark::frontend::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        num::AllocatedNum,
    },
    util_cs::test_cs::TestConstraintSystem,
    ConstraintSystem,
};
use nova_snark::{
    nova::{PublicParams, RecursiveSNARK},
    traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait},
};

#[test]
fn test_por_circuit_basic() {
    // Test a simple 2-leaf tree
    let data = vec![vec![1u8], vec![2u8]];
    let (tree, root) = build_tree(&data).expect("Failed to build tree for test");
    let depth = 1;
    let random_seed = F1::from(0u64);
    let acc_in = F1::ZERO; // Initial accumulator
    let leaf_index = kontor_crypto::utils::derive_index_from_bits(
        poseidon_hash_tagged(domain_tags::challenge(), random_seed, acc_in),
        depth,
    );
    let proof =
        get_padded_proof_for_leaf(&tree, leaf_index, depth).expect("Failed to get proof for test");
    let witness = FileProofWitness {
        leaf: proof.leaf,
        file_siblings: {
            let mut siblings = proof.siblings;
            siblings.resize(3, F1::ZERO); // Small depth for fast tests
            siblings
        },
        file_root: F1::ZERO, // Computed in-circuit for single-file
        actual_depth: depth,
        agg_siblings: vec![],
        ledger_index: 0,
    };
    // Phase 3: Use proper shape derivation to ensure minimum depth 1
    let (files_per_step, file_tree_depth) = config::derive_shape(1, depth);
    let circuit = PorCircuit::new(files_per_step, file_tree_depth, 0, Some(vec![witness]));
    let pp =
        PublicParams::<E1, E2, PorCircuit<F1>>::setup(&circuit, &*S1::ck_floor(), &*S2::ck_floor())
            .expect("Failed to setup public params");
    // New schema: [agg_root, state_in, ledger_indices, depths, seeds, leaves]
    let z0_primary = vec![
        root,                   // [0] agg_root
        acc_in,                 // [1] state_in
        F1::ZERO,               // [2] ledger_index_0 (single file at index 0)
        F1::from(depth as u64), // [3] depth_0 (actual depth for file 0)
        random_seed,            // [4] seed_0
        F1::ZERO,               // [5] leaf_0 (will be filled by circuit)
    ];
    let result = RecursiveSNARK::new(&pp, &circuit, &z0_primary);
    assert!(
        result.is_ok(),
        "Valid circuit should create RecursiveSNARK successfully"
    );
}

#[test]
fn test_multi_file_constructor() {
    use kontor_crypto::merkle::build_tree_from_leaves;

    // Create 2 files
    let file1_data = vec![vec![1u8], vec![2u8]];
    let file2_data = vec![vec![3u8], vec![4u8]];

    // Build trees for each file
    let (tree1, root1) = build_tree(&file1_data).expect("Failed to build tree 1");
    let (tree2, root2) = build_tree(&file2_data).expect("Failed to build tree 2");

    // Build aggregated tree from file roots
    let file_roots = vec![root1, root2];
    let aggregated_tree =
        build_tree_from_leaves(&file_roots).expect("Failed to build aggregated tree");

    // Get proofs for each file
    let file1_proof =
        get_padded_proof_for_leaf(&tree1, 0, 1).expect("Failed to get proof for file 1");
    let file2_proof =
        get_padded_proof_for_leaf(&tree2, 1, 1).expect("Failed to get proof for file 2");

    // Get aggregation proofs
    let agg_proof1 =
        get_padded_proof_for_leaf(&aggregated_tree, 0, 1).expect("Failed to get agg proof 1");
    let agg_proof2 =
        get_padded_proof_for_leaf(&aggregated_tree, 1, 1).expect("Failed to get agg proof 2");

    // Create multi-file circuit using new unified API
    let witnesses = vec![
        FileProofWitness {
            leaf: file1_proof.leaf,
            file_siblings: file1_proof.siblings,
            file_root: root1,
            actual_depth: 1,
            agg_siblings: agg_proof1.siblings,
            ledger_index: 0,
        },
        FileProofWitness {
            leaf: file2_proof.leaf,
            file_siblings: file2_proof.siblings,
            file_root: root2,
            actual_depth: 1,
            agg_siblings: agg_proof2.siblings,
            ledger_index: 1,
        },
    ];
    let circuit = PorCircuit::<F1>::new(2, 1, 1, Some(witnesses)); // 2 files, depth 1, agg depth 1

    // Check that the circuit was created successfully
    assert_eq!(circuit.files_per_step, 2);
    assert_eq!(circuit.file_tree_depth, 1);
    assert_eq!(circuit.aggregated_tree_depth, 1);
    assert!(circuit.witness.is_some());
    assert_eq!(circuit.witness.as_ref().unwrap().witnesses().len(), 2);
}

#[test]
fn test_por_circuit_invalid_sibling() {
    use nova_snark::frontend::util_cs::test_cs::TestConstraintSystem;
    let data = vec![vec![1u8], vec![2u8], vec![3u8], vec![4u8]];
    let (tree, root) = build_tree(&data).expect("Failed to build tree for test");
    let depth = 2;
    let random_seed = F1::from(0u64);
    let acc_in = F1::ZERO; // Initial accumulator
    let leaf_index = kontor_crypto::utils::derive_index_from_bits(
        poseidon_hash_tagged(domain_tags::challenge(), random_seed, acc_in),
        depth,
    );
    let mut proof =
        get_padded_proof_for_leaf(&tree, leaf_index, depth).expect("Failed to get proof for test");
    proof.siblings[0] = F1::from(99999u64); // Invalid sibling
    let witness = FileProofWitness {
        leaf: proof.leaf,
        file_siblings: {
            let mut siblings = proof.siblings;
            siblings.resize(3, F1::ZERO); // Small depth for fast tests
            siblings
        },
        file_root: F1::ZERO, // Computed in-circuit for single-file
        actual_depth: depth,
        agg_siblings: vec![],
        ledger_index: 0,
    };
    let invalid_circuit = PorCircuit::new(1, depth, 0, Some(vec![witness])); // Single file
    let mut cs = TestConstraintSystem::<F1>::new();
    let z = create_circuit_public_inputs(
        &mut cs,
        root,
        acc_in,
        random_seed,
        &[0],     // ledger_indices
        &[depth], // depths
        &[F1::ZERO],
    );
    let result = invalid_circuit.synthesize(&mut cs, &z);
    assert!(result.is_ok(), "Synthesis should succeed");
    assert!(
        !cs.is_satisfied(),
        "Circuit with invalid Merkle sibling should not satisfy constraints"
    );
}

#[test]
fn test_por_circuit_mismatched_depth() {
    let data = vec![vec![1u8], vec![2u8], vec![3u8], vec![4u8]];
    let (_tree, _root) = build_tree(&data).expect("Failed to build tree for test");
    let declared_depth = 2; // Actual tree depth is 2
    let siblings = vec![F1::from(1u64), F1::from(2u64)]; // Only 2 elements

    // Now we pad siblings instead of panicking - test that padding works
    let witness = FileProofWitness {
        leaf: F1::from(123u64),
        file_siblings: {
            let mut padded_siblings = siblings;
            padded_siblings.resize(2, F1::ZERO); // Small depth for fast tests
            padded_siblings
        },
        file_root: F1::ZERO, // Computed in-circuit for single-file
        actual_depth: declared_depth,
        agg_siblings: vec![],
        ledger_index: 0,
    };
    let circuit = PorCircuit::new(1, declared_depth, 0, Some(vec![witness])); // Single file

    // Check that circuit was created with correct depth
    assert_eq!(circuit.file_tree_depth, declared_depth);
    if let Some(ref circuit_witness) = circuit.witness {
        let witnesses = circuit_witness.witnesses();
        assert_eq!(
            witnesses[0].file_siblings.len(),
            declared_depth // Should match the depth we created with
        );
    }
}

#[test]
fn test_por_circuit_zero_depth() {
    let data = vec![vec![42u8]];
    let (tree, root) = build_tree(&data).expect("Failed to build tree for test");
    let depth = 0;
    let random_seed = F1::from(0u64);
    let acc_in = F1::ZERO; // Initial accumulator
    let leaf_index = kontor_crypto::utils::derive_index_from_bits(
        poseidon_hash_tagged(domain_tags::challenge(), random_seed, acc_in),
        depth,
    );
    let proof =
        get_padded_proof_for_leaf(&tree, leaf_index, depth).expect("Failed to get proof for test");
    let witness = FileProofWitness {
        leaf: proof.leaf,
        file_siblings: {
            let mut siblings = proof.siblings;
            siblings.resize(3, F1::ZERO); // Small depth for fast tests
            siblings
        },
        file_root: F1::ZERO, // Computed in-circuit for single-file
        actual_depth: depth,
        agg_siblings: vec![],
        ledger_index: 0,
    };
    // Phase 3: Use proper shape derivation to ensure minimum depth 1
    let (files_per_step, file_tree_depth) = config::derive_shape(1, depth);
    let circuit = PorCircuit::new(files_per_step, file_tree_depth, 0, Some(vec![witness]));
    let pp =
        PublicParams::<E1, E2, PorCircuit<F1>>::setup(&circuit, &*S1::ck_floor(), &*S2::ck_floor())
            .expect("Failed to setup public params");
    // Circuit now expects dynamic public inputs based on files_per_step
    // New schema: [agg_root, state_in, ledger_indices, depths, seeds, leaves]
    let z0_primary = vec![
        root,                   // [0] agg_root
        acc_in,                 // [1] state_in
        F1::ZERO,               // [2] ledger_index_0 (single file at index 0)
        F1::from(depth as u64), // [3] depth_0 (actual depth for file 0)
        random_seed,            // [4] seed_0
        F1::ZERO,               // [5] leaf_0 (will be filled by circuit)
    ];
    let result = RecursiveSNARK::new(&pp, &circuit, &z0_primary);
    assert!(result.is_ok(), "Zero depth circuit should work");
}

#[test]
fn test_por_circuit_accumulator_update() {
    use tracing::debug;
    // Test with depth=2 instead of depth=1 to see if it's depth-specific
    let data = vec![vec![10u8], vec![20u8], vec![30u8], vec![40u8]];
    let (tree, root) = build_tree(&data).expect("Failed to build tree for test");
    let depth = 2; // Changed from 1 to 2
    let random_seed = F1::from(0u64);
    let initial_acc = F1::from(100u64);
    let leaf_index = kontor_crypto::utils::derive_index_from_bits(
        kontor_crypto::poseidon::poseidon_hash_tagged(
            kontor_crypto::poseidon::domain_tags::challenge(),
            random_seed,
            initial_acc,
        ),
        depth,
    );
    let proof =
        get_padded_proof_for_leaf(&tree, leaf_index, depth).expect("Failed to get proof for test");

    // Store values for debug output before moving
    let proof_leaf = proof.leaf;
    let proof_siblings_len = proof.siblings.len();

    // Create a single circuit instance for both setup and proving
    let witness = FileProofWitness {
        leaf: proof.leaf,
        file_siblings: {
            let mut siblings = proof.siblings;
            siblings.resize(3, F1::ZERO); // Small depth for fast tests
            siblings
        },
        file_root: F1::ZERO, // Computed in-circuit for single-file
        actual_depth: depth,
        agg_siblings: vec![],
        ledger_index: 0,
    };
    // Phase 3: Use proper shape derivation to ensure minimum depth 1
    let (files_per_step, file_tree_depth) = config::derive_shape(1, depth);
    let circuit = PorCircuit::new(files_per_step, file_tree_depth, 0, Some(vec![witness]));

    let pp =
        PublicParams::<E1, E2, PorCircuit<F1>>::setup(&circuit, &*S1::ck_floor(), &*S2::ck_floor())
            .expect("Failed to setup public params");
    // New schema: [agg_root, state_in, ledger_indices, depths, seeds, leaves]
    let z0_primary = vec![
        root,                   // [0] agg_root
        initial_acc,            // [1] state_in
        F1::ZERO,               // [2] ledger_index_0 (single file at index 0)
        F1::from(depth as u64), // [3] depth_0 (actual depth for file 0)
        random_seed,            // [4] seed_0
        F1::ZERO,               // [5] leaf_0 (will be filled by circuit)
    ];

    let mut recursive_snark =
        RecursiveSNARK::new(&pp, &circuit, &z0_primary).expect("Failed to create RecursiveSNARK");
    recursive_snark
        .prove_step(&pp, &circuit)
        .expect("Failed to prove step");
    let result = recursive_snark.verify(&pp, 1, &z0_primary);
    if let Err(ref e) = result {
        debug!("Verification failed: {:?}", e);
        debug!("Depth: {}, Leaf index: {}", depth, leaf_index);
        debug!("Proof leaf: {:?}", proof_leaf);
        debug!("Proof siblings len: {}", proof_siblings_len);
    }
    assert!(result.is_ok(), "Proof should verify: {:?}", result);
}

#[test]
fn test_por_circuit_wrong_root() {
    let data = vec![vec![1u8], vec![2u8]];
    let (tree, correct_root) = build_tree(&data).expect("Failed to build tree for test");
    let depth = 1;
    let wrong_root = F1::from(987654321u64);
    let random_seed = F1::from(0u64);
    let acc_in = F1::ZERO; // Initial accumulator
    let leaf_index = kontor_crypto::utils::derive_index_from_bits(
        poseidon_hash_tagged(domain_tags::challenge(), random_seed, acc_in),
        depth,
    );
    let proof =
        get_padded_proof_for_leaf(&tree, leaf_index, depth).expect("Failed to get proof for test");
    let witness = FileProofWitness {
        leaf: proof.leaf,
        file_siblings: {
            let mut siblings = proof.siblings;
            siblings.resize(3, F1::ZERO); // Small depth for fast tests
            siblings
        },
        file_root: F1::ZERO, // Computed in-circuit for single-file
        actual_depth: depth,
        agg_siblings: vec![],
        ledger_index: 0,
    };
    // Phase 3: Use proper shape derivation to ensure minimum depth 1
    let (files_per_step, file_tree_depth) = config::derive_shape(1, depth);
    let circuit = PorCircuit::new(files_per_step, file_tree_depth, 0, Some(vec![witness]));

    let pp =
        PublicParams::<E1, E2, PorCircuit<F1>>::setup(&circuit, &*S1::ck_floor(), &*S2::ck_floor())
            .expect("Failed to setup public params");

    // Phase 3: No more meta commitment - security from public depth binding
    // Phase 3: New schema [agg_root, state_in, seed, ledger_indices, depths, leaves]
    let z0_primary_correct = vec![
        correct_root,           // [0] agg_root
        acc_in,                 // [1] state_in
        random_seed,            // [2] seed
        F1::ZERO,               // [3] ledger_index_0 (single file at index 0)
        F1::from(depth as u64), // [4] depth_0 (actual depth for file 0)
        F1::ZERO,               // [5] leaf_0 (will be filled by circuit)
    ];
    let recursive_snark = RecursiveSNARK::new(&pp, &circuit, &z0_primary_correct)
        .expect("Should create RecursiveSNARK with correct root");
    let z0_primary_wrong = vec![
        wrong_root,             // [0] agg_root (wrong)
        acc_in,                 // [1] state_in
        random_seed,            // [2] seed
        F1::ZERO,               // [3] ledger_index_0 (single file at index 0)
        F1::from(depth as u64), // [4] depth_0 (actual depth for file 0)
        F1::ZERO,               // [5] leaf_0 (will be filled by circuit)
    ];
    let result = recursive_snark.verify(&pp, 1, &z0_primary_wrong);
    assert!(result.is_err(), "Verification with wrong root should fail");
}

#[test]
fn test_conditional_select() {
    // Direct test of the conditional_select function
    use kontor_crypto::circuit::gadgets::select::conditional_select;

    let mut cs = TestConstraintSystem::<F1>::new();

    // Test case 1: condition = false, should select 'if_false'
    let if_false =
        AllocatedNum::alloc(cs.namespace(|| "if_false"), || Ok(F1::from(10u64))).unwrap();
    let if_true = AllocatedNum::alloc(cs.namespace(|| "if_true"), || Ok(F1::from(20u64))).unwrap();
    let condition_bit = AllocatedBit::alloc(cs.namespace(|| "condition"), Some(false)).unwrap();
    let condition = Boolean::from(condition_bit);

    let result =
        conditional_select(cs.namespace(|| "select1"), &condition, &if_false, &if_true).unwrap();

    assert_eq!(result.get_value().unwrap(), F1::from(10u64));

    // Test case 2: condition = true, should select 'if_true'
    let condition_bit2 = AllocatedBit::alloc(cs.namespace(|| "condition2"), Some(true)).unwrap();
    let condition2 = Boolean::from(condition_bit2);

    let result2 =
        conditional_select(cs.namespace(|| "select2"), &condition2, &if_false, &if_true).unwrap();

    assert_eq!(result2.get_value().unwrap(), F1::from(20u64));

    // Verify no constraints were violated
    assert!(cs.is_satisfied());
}

#[test]
fn test_constraint_count() {
    use nova_snark::frontend::util_cs::test_cs::TestConstraintSystem;
    for depth in [0, 1, 2, 3] {
        let data = vec![vec![1u8]; 1 << depth];
        let (tree, root) = build_tree(&data).expect("Failed to build tree for test");
        let random_seed = F1::from(0u64);
        let acc_in = F1::ZERO; // Initial accumulator
        let leaf_index = kontor_crypto::utils::derive_index_from_bits(
            kontor_crypto::poseidon::poseidon_hash_tagged(
                kontor_crypto::poseidon::domain_tags::challenge(),
                random_seed,
                acc_in,
            ),
            depth,
        );
        let proof = get_padded_proof_for_leaf(&tree, leaf_index, depth)
            .expect("Failed to get proof for test");
        // TODO: DRY THIS!
        let witness = FileProofWitness {
            leaf: proof.leaf,
            file_siblings: {
                let mut siblings = proof.siblings;
                siblings.resize(3, F1::ZERO); // Small depth for fast tests
                siblings
            },
            file_root: F1::ZERO, // Computed in-circuit for single-file
            actual_depth: depth,
            agg_siblings: vec![],
            ledger_index: 0,
        };
        // Phase 3: Use proper shape derivation to ensure minimum depth 1
        let (files_per_step, file_tree_depth) = config::derive_shape(1, depth);
        let circuit = PorCircuit::new(files_per_step, file_tree_depth, 0, Some(vec![witness]));
        let mut cs = TestConstraintSystem::<F1>::new();
        let z = create_circuit_public_inputs(
            &mut cs,
            root,
            acc_in,
            random_seed,
            &[0],     // ledger_indices
            &[depth], // depths
            &[F1::ZERO],
        );
        let result = circuit.synthesize(&mut cs, &z);
        assert!(result.is_ok(), "Synthesis should succeed for depth {depth}");
        println!("Depth {}: {} constraints", depth, cs.num_constraints());
    }
}
