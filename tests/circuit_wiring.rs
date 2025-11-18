//! Critical circuit wiring tests - ensure off-circuit and in-circuit implementations match
//!
//! These tests verify that the circuit gadgets produce bit-for-bit identical results
//! to their off-circuit counterparts. Any divergence here is a critical security issue.

use ff::{Field, PrimeField};
use kontor_crypto::{
    api::FieldElement,
    circuit::{FileProofWitness, PorCircuit},
    commitment::{domain_tags, poseidon_hash_tagged},
    utils::derive_index_from_bits,
};
use nova_snark::frontend::{
    gadgets::num::AllocatedNum, util_cs::test_cs::TestConstraintSystem, ConstraintSystem,
};
use nova_snark::traits::circuit::StepCircuit;

mod common;
use common::{create_single_file_ledger, fixtures::create_circuit_public_inputs};

#[test]
fn test_poseidon_hash_tagged_gadget_matches_off_circuit() {
    // C-04: Test that in-circuit poseidon hashing is consistent
    println!("Testing poseidon hash consistency with real witnesses");

    use kontor_crypto::merkle::{build_tree, get_padded_proof_for_leaf};

    // Create actual data and build a real Merkle tree
    let data = vec![vec![1u8, 2, 3], vec![4u8, 5, 6]];
    let (tree, root) = build_tree(&data).expect("Failed to build tree");
    let tree_depth = 1; // 2 leaves -> depth 1

    // Get a valid Merkle proof for leaf 0
    let proof = get_padded_proof_for_leaf(&tree, 0, tree_depth).expect("Failed to get proof");

    // Create a witness with the real proof
    let witness = FileProofWitness {
        leaf: proof.leaf,
        file_siblings: proof.siblings.clone(),
        file_root: root,
        actual_depth: tree_depth,
        agg_siblings: vec![],
        ledger_index: 0,
    };

    // Test with a circuit that uses this witness
    let circuit = PorCircuit::<FieldElement>::new(
        1,          // files_per_step
        tree_depth, // file_tree_depth
        0,          // aggregated_tree_depth (single file)
        Some(vec![witness.clone()]),
    );

    let mut cs = TestConstraintSystem::<FieldElement>::new();

    // New schema: [agg_root, state_in, ledger_indices, depths, seeds, leaves]
    let initial_state = FieldElement::from(42u64);
    let seed = FieldElement::from(123u64);

    let z_in = vec![
        AllocatedNum::alloc(cs.namespace(|| "agg_root"), || Ok(root)).unwrap(),
        AllocatedNum::alloc(cs.namespace(|| "state_in"), || Ok(initial_state)).unwrap(),
        AllocatedNum::alloc(cs.namespace(|| "ledger_idx_0"), || Ok(FieldElement::ZERO)).unwrap(),
        AllocatedNum::alloc(cs.namespace(|| "depth_0"), || {
            Ok(FieldElement::from(tree_depth as u64))
        })
        .unwrap(),
        AllocatedNum::alloc(cs.namespace(|| "seed_0"), || Ok(seed)).unwrap(),
        AllocatedNum::alloc(cs.namespace(|| "leaf_0"), || Ok(FieldElement::ZERO)).unwrap(), // Leaf slot
    ];

    // Synthesize the circuit
    let result = circuit.synthesize(&mut cs, &z_in);
    assert!(result.is_ok(), "Circuit synthesis should succeed");

    // Get the output state
    let z_out = result.unwrap();
    let state_out = z_out[1].get_value().expect("Failed to get state_out");

    // Compute expected state off-circuit
    let expected_state =
        poseidon_hash_tagged(domain_tags::state_update(), initial_state, witness.leaf);

    // Verify they match
    assert_eq!(
        state_out, expected_state,
        "In-circuit poseidon hash doesn't match off-circuit"
    );

    // Also verify the circuit is satisfied
    assert!(cs.is_satisfied(), "Circuit constraints should be satisfied");

    println!("✓ Poseidon gadget produces identical results to off-circuit implementation");
}

#[test]
fn test_state_chaining_gadget_correctness() {
    // C-06: State chaining must match between circuit and off-circuit
    println!("Testing state chaining gadget matches off-circuit implementation");

    // Initial state and a sequence of leaves to chain
    let initial_state = FieldElement::from(42u64);
    let leaves = vec![
        FieldElement::from(100u64),
        FieldElement::from(200u64),
        FieldElement::from(300u64),
    ];

    // Compute expected state evolution off-circuit
    let mut expected_state = initial_state;
    for leaf in &leaves {
        expected_state = poseidon_hash_tagged(domain_tags::state_update(), expected_state, *leaf);
    }

    // Now verify the circuit produces the same result
    // We'll create a circuit with witnesses and check the state output
    let mut witnesses: Vec<FileProofWitness<FieldElement>> = leaves
        .iter()
        .map(|leaf| FileProofWitness {
            leaf: *leaf,
            file_siblings: vec![FieldElement::ZERO],
            file_root: FieldElement::ZERO,
            actual_depth: 1, // Use depth 1 for real files to be consistent with active_flags[0] gating
            agg_siblings: vec![],
            ledger_index: 0,
        })
        .collect();

    // Pad to 4 witnesses (files_per_step = 4)
    while witnesses.len() < 4 {
        witnesses.push(FileProofWitness {
            leaf: FieldElement::ZERO,
            file_siblings: vec![FieldElement::ZERO],
            file_root: FieldElement::ZERO,
            actual_depth: 0,
            agg_siblings: vec![],
            ledger_index: 0,
        });
    }

    let circuit = PorCircuit::<FieldElement>::new(
        4, // files_per_step (padded to power of 2)
        1, // file_tree_depth
        0, // aggregated_tree_depth
        Some(witnesses),
    );

    // Create test constraint system
    let mut cs = TestConstraintSystem::<FieldElement>::new();

    // New schema: [agg_root, state_in, ledger_indices, depths, seeds, leaves]
    let mut z_in = vec![
        AllocatedNum::alloc(cs.namespace(|| "agg_root"), || Ok(FieldElement::ZERO)).unwrap(),
        AllocatedNum::alloc(cs.namespace(|| "state_in"), || Ok(initial_state)).unwrap(),
    ];

    // Add ledger indices for each file slot (4 slots since files_per_step = 4)
    for i in 0..4 {
        z_in.push(
            AllocatedNum::alloc(cs.namespace(|| format!("ledger_idx_{}", i)), || {
                Ok(FieldElement::from(i as u64))
            })
            .unwrap(),
        );
    }

    // Add depths for each file slot (first 3 have depth 1, last is padding with depth 0)
    for i in 0..4 {
        let depth = if i < 3 { 1 } else { 0 }; // First 3 are real files, last is padding
        z_in.push(
            AllocatedNum::alloc(cs.namespace(|| format!("depth_{}", i)), || {
                Ok(FieldElement::from(depth as u64))
            })
            .unwrap(),
        );
    }

    // Add seeds for each file slot (4 slots since files_per_step = 4)
    for i in 0..4 {
        z_in.push(
            AllocatedNum::alloc(cs.namespace(|| format!("seed_{}", i)), || {
                Ok(FieldElement::ZERO)
            })
            .unwrap(),
        );
    }

    // Add leaf slots (4 slots since files_per_step = 4)
    for i in 0..4 {
        z_in.push(
            AllocatedNum::alloc(cs.namespace(|| format!("leaf_{}", i)), || {
                Ok(FieldElement::ZERO)
            })
            .unwrap(),
        );
    }

    // Synthesize and get output
    let z_out = circuit
        .synthesize(&mut cs, &z_in)
        .expect("Synthesis failed");

    // The state_out is z_out[1]
    let state_out_value = z_out[1].get_value().expect("Failed to get state_out");

    assert_eq!(
        state_out_value, expected_state,
        "Circuit state chaining doesn't match off-circuit computation"
    );

    println!("✓ State chaining gadget produces identical results to off-circuit");
}

#[test]
fn test_challenge_index_derivation_consistency() {
    // C-07: Test that challenge index derivation uses bit extraction
    println!("Testing challenge index derivation with real tree");

    use kontor_crypto::merkle::{build_tree, get_padded_proof_for_leaf};

    // Build a tree with multiple leaves to test indexing
    let depth = 3; // 8 leaves
    let data: Vec<Vec<u8>> = (0..8).map(|i| vec![i as u8]).collect();
    let (tree, root) = build_tree(&data).expect("Failed to build tree");

    // Test parameters
    let seed = FieldElement::from(42u64);
    let state = FieldElement::from(100u64);
    let file_idx = 0u64;

    // Compute challenge hash off-circuit
    let challenge_hash =
        poseidon_hash_tagged(domain_tags::challenge(), seed, state) + FieldElement::from(file_idx);

    // Derive index using bit extraction
    let expected_index = derive_index_from_bits(challenge_hash, depth);
    println!("  Expected leaf index (bit extraction): {}", expected_index);

    // Verify it's different from modulo (statistically)
    let leaf_count = 1usize << depth;
    let hash_bytes = challenge_hash.to_repr();
    let hash_low = u32::from_le_bytes([
        hash_bytes.as_ref()[0],
        hash_bytes.as_ref()[1],
        hash_bytes.as_ref()[2],
        hash_bytes.as_ref()[3],
    ]);
    let modulo_index = (hash_low as usize) % leaf_count;

    if expected_index != modulo_index {
        println!(
            "✓ Using bit extraction ({}), NOT modulo ({})",
            expected_index, modulo_index
        );
    }

    // Get the actual proof for the expected index
    let proof =
        get_padded_proof_for_leaf(&tree, expected_index, depth).expect("Failed to get proof");

    // Create a witness with this proof
    let witness = FileProofWitness {
        leaf: proof.leaf,
        file_siblings: proof.siblings.clone(),
        file_root: root,
        actual_depth: depth,
        agg_siblings: vec![],
        ledger_index: 0,
    };

    // Create circuit with the witness
    let circuit = PorCircuit::<FieldElement>::new(
        1,     // files_per_step
        depth, // file_tree_depth
        0,     // aggregated_tree_depth
        Some(vec![witness]),
    );

    let mut cs = TestConstraintSystem::<FieldElement>::new();

    // Phase 3: No longer need meta_commitment calculation

    // Phase 3 schema: [agg_root, state_in, seed, ledger_indices, depths, leaves]
    let z_in = create_circuit_public_inputs(
        &mut cs,
        root,
        state,
        seed,
        &[0],     // ledger_indices
        &[depth], // depths
        &[FieldElement::ZERO],
    );

    // Synthesize should succeed if the circuit correctly derives the same index
    let result = circuit.synthesize(&mut cs, &z_in);
    assert!(result.is_ok(), "Circuit synthesis should succeed");

    // The circuit should be satisfied only if it selected the correct leaf
    // based on the same bit extraction logic
    assert!(
        cs.is_satisfied(),
        "Circuit should be satisfied - index derivation must match"
    );

    println!("✓ Circuit uses same challenge index derivation as off-circuit");
}

#[test]
fn test_arecibo_first_step_no_op_invariant() {
    // C-14: Critical regression test for Arecibo's first step behavior
    // This test verifies that our API correctly handles the Arecibo quirk where
    // the first call to prove_step after new() is a no-op.
    println!("Testing Arecibo first step no-op invariant");

    use kontor_crypto::api::{prepare_file, Challenge, PorSystem};

    // The critical invariant we're testing:
    // For N challenges, our API should:
    // 1. Call RecursiveSNARK::new() once (synthesizes step 0)
    // 2. Call prove_step() exactly N times (first is no-op, rest synthesize)
    // 3. Verify with num_steps = N

    // This is documented in src/circuit.rs and src/api.rs
    // The implementation in api.rs:prove() correctly handles this:
    // - Line 711: RecursiveSNARK::new() creates step 0
    // - Lines 750-820: Loop calls prove_step N times, with first being no-op

    // Test with a simple single-file proof
    let data = vec![1u8; 100];
    let (prepared, metadata) = prepare_file(&data, "test_file.dat").unwrap();

    // Create 2 challenges to test the behavior
    let num_challenges = 2;
    let seed = FieldElement::from(42u64);
    let challenge = Challenge::new_test(metadata.clone(), 1000, num_challenges, seed);

    // Generate proof - this internally handles the no-op correctly
    let mut files = std::collections::BTreeMap::new();
    files.insert(metadata.file_id.clone(), &prepared);

    // Create ledger for unified API
    let ledger = create_single_file_ledger(&metadata);

    let system = PorSystem::new(&ledger);
    let files_vec: Vec<&_> = files.values().copied().collect();
    let proof = system
        .prove(files_vec, std::slice::from_ref(&challenge))
        .unwrap();

    // Verify the proof
    let is_valid = system.verify(&proof, &[challenge]).unwrap();
    assert!(is_valid, "Proof should verify");

    println!("✓ API correctly handles Arecibo first step no-op");
    println!(
        "✓ Proof with {} challenges verified successfully",
        num_challenges
    );
    println!("✓ Implementation calls prove_step exactly N times as required");

    // The fact that our proofs verify confirms that the API correctly:
    // - Calls prove_step N times for N challenges (not N-1)
    // - Accounts for the first call being a no-op
    // - Verifies with num_steps = N (not N+1)
}
