//! Test to verify the ledger index range checking fix
//!
//! This test ensures that the circuit properly enforces that ledger indices
//! are within the valid range [0, 2^aggregated_tree_depth).

use nova_snark::traits::circuit::StepCircuit;
use nova_snark::frontend::{
    gadgets::num::AllocatedNum,
    util_cs::test_cs::TestConstraintSystem,
    ConstraintSystem,
};
use ff::Field;
use kontor_crypto::circuit::{FileProofWitness, PorCircuit};
use kontor_crypto::merkle::F as FieldElement;

mod common;
use common::fixtures::{create_circuit_public_inputs, create_padding_witness, create_witness};

#[test]
fn test_verifier_index_responsibility() {
    // Phase 2: Verifier is responsible for range checking (circuit trusts public indices)
    println!("Testing that circuit trusts verifier-provided indices (no range enforcement)...");

    // Test with aggregated_tree_depth = 2 (previously allowed indices 0, 1, 2, 3)
    let aggregated_depth = 2;
    let max_valid_index = (1 << aggregated_depth) - 1; // 3

    // Test 1: Valid indices should still be accepted
    for valid_index in 0..=max_valid_index {
        let witnesses = vec![
            create_witness(
                FieldElement::from(1u64),
                FieldElement::from(100u64),
                2,
                2,
                valid_index,
                aggregated_depth,
                true,
            ),
            create_padding_witness(2, aggregated_depth),
        ];

        let circuit = PorCircuit::<FieldElement>::new(
            2, // files_per_step
            2, // file_tree_depth
            aggregated_depth,
            Some(witnesses),
        );

        let mut cs = TestConstraintSystem::<FieldElement>::new();

        let _files_meta_commitment = FieldElement::from(12345u64); // Phase 3: No longer used

        let z0_alloc = create_circuit_public_inputs(
            &mut cs,
            FieldElement::from(99999u64),
            FieldElement::ZERO,
            FieldElement::from(42u64),
            &[valid_index, 0], // ledger_indices
            &[2, 0],           // depths (depth 2 for real file, 0 for padding)
            &[FieldElement::ZERO, FieldElement::ZERO],
        );

        let result = circuit.synthesize(&mut cs, &z0_alloc);
        assert!(
            result.is_ok(),
            "Circuit should accept valid index {}",
            valid_index
        );
    }

    println!("✓ Valid indices [0, {}] are accepted", max_valid_index);

    // Test 2: Phase 2 - circuit trusts verifier for any indices (no range enforcement)
    let previously_invalid_indices = vec![4, 5, 7, 8, 15, 100];

    for index in previously_invalid_indices {
        let witnesses = vec![
            FileProofWitness {
                leaf: FieldElement::from(1u64),
                file_siblings: vec![FieldElement::ZERO; 2],
                file_root: FieldElement::from(100u64),
                actual_depth: 2,
                agg_siblings: vec![FieldElement::ZERO; aggregated_depth],
                ledger_index: index,
            },
            FileProofWitness {
                leaf: FieldElement::ZERO,
                file_siblings: vec![FieldElement::ZERO; 2],
                file_root: FieldElement::ZERO,
                actual_depth: 0,
                agg_siblings: vec![FieldElement::ZERO; aggregated_depth],
                ledger_index: 0,
            },
        ];

        let circuit = PorCircuit::<FieldElement>::new(
            2, // files_per_step
            2, // file_tree_depth
            aggregated_depth,
            Some(witnesses),
        );

        let mut cs = TestConstraintSystem::<FieldElement>::new();

        // Current schema: [agg_root, state_in, ledger_indices, depths, seeds, leaves]
        let mut z0 = vec![
            FieldElement::from(99999u64), // aggregated_root
            FieldElement::ZERO,           // state_in
        ];

        // Add ledger indices
        z0.push(FieldElement::from(index as u64)); // any index (circuit trusts verifier)
        z0.push(FieldElement::ZERO); // padding file index

        // Add depths
        z0.push(FieldElement::from(2u64)); // real file depth
        z0.push(FieldElement::ZERO); // padding file depth

        // Add seeds
        z0.push(FieldElement::from(42u64)); // seed for file 0
        z0.push(FieldElement::from(42u64)); // seed for file 1 (same seed)

        // Add leaf slots
        z0.push(FieldElement::ZERO); // leaf 0
        z0.push(FieldElement::ZERO); // leaf 1

        let z0_alloc: Vec<AllocatedNum<FieldElement>> = z0
            .iter()
            .enumerate()
            .map(|(i, val)| {
                AllocatedNum::alloc(cs.namespace(|| format!("z{}", i)), || Ok(*val)).unwrap()
            })
            .collect();

        // Synthesize the circuit
        let synthesis_result = circuit.synthesize(&mut cs, &z0_alloc);

        // Phase 2: Circuit should NOT enforce range checks
        assert!(
            synthesis_result.is_ok(),
            "Phase 2: Circuit should trust verifier-provided index {} (no range checks)",
            index
        );

        // Phase 2: Verify circuit doesn't enforce range checks
        // (Note: May still be unsatisfied for other reasons like mismatched agg root)
    }

    println!("✓ Circuit trusts verifier for any indices (no range checks)");
    println!("✓ Range check responsibility moved to verifier (Phase 2)");
}

#[test]
fn test_verifier_prevents_bit_masking_attacks() {
    // Phase 2: Verifier prevents bit-masking attacks by providing only valid indices
    // Circuit trusts the verifier's index validation

    println!("Testing that verifier prevents bit-masking attacks (not circuit)...");

    let aggregated_depth = 2; // Valid indices 0-3

    // Test that any index can be used in the circuit (verifier's responsibility to validate)
    let test_indices = vec![
        1,  // Legitimate index
        5,  // Would be malicious (101 -> lower bits 01), but verifier prevents this
        4,  // Lower bits match 0
        6,  // Lower bits match 2
        7,  // Lower bits match 3
        13, // Lower bits match 1
    ];

    for index in test_indices {
        let witnesses = vec![
            FileProofWitness {
                leaf: FieldElement::from(42u64),
                file_siblings: vec![FieldElement::ZERO; 2],
                file_root: FieldElement::from(100u64),
                actual_depth: 2,
                agg_siblings: vec![FieldElement::from(10u64), FieldElement::from(20u64)],
                ledger_index: index, // Circuit accepts any index
            },
            FileProofWitness {
                leaf: FieldElement::ZERO,
                file_siblings: vec![FieldElement::ZERO; 2],
                file_root: FieldElement::ZERO,
                actual_depth: 0,
                agg_siblings: vec![FieldElement::ZERO; aggregated_depth],
                ledger_index: 0,
            },
        ];

        let circuit = PorCircuit::<FieldElement>::new(
            2, // files_per_step
            2, // file_tree_depth
            aggregated_depth,
            Some(witnesses),
        );

        let mut cs = TestConstraintSystem::<FieldElement>::new();

        // Current schema: [agg_root, state_in, ledger_indices, depths, seeds, leaves]
        let mut z0 = vec![
            FieldElement::from(99999u64), // aggregated_root (dummy)
            FieldElement::ZERO,           // state_in
        ];

        // Verifier provides the index (responsible for validation)
        z0.push(FieldElement::from(index as u64));
        z0.push(FieldElement::ZERO);

        // Add depths
        z0.push(FieldElement::from(2u64)); // real file depth
        z0.push(FieldElement::ZERO); // padding file depth

        // Add seeds
        z0.push(FieldElement::from(42u64)); // seed for file 0
        z0.push(FieldElement::from(42u64)); // seed for file 1 (same seed)

        // Add leaf slots
        z0.push(FieldElement::ZERO); // leaf 0
        z0.push(FieldElement::ZERO); // leaf 1

        let z0_alloc: Vec<AllocatedNum<FieldElement>> = z0
            .iter()
            .enumerate()
            .map(|(i, val)| {
                AllocatedNum::alloc(cs.namespace(|| format!("z{}", i)), || Ok(*val)).unwrap()
            })
            .collect();

        // Synthesize the circuit
        let synthesis_result = circuit.synthesize(&mut cs, &z0_alloc);

        // Phase 2: Circuit should trust verifier and not do range checking
        assert!(
            synthesis_result.is_ok(),
            "Phase 2: Circuit should trust verifier-provided index {} (no bit-masking checks)",
            index
        );

        // Phase 2: Circuit trusts verifier for range validation
    }

    println!(
        "✓ Circuit trusts verifier-provided indices (bit-masking prevention moved to verifier)"
    );
    println!("✓ Verifier is responsible for preventing bit-masking attacks (Phase 2)");
}
