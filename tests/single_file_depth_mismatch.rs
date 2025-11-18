//! Test that single-file proofs reject public depth mismatches
//!
//! This test verifies that in single-file mode, the circuit enforces
//! that the public depth matches the actual file depth.

use nova_snark::traits::circuit::StepCircuit;
use nova_snark::frontend::util_cs::test_cs::TestConstraintSystem;
use ff::Field;
use kontor_crypto::{
    api::FieldElement,
    circuit::CircuitWitness,
    circuit::{FileProofWitness, PorCircuit},
};

mod common;
use common::fixtures::create_circuit_public_inputs;

#[test]
fn test_single_file_depth_mismatch_rejected() {
    // Test that providing wrong public depth for a single-file proof fails
    println!("Testing single-file depth mismatch rejection...");

    // Create a witness for a file with actual_depth = 2
    let witness = FileProofWitness {
        leaf: FieldElement::from(100u64),
        file_siblings: vec![FieldElement::ZERO; 3], // Padded to file_tree_depth=3
        file_root: FieldElement::from(200u64),
        actual_depth: 2,      // Real depth is 2
        agg_siblings: vec![], // Single-file: no aggregation
        ledger_index: 0,
    };

    let circuit_witness = CircuitWitness::new(vec![witness], 1);
    let circuit = PorCircuit::new(
        1, // files_per_step (single-file)
        3, // file_tree_depth
        0, // aggregated_tree_depth (single-file)
        Some(circuit_witness.witnesses().to_vec()),
    );

    let mut cs = TestConstraintSystem::<FieldElement>::new();

    // Create public inputs with WRONG depth (claim depth=1 when actual is 2)
    let z_in = create_circuit_public_inputs(
        &mut cs,
        FieldElement::from(999u64), // aggregated_root
        FieldElement::ZERO,         // state_in
        FieldElement::from(42u64),  // seed
        &[0],                       // ledger_indices
        &[1],                       // depths: WRONG! claim depth=1 when actual=2
        &[FieldElement::ZERO],      // leaves
    );

    // Synthesize the circuit
    let result = circuit.synthesize(&mut cs, &z_in);
    assert!(result.is_ok(), "Circuit synthesis should succeed");

    // The circuit should NOT be satisfied due to depth mismatch
    // sum(active_flags) = 2 but public_depth = 1
    assert!(
        !cs.is_satisfied(),
        "Circuit should reject depth mismatch: witness depth=2 vs public depth=1"
    );

    println!("✓ Single-file depth mismatch correctly rejected");
}

#[test]
fn test_single_file_zero_depth_accepted() {
    // Test that a real single-file with depth=0 works correctly
    println!("Testing single-file zero depth acceptance...");

    // Create a witness for a file with actual_depth = 0 (minimal case)
    let witness = FileProofWitness {
        leaf: FieldElement::from(100u64),
        file_siblings: vec![FieldElement::ZERO; 3], // Padded to file_tree_depth=3
        file_root: FieldElement::from(100u64),      // For depth=0, root = leaf
        actual_depth: 0,                            // Real depth is 0
        agg_siblings: vec![],                       // Single-file: no aggregation
        ledger_index: 0,
    };

    let circuit_witness = CircuitWitness::new(vec![witness], 1);
    let circuit = PorCircuit::new(
        1, // files_per_step (single-file)
        3, // file_tree_depth
        0, // aggregated_tree_depth (single-file)
        Some(circuit_witness.witnesses().to_vec()),
    );

    let mut cs = TestConstraintSystem::<FieldElement>::new();

    // Create public inputs with CORRECT depth=0
    let z_in = create_circuit_public_inputs(
        &mut cs,
        FieldElement::from(100u64), // aggregated_root (matches leaf for depth=0)
        FieldElement::ZERO,         // state_in
        FieldElement::from(42u64),  // seed
        &[0],                       // ledger_indices
        &[0],                       // depths: CORRECT! depth=0 matches actual
        &[FieldElement::ZERO],      // leaves
    );

    // Synthesize the circuit
    let result = circuit.synthesize(&mut cs, &z_in);
    assert!(result.is_ok(), "Circuit synthesis should succeed");

    // The circuit should be satisfied with correct depth=0
    assert!(
        cs.is_satisfied(),
        "Circuit should accept correct depth=0: witness depth=0 and public depth=0"
    );

    println!("✓ Single-file zero depth accepted");
}
