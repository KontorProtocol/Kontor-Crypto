//! Circuit structure uniformity tests.
//!
//! These tests verify that PorCircuit maintains uniform constraint structure
//! regardless of the actual file depths being proven. This is critical for
//! Nova's correctness.

use ff::Field;
use kontor_crypto::{
    api::FieldElement,
    circuit::{FileProofWitness, PorCircuit},
};

mod common;
use common::fixtures::{create_witness, create_witness_with_siblings};

#[test]
#[cfg(debug_assertions)]
fn test_mixed_depth_proofs_have_identical_fingerprints() {
    use kontor_crypto::circuit::debug::fingerprint_shape;

    println!("Testing circuit uniformity with fingerprinting...");

    // Use small depths for fast testing
    const TEST_DEPTH: usize = 3; // depth 3 = 8 leaves, fast for testing
    const FILES_PER_STEP: usize = 2;
    const AGG_DEPTH: usize = 1;

    // Create multi-file circuits for proofs with files of different depths
    // The critical test: different file depths should produce IDENTICAL circuit structures

    let witness1_file1 = create_witness(
        FieldElement::from(1u64),
        FieldElement::from(100u64),
        0, // depth-0 file
        TEST_DEPTH,
        0,
        AGG_DEPTH,
        true,
    );

    let witness1_file2 = create_witness(
        FieldElement::from(2u64),
        FieldElement::from(200u64),
        2, // depth-2 file
        TEST_DEPTH,
        1,
        AGG_DEPTH,
        true,
    );

    let circuit1 = PorCircuit::<FieldElement>::new(
        FILES_PER_STEP,
        TEST_DEPTH,
        AGG_DEPTH,
        Some(vec![witness1_file1, witness1_file2]),
    );

    // Same setup but with file depths swapped in the witness order
    let witness2_file1 = create_witness(
        FieldElement::from(3u64),
        FieldElement::from(300u64),
        3, // depth-3 file (full depth)
        TEST_DEPTH,
        0,
        AGG_DEPTH,
        true,
    );

    let witness2_file2 = create_witness(
        FieldElement::from(4u64),
        FieldElement::from(400u64),
        1, // depth-1 file
        TEST_DEPTH,
        1,
        AGG_DEPTH,
        true,
    );

    let circuit2 = PorCircuit::<FieldElement>::new(
        FILES_PER_STEP,
        TEST_DEPTH,
        AGG_DEPTH,
        Some(vec![witness2_file1, witness2_file2]),
    );

    // Get fingerprints for both circuits
    let fp1 = fingerprint_shape(&circuit1);
    let fp2 = fingerprint_shape(&circuit2);

    // Create a circuit with mixed depths (different from above)
    let witness3_file1 = create_witness_with_siblings(
        FieldElement::from(99u64),
        vec![FieldElement::from(1u64); TEST_DEPTH],
        FieldElement::from(999u64),
        2, // Same actual depth as circuit1's file2
        vec![FieldElement::ZERO; AGG_DEPTH],
        0,
        true,
    );

    let witness3_file2 = create_witness_with_siblings(
        FieldElement::from(88u64),
        vec![FieldElement::from(2u64); TEST_DEPTH],
        FieldElement::from(888u64),
        0, // Same actual depth as circuit1's file1
        vec![FieldElement::ZERO; AGG_DEPTH],
        1,
        true,
    );

    let circuit3 = PorCircuit::<FieldElement>::new(
        FILES_PER_STEP,
        TEST_DEPTH,
        AGG_DEPTH,
        Some(vec![witness3_file1, witness3_file2]),
    );
    let fp3 = fingerprint_shape(&circuit3);

    // Single-file circuits should also have uniform structure
    let single_witness1 = create_witness(
        FieldElement::from(77u64),
        FieldElement::ZERO, // Computed in-circuit for single-file
        0,                  // depth-0
        TEST_DEPTH,
        0,
        0, // No aggregation
        true,
    );

    let single_circuit1 = PorCircuit::<FieldElement>::new(
        1, // Single file
        TEST_DEPTH,
        0, // No aggregation
        Some(vec![single_witness1]),
    );
    let single_fp1 = fingerprint_shape(&single_circuit1);

    // Another single-file circuit with different depth
    let single_witness2 = create_witness_with_siblings(
        FieldElement::from(88u64),
        vec![FieldElement::from(1u64); TEST_DEPTH],
        FieldElement::ZERO, // Computed in-circuit for single-file
        3,                  // different depth
        vec![],
        0,
        true,
    );

    let single_circuit2 = PorCircuit::<FieldElement>::new(
        1, // Single file
        TEST_DEPTH,
        0, // No aggregation
        Some(vec![single_witness2]),
    );
    let single_fp2 = fingerprint_shape(&single_circuit2);

    // All multi-file circuits should have identical fingerprints
    assert_eq!(
        fp1, fp2,
        "Multi-file circuits with different file depths must have identical R1CS structure!"
    );
    assert_eq!(
        fp1, fp3,
        "Multi-file circuits with different witness values must have identical R1CS structure!"
    );

    // All single-file circuits should have identical fingerprints
    assert_eq!(
        single_fp1, single_fp2,
        "Single-file circuits with different depths must have identical R1CS structure!"
    );

    println!("✓ All circuits have uniform structure");
}

#[test]
fn test_setup_circuit_has_correct_structure() {
    // Test that a setup circuit (no witnesses) has the expected structure
    const TEST_DEPTH: usize = 2; // Small depth for fast testing

    // Single-file setup circuit
    let single_circuit = PorCircuit::<FieldElement>::new(
        1, TEST_DEPTH, 0, None, // No witnesses for setup
    );

    assert_eq!(single_circuit.file_tree_depth, TEST_DEPTH);
    assert_eq!(single_circuit.files_per_step, 1);
    assert_eq!(single_circuit.aggregated_tree_depth, 0);

    // Multi-file setup circuit with aggregation
    let setup_circuit = PorCircuit::<FieldElement>::new(
        4, // 4 files per step
        TEST_DEPTH, 2,    // aggregation depth
        None, // No witnesses for setup
    );

    assert_eq!(setup_circuit.file_tree_depth, TEST_DEPTH);
    assert_eq!(setup_circuit.files_per_step, 4);
    assert_eq!(setup_circuit.aggregated_tree_depth, 2);
}

#[test]
fn test_circuit_witness_structure() {
    // Test that the witness structure is correct for different scenarios
    const TEST_DEPTH: usize = 2; // Small depth for fast testing
    const FILES: usize = 4;
    const AGG_DEPTH: usize = 2;

    // Create some test witnesses (fewer than FILES to test padding)
    let mut witnesses = Vec::new();
    for i in 0..3 {
        // Only 3 witnesses, will be padded to 4
        witnesses.push(FileProofWitness {
            leaf: FieldElement::from(i as u64 + 1),
            file_siblings: vec![FieldElement::ZERO; TEST_DEPTH],
            file_root: FieldElement::from((i + 100) as u64),
            actual_depth: i % 3, // Varying depths
            agg_siblings: vec![FieldElement::ZERO; AGG_DEPTH],
            ledger_index: i,
        });
    }

    let circuit = PorCircuit::<FieldElement>::new(FILES, TEST_DEPTH, AGG_DEPTH, Some(witnesses));

    // Basic validation
    assert_eq!(circuit.file_tree_depth, TEST_DEPTH);
    assert_eq!(circuit.files_per_step, FILES);
    assert_eq!(circuit.aggregated_tree_depth, AGG_DEPTH);

    // Check witness structure
    assert!(circuit.witness.is_some(), "Circuit should have witnesses");
}
