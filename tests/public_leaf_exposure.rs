//! Tests for public leaf exposure functionality
//!
//! This module tests that:
//! 1. Leaves are correctly exposed as public outputs
//! 2. Round-trip encoding works correctly
//! 3. Public leaves match private witnesses
//! 4. Padding slots output zero

use ff::Field;
use kontor_crypto::{
    api::{self, Challenge, FieldElement},
    circuit::PorCircuit,
    leaf_to_bytes31, merkle, FileLedger,
};
use nova_snark::frontend::util_cs::test_cs::TestConstraintSystem;
use nova_snark::traits::circuit::StepCircuit;
use std::collections::BTreeMap;

mod common;
use common::{
    create_single_file_ledger,
    fixtures::{create_circuit_public_inputs, create_padding_witness, create_witness},
};

#[test]
fn test_public_leaf_binding() {
    // Test that public leaf outputs match the private leaf values for real files
    // and are zero for padding slots
    println!("Testing public leaf binding...");

    // Create a simple witness with 2 real files and 2 padding slots
    let witnesses = vec![
        create_witness(
            FieldElement::from(42u64),
            FieldElement::from(100u64),
            2,
            2,
            0,
            2,
            true,
        ),
        create_witness(
            FieldElement::from(123u64),
            FieldElement::from(200u64),
            2,
            2,
            1,
            2,
            true,
        ),
        create_padding_witness(2, 2),
        create_padding_witness(2, 2),
    ];

    let circuit = PorCircuit::<FieldElement>::new(
        4, // files_per_step
        2, // file_tree_depth
        2, // aggregated_tree_depth
        Some(witnesses.clone()),
    );

    let mut cs = TestConstraintSystem::<FieldElement>::new();

    // Create public inputs with leaf slots
    let z = create_circuit_public_inputs(
        &mut cs,
        FieldElement::from(999u64),
        FieldElement::ZERO,
        FieldElement::from(42u64),
        &[0, 1, 2, 3], // ledger_indices
        &[2, 2, 0, 0], // depths (2 real files with depth 2, 2 padding with depth 0)
        &[FieldElement::ZERO; 4],
    );

    // Synthesize the circuit
    let outputs = circuit.synthesize(&mut cs, &z).unwrap();

    // Check that the public leaf outputs match expectations
    // Current schema: [2 fixed] + [4 ledger_indices] + [4 depths] + [4 seeds] + [4 leaves]
    let leaf_start_idx = 2 + 4 + 4 + 4; // 14

    // First leaf should be 42 (real file)
    assert_eq!(
        outputs[leaf_start_idx].get_value(),
        Some(FieldElement::from(42u64)),
        "First public leaf should match witness"
    );

    // Second leaf should be 123 (real file)
    assert_eq!(
        outputs[leaf_start_idx + 1].get_value(),
        Some(FieldElement::from(123u64)),
        "Second public leaf should match witness"
    );

    // Third leaf should be 0 (padding)
    assert_eq!(
        outputs[leaf_start_idx + 2].get_value(),
        Some(FieldElement::ZERO),
        "Third public leaf should be zero (padding)"
    );

    // Fourth leaf should be 0 (padding)
    assert_eq!(
        outputs[leaf_start_idx + 3].get_value(),
        Some(FieldElement::ZERO),
        "Fourth public leaf should be zero (padding)"
    );

    println!("✓ Public leaves correctly match private witnesses");
}

#[test]
fn test_bytes31_field_helpers_round_trip_and_known_values() {
    use kontor_crypto::utils::{bytes31_to_field_le, field_to_bytes31_le};

    // Round-trip a few patterns
    let patterns: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x01],
        vec![0x00, 0x01],
        vec![0x12, 0x34, 0x56, 0x78],
        (0u8..31).collect(),
        vec![0xFF; 31],
    ];

    for p in patterns {
        let fe = bytes31_to_field_le::<FieldElement>(&p);
        let back = field_to_bytes31_le(&fe);
        assert_eq!(back[..p.len()], p[..]);
        assert!(back[p.len()..].iter().all(|&b| b == 0));
    }

    // Known small numbers
    for i in 0u8..=16 {
        let fe = bytes31_to_field_le::<FieldElement>(&[i]);
        assert_eq!(fe, FieldElement::from(i as u64));
    }
}

#[test]
fn test_leaf_round_trip_encoding() {
    // Test that we can encode bytes to a leaf and decode back correctly
    println!("Testing leaf round-trip encoding...");

    // Test various byte patterns
    let test_cases = vec![
        vec![0x01],                    // Single byte
        vec![0x00, 0x01],              // Two bytes (LE should be 256)
        vec![0xFF; 31],                // Maximum 31 bytes
        vec![0x12, 0x34, 0x56, 0x78],  // Multi-byte pattern
        (0u8..31).collect::<Vec<_>>(), // Sequential bytes
    ];

    for test_data in test_cases {
        // Encode to field element
        let leaf_field = merkle::get_leaf_hash(&test_data).unwrap();

        // Decode back to bytes
        let decoded_bytes = leaf_to_bytes31(&leaf_field);

        // Compare (only up to original length, rest should be zeros)
        for i in 0..test_data.len() {
            assert_eq!(
                decoded_bytes[i], test_data[i],
                "Byte {} mismatch for data {:?}",
                i, test_data
            );
        }

        // Rest should be zeros
        for (i, b) in decoded_bytes
            .iter()
            .enumerate()
            .skip(test_data.len())
            .take(31 - test_data.len())
        {
            assert_eq!(*b, 0, "Byte {} should be zero for data {:?}", i, test_data);
        }
    }

    println!("✓ Round-trip encoding works correctly");
}

#[test]
fn test_public_leaves_in_proof() {
    // Test end-to-end proof generation and verification with public leaves
    println!("Testing public leaves in actual proof...");

    // Create test data
    let test_data = b"This is test data for public leaf exposure!";

    let (prepared, metadata) =
        api::prepare_file(test_data, "test_file.dat", b"").expect("Failed to prepare file");

    // Create challenge
    let challenge = Challenge::new_test(metadata.clone(), 1000, 1, FieldElement::from(42u64));

    let mut files = BTreeMap::new();
    files.insert(metadata.file_id.clone(), &prepared);

    // Create ledger for unified API
    let ledger = create_single_file_ledger(&metadata);

    // Generate proof
    let system = kontor_crypto::api::PorSystem::new(&ledger);
    let files_vec: Vec<&_> = files.values().copied().collect();
    let proof = system
        .prove(files_vec, std::slice::from_ref(&challenge))
        .expect("Failed to generate proof");

    // Verify proof
    assert!(
        system
            .verify(&proof, &[challenge])
            .expect("Verification failed"),
        "Proof should verify"
    );

    // Note: The compressed proof doesn't expose z_T directly through the API.
    // The fact that verification succeeds means the public leaves were correctly
    // computed and verified. The actual leaf exposure is tested in the
    // test_public_leaf_binding test above at the circuit level.

    println!("✓ Public leaves work correctly in end-to-end proof");
}

#[test]
fn test_multi_file_public_leaves() {
    // Test that multi-file proofs correctly expose leaves for each file
    println!("Testing multi-file public leaf exposure...");

    // Create two files
    let data1 = b"File 1 data";
    let data2 = b"File 2 data";

    let (prepared1, metadata1) =
        api::prepare_file(data1, "test_file.dat", b"").expect("Failed to prepare file 1");

    let (prepared2, metadata2) =
        api::prepare_file(data2, "test_file.dat", b"").expect("Failed to prepare file 2");

    // Create ledger
    let mut ledger = FileLedger::new();
    ledger.add_file(&metadata1).unwrap();
    ledger.add_file(&metadata2).unwrap();

    // Create challenges
    let seed = FieldElement::from(42u64);
    let challenges = vec![
        Challenge::new_test(metadata1.clone(), 1000, 1, seed),
        Challenge::new_test(metadata2.clone(), 1000, 1, seed),
    ];

    let mut files = BTreeMap::new();
    files.insert(metadata1.file_id, &prepared1);
    files.insert(metadata2.file_id, &prepared2);

    // Generate and verify proof
    let system = kontor_crypto::api::PorSystem::new(&ledger);
    let files_vec: Vec<&_> = files.values().copied().collect();
    let proof = system
        .prove(files_vec, &challenges)
        .expect("Failed to generate multi-file proof");

    assert!(
        system
            .verify(&proof, &challenges)
            .expect("Verification failed"),
        "Multi-file proof should verify"
    );

    // Note: The compressed proof doesn't expose z_T directly through the API.
    // The fact that verification succeeds with the expanded arity (including leaves)
    // means the public leaves were correctly computed and verified.

    println!("✓ Multi-file public leaves work correctly");
}
