//! Regression tests for Merkle depth gating constraints.
//!
//! The file Merkle path gadget supports a variable "effective depth" via per-level active flags.
//! For soundness, those flags must be prefix-ones: [1, 1, ..., 1, 0, 0, ...].

use ff::Field;
use kontor_crypto::api::FieldElement;
use kontor_crypto::circuit::{FileProofWitness, PorCircuit};
use kontor_crypto::poseidon::calculate_root_commitment;
use nova_snark::frontend::util_cs::test_cs::TestConstraintSystem;
use nova_snark::traits::circuit::StepCircuit;

mod common;
use common::fixtures::create_circuit_public_inputs;

#[test]
fn regression_active_flags_prefix_constraints_present() {
    let files_per_step = 1;
    let file_tree_depth = 3;
    let aggregated_tree_depth = 0;
    let actual_depth = 2;

    let witness = FileProofWitness {
        leaf: FieldElement::from(7u64),
        file_siblings: vec![FieldElement::ZERO; file_tree_depth],
        file_root: FieldElement::ZERO,
        actual_depth,
        agg_siblings: vec![],
        ledger_index: 0,
    };

    let circuit = PorCircuit::<FieldElement>::new(
        files_per_step,
        file_tree_depth,
        aggregated_tree_depth,
        Some(vec![witness]),
    );

    let mut cs = TestConstraintSystem::<FieldElement>::new();

    let root = FieldElement::from(123u64);
    let z = create_circuit_public_inputs(
        &mut cs,
        root,
        FieldElement::ZERO,
        FieldElement::from(42u64),
        &[0],
        &[actual_depth],
        &[calculate_root_commitment(
            root,
            FieldElement::from(actual_depth as u64),
        )],
        &[FieldElement::ZERO],
    );
    let _ = circuit.synthesize(&mut cs, &z).unwrap();

    // We can't directly introspect constraint names without reaching into private fields,
    // so we assert on the Debug representation to ensure the prefix constraints exist.
    let dbg = format!("{cs:?}");
    assert!(
        dbg.contains("active_flags_prefix_file0_lvl1"),
        "missing prefix constraint for level 1"
    );
    assert!(
        dbg.contains("active_flags_prefix_file0_lvl2"),
        "missing prefix constraint for level 2"
    );
    assert!(
        dbg.contains("sum_active_init_is_zero_file0"),
        "missing sum_active initializer zero-binding constraint"
    );
}
