//! Regression tests for canonical public inputs on inactive (padding) slots.
//!
//! Rationale:
//! - The circuit has fixed arity and always includes per-slot public inputs.
//! - For padding slots (public_depth == 0), those public inputs must be forced to canonical
//!   zeros to avoid ambiguous / non-canonical statements.

use ff::Field;
use kontor_crypto::api::FieldElement;
use kontor_crypto::circuit::PorCircuit;
use nova_snark::frontend::util_cs::test_cs::TestConstraintSystem;
use nova_snark::frontend::ConstraintSystem;
use nova_snark::traits::circuit::StepCircuit;

mod common;
use common::fixtures::create_padding_witness;

#[allow(clippy::too_many_arguments)]
fn alloc_public_inputs(
    cs: &mut TestConstraintSystem<FieldElement>,
    files_per_step: usize,
    agg_root: FieldElement,
    state_in: FieldElement,
    ledger_indices: &[FieldElement],
    depths: &[FieldElement],
    seeds: &[FieldElement],
    expected_rcs: &[FieldElement],
    leaf_inputs: &[FieldElement],
) -> Vec<nova_snark::frontend::gadgets::num::AllocatedNum<FieldElement>> {
    assert_eq!(ledger_indices.len(), files_per_step);
    assert_eq!(depths.len(), files_per_step);
    assert_eq!(seeds.len(), files_per_step);
    assert_eq!(expected_rcs.len(), files_per_step);
    assert_eq!(leaf_inputs.len(), files_per_step);

    let mut z = Vec::with_capacity(kontor_crypto::config::circuit_arity(files_per_step));
    z.push(
        nova_snark::frontend::gadgets::num::AllocatedNum::alloc(
            cs.namespace(|| "agg_root"),
            || Ok(agg_root),
        )
        .unwrap(),
    );
    z.push(
        nova_snark::frontend::gadgets::num::AllocatedNum::alloc(
            cs.namespace(|| "state_in"),
            || Ok(state_in),
        )
        .unwrap(),
    );

    for (i, v) in ledger_indices.iter().copied().enumerate() {
        z.push(
            nova_snark::frontend::gadgets::num::AllocatedNum::alloc(
                cs.namespace(|| format!("ledger_index_{}", i)),
                || Ok(v),
            )
            .unwrap(),
        );
    }
    for (i, v) in depths.iter().copied().enumerate() {
        z.push(
            nova_snark::frontend::gadgets::num::AllocatedNum::alloc(
                cs.namespace(|| format!("depth_{}", i)),
                || Ok(v),
            )
            .unwrap(),
        );
    }
    for (i, v) in seeds.iter().copied().enumerate() {
        z.push(
            nova_snark::frontend::gadgets::num::AllocatedNum::alloc(
                cs.namespace(|| format!("seed_{}", i)),
                || Ok(v),
            )
            .unwrap(),
        );
    }
    for (i, v) in expected_rcs.iter().copied().enumerate() {
        z.push(
            nova_snark::frontend::gadgets::num::AllocatedNum::alloc(
                cs.namespace(|| format!("expected_rc_{}", i)),
                || Ok(v),
            )
            .unwrap(),
        );
    }
    for (i, v) in leaf_inputs.iter().copied().enumerate() {
        z.push(
            nova_snark::frontend::gadgets::num::AllocatedNum::alloc(
                cs.namespace(|| format!("leaf_input_{}", i)),
                || Ok(v),
            )
            .unwrap(),
        );
    }

    z
}

#[test]
fn regression_padding_slot_public_inputs_must_be_canonical_zeros() {
    let files_per_step = 4;
    let file_tree_depth = 2;
    let aggregated_tree_depth = 2;

    // All padding witnesses: actual_depth == 0 for all slots.
    let witnesses = (0..files_per_step)
        .map(|_| create_padding_witness(file_tree_depth, aggregated_tree_depth))
        .collect::<Vec<_>>();

    let circuit = PorCircuit::<FieldElement>::new(
        files_per_step,
        file_tree_depth,
        aggregated_tree_depth,
        Some(witnesses),
    );

    // Baseline: all inactive-slot public inputs are zero -> circuit must satisfy.
    let mut cs = TestConstraintSystem::<FieldElement>::new();
    let z_ok = alloc_public_inputs(
        &mut cs,
        files_per_step,
        FieldElement::ZERO,
        FieldElement::ZERO,
        &[FieldElement::ZERO; 4],
        &[FieldElement::ZERO; 4],
        &[FieldElement::ZERO; 4],
        &[FieldElement::ZERO; 4],
        &[FieldElement::ZERO; 4],
    );
    let _ = circuit.synthesize(&mut cs, &z_ok).unwrap();
    assert!(
        cs.is_satisfied(),
        "baseline padding circuit must be satisfied"
    );

    let layout = kontor_crypto::config::PublicIOLayout::new(files_per_step);

    // Helper: run a single mutation against slot 0 (which is padding/inactive).
    let run = |label: &str, mut z_vals: Vec<FieldElement>| {
        let mut cs = TestConstraintSystem::<FieldElement>::new();
        let z_alloc = z_vals
            .drain(..)
            .enumerate()
            .map(|(idx, v)| {
                nova_snark::frontend::gadgets::num::AllocatedNum::alloc(
                    cs.namespace(|| format!("z_{}", idx)),
                    || Ok(v),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let _ = circuit.synthesize(&mut cs, &z_alloc).unwrap();
        assert!(
            !cs.is_satisfied(),
            "SECURITY REGRESSION: padding slot {label} accepted as non-zero"
        );
    };

    let mut z_base = vec![FieldElement::ZERO; kontor_crypto::config::circuit_arity(files_per_step)];
    z_base[layout.idx_agg_root()] = FieldElement::ZERO;
    z_base[layout.idx_state_in()] = FieldElement::ZERO;

    let mut z = z_base.clone();
    z[layout.idx_ledger(0)] = FieldElement::ONE;
    run("ledger_index", z);

    let mut z = z_base.clone();
    z[layout.idx_seed(0)] = FieldElement::ONE;
    run("seed", z);

    let mut z = z_base.clone();
    z[layout.idx_expected_rc(0)] = FieldElement::ONE;
    run("expected_rc", z);

    let mut z = z_base;
    z[layout.idx_leaf(0)] = FieldElement::ONE;
    run("leaf_input", z);
}
