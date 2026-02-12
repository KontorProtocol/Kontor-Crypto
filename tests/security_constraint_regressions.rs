//! Regression tests for circuit-constraint soundness issues.
//!
//! These tests assert security properties that should hold in a sound circuit:
//! 1. Depth gating cannot be bypassed by tampering unconstrained intermediates.
//! 2. Recursive carry-forward public outputs are constrained to their inputs.
//!
//! On vulnerable code, these tests fail.

mod common;

use common::fixtures::{create_circuit_public_inputs, setup_test_scenario, TestConfig};
use ff::Field;
use kontor_crypto::{
    api::{self, generate_circuit_witness, FieldElement},
    circuit::{FileProofWitness, PorCircuit},
};
use nova_snark::frontend::util_cs::test_cs::TestConstraintSystem;
use nova_snark::{
    frontend::{ConstraintSystem, Index, LinearCombination, SynthesisError, Variable},
    traits::circuit::StepCircuit,
};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum VarKey {
    Input(usize),
    Aux(usize),
}

/// Test-only constraint system wrapper that simulates a malicious prover by
/// overriding selected witness assignments while keeping the circuit unchanged.
///
/// This lets us verify whether constraints actually bind those values.
#[derive(Default)]
struct TamperingCS {
    inner: TestConstraintSystem<FieldElement>,
    tamper_carry_outputs_to: Option<FieldElement>,
    tampered_allocs: usize,
    current_namespace: Vec<String>,
    path_to_var: HashMap<String, VarKey>,
    var_usage: HashMap<VarKey, usize>,
}

impl TamperingCS {
    fn with_carry_output_tamper(value: FieldElement) -> Self {
        Self {
            tamper_carry_outputs_to: Some(value),
            ..Self::default()
        }
    }

    fn with_path(&self, name: &str) -> String {
        if self.current_namespace.is_empty() {
            name.to_string()
        } else {
            format!("{}/{}", self.current_namespace.join("/"), name)
        }
    }

    fn tamper_value_for(&self, full_path: &str) -> Option<FieldElement> {
        if let Some(value) = self.tamper_carry_outputs_to {
            if full_path.contains("root_out")
                || full_path.contains("ledger_index_out_")
                || full_path.contains("depth_out_")
                || full_path.contains("seed_out_")
            {
                return Some(value);
            }
        }

        None
    }

    fn is_satisfied(&self) -> bool {
        self.inner.is_satisfied()
    }

    fn tampered_allocs(&self) -> usize {
        self.tampered_allocs
    }

    fn var_key(var: Variable) -> VarKey {
        match var.get_unchecked() {
            Index::Input(i) => VarKey::Input(i),
            Index::Aux(i) => VarKey::Aux(i),
        }
    }

    fn track_usage(&mut self, lc: &LinearCombination<FieldElement>) {
        for (var, _coeff) in lc.iter() {
            let key = Self::var_key(var);
            *self.var_usage.entry(key).or_insert(0) += 1;
        }
    }

    fn count_allocs_matching(&self, pattern: &str) -> usize {
        self.path_to_var
            .keys()
            .filter(|p| p.contains(pattern))
            .count()
    }

    fn count_constrained_allocs_matching(&self, pattern: &str) -> usize {
        self.path_to_var
            .iter()
            .filter(|(path, key)| {
                path.contains(pattern) && self.var_usage.get(key).copied().unwrap_or(0) > 0
            })
            .count()
    }
}

impl ConstraintSystem<FieldElement> for TamperingCS {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, annotation: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<FieldElement, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let name = annotation().into();
        let full_path = self.with_path(&name);
        if let Some(value) = self.tamper_value_for(&full_path) {
            self.tampered_allocs += 1;
            let var = self.inner.alloc(|| name, || Ok(value))?;
            let key = Self::var_key(var);
            self.path_to_var.insert(full_path, key);
            return Ok(var);
        }

        let var = self.inner.alloc(|| name, f)?;
        let key = Self::var_key(var);
        self.path_to_var.insert(full_path, key);
        Ok(var)
    }

    fn alloc_input<F, A, AR>(&mut self, annotation: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<FieldElement, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let name = annotation().into();
        let full_path = self.with_path(&name);
        let var = self.inner.alloc_input(|| name, f)?;
        let key = Self::var_key(var);
        self.path_to_var.insert(full_path, key);
        Ok(var)
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, annotation: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<FieldElement>) -> LinearCombination<FieldElement>,
        LB: FnOnce(LinearCombination<FieldElement>) -> LinearCombination<FieldElement>,
        LC: FnOnce(LinearCombination<FieldElement>) -> LinearCombination<FieldElement>,
    {
        let annotation_name = annotation().into();
        let a_lc = a(LinearCombination::zero());
        let b_lc = b(LinearCombination::zero());
        let c_lc = c(LinearCombination::zero());

        self.track_usage(&a_lc);
        self.track_usage(&b_lc);
        self.track_usage(&c_lc);

        self.inner.enforce(
            || annotation_name,
            |_| a_lc.clone(),
            |_| b_lc.clone(),
            |_| c_lc.clone(),
        )
    }

    fn push_namespace<NR, N>(&mut self, name_fn: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        let name = name_fn().into();
        self.current_namespace.push(name.clone());
        self.inner.push_namespace(|| name)
    }

    fn pop_namespace(&mut self) {
        let _ = self.current_namespace.pop();
        self.inner.pop_namespace()
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}

#[test]
fn regression_sum_active_chain_variables_must_be_constrained() {
    let setup = setup_test_scenario(&TestConfig::default()).expect("fixture setup must succeed");
    let challenge = &setup.challenges[0];
    let metadata = &challenge.file_metadata;

    let public_depth = api::tree_depth_from_metadata(metadata);
    assert!(public_depth > 0, "fixture must produce a non-zero depth");

    let file_tree_depth = setup.params.file_tree_depth;
    let honest_witness = FileProofWitness {
        leaf: metadata.root,
        file_siblings: vec![FieldElement::ZERO; file_tree_depth],
        file_root: metadata.root,
        actual_depth: public_depth,
        agg_siblings: vec![],
        ledger_index: 0,
    };

    let circuit = PorCircuit::new(1, file_tree_depth, 0, Some(vec![honest_witness]));

    // No tampering: structural check only.
    let mut cs = TamperingCS::default();

    let z = create_circuit_public_inputs(
        &mut cs,
        metadata.root,
        FieldElement::ZERO,
        challenge.seed,
        &[0],
        &[public_depth],
        &[FieldElement::ZERO],
    );

    circuit
        .synthesize(&mut cs, &z)
        .expect("synthesis should complete");

    let sum_active_allocs = cs.count_allocs_matching("sum_active_file0_lvl");
    let constrained_sum_active_allocs =
        cs.count_constrained_allocs_matching("sum_active_file0_lvl");

    assert!(
        sum_active_allocs > 0,
        "test did not find any sum_active allocations"
    );

    assert!(
        constrained_sum_active_allocs == sum_active_allocs,
        "SECURITY REGRESSION: only {}/{} sum_active chain vars are constrained",
        constrained_sum_active_allocs,
        sum_active_allocs
    );
}

#[test]
fn regression_recursive_carry_outputs_must_be_constrained() {
    let setup = setup_test_scenario(&TestConfig::default()).expect("fixture setup must succeed");
    let ledger = setup
        .ledger_ref()
        .expect("default fixture should provide a ledger");
    let file_refs = setup.file_refs();
    let sorted_challenges_refs: Vec<_> = setup.challenges.iter().collect();

    // Build an honest witness for step 0.
    let (witness, _new_state) = generate_circuit_witness(
        &sorted_challenges_refs,
        Some(&file_refs),
        ledger,
        setup.params.file_tree_depth,
        setup.params.max_supported_depth,
        FieldElement::ZERO,
        setup.params.aggregated_tree_depth,
        0,
        &[0],
    )
    .expect("witness generation should succeed");

    let circuit = PorCircuit::new(
        1,
        setup.params.file_tree_depth,
        setup.params.aggregated_tree_depth,
        Some(witness.witnesses().to_vec()),
    );

    let challenge = &setup.challenges[0];
    let public_depth = api::tree_depth_from_metadata(&challenge.file_metadata);

    // Simulate malicious prover assignment: tamper the recursive carry-forward outputs.
    let mut cs = TamperingCS::with_carry_output_tamper(FieldElement::from(999_999u64));
    let z = create_circuit_public_inputs(
        &mut cs,
        challenge.file_metadata.root,
        FieldElement::ZERO,
        challenge.seed,
        &[0],
        &[public_depth],
        &[FieldElement::ZERO],
    );

    circuit
        .synthesize(&mut cs, &z)
        .expect("synthesis should complete");

    assert!(
        cs.tampered_allocs() >= 4,
        "test failed to tamper expected carry output allocations"
    );

    assert!(
        !cs.is_satisfied(),
        "SECURITY REGRESSION: tampered recursive carry outputs are satisfiable without equality constraints"
    );
}
