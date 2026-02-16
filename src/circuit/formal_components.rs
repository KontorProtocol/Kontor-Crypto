//! Component-focused formal circuits built from production gadgets.
//!
//! These are used by Picus formal verification to prove determinism of smaller,
//! compositional sub-circuits instead of the full monolithic `PorCircuit`.

use ff::{PrimeField, PrimeFieldBits};
use nova_snark::{
    frontend::{
        gadgets::{
            boolean::{AllocatedBit, Boolean},
            num::AllocatedNum,
        },
        ConstraintSystem, Index, SynthesisError,
    },
    traits::circuit::StepCircuit,
};

use crate::config::PublicIOLayout;
use crate::poseidon::domain_tags;

use super::gadgets::{conditional_select, poseidon_hash_tagged_gadget};
use super::gadgets::{verify_aggregation_path_gated, verify_merkle_path_gated};
use super::witness::{CircuitWitness, FileProofWitness};

#[derive(Clone, Debug, Default)]
pub struct ComponentWitnessTrace {
    pub leaf_aux: Vec<usize>,
    pub file_sibling_aux: Vec<usize>,
    pub agg_sibling_aux: Vec<usize>,
    pub path_bit_aux: Vec<usize>,
    pub gate_bit_aux: Vec<usize>,
}

impl ComponentWitnessTrace {
    pub fn leafpath_aux_indices(&self) -> Vec<usize> {
        let mut aux = Vec::new();
        aux.extend(self.leaf_aux.iter().copied());
        aux.extend(self.file_sibling_aux.iter().copied());
        aux.extend(self.agg_sibling_aux.iter().copied());
        aux.extend(self.path_bit_aux.iter().copied());
        aux.extend(self.gate_bit_aux.iter().copied());
        aux.sort_unstable();
        aux.dedup();
        aux
    }
}

fn aux_index<F: PrimeField>(n: &AllocatedNum<F>) -> Result<usize, SynthesisError> {
    match n.get_variable().get_unchecked() {
        Index::Aux(i) => Ok(i),
        _ => Err(SynthesisError::Unsatisfiable),
    }
}

fn bool_aux_index(b: &Boolean) -> Option<usize> {
    let idx = match b {
        Boolean::Is(bit) | Boolean::Not(bit) => bit.get_variable(),
        Boolean::Constant(_) => return None,
    };
    match idx.get_unchecked() {
        Index::Aux(i) => Some(i),
        _ => None,
    }
}

fn copy_all_inputs_to_aux<F: PrimeField + PrimeFieldBits, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    z: &[AllocatedNum<F>],
    enforce_copy: bool,
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let mut out = Vec::with_capacity(z.len());
    for (i, input) in z.iter().enumerate() {
        let copied = AllocatedNum::alloc(cs.namespace(|| format!("out_copy_{i}")), || {
            Ok(input.get_value().unwrap_or(F::ZERO))
        })?;
        if enforce_copy {
            // Encode equality as (expr + 1) * 1 = 1 so C-matrix rows are non-empty.
            cs.enforce(
                || format!("out_copy_eq_{i}"),
                |lc| lc + copied.get_variable() - input.get_variable() + CS::one(),
                |lc| lc + CS::one(),
                |lc| lc + CS::one(),
            );
        }
        out.push(copied);
    }
    if !enforce_copy {
        // Keep mutant circuits structurally non-empty for downstream sparse R1CS handling.
        cs.enforce(
            || "mutant_tautology",
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );
    }
    Ok(out)
}

fn witness_for_slot<F: PrimeField>(
    witness: Option<&CircuitWitness<F>>,
    slot: usize,
    file_tree_depth: usize,
    aggregated_tree_depth: usize,
) -> FileProofWitness<F> {
    if let Some(w) = witness.and_then(|w| w.witnesses().get(slot)) {
        return w.clone();
    }

    FileProofWitness {
        leaf: F::ZERO,
        file_siblings: vec![F::ZERO; file_tree_depth],
        file_root: F::ZERO,
        actual_depth: 0,
        agg_siblings: vec![F::ZERO; aggregated_tree_depth],
        ledger_index: 0,
    }
}

fn depth_positive_bit<F: PrimeField + PrimeFieldBits, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    depth_public: &AllocatedNum<F>,
    label_prefix: &str,
    mut trace: Option<&mut ComponentWitnessTrace>,
) -> Result<Boolean, SynthesisError> {
    let depth_bits = {
        let mut ns = cs.namespace(|| format!("{label_prefix}_depth_bits"));
        depth_public.to_bits_le(&mut ns)?
    };

    if let Some(t) = trace.as_deref_mut() {
        for b in &depth_bits {
            if let Some(i) = bool_aux_index(b) {
                t.gate_bit_aux.push(i);
            }
        }
    }

    let mut depth_positive = Boolean::constant(false);
    for (bit_idx, bit) in depth_bits.iter().enumerate() {
        depth_positive = Boolean::or(
            cs.namespace(|| format!("{label_prefix}_depth_positive_or_{bit_idx}")),
            &depth_positive,
            bit,
        )?;
    }

    if let Some(t) = trace {
        if let Some(i) = bool_aux_index(&depth_positive) {
            t.gate_bit_aux.push(i);
        }
    }

    Ok(depth_positive)
}

pub fn synthesize_challenge_component<F: PrimeField + PrimeFieldBits, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    z: &[AllocatedNum<F>],
    files_per_step: usize,
    aggregated_tree_depth: usize,
    mutant: bool,
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let layout = PublicIOLayout::new(files_per_step);
    let mut out = copy_all_inputs_to_aux(cs, z, !mutant)?;
    let state_in = &z[layout.idx_state_in()];

    for i in 0..files_per_step {
        if mutant {
            out[layout.idx_leaf(i)] = AllocatedNum::alloc(
                cs.namespace(|| format!("challenge_unconstrained_{i}")),
                || Ok(F::ZERO),
            )?;
            continue;
        }

        let seed_public = &z[layout.idx_seed(i)];
        let file_idx_field = if aggregated_tree_depth > 0 {
            F::from(i as u64)
        } else {
            F::ZERO
        };
        let file_idx_alloc =
            AllocatedNum::alloc(cs.namespace(|| format!("challenge_file_idx_{i}")), || {
                Ok(file_idx_field)
            })?;

        let challenge = poseidon_hash_tagged_gadget(
            cs.namespace(|| format!("challenge_hash_{i}")),
            domain_tags::challenge(),
            seed_public,
            state_in,
        )?;

        let challenge_with_idx = if aggregated_tree_depth > 0 {
            poseidon_hash_tagged_gadget(
                cs.namespace(|| format!("challenge_with_file_idx_{i}")),
                domain_tags::challenge_per_file(),
                &challenge,
                &file_idx_alloc,
            )?
        } else {
            challenge
        };

        out[layout.idx_leaf(i)] = challenge_with_idx;
    }

    Ok(out)
}

pub fn synthesize_file_merkle_component<F: PrimeField + PrimeFieldBits, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    z: &[AllocatedNum<F>],
    files_per_step: usize,
    file_tree_depth: usize,
    aggregated_tree_depth: usize,
    witness: Option<&CircuitWitness<F>>,
    mut trace: Option<&mut ComponentWitnessTrace>,
    mutant: bool,
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let layout = PublicIOLayout::new(files_per_step);
    let mut out = copy_all_inputs_to_aux(cs, z, !mutant)?;
    let state_in = &z[layout.idx_state_in()];

    for file_idx in 0..files_per_step {
        let w = witness_for_slot(witness, file_idx, file_tree_depth, aggregated_tree_depth);
        let seed_public = &z[layout.idx_seed(file_idx)];
        let depth_public = &z[layout.idx_depth(file_idx)];

        let leaf_alloc =
            AllocatedNum::alloc(cs.namespace(|| format!("merkle_leaf_{file_idx}")), || {
                Ok(w.leaf)
            })?;
        if let Some(t) = trace.as_deref_mut() {
            t.leaf_aux.push(aux_index(&leaf_alloc)?);
        }

        let mut file_siblings_alloc: Vec<AllocatedNum<F>> =
            Vec::with_capacity(w.file_siblings.len());
        for (i, s) in w.file_siblings.iter().enumerate() {
            let sib = AllocatedNum::alloc(
                cs.namespace(|| format!("merkle_file_sibling_{file_idx}_{i}")),
                || Ok(*s),
            )?;
            if let Some(t) = trace.as_deref_mut() {
                t.file_sibling_aux.push(aux_index(&sib)?);
            }
            file_siblings_alloc.push(sib);
        }

        let file_idx_field = if aggregated_tree_depth > 0 {
            F::from(file_idx as u64)
        } else {
            F::ZERO
        };
        let file_idx_alloc = AllocatedNum::alloc(
            cs.namespace(|| format!("merkle_file_index_{file_idx}")),
            || Ok(file_idx_field),
        )?;

        let challenge = poseidon_hash_tagged_gadget(
            cs.namespace(|| format!("merkle_challenge_hash_{file_idx}")),
            domain_tags::challenge(),
            seed_public,
            state_in,
        )?;

        let challenge_with_idx = if aggregated_tree_depth > 0 {
            poseidon_hash_tagged_gadget(
                cs.namespace(|| format!("merkle_challenge_with_idx_{file_idx}")),
                domain_tags::challenge_per_file(),
                &challenge,
                &file_idx_alloc,
            )?
        } else {
            challenge
        };

        let index_bits = {
            let mut ns = cs.namespace(|| format!("merkle_challenge_bits_{file_idx}"));
            challenge_with_idx.to_bits_le(&mut ns)?
        };

        let mut file_path_indices: Vec<Boolean> = Vec::with_capacity(file_tree_depth);
        for i in 0..file_tree_depth {
            if let Some(b) = index_bits.get(i) {
                file_path_indices.push(b.clone());
            } else {
                let pad = AllocatedBit::alloc(
                    cs.namespace(|| format!("merkle_path_pad_{file_idx}_{i}")),
                    Some(false),
                )?;
                file_path_indices.push(Boolean::from(pad));
            }
        }
        if let Some(t) = trace.as_deref_mut() {
            for b in &file_path_indices {
                if let Some(i) = bool_aux_index(b) {
                    t.path_bit_aux.push(i);
                }
            }
        }

        let active_flags: Vec<Boolean> = (0..file_tree_depth)
            .map(|level| {
                let bit = AllocatedBit::alloc(
                    cs.namespace(|| format!("merkle_active_flag_{file_idx}_{level}")),
                    Some(level < w.actual_depth),
                )?;
                Ok(Boolean::from(bit))
            })
            .collect::<Result<_, SynthesisError>>()?;
        if let Some(t) = trace.as_deref_mut() {
            for b in &active_flags {
                if let Some(i) = bool_aux_index(b) {
                    t.gate_bit_aux.push(i);
                }
            }
        }

        // sum(active_flags) == depth_public
        cs.enforce(
            || format!("merkle_depth_equals_public_{file_idx}"),
            |lc| {
                let mut lc = lc + depth_public.get_variable() + CS::one();
                for flag in &active_flags {
                    lc = lc + &flag.lc(CS::one(), -F::ONE);
                }
                lc
            },
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );

        let computed_file_root = verify_merkle_path_gated(
            cs.namespace(|| format!("merkle_verify_file_{file_idx}")),
            &leaf_alloc,
            &file_siblings_alloc,
            &file_path_indices,
            Some(&active_flags),
            file_tree_depth,
        )?;

        if mutant {
            out[layout.idx_leaf(file_idx)] = AllocatedNum::alloc(
                cs.namespace(|| format!("file_merkle_unconstrained_{file_idx}")),
                || Ok(F::ZERO),
            )?;
        } else {
            out[layout.idx_leaf(file_idx)] = computed_file_root;
        }
    }

    Ok(out)
}

pub fn synthesize_aggregation_merkle_component<
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
>(
    cs: &mut CS,
    z: &[AllocatedNum<F>],
    files_per_step: usize,
    file_tree_depth: usize,
    aggregated_tree_depth: usize,
    witness: Option<&CircuitWitness<F>>,
    mut trace: Option<&mut ComponentWitnessTrace>,
    mutant: bool,
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let layout = PublicIOLayout::new(files_per_step);
    let mut out = copy_all_inputs_to_aux(cs, z, !mutant)?;
    let state_in = &z[layout.idx_state_in()];

    for file_idx in 0..files_per_step {
        let w = witness_for_slot(witness, file_idx, file_tree_depth, aggregated_tree_depth);

        let seed_public = &z[layout.idx_seed(file_idx)];
        let depth_public = &z[layout.idx_depth(file_idx)];
        let ledger_index_public = &z[layout.idx_ledger(file_idx)];

        let rc_input = poseidon_hash_tagged_gadget(
            cs.namespace(|| format!("agg_rc_input_{file_idx}")),
            domain_tags::challenge(),
            seed_public,
            state_in,
        )?;
        let rc = poseidon_hash_tagged_gadget(
            cs.namespace(|| format!("agg_rc_{file_idx}")),
            domain_tags::root_commitment(),
            &rc_input,
            depth_public,
        )?;

        let ledger_bits = {
            let mut ns = cs.namespace(|| format!("agg_ledger_bits_{file_idx}"));
            ledger_index_public.to_bits_le(&mut ns)?
        };
        let mut agg_path_indices: Vec<Boolean> = Vec::with_capacity(aggregated_tree_depth);
        for i in 0..aggregated_tree_depth {
            if let Some(b) = ledger_bits.get(i) {
                agg_path_indices.push(b.clone());
            } else {
                let pad = AllocatedBit::alloc(
                    cs.namespace(|| format!("agg_path_pad_{file_idx}_{i}")),
                    Some(false),
                )?;
                agg_path_indices.push(Boolean::from(pad));
            }
        }
        if let Some(t) = trace.as_deref_mut() {
            for b in &agg_path_indices {
                if let Some(i) = bool_aux_index(b) {
                    t.path_bit_aux.push(i);
                }
            }
        }

        let mut agg_siblings_alloc: Vec<AllocatedNum<F>> = Vec::with_capacity(w.agg_siblings.len());
        for (i, s) in w.agg_siblings.iter().enumerate() {
            let sib = AllocatedNum::alloc(
                cs.namespace(|| format!("agg_sibling_{file_idx}_{i}")),
                || Ok(*s),
            )?;
            if let Some(t) = trace.as_deref_mut() {
                t.agg_sibling_aux.push(aux_index(&sib)?);
            }
            agg_siblings_alloc.push(sib);
        }

        let computed_agg_root = verify_aggregation_path_gated(
            cs.namespace(|| format!("agg_verify_{file_idx}")),
            &rc,
            &agg_siblings_alloc,
            &agg_path_indices,
            aggregated_tree_depth,
        )?;

        if mutant {
            out[layout.idx_leaf(file_idx)] = AllocatedNum::alloc(
                cs.namespace(|| format!("agg_merkle_unconstrained_{file_idx}")),
                || Ok(F::ZERO),
            )?;
        } else {
            out[layout.idx_leaf(file_idx)] = computed_agg_root;
        }
    }

    Ok(out)
}

pub fn synthesize_state_update_component<
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
>(
    cs: &mut CS,
    z: &[AllocatedNum<F>],
    files_per_step: usize,
    file_tree_depth: usize,
    aggregated_tree_depth: usize,
    witness: Option<&CircuitWitness<F>>,
    mut trace: Option<&mut ComponentWitnessTrace>,
    mutant: bool,
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let layout = PublicIOLayout::new(files_per_step);
    let mut out = copy_all_inputs_to_aux(cs, z, !mutant)?;

    let mut current_state = z[layout.idx_state_in()].clone();
    for file_idx in 0..files_per_step {
        let w = witness_for_slot(witness, file_idx, file_tree_depth, aggregated_tree_depth);
        let depth_public = &z[layout.idx_depth(file_idx)];

        let leaf_alloc =
            AllocatedNum::alloc(cs.namespace(|| format!("state_leaf_{file_idx}")), || {
                Ok(w.leaf)
            })?;
        if let Some(t) = trace.as_deref_mut() {
            t.leaf_aux.push(aux_index(&leaf_alloc)?);
        }

        let updated_state = poseidon_hash_tagged_gadget(
            cs.namespace(|| format!("state_update_hash_{file_idx}")),
            domain_tags::state_update(),
            &current_state,
            &leaf_alloc,
        )?;

        let gate_for_slot = depth_positive_bit(
            cs,
            depth_public,
            &format!("state_gate_for_slot_{file_idx}"),
            trace.as_deref_mut(),
        )?;

        current_state = conditional_select(
            cs.namespace(|| format!("state_gate_select_{file_idx}")),
            &gate_for_slot,
            &current_state,
            &updated_state,
        )?;

        if mutant {
            out[layout.idx_leaf(file_idx)] = AllocatedNum::alloc(
                cs.namespace(|| format!("state_leaf_unconstrained_{file_idx}")),
                || Ok(F::ZERO),
            )?;
        } else {
            let zero =
                AllocatedNum::alloc(cs.namespace(|| format!("state_zero_{file_idx}")), || {
                    Ok(F::ZERO)
                })?;
            let leaf_pub = conditional_select(
                cs.namespace(|| format!("state_public_leaf_select_{file_idx}")),
                &gate_for_slot,
                &zero,
                &leaf_alloc,
            )?;
            out[layout.idx_leaf(file_idx)] = leaf_pub;
        }
    }

    if mutant {
        out[layout.idx_state_in()] =
            AllocatedNum::alloc(cs.namespace(|| "state_out_unconstrained"), || Ok(F::ZERO))?;
    } else {
        out[layout.idx_state_in()] = current_state;
    }

    Ok(out)
}

pub fn synthesize_carry_forward_component<
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
>(
    cs: &mut CS,
    z: &[AllocatedNum<F>],
    mutant: bool,
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    copy_all_inputs_to_aux(cs, z, !mutant)
}

/// Component: challenge derivation only.
#[derive(Clone, Debug)]
pub struct ChallengeDerivationComponentCircuit<F: PrimeField> {
    pub file_tree_depth: usize,
    pub files_per_step: usize,
    pub aggregated_tree_depth: usize,
    _p: std::marker::PhantomData<F>,
}

impl<F: PrimeField> ChallengeDerivationComponentCircuit<F> {
    pub fn new(
        files_per_step: usize,
        file_tree_depth: usize,
        aggregated_tree_depth: usize,
    ) -> Self {
        Self {
            file_tree_depth,
            files_per_step,
            aggregated_tree_depth,
            _p: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for ChallengeDerivationComponentCircuit<F> {
    fn arity(&self) -> usize {
        PublicIOLayout::new(self.files_per_step).arity()
    }
    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        synthesize_challenge_component(
            cs,
            z,
            self.files_per_step,
            self.aggregated_tree_depth,
            false,
        )
    }
}

#[derive(Clone, Debug)]
pub struct ChallengeDerivationMutantComponentCircuit<F: PrimeField> {
    pub file_tree_depth: usize,
    pub files_per_step: usize,
    pub aggregated_tree_depth: usize,
    _p: std::marker::PhantomData<F>,
}

impl<F: PrimeField> ChallengeDerivationMutantComponentCircuit<F> {
    pub fn new(
        files_per_step: usize,
        file_tree_depth: usize,
        aggregated_tree_depth: usize,
    ) -> Self {
        Self {
            file_tree_depth,
            files_per_step,
            aggregated_tree_depth,
            _p: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F>
    for ChallengeDerivationMutantComponentCircuit<F>
{
    fn arity(&self) -> usize {
        PublicIOLayout::new(self.files_per_step).arity()
    }
    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        synthesize_challenge_component(cs, z, self.files_per_step, self.aggregated_tree_depth, true)
    }
}

#[derive(Clone, Debug)]
pub struct FileMerkleComponentCircuit<F: PrimeField> {
    pub file_tree_depth: usize,
    pub files_per_step: usize,
    pub aggregated_tree_depth: usize,
    pub witness: Option<CircuitWitness<F>>,
    _p: std::marker::PhantomData<F>,
}

impl<F: PrimeField> FileMerkleComponentCircuit<F> {
    pub fn new(
        files_per_step: usize,
        file_tree_depth: usize,
        aggregated_tree_depth: usize,
        witness: Option<CircuitWitness<F>>,
    ) -> Self {
        Self {
            file_tree_depth,
            files_per_step,
            aggregated_tree_depth,
            witness,
            _p: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for FileMerkleComponentCircuit<F> {
    fn arity(&self) -> usize {
        PublicIOLayout::new(self.files_per_step).arity()
    }
    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        synthesize_file_merkle_component(
            cs,
            z,
            self.files_per_step,
            self.file_tree_depth,
            self.aggregated_tree_depth,
            self.witness.as_ref(),
            None,
            false,
        )
    }
}

#[derive(Clone, Debug)]
pub struct FileMerkleMutantComponentCircuit<F: PrimeField> {
    pub file_tree_depth: usize,
    pub files_per_step: usize,
    pub aggregated_tree_depth: usize,
    pub witness: Option<CircuitWitness<F>>,
    _p: std::marker::PhantomData<F>,
}

impl<F: PrimeField> FileMerkleMutantComponentCircuit<F> {
    pub fn new(
        files_per_step: usize,
        file_tree_depth: usize,
        aggregated_tree_depth: usize,
        witness: Option<CircuitWitness<F>>,
    ) -> Self {
        Self {
            file_tree_depth,
            files_per_step,
            aggregated_tree_depth,
            witness,
            _p: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for FileMerkleMutantComponentCircuit<F> {
    fn arity(&self) -> usize {
        PublicIOLayout::new(self.files_per_step).arity()
    }
    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        synthesize_file_merkle_component(
            cs,
            z,
            self.files_per_step,
            self.file_tree_depth,
            self.aggregated_tree_depth,
            self.witness.as_ref(),
            None,
            true,
        )
    }
}

#[derive(Clone, Debug)]
pub struct AggregationMerkleComponentCircuit<F: PrimeField> {
    pub file_tree_depth: usize,
    pub files_per_step: usize,
    pub aggregated_tree_depth: usize,
    pub witness: Option<CircuitWitness<F>>,
    _p: std::marker::PhantomData<F>,
}

impl<F: PrimeField> AggregationMerkleComponentCircuit<F> {
    pub fn new(
        files_per_step: usize,
        file_tree_depth: usize,
        aggregated_tree_depth: usize,
        witness: Option<CircuitWitness<F>>,
    ) -> Self {
        Self {
            file_tree_depth,
            files_per_step,
            aggregated_tree_depth,
            witness,
            _p: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for AggregationMerkleComponentCircuit<F> {
    fn arity(&self) -> usize {
        PublicIOLayout::new(self.files_per_step).arity()
    }
    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        synthesize_aggregation_merkle_component(
            cs,
            z,
            self.files_per_step,
            self.file_tree_depth,
            self.aggregated_tree_depth,
            self.witness.as_ref(),
            None,
            false,
        )
    }
}

#[derive(Clone, Debug)]
pub struct AggregationMerkleMutantComponentCircuit<F: PrimeField> {
    pub file_tree_depth: usize,
    pub files_per_step: usize,
    pub aggregated_tree_depth: usize,
    pub witness: Option<CircuitWitness<F>>,
    _p: std::marker::PhantomData<F>,
}

impl<F: PrimeField> AggregationMerkleMutantComponentCircuit<F> {
    pub fn new(
        files_per_step: usize,
        file_tree_depth: usize,
        aggregated_tree_depth: usize,
        witness: Option<CircuitWitness<F>>,
    ) -> Self {
        Self {
            file_tree_depth,
            files_per_step,
            aggregated_tree_depth,
            witness,
            _p: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for AggregationMerkleMutantComponentCircuit<F> {
    fn arity(&self) -> usize {
        PublicIOLayout::new(self.files_per_step).arity()
    }
    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        synthesize_aggregation_merkle_component(
            cs,
            z,
            self.files_per_step,
            self.file_tree_depth,
            self.aggregated_tree_depth,
            self.witness.as_ref(),
            None,
            true,
        )
    }
}

#[derive(Clone, Debug)]
pub struct StateUpdateComponentCircuit<F: PrimeField> {
    pub file_tree_depth: usize,
    pub files_per_step: usize,
    pub aggregated_tree_depth: usize,
    pub witness: Option<CircuitWitness<F>>,
    _p: std::marker::PhantomData<F>,
}

impl<F: PrimeField> StateUpdateComponentCircuit<F> {
    pub fn new(
        files_per_step: usize,
        file_tree_depth: usize,
        aggregated_tree_depth: usize,
        witness: Option<CircuitWitness<F>>,
    ) -> Self {
        Self {
            file_tree_depth,
            files_per_step,
            aggregated_tree_depth,
            witness,
            _p: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for StateUpdateComponentCircuit<F> {
    fn arity(&self) -> usize {
        PublicIOLayout::new(self.files_per_step).arity()
    }
    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        synthesize_state_update_component(
            cs,
            z,
            self.files_per_step,
            self.file_tree_depth,
            self.aggregated_tree_depth,
            self.witness.as_ref(),
            None,
            false,
        )
    }
}

#[derive(Clone, Debug)]
pub struct StateUpdateMutantComponentCircuit<F: PrimeField> {
    pub file_tree_depth: usize,
    pub files_per_step: usize,
    pub aggregated_tree_depth: usize,
    pub witness: Option<CircuitWitness<F>>,
    _p: std::marker::PhantomData<F>,
}

impl<F: PrimeField> StateUpdateMutantComponentCircuit<F> {
    pub fn new(
        files_per_step: usize,
        file_tree_depth: usize,
        aggregated_tree_depth: usize,
        witness: Option<CircuitWitness<F>>,
    ) -> Self {
        Self {
            file_tree_depth,
            files_per_step,
            aggregated_tree_depth,
            witness,
            _p: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for StateUpdateMutantComponentCircuit<F> {
    fn arity(&self) -> usize {
        PublicIOLayout::new(self.files_per_step).arity()
    }
    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        synthesize_state_update_component(
            cs,
            z,
            self.files_per_step,
            self.file_tree_depth,
            self.aggregated_tree_depth,
            self.witness.as_ref(),
            None,
            true,
        )
    }
}

#[derive(Clone, Debug)]
pub struct CarryForwardComponentCircuit<F: PrimeField> {
    pub files_per_step: usize,
    _p: std::marker::PhantomData<F>,
}

impl<F: PrimeField> CarryForwardComponentCircuit<F> {
    pub fn new(files_per_step: usize) -> Self {
        Self {
            files_per_step,
            _p: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for CarryForwardComponentCircuit<F> {
    fn arity(&self) -> usize {
        PublicIOLayout::new(self.files_per_step).arity()
    }
    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        synthesize_carry_forward_component(cs, z, false)
    }
}

#[derive(Clone, Debug)]
pub struct CarryForwardMutantComponentCircuit<F: PrimeField> {
    pub files_per_step: usize,
    _p: std::marker::PhantomData<F>,
}

impl<F: PrimeField> CarryForwardMutantComponentCircuit<F> {
    pub fn new(files_per_step: usize) -> Self {
        Self {
            files_per_step,
            _p: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for CarryForwardMutantComponentCircuit<F> {
    fn arity(&self) -> usize {
        PublicIOLayout::new(self.files_per_step).arity()
    }
    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        synthesize_carry_forward_component(cs, z, true)
    }
}
