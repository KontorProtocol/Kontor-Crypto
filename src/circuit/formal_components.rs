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
        ConstraintSystem, SynthesisError,
    },
    traits::circuit::StepCircuit,
};

use crate::config::PublicIOLayout;
use crate::poseidon::domain_tags;

use super::gadgets::{conditional_select, poseidon_hash_tagged_gadget};
use super::gadgets::{verify_aggregation_path_gated, verify_merkle_path_gated};
use super::witness::{CircuitWitness, FileProofWitness};

fn copy_all_inputs_to_aux<F: PrimeField + PrimeFieldBits, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    z: &[AllocatedNum<F>],
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let mut out = Vec::with_capacity(z.len());
    for (i, input) in z.iter().enumerate() {
        let copied = AllocatedNum::alloc(cs.namespace(|| format!("out_copy_{i}")), || {
            Ok(input.get_value().unwrap_or(F::ZERO))
        })?;
        // Encode equality as (expr + 1) * 1 = 1 so C-matrix rows are non-empty.
        cs.enforce(
            || format!("out_copy_eq_{i}"),
            |lc| lc + copied.get_variable() - input.get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );
        out.push(copied);
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
) -> Result<Boolean, SynthesisError> {
    let depth_bits = {
        let mut ns = cs.namespace(|| format!("{label_prefix}_depth_bits"));
        depth_public.to_bits_le(&mut ns)?
    };

    let mut depth_positive = Boolean::constant(false);
    for (bit_idx, bit) in depth_bits.iter().enumerate() {
        depth_positive = Boolean::or(
            cs.namespace(|| format!("{label_prefix}_depth_positive_or_{bit_idx}")),
            &depth_positive,
            bit,
        )?;
    }
    Ok(depth_positive)
}

/// Component: challenge derivation only.
///
/// Writes challenge values into the public leaf-output slots.
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
        let layout = PublicIOLayout::new(self.files_per_step);
        let mut out = copy_all_inputs_to_aux(cs, z)?;
        let state_in = &z[layout.idx_state_in()];

        for i in 0..self.files_per_step {
            let seed_public = &z[layout.idx_seed(i)];
            let file_idx_field = if self.aggregated_tree_depth > 0 {
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

            let challenge_with_idx = if self.aggregated_tree_depth > 0 {
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
}

/// Component: per-file Merkle-path verification only.
///
/// Writes each computed file root into the corresponding public leaf-output slot.
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
        let layout = PublicIOLayout::new(self.files_per_step);
        let mut out = copy_all_inputs_to_aux(cs, z)?;
        let state_in = &z[layout.idx_state_in()];

        for file_idx in 0..self.files_per_step {
            let w = witness_for_slot(
                self.witness.as_ref(),
                file_idx,
                self.file_tree_depth,
                self.aggregated_tree_depth,
            );
            let seed_public = &z[layout.idx_seed(file_idx)];
            let depth_public = &z[layout.idx_depth(file_idx)];

            let leaf_alloc =
                AllocatedNum::alloc(cs.namespace(|| format!("merkle_leaf_{file_idx}")), || {
                    Ok(w.leaf)
                })?;
            let file_siblings_alloc: Vec<AllocatedNum<F>> = w
                .file_siblings
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    AllocatedNum::alloc(
                        cs.namespace(|| format!("merkle_file_sibling_{file_idx}_{i}")),
                        || Ok(*s),
                    )
                })
                .collect::<Result<_, _>>()?;

            let file_idx_field = if self.aggregated_tree_depth > 0 {
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

            let challenge_with_idx = if self.aggregated_tree_depth > 0 {
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
            let mut file_path_indices: Vec<Boolean> = Vec::with_capacity(self.file_tree_depth);
            for i in 0..self.file_tree_depth {
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

            let active_flags: Vec<Boolean> = (0..self.file_tree_depth)
                .map(|level| {
                    let bit = AllocatedBit::alloc(
                        cs.namespace(|| format!("merkle_active_flag_{file_idx}_{level}")),
                        Some(level < w.actual_depth),
                    )?;
                    Ok(Boolean::from(bit))
                })
                .collect::<Result<_, SynthesisError>>()?;

            // sum(active_flags) == depth_public
            // Encode as (depth - sum + 1) * 1 = 1 to keep C-matrix non-empty.
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
                self.file_tree_depth,
            )?;

            out[layout.idx_leaf(file_idx)] = computed_file_root;
        }

        Ok(out)
    }
}

/// Component: aggregation-path verification only.
///
/// Writes each computed aggregation root into the corresponding public leaf-output slot.
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
        let layout = PublicIOLayout::new(self.files_per_step);
        let mut out = copy_all_inputs_to_aux(cs, z)?;
        let state_in = &z[layout.idx_state_in()];

        for file_idx in 0..self.files_per_step {
            let w = witness_for_slot(
                self.witness.as_ref(),
                file_idx,
                self.file_tree_depth,
                self.aggregated_tree_depth,
            );

            let seed_public = &z[layout.idx_seed(file_idx)];
            let depth_public = &z[layout.idx_depth(file_idx)];
            let ledger_index_public = &z[layout.idx_ledger(file_idx)];

            // Use a deterministic rc expression from public values.
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
            let mut agg_path_indices: Vec<Boolean> = Vec::with_capacity(self.aggregated_tree_depth);
            for i in 0..self.aggregated_tree_depth {
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

            let agg_siblings_alloc: Vec<AllocatedNum<F>> = w
                .agg_siblings
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    AllocatedNum::alloc(
                        cs.namespace(|| format!("agg_sibling_{file_idx}_{i}")),
                        || Ok(*s),
                    )
                })
                .collect::<Result<_, _>>()?;

            let computed_agg_root = verify_aggregation_path_gated(
                cs.namespace(|| format!("agg_verify_{file_idx}")),
                &rc,
                &agg_siblings_alloc,
                &agg_path_indices,
                self.aggregated_tree_depth,
            )?;

            out[layout.idx_leaf(file_idx)] = computed_agg_root;
        }

        Ok(out)
    }
}

/// Component: state update and public leaf gating only.
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
        let layout = PublicIOLayout::new(self.files_per_step);
        let mut out = copy_all_inputs_to_aux(cs, z)?;

        let mut current_state = z[layout.idx_state_in()].clone();
        for file_idx in 0..self.files_per_step {
            let w = witness_for_slot(
                self.witness.as_ref(),
                file_idx,
                self.file_tree_depth,
                self.aggregated_tree_depth,
            );
            let depth_public = &z[layout.idx_depth(file_idx)];

            let leaf_alloc =
                AllocatedNum::alloc(cs.namespace(|| format!("state_leaf_{file_idx}")), || {
                    Ok(w.leaf)
                })?;

            let updated_state = poseidon_hash_tagged_gadget(
                cs.namespace(|| format!("state_update_hash_{file_idx}")),
                domain_tags::state_update(),
                &current_state,
                &leaf_alloc,
            )?;

            let gate_for_slot =
                depth_positive_bit(cs, depth_public, &format!("state_gate_for_slot_{file_idx}"))?;

            current_state = conditional_select(
                cs.namespace(|| format!("state_gate_select_{file_idx}")),
                &gate_for_slot,
                &current_state,
                &updated_state,
            )?;

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

        out[layout.idx_state_in()] = current_state;
        Ok(out)
    }
}

/// Component: carry-forward equality constraints only.
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
        copy_all_inputs_to_aux(cs, z)
    }
}
