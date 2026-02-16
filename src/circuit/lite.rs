//! Stripped-down circuit variants used for formal/SMT convergence experiments.
//!
//! These circuits are NOT used in production proving/verification. They exist to:
//! - validate the Picus toolchain end-to-end on a circuit that should be easy for QF_FF;
//! - incrementally add back structure to isolate which gadgets make determinism hard.

use ff::{PrimeField, PrimeFieldBits};
use nova_snark::{
    frontend::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError},
    traits::circuit::StepCircuit,
};

use super::gadgets::poseidon::poseidon_hash_tagged_gadget;
use super::gadgets::{conditional_select, verify_merkle_path_gated};
use crate::config;
use crate::poseidon::domain_tags;
use nova_snark::frontend::gadgets::boolean::{AllocatedBit, Boolean};

/// A very small, deterministic, linear circuit with the same public I/O layout as `PorCircuit`.
///
/// Behavior:
/// - Copies all public inputs to outputs, except:
/// - Updates `state` and `leaf_outputs[i]` with simple linear functions of inputs.
///
/// This is meant to be "solver-friendly" while still exercising Picus's determinism check on
/// non-trivial outputs (the leaf outputs).
#[derive(Clone, Debug)]
pub struct PorCircuitLiteLinear<F: PrimeField> {
    pub file_tree_depth: usize,
    pub files_per_step: usize,
    pub aggregated_tree_depth: usize,
    _p: std::marker::PhantomData<F>,
}

impl<F: PrimeField> PorCircuitLiteLinear<F> {
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

    fn enforce_lc_zero<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        name: &str,
        a: impl FnOnce(
            nova_snark::frontend::LinearCombination<F>,
        ) -> nova_snark::frontend::LinearCombination<F>,
    ) {
        // Workaround: nova-snark's SparseMatrix iterator panics on entirely-empty matrices.
        // Encoding `expr == 0` as `expr * 1 == 0` produces an all-zero C-matrix for circuits
        // that are purely linear. Instead, encode `expr == 0` as `(expr + 1) * 1 == 1`,
        // which is equivalent and ensures the C-matrix is non-empty.
        cs.enforce(
            || name,
            |lc| a(lc) + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for PorCircuitLiteLinear<F> {
    fn arity(&self) -> usize {
        config::PublicIOLayout::new(self.files_per_step).arity()
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // Keep the same public I/O layout as the real circuit so fixtures/export remain identical.
        let layout = config::PublicIOLayout::new(self.files_per_step);
        assert_eq!(z.len(), layout.arity());

        let root_in = &z[layout.idx_agg_root()];
        let state_in = &z[layout.idx_state_in()];

        // z_next starts as an identity update for all fields.
        let mut z_next: Vec<AllocatedNum<F>> = z.to_vec();

        // root_out = root_in (explicitly allocate + constrain so this circuit is clearly functional)
        let root_out = AllocatedNum::alloc(cs.namespace(|| "root_out"), || {
            Ok(root_in.get_value().unwrap_or(F::ZERO))
        })?;
        Self::enforce_lc_zero(cs, "root_copy", |lc| {
            lc + root_out.get_variable() - root_in.get_variable()
        });
        z_next[layout.idx_agg_root()] = root_out;

        // Copy-through fields must also be aux variables (Picus exporter expects outputs to be Aux).
        for i in 0..self.files_per_step {
            let ledger_in = &z[layout.idx_ledger(i)];
            let depth_in = &z[layout.idx_depth(i)];
            let seed_in = &z[layout.idx_seed(i)];

            let ledger_out =
                AllocatedNum::alloc(cs.namespace(|| format!("ledger_out_{}", i)), || {
                    Ok(ledger_in.get_value().unwrap_or(F::ZERO))
                })?;
            Self::enforce_lc_zero(cs, &format!("ledger_copy_{}", i), |lc| {
                lc + ledger_out.get_variable() - ledger_in.get_variable()
            });
            z_next[layout.idx_ledger(i)] = ledger_out;

            let depth_out =
                AllocatedNum::alloc(cs.namespace(|| format!("depth_out_{}", i)), || {
                    Ok(depth_in.get_value().unwrap_or(F::ZERO))
                })?;
            Self::enforce_lc_zero(cs, &format!("depth_copy_{}", i), |lc| {
                lc + depth_out.get_variable() - depth_in.get_variable()
            });
            z_next[layout.idx_depth(i)] = depth_out;

            let seed_out = AllocatedNum::alloc(cs.namespace(|| format!("seed_out_{}", i)), || {
                Ok(seed_in.get_value().unwrap_or(F::ZERO))
            })?;
            Self::enforce_lc_zero(cs, &format!("seed_copy_{}", i), |lc| {
                lc + seed_out.get_variable() - seed_in.get_variable()
            });
            z_next[layout.idx_seed(i)] = seed_out;
        }

        // state_out = state_in + 1
        let state_out = AllocatedNum::alloc(cs.namespace(|| "state_out"), || {
            Ok(state_in.get_value().unwrap_or(F::ZERO) + F::ONE)
        })?;
        // Enforce: state_out - state_in - 1 == 0
        Self::enforce_lc_zero(cs, "state_update", |lc| {
            lc + state_out.get_variable() - state_in.get_variable() - (F::ONE, CS::one())
        });
        z_next[layout.idx_state_in()] = state_out;

        // For each file slot:
        // leaf_out[i] = state_in + seed[i] + depth[i] + ledger_index[i] + (i+1)
        //
        // This is intentionally linear and cheap.
        for i in 0..self.files_per_step {
            let seed = &z[layout.idx_seed(i)];
            let depth = &z[layout.idx_depth(i)];
            let ledger = &z[layout.idx_ledger(i)];

            let leaf_out = AllocatedNum::alloc(cs.namespace(|| format!("leaf_out_{}", i)), || {
                let s = state_in.get_value().unwrap_or(F::ZERO);
                let seedv = seed.get_value().unwrap_or(F::ZERO);
                let dv = depth.get_value().unwrap_or(F::ZERO);
                let lv = ledger.get_value().unwrap_or(F::ZERO);
                Ok(s + seedv + dv + lv + F::from((i as u64) + 1))
            })?;

            Self::enforce_lc_zero(cs, &format!("leaf_out_def_{}", i), |lc| {
                lc + leaf_out.get_variable()
                    - state_in.get_variable()
                    - seed.get_variable()
                    - depth.get_variable()
                    - ledger.get_variable()
                    - (F::from((i as u64) + 1), CS::one())
            });

            z_next[layout.idx_leaf(i)] = leaf_out;
        }

        Ok(z_next)
    }
}

/// A small deterministic circuit that introduces a few multiplicative constraints.
///
/// Purpose: provide the next rung above `PorCircuitLiteLinear` to validate that Picus + cvc5
/// can handle non-linear constraints and still converge quickly to `safe`.
#[derive(Clone, Debug)]
pub struct PorCircuitLiteMul<F: PrimeField> {
    pub file_tree_depth: usize,
    pub files_per_step: usize,
    pub aggregated_tree_depth: usize,
    _p: std::marker::PhantomData<F>,
}

impl<F: PrimeField> PorCircuitLiteMul<F> {
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

    fn enforce_lc_zero<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        name: &str,
        a: impl FnOnce(
            nova_snark::frontend::LinearCombination<F>,
        ) -> nova_snark::frontend::LinearCombination<F>,
    ) {
        // Use the same non-empty-C workaround as the linear canary so this remains robust even if
        // future edits accidentally remove all multiplicative constraints.
        cs.enforce(
            || name,
            |lc| a(lc) + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for PorCircuitLiteMul<F> {
    fn arity(&self) -> usize {
        config::PublicIOLayout::new(self.files_per_step).arity()
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let layout = config::PublicIOLayout::new(self.files_per_step);
        assert_eq!(z.len(), layout.arity());

        let root_in = &z[layout.idx_agg_root()];
        let state_in = &z[layout.idx_state_in()];

        let mut z_next: Vec<AllocatedNum<F>> = z.to_vec();

        let root_out = AllocatedNum::alloc(cs.namespace(|| "root_out"), || {
            Ok(root_in.get_value().unwrap_or(F::ZERO))
        })?;
        Self::enforce_lc_zero(cs, "root_copy", |lc| {
            lc + root_out.get_variable() - root_in.get_variable()
        });
        z_next[layout.idx_agg_root()] = root_out;

        // Copy-through fields must be aux variables (Picus exporter expects outputs to be Aux).
        for i in 0..self.files_per_step {
            let ledger_in = &z[layout.idx_ledger(i)];
            let depth_in = &z[layout.idx_depth(i)];
            let seed_in = &z[layout.idx_seed(i)];

            let ledger_out =
                AllocatedNum::alloc(cs.namespace(|| format!("ledger_out_{}", i)), || {
                    Ok(ledger_in.get_value().unwrap_or(F::ZERO))
                })?;
            Self::enforce_lc_zero(cs, &format!("ledger_copy_{}", i), |lc| {
                lc + ledger_out.get_variable() - ledger_in.get_variable()
            });
            z_next[layout.idx_ledger(i)] = ledger_out;

            let depth_out =
                AllocatedNum::alloc(cs.namespace(|| format!("depth_out_{}", i)), || {
                    Ok(depth_in.get_value().unwrap_or(F::ZERO))
                })?;
            Self::enforce_lc_zero(cs, &format!("depth_copy_{}", i), |lc| {
                lc + depth_out.get_variable() - depth_in.get_variable()
            });
            z_next[layout.idx_depth(i)] = depth_out;

            let seed_out = AllocatedNum::alloc(cs.namespace(|| format!("seed_out_{}", i)), || {
                Ok(seed_in.get_value().unwrap_or(F::ZERO))
            })?;
            Self::enforce_lc_zero(cs, &format!("seed_copy_{}", i), |lc| {
                lc + seed_out.get_variable() - seed_in.get_variable()
            });
            z_next[layout.idx_seed(i)] = seed_out;
        }

        // Introduce small non-linear structure:
        // t_i = seed_i * depth_i
        // leaf_out_i = state_in + t_i + (i+1)
        // state_out = state_in + 1 + sum_i t_i
        let mut t_vars: Vec<AllocatedNum<F>> = Vec::with_capacity(self.files_per_step);

        for i in 0..self.files_per_step {
            let seed = &z[layout.idx_seed(i)];
            let depth = &z[layout.idx_depth(i)];

            let t =
                AllocatedNum::alloc(cs.namespace(|| format!("t_seed_mul_depth_{}", i)), || {
                    let sv = seed.get_value().unwrap_or(F::ZERO);
                    let dv = depth.get_value().unwrap_or(F::ZERO);
                    Ok(sv * dv)
                })?;

            cs.enforce(
                || format!("mul_seed_depth_{}", i),
                |lc| lc + seed.get_variable(),
                |lc| lc + depth.get_variable(),
                |lc| lc + t.get_variable(),
            );

            t_vars.push(t);
        }

        for i in 0..self.files_per_step {
            let t = &t_vars[i];

            let leaf_out = AllocatedNum::alloc(cs.namespace(|| format!("leaf_out_{}", i)), || {
                let s = state_in.get_value().unwrap_or(F::ZERO);
                let tv = t.get_value().unwrap_or(F::ZERO);
                Ok(s + tv + F::from((i as u64) + 1))
            })?;

            Self::enforce_lc_zero(cs, &format!("leaf_out_def_{}", i), |lc| {
                lc + leaf_out.get_variable()
                    - state_in.get_variable()
                    - t.get_variable()
                    - (F::from((i as u64) + 1), CS::one())
            });

            z_next[layout.idx_leaf(i)] = leaf_out;
        }

        let state_out = AllocatedNum::alloc(cs.namespace(|| "state_out"), || {
            let mut acc = state_in.get_value().unwrap_or(F::ZERO) + F::ONE;
            for t in &t_vars {
                acc += t.get_value().unwrap_or(F::ZERO);
            }
            Ok(acc)
        })?;

        Self::enforce_lc_zero(cs, "state_out_def", |lc| {
            let mut lc =
                lc + state_out.get_variable() - state_in.get_variable() - (F::ONE, CS::one());
            for t in &t_vars {
                lc = lc - t.get_variable();
            }
            lc
        });
        z_next[layout.idx_state_in()] = state_out;

        Ok(z_next)
    }
}

/// A small deterministic circuit that uses the *real* Poseidon gadget (no Merkle).
///
/// Purpose: isolate solver hardness introduced by Poseidon constraints alone.
/// This circuit is a function of public inputs only (no witness), so Picus should be
/// able to conclude `safe` under an input-fixed precondition.
#[derive(Clone, Debug)]
pub struct PorCircuitLitePoseidonStateOnly<F: PrimeField> {
    pub file_tree_depth: usize,
    pub files_per_step: usize,
    pub aggregated_tree_depth: usize,
    _p: std::marker::PhantomData<F>,
}

impl<F: PrimeField> PorCircuitLitePoseidonStateOnly<F> {
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

    fn enforce_lc_zero<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        name: &str,
        a: impl FnOnce(
            nova_snark::frontend::LinearCombination<F>,
        ) -> nova_snark::frontend::LinearCombination<F>,
    ) {
        // Keep the non-empty-C workaround in case a caller reduces multiplicative constraints.
        cs.enforce(
            || name,
            |lc| a(lc) + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for PorCircuitLitePoseidonStateOnly<F> {
    fn arity(&self) -> usize {
        config::PublicIOLayout::new(self.files_per_step).arity()
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let layout = config::PublicIOLayout::new(self.files_per_step);
        assert_eq!(z.len(), layout.arity());

        let root_in = &z[layout.idx_agg_root()];
        let state_in = &z[layout.idx_state_in()];

        let mut z_next: Vec<AllocatedNum<F>> = z.to_vec();

        // root_out = root_in (aux copy)
        let root_out = AllocatedNum::alloc(cs.namespace(|| "root_out"), || {
            Ok(root_in.get_value().unwrap_or(F::ZERO))
        })?;
        Self::enforce_lc_zero(cs, "root_copy", |lc| {
            lc + root_out.get_variable() - root_in.get_variable()
        });
        z_next[layout.idx_agg_root()] = root_out;

        // Copy-through public fields as aux variables (Picus exporter expects outputs to be Aux).
        for i in 0..self.files_per_step {
            let ledger_in = &z[layout.idx_ledger(i)];
            let depth_in = &z[layout.idx_depth(i)];
            let seed_in = &z[layout.idx_seed(i)];

            let ledger_out =
                AllocatedNum::alloc(cs.namespace(|| format!("ledger_out_{}", i)), || {
                    Ok(ledger_in.get_value().unwrap_or(F::ZERO))
                })?;
            Self::enforce_lc_zero(cs, &format!("ledger_copy_{}", i), |lc| {
                lc + ledger_out.get_variable() - ledger_in.get_variable()
            });
            z_next[layout.idx_ledger(i)] = ledger_out;

            let depth_out =
                AllocatedNum::alloc(cs.namespace(|| format!("depth_out_{}", i)), || {
                    Ok(depth_in.get_value().unwrap_or(F::ZERO))
                })?;
            Self::enforce_lc_zero(cs, &format!("depth_copy_{}", i), |lc| {
                lc + depth_out.get_variable() - depth_in.get_variable()
            });
            z_next[layout.idx_depth(i)] = depth_out;

            let seed_out = AllocatedNum::alloc(cs.namespace(|| format!("seed_out_{}", i)), || {
                Ok(seed_in.get_value().unwrap_or(F::ZERO))
            })?;
            Self::enforce_lc_zero(cs, &format!("seed_copy_{}", i), |lc| {
                lc + seed_out.get_variable() - seed_in.get_variable()
            });
            z_next[layout.idx_seed(i)] = seed_out;
        }

        // state_out = Poseidon(TAG_STATE_UPDATE, state_in, seed_0)
        let seed0 = &z[layout.idx_seed(0)];
        let state_out = poseidon_hash_tagged_gadget(
            cs.namespace(|| "state_out_poseidon"),
            domain_tags::state_update(),
            state_in,
            seed0,
        )?;
        z_next[layout.idx_state_in()] = state_out;

        // leaf_out[i] = Poseidon(TAG_CHALLENGE_PER_FILE, seed_i, state_in + (i+1))
        for i in 0..self.files_per_step {
            let seed = &z[layout.idx_seed(i)];

            let state_plus_i =
                AllocatedNum::alloc(cs.namespace(|| format!("state_plus_{}", i)), || {
                    Ok(state_in.get_value().unwrap_or(F::ZERO) + F::from((i as u64) + 1))
                })?;
            Self::enforce_lc_zero(cs, &format!("state_plus_def_{}", i), |lc| {
                lc + state_plus_i.get_variable()
                    - state_in.get_variable()
                    - (F::from((i as u64) + 1), CS::one())
            });

            let leaf_out = poseidon_hash_tagged_gadget(
                cs.namespace(|| format!("leaf_out_poseidon_{}", i)),
                domain_tags::challenge_per_file(),
                seed,
                &state_plus_i,
            )?;
            z_next[layout.idx_leaf(i)] = leaf_out;
        }

        Ok(z_next)
    }
}

/// A small deterministic circuit that includes the *real* Merkle gadget (Poseidon-based),
/// but avoids private witness inputs by deriving the leaf/sibling values from public inputs.
///
/// Purpose: isolate solver hardness introduced by Merkle verification constraints (including
/// bit decomposition + conditional selects) without the extra degrees of freedom from
/// witness-provided Merkle paths.
#[derive(Clone, Debug)]
pub struct PorCircuitLiteMerklePoseidonDet<F: PrimeField> {
    pub file_tree_depth: usize,
    pub files_per_step: usize,
    pub aggregated_tree_depth: usize,
    _p: std::marker::PhantomData<F>,
}

/// A small deterministic circuit that performs Poseidon hashing followed by bit-decomposition.
///
/// Purpose: isolate solver hardness from `to_bits_le()` on a Poseidon output (used by the
/// production circuit to derive Merkle path bits).
#[derive(Clone, Debug)]
pub struct PorCircuitLitePoseidonBits<F: PrimeField> {
    pub file_tree_depth: usize,
    pub files_per_step: usize,
    pub aggregated_tree_depth: usize,
    _p: std::marker::PhantomData<F>,
}

/// Like `PorCircuitLiteMerklePoseidonDet`, but derives Merkle path bits by hashing
/// (seed, state) with Poseidon and bit-decomposing the result.
///
/// Purpose: isolate the production-critical pattern `Poseidon -> to_bits_le -> Merkle selects`
/// without involving witness-provided Merkle paths.
#[derive(Clone, Debug)]
pub struct PorCircuitLiteMerklePoseidonChallengeBits<F: PrimeField> {
    pub file_tree_depth: usize,
    pub files_per_step: usize,
    pub aggregated_tree_depth: usize,
    _p: std::marker::PhantomData<F>,
}

impl<F: PrimeField> PorCircuitLiteMerklePoseidonChallengeBits<F> {
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

    fn enforce_lc_zero<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        name: &str,
        a: impl FnOnce(
            nova_snark::frontend::LinearCombination<F>,
        ) -> nova_snark::frontend::LinearCombination<F>,
    ) {
        cs.enforce(
            || name,
            |lc| a(lc) + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F>
    for PorCircuitLiteMerklePoseidonChallengeBits<F>
{
    fn arity(&self) -> usize {
        config::PublicIOLayout::new(self.files_per_step).arity()
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let layout = config::PublicIOLayout::new(self.files_per_step);
        assert_eq!(z.len(), layout.arity());

        let _root_in = &z[layout.idx_agg_root()];
        let state_in = &z[layout.idx_state_in()];

        let mut z_next: Vec<AllocatedNum<F>> = z.to_vec();

        // Copy public fields through as aux outputs (except root_out; see below).
        for i in 0..self.files_per_step {
            let ledger_in = &z[layout.idx_ledger(i)];
            let depth_in = &z[layout.idx_depth(i)];
            let seed_in = &z[layout.idx_seed(i)];

            let ledger_out =
                AllocatedNum::alloc(cs.namespace(|| format!("ledger_out_{}", i)), || {
                    Ok(ledger_in.get_value().unwrap_or(F::ZERO))
                })?;
            Self::enforce_lc_zero(cs, &format!("ledger_copy_{}", i), |lc| {
                lc + ledger_out.get_variable() - ledger_in.get_variable()
            });
            z_next[layout.idx_ledger(i)] = ledger_out;

            let depth_out =
                AllocatedNum::alloc(cs.namespace(|| format!("depth_out_{}", i)), || {
                    Ok(depth_in.get_value().unwrap_or(F::ZERO))
                })?;
            Self::enforce_lc_zero(cs, &format!("depth_copy_{}", i), |lc| {
                lc + depth_out.get_variable() - depth_in.get_variable()
            });
            z_next[layout.idx_depth(i)] = depth_out;

            let seed_out = AllocatedNum::alloc(cs.namespace(|| format!("seed_out_{}", i)), || {
                Ok(seed_in.get_value().unwrap_or(F::ZERO))
            })?;
            Self::enforce_lc_zero(cs, &format!("seed_copy_{}", i), |lc| {
                lc + seed_out.get_variable() - seed_in.get_variable()
            });
            z_next[layout.idx_seed(i)] = seed_out;
        }

        let depth_public = &z[layout.idx_depth(0)];
        let seed0 = &z[layout.idx_seed(0)];

        // leaf = Poseidon(TAG_LEAF, state_in, seed0)
        let leaf = poseidon_hash_tagged_gadget(
            cs.namespace(|| "leaf_poseidon"),
            domain_tags::leaf(),
            state_in,
            seed0,
        )?;

        // siblings[i] = seed0 + (i+7)
        let mut siblings = Vec::with_capacity(self.file_tree_depth);
        for i in 0..self.file_tree_depth {
            let s = AllocatedNum::alloc(cs.namespace(|| format!("sibling_{}", i)), || {
                Ok(seed0.get_value().unwrap_or(F::ZERO) + F::from((i as u64) + 7))
            })?;
            Self::enforce_lc_zero(cs, &format!("sibling_def_{}", i), |lc| {
                lc + s.get_variable() - seed0.get_variable() - (F::from((i as u64) + 7), CS::one())
            });
            siblings.push(s);
        }

        // path bits: Poseidon(TAG_CHALLENGE, seed0, state_in) then bit-decompose.
        let challenge = poseidon_hash_tagged_gadget(
            cs.namespace(|| "challenge_poseidon"),
            domain_tags::challenge(),
            seed0,
            state_in,
        )?;
        let challenge_bits = {
            let mut ns = cs.namespace(|| "challenge_bits");
            challenge.to_bits_le(&mut ns)?
        };
        let mut path_bits = Vec::with_capacity(self.file_tree_depth);
        for i in 0..self.file_tree_depth {
            if let Some(b) = challenge_bits.get(i) {
                path_bits.push(b.clone());
            } else {
                let pad = AllocatedBit::alloc(
                    cs.namespace(|| format!("pad_path_bit_{}", i)),
                    Some(false),
                )
                .map_err(|_| SynthesisError::AssignmentMissing)?;
                path_bits.push(Boolean::from(pad));
            }
        }

        // active_flags: allocated bits, constrained only by sum==depth_public (matches real circuit style).
        let mut active_flags = Vec::with_capacity(self.file_tree_depth);
        for i in 0..self.file_tree_depth {
            let bit =
                AllocatedBit::alloc(cs.namespace(|| format!("active_flag_{}", i)), Some(true))
                    .map_err(|_| SynthesisError::AssignmentMissing)?;
            active_flags.push(Boolean::from(bit));
        }

        Self::enforce_lc_zero(cs, "depth_equals_sum_active", |lc| {
            let mut lc = lc + depth_public.get_variable();
            for f in &active_flags {
                lc = lc + &f.lc(CS::one(), -F::ONE);
            }
            lc
        });

        let computed_root = verify_merkle_path_gated(
            cs.namespace(|| "verify_merkle"),
            &leaf,
            &siblings,
            &path_bits,
            Some(&active_flags),
            self.file_tree_depth,
        )?;

        // root_out is computed_root (deterministic function of public inputs).
        z_next[layout.idx_agg_root()] = computed_root.clone();

        // state_out = Poseidon(TAG_STATE_UPDATE, state_in, leaf)
        let state_out = poseidon_hash_tagged_gadget(
            cs.namespace(|| "state_update"),
            domain_tags::state_update(),
            state_in,
            &leaf,
        )?;
        z_next[layout.idx_state_in()] = state_out;

        // leaf_out = leaf (public output position)
        z_next[layout.idx_leaf(0)] = leaf;

        Ok(z_next)
    }
}

impl<F: PrimeField> PorCircuitLitePoseidonBits<F> {
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

    fn enforce_lc_zero<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        name: &str,
        a: impl FnOnce(
            nova_snark::frontend::LinearCombination<F>,
        ) -> nova_snark::frontend::LinearCombination<F>,
    ) {
        cs.enforce(
            || name,
            |lc| a(lc) + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for PorCircuitLitePoseidonBits<F> {
    fn arity(&self) -> usize {
        config::PublicIOLayout::new(self.files_per_step).arity()
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let layout = config::PublicIOLayout::new(self.files_per_step);
        assert_eq!(z.len(), layout.arity());

        let root_in = &z[layout.idx_agg_root()];
        let state_in = &z[layout.idx_state_in()];

        let mut z_next: Vec<AllocatedNum<F>> = z.to_vec();

        // Copy root + public fields through as aux outputs.
        let root_out = AllocatedNum::alloc(cs.namespace(|| "root_out"), || {
            Ok(root_in.get_value().unwrap_or(F::ZERO))
        })?;
        Self::enforce_lc_zero(cs, "root_copy", |lc| {
            lc + root_out.get_variable() - root_in.get_variable()
        });
        z_next[layout.idx_agg_root()] = root_out;

        for i in 0..self.files_per_step {
            let ledger_in = &z[layout.idx_ledger(i)];
            let depth_in = &z[layout.idx_depth(i)];
            let seed_in = &z[layout.idx_seed(i)];

            let ledger_out =
                AllocatedNum::alloc(cs.namespace(|| format!("ledger_out_{}", i)), || {
                    Ok(ledger_in.get_value().unwrap_or(F::ZERO))
                })?;
            Self::enforce_lc_zero(cs, &format!("ledger_copy_{}", i), |lc| {
                lc + ledger_out.get_variable() - ledger_in.get_variable()
            });
            z_next[layout.idx_ledger(i)] = ledger_out;

            let depth_out =
                AllocatedNum::alloc(cs.namespace(|| format!("depth_out_{}", i)), || {
                    Ok(depth_in.get_value().unwrap_or(F::ZERO))
                })?;
            Self::enforce_lc_zero(cs, &format!("depth_copy_{}", i), |lc| {
                lc + depth_out.get_variable() - depth_in.get_variable()
            });
            z_next[layout.idx_depth(i)] = depth_out;

            let seed_out = AllocatedNum::alloc(cs.namespace(|| format!("seed_out_{}", i)), || {
                Ok(seed_in.get_value().unwrap_or(F::ZERO))
            })?;
            Self::enforce_lc_zero(cs, &format!("seed_copy_{}", i), |lc| {
                lc + seed_out.get_variable() - seed_in.get_variable()
            });
            z_next[layout.idx_seed(i)] = seed_out;
        }

        let seed0 = &z[layout.idx_seed(0)];
        let h = poseidon_hash_tagged_gadget(
            cs.namespace(|| "poseidon_hash"),
            domain_tags::challenge(),
            seed0,
            state_in,
        )?;

        // state_out = h (non-trivial output)
        z_next[layout.idx_state_in()] = h.clone();

        // Decompose h to bits and constrain an explicit low8 accumulator.
        let bits = {
            let mut ns = cs.namespace(|| "h_bits");
            h.to_bits_le(&mut ns)?
        };

        let low8 = AllocatedNum::alloc(cs.namespace(|| "low8"), || {
            let hv = h.get_value().unwrap_or(F::ZERO);
            let b0 = hv.to_repr().as_ref().get(0).copied().unwrap_or(0);
            Ok(F::from(b0 as u64))
        })?;
        Self::enforce_lc_zero(cs, "low8_def", |lc| {
            let mut lc = lc + low8.get_variable();
            for i in 0..8 {
                if let Some(b) = bits.get(i) {
                    // subtract (2^i)*b
                    lc = lc + &b.lc(CS::one(), -F::from(1u64 << i));
                }
            }
            lc
        });

        // leaf_out[0] = low8 (exercises non-trivial aux output position)
        z_next[layout.idx_leaf(0)] = low8;

        Ok(z_next)
    }
}

impl<F: PrimeField> PorCircuitLiteMerklePoseidonDet<F> {
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

    fn enforce_lc_zero<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        name: &str,
        a: impl FnOnce(
            nova_snark::frontend::LinearCombination<F>,
        ) -> nova_snark::frontend::LinearCombination<F>,
    ) {
        cs.enforce(
            || name,
            |lc| a(lc) + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for PorCircuitLiteMerklePoseidonDet<F> {
    fn arity(&self) -> usize {
        config::PublicIOLayout::new(self.files_per_step).arity()
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let layout = config::PublicIOLayout::new(self.files_per_step);
        assert_eq!(z.len(), layout.arity());

        let _root_in = &z[layout.idx_agg_root()];
        let state_in = &z[layout.idx_state_in()];

        let mut z_next: Vec<AllocatedNum<F>> = z.to_vec();

        // Copy public fields through as aux outputs (except root_out; see below).
        for i in 0..self.files_per_step {
            let ledger_in = &z[layout.idx_ledger(i)];
            let depth_in = &z[layout.idx_depth(i)];
            let seed_in = &z[layout.idx_seed(i)];

            let ledger_out =
                AllocatedNum::alloc(cs.namespace(|| format!("ledger_out_{}", i)), || {
                    Ok(ledger_in.get_value().unwrap_or(F::ZERO))
                })?;
            Self::enforce_lc_zero(cs, &format!("ledger_copy_{}", i), |lc| {
                lc + ledger_out.get_variable() - ledger_in.get_variable()
            });
            z_next[layout.idx_ledger(i)] = ledger_out;

            let depth_out =
                AllocatedNum::alloc(cs.namespace(|| format!("depth_out_{}", i)), || {
                    Ok(depth_in.get_value().unwrap_or(F::ZERO))
                })?;
            Self::enforce_lc_zero(cs, &format!("depth_copy_{}", i), |lc| {
                lc + depth_out.get_variable() - depth_in.get_variable()
            });
            z_next[layout.idx_depth(i)] = depth_out;

            let seed_out = AllocatedNum::alloc(cs.namespace(|| format!("seed_out_{}", i)), || {
                Ok(seed_in.get_value().unwrap_or(F::ZERO))
            })?;
            Self::enforce_lc_zero(cs, &format!("seed_copy_{}", i), |lc| {
                lc + seed_out.get_variable() - seed_in.get_variable()
            });
            z_next[layout.idx_seed(i)] = seed_out;
        }

        // Single-file deterministic Merkle: derive leaf + siblings from public inputs.
        // (We still keep the "file slot" structure aligned with the real circuit.)
        let depth_public = &z[layout.idx_depth(0)];
        let seed0 = &z[layout.idx_seed(0)];

        // leaf = Poseidon(TAG_LEAF, state_in, seed0)
        let leaf = poseidon_hash_tagged_gadget(
            cs.namespace(|| "leaf_poseidon"),
            domain_tags::leaf(),
            state_in,
            seed0,
        )?;

        // siblings[i] = seed0 + (i+7)
        let mut siblings = Vec::with_capacity(self.file_tree_depth);
        for i in 0..self.file_tree_depth {
            let s = AllocatedNum::alloc(cs.namespace(|| format!("sibling_{}", i)), || {
                Ok(seed0.get_value().unwrap_or(F::ZERO) + F::from((i as u64) + 7))
            })?;
            Self::enforce_lc_zero(cs, &format!("sibling_def_{}", i), |lc| {
                lc + s.get_variable() - seed0.get_variable() - (F::from((i as u64) + 7), CS::one())
            });
            siblings.push(s);
        }

        // path bits: use seed0 bits (cheap and deterministic)
        let seed_bits = {
            let mut ns = cs.namespace(|| "seed_bits");
            seed0.to_bits_le(&mut ns)?
        };
        let mut path_bits = Vec::with_capacity(self.file_tree_depth);
        for i in 0..self.file_tree_depth {
            if let Some(b) = seed_bits.get(i) {
                path_bits.push(b.clone());
            } else {
                let pad = AllocatedBit::alloc(
                    cs.namespace(|| format!("pad_path_bit_{}", i)),
                    Some(false),
                )
                .map_err(|_| SynthesisError::AssignmentMissing)?;
                path_bits.push(Boolean::from(pad));
            }
        }

        // active_flags: allocated bits, constrained only by sum==depth_public (matches real circuit style).
        let mut active_flags = Vec::with_capacity(self.file_tree_depth);
        for i in 0..self.file_tree_depth {
            let bit =
                AllocatedBit::alloc(cs.namespace(|| format!("active_flag_{}", i)), Some(true))
                    .map_err(|_| SynthesisError::AssignmentMissing)?;
            active_flags.push(Boolean::from(bit));
        }

        // Enforce sum(active_flags) == depth_public
        Self::enforce_lc_zero(cs, "depth_equals_sum_active", |lc| {
            let mut lc = lc + depth_public.get_variable();
            for f in &active_flags {
                lc = lc + &f.lc(CS::one(), -F::ONE);
            }
            lc
        });

        // gate_for_slot = depth_public > 0  (same pattern as real circuit)
        let depth_bits = {
            let mut ns = cs.namespace(|| "depth_bits");
            depth_public.to_bits_le(&mut ns)?
        };
        let mut depth_is_positive = Boolean::constant(false);
        for (bit_idx, bit) in depth_bits.iter().enumerate() {
            depth_is_positive = Boolean::or(
                cs.namespace(|| format!("depth_positive_or_bit{}", bit_idx)),
                &depth_is_positive,
                bit,
            )?;
        }
        let gate_for_slot = depth_is_positive;

        let computed_root = verify_merkle_path_gated(
            cs.namespace(|| "verify_merkle"),
            &leaf,
            &siblings,
            &path_bits,
            Some(&active_flags),
            self.file_tree_depth,
        )?;

        // root_out is the computed Merkle root (deterministic function of public inputs).
        // Note: root_in is intentionally unused in this rung circuit.
        z_next[layout.idx_agg_root()] = computed_root.clone();

        // state_out = Poseidon(TAG_STATE_UPDATE, state_in, leaf) (gated)
        let updated_state = poseidon_hash_tagged_gadget(
            cs.namespace(|| "state_update"),
            domain_tags::state_update(),
            state_in,
            &leaf,
        )?;
        let state_out = conditional_select(
            cs.namespace(|| "gate_state_update"),
            &gate_for_slot,
            state_in,
            &updated_state,
        )?;
        z_next[layout.idx_state_in()] = state_out;

        // leaf_out = gate ? leaf : 0
        let zero = AllocatedNum::alloc(cs.namespace(|| "zero"), || Ok(F::ZERO))?;
        let leaf_out = conditional_select(
            cs.namespace(|| "public_leaf_select"),
            &gate_for_slot,
            &zero,
            &leaf,
        )?;
        z_next[layout.idx_leaf(0)] = leaf_out;

        Ok(z_next)
    }
}
