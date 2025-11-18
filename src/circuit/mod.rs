//! Nova PoR circuit module structure.
//!
//! This module is organized into smaller, focused sub-modules for better maintainability:
//!
//! - `gadgets/`: Low-level circuit gadgets (hash, merkle, etc.)
//! - `witness`: Witness data structures and constructors  
//! - `synth`: Main synthesis logic
//!
//! The main `PorCircuit` struct and `StepCircuit` implementation remain here for
//! backward compatibility with the existing API.

#[cfg(debug_assertions)]
pub mod debug;
pub mod gadgets;
pub mod synth;
pub mod witness;

// Re-export key types for backward compatibility
pub use witness::{CircuitWitness, FileProofWitness};

use ff::PrimeField;
use ff::PrimeFieldBits;
use nova_snark::{
    frontend::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError},
    traits::circuit::StepCircuit,
};
use std::marker::PhantomData;

use crate::config;

/// A Nova step circuit for Proof-of-Retrievability that verifies Merkle proofs.
///
/// This circuit implements the `StepCircuit` trait to prove knowledge of data by
/// verifying Merkle inclusion proofs. Each step calculates a challenged leaf index
/// deterministically and verifies the corresponding Merkle proof for that index.
///
/// The circuit's behavior is primarily defined in its `synthesize` method.
#[derive(Clone, Debug)]
pub struct PorCircuit<F: PrimeField> {
    /// The depth of individual file Merkle trees for this circuit shape.
    pub file_tree_depth: usize,
    /// Number of file slots in this circuit (power of 2).
    pub files_per_step: usize,
    /// The depth of the aggregated tree (tree of file roots).
    pub aggregated_tree_depth: usize,
    /// Structured witness data, guaranteed to be properly formed with correct padding.
    pub witness: Option<CircuitWitness<F>>,
    /// Phantom data to make the struct generic over the field `F`.
    _p: PhantomData<F>,
}

impl<F: PrimeField> PorCircuit<F> {
    /// Creates a new unified `PorCircuit` that supports both single and multi-file proofs.
    ///
    /// This is the single, canonical constructor for all circuit types. Single-file proofs
    /// are just a special case with `aggregated_tree_depth = 0` and one witness.
    ///
    /// # Arguments
    ///
    /// * `aggregated_tree_depth` - The depth of the aggregated tree (0 for single-file).
    /// * `witnesses` - Optional vector of file proof witnesses (None for setup).
    ///
    /// # Single-file usage:
    /// ```rust,ignore
    /// let witness = FileProofWitness {
    ///     leaf: some_leaf,
    ///     file_siblings: padded_siblings,  // padded to file_tree_depth
    ///     file_root: F::ZERO,              // computed in-circuit for single-file
    ///     actual_depth: file_depth,        // used for gating
    ///     agg_siblings: vec![],            // empty for single-file
    ///     ledger_index: 0,                 // single-file doesn't use ledger
    /// };
    /// let circuit = PorCircuit::new(0, Some(vec![witness]));
    /// ```
    ///
    /// # Multi-file usage:
    /// ```rust,ignore
    /// // Supports 1 to files_per_step files with automatic padding
    /// let witnesses = vec![witness1, witness2];  // one per file
    /// let circuit = PorCircuit::new(files_per_step, file_tree_depth, aggregated_depth, Some(witnesses));
    /// ```
    pub fn new(
        files_per_step: usize,
        file_tree_depth: usize,
        aggregated_tree_depth: usize,
        witnesses: Option<Vec<FileProofWitness<F>>>,
    ) -> Self {
        // Wrap witness vector in CircuitWitness
        // Note: The canonical way to create witnesses is via generate_circuit_witness()
        let circuit_witness = witnesses.map(|w| {
            // For manual constructor, assume all witnesses are real
            let num_real = w.len();
            CircuitWitness::new(w, num_real)
        });

        Self {
            file_tree_depth,
            files_per_step,
            aggregated_tree_depth,
            witness: circuit_witness,
            _p: PhantomData,
        }
    }
}

impl<F: PrimeField> Default for PorCircuit<F> {
    /// Creates a default `PorCircuit` with placeholder witness data.
    /// Uses minimal shape (1 file, depth 1) for compatibility.
    fn default() -> Self {
        Self {
            file_tree_depth: 1,
            files_per_step: 1,
            aggregated_tree_depth: 0,
            witness: None,
            _p: PhantomData,
        }
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for PorCircuit<F> {
    fn arity(&self) -> usize {
        // Use centralized layout helper
        config::PublicIOLayout::new(self.files_per_step).arity()
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        synth::synthesize_por_circuit(
            cs,
            z,
            self.files_per_step,
            self.file_tree_depth,
            self.aggregated_tree_depth,
            self.witness.as_ref(),
        )
    }
}
