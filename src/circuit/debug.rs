//! Debug utilities for validating circuit structure consistency.
//! This module is only compiled in debug builds to help detect
//! circuit structure variations that would break Nova's folding.

use arecibo::traits::circuit::StepCircuit;
use bellpepper_core::Circuit;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

/// Tracks circuit structure metrics during synthesis
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct CircuitFingerprint {
    pub num_constraints: usize,
    pub num_inputs: usize,
    pub num_aux: usize,
    /// Hash of constraint allocation sequence (namespace names)
    pub structure_hash: u64,
}

impl CircuitFingerprint {
    pub fn new() -> Self {
        Self::default()
    }
}

/// A constraint system wrapper that tracks circuit structure
pub struct FingerprintCS<F: PrimeField, CS: ConstraintSystem<F>> {
    inner: CS,
    fingerprint: CircuitFingerprint,
    namespace_hasher: DefaultHasher,
    _marker: PhantomData<F>,
}

impl<F: PrimeField, CS: ConstraintSystem<F>> FingerprintCS<F, CS> {
    pub fn new(inner: CS) -> Self {
        Self {
            inner,
            fingerprint: CircuitFingerprint::new(),
            namespace_hasher: DefaultHasher::new(),
            _marker: PhantomData,
        }
    }

    pub fn fingerprint(&self) -> &CircuitFingerprint {
        &self.fingerprint
    }

    pub fn into_inner(self) -> CS {
        self.inner
    }
}

impl<F: PrimeField, CS: ConstraintSystem<F>> ConstraintSystem<F> for FingerprintCS<F, CS> {
    type Root = Self;

    fn alloc<FN, A, AR>(
        &mut self,
        annotation: A,
        f: FN,
    ) -> Result<bellpepper_core::Variable, SynthesisError>
    where
        FN: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.fingerprint.num_aux += 1;

        // We can't call annotation twice (it's FnOnce)
        // Just count the allocation

        self.inner.alloc(annotation, f)
    }

    fn alloc_input<FN, A, AR>(
        &mut self,
        annotation: A,
        f: FN,
    ) -> Result<bellpepper_core::Variable, SynthesisError>
    where
        FN: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.fingerprint.num_inputs += 1;

        // We can't call annotation twice (it's FnOnce)
        // Just count the allocation

        self.inner.alloc_input(annotation, f)
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, annotation: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(bellpepper_core::LinearCombination<F>) -> bellpepper_core::LinearCombination<F>,
        LB: FnOnce(bellpepper_core::LinearCombination<F>) -> bellpepper_core::LinearCombination<F>,
        LC: FnOnce(bellpepper_core::LinearCombination<F>) -> bellpepper_core::LinearCombination<F>,
    {
        self.fingerprint.num_constraints += 1;

        // We can't call annotation twice, so we don't hash it here
        // This is a limitation but acceptable for debug purposes

        self.inner.enforce(annotation, a, b, c)
    }

    fn push_namespace<NR, N>(&mut self, name_fn: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // Hash namespace transitions
        let name = name_fn().into();
        ("push:".to_string() + &name).hash(&mut self.namespace_hasher);

        self.inner.push_namespace(|| name)
    }

    fn pop_namespace(&mut self) {
        "pop".hash(&mut self.namespace_hasher);
        self.inner.pop_namespace()
    }

    fn get_root(&mut self) -> &mut Self::Root {
        // Finalize the structure hash when getting root
        self.fingerprint.structure_hash = self.namespace_hasher.finish();
        self
    }
}

/// Validates that two circuit fingerprints match
pub fn validate_circuit_structure(
    fp1: &CircuitFingerprint,
    fp2: &CircuitFingerprint,
    context: &str,
) -> Result<(), String> {
    if fp1.num_constraints != fp2.num_constraints {
        return Err(format!(
            "{}: Constraint count mismatch: {} vs {}",
            context, fp1.num_constraints, fp2.num_constraints
        ));
    }

    if fp1.num_inputs != fp2.num_inputs {
        return Err(format!(
            "{}: Input count mismatch: {} vs {}",
            context, fp1.num_inputs, fp2.num_inputs
        ));
    }

    if fp1.num_aux != fp2.num_aux {
        return Err(format!(
            "{}: Auxiliary variable count mismatch: {} vs {}",
            context, fp1.num_aux, fp2.num_aux
        ));
    }

    if fp1.structure_hash != fp2.structure_hash {
        return Err(format!(
            "{}: Circuit structure hash mismatch: {:x} vs {:x}",
            context, fp1.structure_hash, fp2.structure_hash
        ));
    }

    Ok(())
}

/// Captures a fingerprint of a circuit's structure
/// This is used to detect when different instances of the same circuit
/// have different constraint structures, which would break Nova's uniformity requirement
pub fn fingerprint_circuit<F: PrimeField, C: Circuit<F> + Clone>(
    circuit: &C,
) -> Result<CircuitFingerprint, SynthesisError> {
    use bellpepper_core::test_cs::TestConstraintSystem;

    let cs = TestConstraintSystem::<F>::new();
    let mut fp_cs = FingerprintCS::new(cs);

    let circuit_clone = circuit.clone();
    circuit_clone.synthesize(&mut fp_cs)?;

    // Get root to finalize the structure hash
    let _ = fp_cs.get_root();

    Ok(fp_cs.fingerprint().clone())
}

/// Debug helper: prints detailed fingerprint comparison
pub fn debug_fingerprint_diff(
    fp1: &CircuitFingerprint,
    fp2: &CircuitFingerprint,
    label1: &str,
    label2: &str,
) {
    eprintln!("=== Circuit Fingerprint Comparison ===");
    eprintln!("{} vs {}", label1, label2);
    eprintln!(
        "Constraints: {} vs {} (diff: {})",
        fp1.num_constraints,
        fp2.num_constraints,
        (fp1.num_constraints as i64) - (fp2.num_constraints as i64)
    );
    eprintln!(
        "Inputs: {} vs {} (diff: {})",
        fp1.num_inputs,
        fp2.num_inputs,
        (fp1.num_inputs as i64) - (fp2.num_inputs as i64)
    );
    eprintln!(
        "Aux vars: {} vs {} (diff: {})",
        fp1.num_aux,
        fp2.num_aux,
        (fp1.num_aux as i64) - (fp2.num_aux as i64)
    );
    eprintln!(
        "Structure hash: {:x} vs {:x} (match: {})",
        fp1.structure_hash,
        fp2.structure_hash,
        fp1.structure_hash == fp2.structure_hash
    );
    eprintln!("======================================");
}

/// Simple shape fingerprint for quick uniformity checking
pub fn fingerprint_shape<F: PrimeField>(circ: &impl StepCircuit<F>) -> (usize, usize, usize) {
    use bellpepper_core::test_cs::TestConstraintSystem;
    use bellpepper_core::Comparable;

    let mut cs = TestConstraintSystem::<F>::new();

    // Provide a dynamic-size z vector based on circuit arity
    // Use allocated zeros so allocation patterns match proving.
    let arity = circ.arity();
    let mut z_in = Vec::new();
    for i in 0..arity {
        z_in.push(AllocatedNum::alloc(cs.namespace(|| format!("z{}", i)), || Ok(F::ZERO)).unwrap());
    }
    let _ = circ.synthesize(&mut cs, &z_in).unwrap();

    (cs.num_constraints(), cs.num_inputs(), cs.aux().len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use arecibo::provider::PallasEngine;
    use arecibo::traits::Engine;
    use bellpepper_core::test_cs::TestConstraintSystem;
    type Fp = <PallasEngine as Engine>::Scalar;

    #[test]
    fn test_fingerprint_consistency() {
        let cs1 = TestConstraintSystem::<Fp>::new();
        let mut fp_cs1 = FingerprintCS::new(cs1);

        // Allocate some variables
        let _a = fp_cs1.alloc(|| "a", || Ok(Fp::from(1))).unwrap();
        let _b = fp_cs1.alloc(|| "b", || Ok(Fp::from(2))).unwrap();

        // Add a constraint
        fp_cs1.enforce(|| "test constraint", |lc| lc, |lc| lc, |lc| lc);

        let fp1 = fp_cs1.fingerprint().clone();

        // Create another circuit with same structure
        let cs2 = TestConstraintSystem::<Fp>::new();
        let mut fp_cs2 = FingerprintCS::new(cs2);

        let _a2 = fp_cs2.alloc(|| "a", || Ok(Fp::from(3))).unwrap(); // Different value
        let _b2 = fp_cs2.alloc(|| "b", || Ok(Fp::from(4))).unwrap(); // Different value

        fp_cs2.enforce(|| "test constraint", |lc| lc, |lc| lc, |lc| lc);

        let fp2 = fp_cs2.fingerprint().clone();

        // Fingerprints should match despite different witness values
        assert_eq!(fp1.num_constraints, fp2.num_constraints);
        assert_eq!(fp1.num_aux, fp2.num_aux);
        // Note: structure_hash might differ due to namespace handling
    }

    #[test]
    fn test_fingerprint_mismatch() {
        let cs1 = TestConstraintSystem::<Fp>::new();
        let mut fp_cs1 = FingerprintCS::new(cs1);

        let _a = fp_cs1.alloc(|| "a", || Ok(Fp::from(1))).unwrap();

        let fp1 = fp_cs1.fingerprint().clone();

        // Create circuit with different structure
        let cs2 = TestConstraintSystem::<Fp>::new();
        let mut fp_cs2 = FingerprintCS::new(cs2);

        let _a2 = fp_cs2.alloc(|| "a", || Ok(Fp::from(1))).unwrap();
        let _b2 = fp_cs2.alloc(|| "b", || Ok(Fp::from(2))).unwrap(); // Extra variable

        let fp2 = fp_cs2.fingerprint().clone();

        // Should have different aux counts
        assert_ne!(fp1.num_aux, fp2.num_aux);
    }
}
