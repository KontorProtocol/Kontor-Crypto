//! Field conversion utilities for Pallas scalar (31-byte chunks).

use ff::PrimeField;

/// Convert up to 31 little-endian bytes into a field element using the
/// canonical byte representation expected by `ff::PrimeField::from_repr`.
pub fn bytes31_to_field_le<F: PrimeField>(bytes31: &[u8]) -> F {
    debug_assert!(bytes31.len() <= 31);
    let mut repr = <F as PrimeField>::Repr::default();
    let buf = repr.as_mut();
    buf[..bytes31.len()].copy_from_slice(bytes31);
    F::from_repr(repr).expect("31-byte chunks should always fit in the field")
}

/// Convert a field element to its first 31 little-endian bytes.
pub fn field_to_bytes31_le<F: PrimeField>(element: &F) -> [u8; 31] {
    let repr = element.to_repr();
    let bytes = repr.as_ref();
    let mut out = [0u8; 31];
    out.copy_from_slice(&bytes[..31]);
    out
}
