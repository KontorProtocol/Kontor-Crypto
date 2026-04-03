//! Field conversion utilities for Pallas scalar (31-byte chunks).

use ff::PrimeField;

/// Convert up to 31 little-endian bytes into a field element using the
/// canonical byte representation expected by `ff::PrimeField::from_repr`.
pub fn bytes31_to_field_le<F: PrimeField>(bytes31: &[u8]) -> F {
    assert!(
        bytes31.len() <= 31,
        "bytes31_to_field_le: input length {} exceeds 31 bytes",
        bytes31.len()
    );
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

/// Render a field element as a lowercase hex string (MSB-first / big-endian),
/// consistent with [`field_from_hex`].
pub fn field_to_hex<F: PrimeField>(f: &F) -> String {
    use std::fmt::Write;
    let repr = f.to_repr();
    repr.as_ref()
        .iter()
        .rev()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{:02x}", b);
            s
        })
}

/// Parse a hex string (optionally `0x`-prefixed) into a field element.
/// Bytes are interpreted MSB-first and stored in reverse (little-endian repr).
pub fn field_from_hex<F: PrimeField>(hex: &str) -> F {
    let hex = hex.trim_start_matches("0x");
    let mut buf = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = core::str::from_utf8(chunk).expect("hex must be valid UTF-8");
        buf[31 - i] = u8::from_str_radix(s, 16).expect("hex must contain valid hex digits");
    }
    let mut repr = <F as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&buf);
    F::from_repr(repr).expect("hex value must fit in the field")
}
