//! Field conversion utilities for Pallas scalar (31-byte chunks).

use crate::error::{CoreError, Result};
use ff::PrimeField;

/// Convert up to 31 little-endian bytes into a field element using the
/// canonical byte representation expected by `ff::PrimeField::from_repr`.
pub fn bytes31_to_field_le<F: PrimeField>(bytes31: &[u8]) -> Result<F> {
    if bytes31.len() > 31 {
        return Err(CoreError::InvalidInput(format!(
            "bytes31_to_field_le: input length {} exceeds 31 bytes",
            bytes31.len()
        )));
    }
    let mut repr = <F as PrimeField>::Repr::default();
    let buf = repr.as_mut();
    buf[..bytes31.len()].copy_from_slice(bytes31);
    F::from_repr(repr).into_option().ok_or_else(|| {
        CoreError::InvalidInput("bytes31_to_field_le: input does not fit in field".to_string())
    })
}

/// Convert a field element to its first 31 little-endian bytes.
pub fn field_to_bytes31_le<F: PrimeField>(element: &F) -> [u8; 31] {
    let repr = element.to_repr();
    let bytes = repr.as_ref();
    let mut out = [0u8; 31];
    out.copy_from_slice(&bytes[..31]);
    out
}

/// Render a field element as a lowercase hex string in canonical
/// `PrimeField::to_repr()` byte order (little-endian for Pallas Fq).
///
/// This produces the same output as `hex::encode(f.to_repr())` and is the
/// inverse of [`field_from_hex`]. The byte order matches what the Kontor
/// indexer (`bytes_to_field_element`) and the filestorage contract expect
/// when consuming a `root` field via WIT.
pub fn field_to_hex<F: PrimeField>(f: &F) -> String {
    use std::fmt::Write;
    let repr = f.to_repr();
    repr.as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{:02x}", b);
            s
        })
}

/// Parse a hex string (optionally `0x`-prefixed) into a field element.
///
/// Bytes are interpreted as the canonical `PrimeField::Repr`
/// (little-endian for Pallas Fq), matching [`field_to_hex`].
pub fn field_from_hex<F: PrimeField>(hex: &str) -> Result<F> {
    let hex = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);
    if hex.len() != 64 {
        return Err(CoreError::InvalidInput(format!(
            "field_from_hex: expected 64 hex characters, got {}",
            hex.len()
        )));
    }
    if !hex.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(CoreError::InvalidInput(
            "field_from_hex: input contains non-hex characters".to_string(),
        ));
    }

    let mut buf = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = core::str::from_utf8(chunk).map_err(|_| {
            CoreError::InvalidInput("field_from_hex: hex must be valid UTF-8".to_string())
        })?;
        buf[i] = u8::from_str_radix(s, 16)
            .map_err(|_| CoreError::InvalidInput("field_from_hex: invalid hex byte".to_string()))?;
    }
    let mut repr = <F as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&buf);
    F::from_repr(repr).into_option().ok_or_else(|| {
        CoreError::InvalidInput(
            "field_from_hex: hex value is not a canonical field element".to_string(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2curves::pasta::Fq;

    #[test]
    fn field_to_hex_matches_hex_encode_to_repr() {
        // Spec invariant: field_to_hex MUST be byte-equivalent to hex::encode(fe.to_repr()).
        for i in 0u64..100 {
            let fe = Fq::from(i.wrapping_mul(2654435761));
            let via_field_to_hex = field_to_hex(&fe);
            let via_hex_encode = hex::encode(fe.to_repr());
            assert_eq!(via_field_to_hex, via_hex_encode, "mismatch at i={i}");
        }
    }

    #[test]
    fn field_to_hex_field_from_hex_round_trip() {
        for i in 0u64..100 {
            let fe = Fq::from(i.wrapping_mul(2654435761));
            let hex = field_to_hex(&fe);
            let recovered: Fq = field_from_hex(&hex).unwrap();
            assert_eq!(fe, recovered, "round-trip failed at i={i}");
        }
    }

    #[test]
    fn field_from_hex_field_to_hex_round_trip() {
        // hex string round-trip
        let fe = Fq::from(0x1234_5678_9abc_def0u64);
        let hex = field_to_hex(&fe);
        let again = field_to_hex(&field_from_hex::<Fq>(&hex).unwrap());
        assert_eq!(hex, again);
    }

    #[test]
    fn field_from_hex_accepts_0x_prefix() {
        let fe = Fq::from(42u64);
        let hex = field_to_hex(&fe);
        let prefixed = format!("0x{hex}");
        assert_eq!(field_from_hex::<Fq>(&prefixed).unwrap(), fe);
    }

    #[test]
    fn field_from_hex_rejects_malformed_input() {
        assert!(field_from_hex::<Fq>("").is_err());
        assert!(field_from_hex::<Fq>("abc").is_err());
        assert!(field_from_hex::<Fq>(&"00".repeat(33)).is_err());
        assert!(field_from_hex::<Fq>(&format!("{}zz", "00".repeat(31))).is_err());
    }

    #[test]
    fn bytes31_to_field_le_rejects_overlong_input() {
        assert!(bytes31_to_field_le::<Fq>(&[0u8; 31]).is_ok());
        assert!(bytes31_to_field_le::<Fq>(&[0u8; 32]).is_err());
    }
}
