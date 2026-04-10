//! Reed-Solomon erasure coding — thin delegation to `kontor-crypto-core`.
//!
//! Error conversion from `CoreError` to `KontorPoRError` is handled
//! automatically via the `From` impl in `error.rs`.

use crate::Result;

/// Encodes a file into 31-byte symbols using multi-codeword Reed-Solomon (core implementation).
pub fn encode_file_symbols(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    Ok(kontor_crypto_core::erasure::encode_file_symbols(data)?)
}

/// Reconstructs original file from erasure-coded symbols (core implementation).
pub fn decode_file_symbols(
    symbols: &mut [Option<Vec<u8>>],
    num_codewords: usize,
    original_size: usize,
) -> Result<Vec<u8>> {
    Ok(kontor_crypto_core::erasure::decode_file_symbols(
        symbols,
        num_codewords,
        original_size,
    )?)
}
