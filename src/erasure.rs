//! Reed-Solomon erasure coding module for the Kontor PoR system.
//!
//! This module implements multi-codeword Reed-Solomon erasure coding using fixed
//! 31-byte symbols. This design ensures that Merkle tree leaves directly encode
//! retrievable data rather than hashes, providing Proof of Retrievability security.
//!
//! ## Design
//!
//! - **Symbol Size**: Fixed at 31 bytes (max field element size for Pallas curve)
//! - **Codeword Structure**: 231 data symbols + 24 parity symbols = 255 total (GF(2^8) constraint)
//! - **Multi-Codeword**: Files larger than 231 symbols are encoded as multiple independent codewords
//! - **Redundancy**: ~10% overhead (24/231 ≈ 10.4%)
//!
//! ## Example
//!
//! ```rust,no_run
//! use kontor_crypto::erasure::{encode_file_symbols, decode_file_symbols};
//!
//! // Encode file into 31-byte symbols
//! let data = b"Hello, world! This is test data.";
//! let symbols = encode_file_symbols(data)?;
//!
//! // Simulate losing some symbols
//! let mut damaged_symbols: Vec<Option<Vec<u8>>> = symbols.into_iter().map(Some).collect();
//! damaged_symbols[0] = None;
//! damaged_symbols[10] = None;
//!
//! // Reconstruct (assuming we know num_codewords and original_size)
//! let num_codewords = 1;  // For small files
//! let reconstructed = decode_file_symbols(&mut damaged_symbols, num_codewords, data.len())?;
//! assert_eq!(reconstructed, data);
//! # Ok::<(), kontor_crypto::KontorPoRError>(())
//! ```

use crate::{config, KontorPoRError, Result};
use reed_solomon_erasure::galois_8::ReedSolomon;

/// Encodes a file into 31-byte symbols using multi-codeword Reed-Solomon.
///
/// This function partitions the file into 31-byte chunks, groups them into
/// codewords of 231 data symbols each, applies RS encoding to each codeword,
/// and returns all symbols (data + parity) as a flat list.
///
/// # Arguments
///
/// * `data` - The raw file bytes to encode
///
/// # Returns
///
/// Returns a vector of all symbols (each 31 bytes), including both data and parity.
/// Symbols are ordered by codeword: [cw0_data, cw0_parity, cw1_data, cw1_parity, ...]
///
/// # Example
///
/// ```rust,no_run
/// use kontor_crypto::erasure::encode_file_symbols;
///
/// let data = b"Hello, world!";
/// let symbols = encode_file_symbols(data)?;
/// // Each symbol is 31 bytes, symbols.len() will be a multiple of 255
/// # Ok::<(), kontor_crypto::KontorPoRError>(())
/// ```
pub fn encode_file_symbols(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    if data.is_empty() {
        return Err(KontorPoRError::EmptyData {
            operation: "encode_file_symbols".to_string(),
        });
    }

    // Partition into 31-byte chunks
    let mut chunks = Vec::new();
    for chunk_start in (0..data.len()).step_by(config::CHUNK_SIZE_BYTES) {
        let chunk_end = std::cmp::min(chunk_start + config::CHUNK_SIZE_BYTES, data.len());
        let mut chunk = data[chunk_start..chunk_end].to_vec();
        chunk.resize(config::CHUNK_SIZE_BYTES, 0); // Pad final chunk
        chunks.push(chunk);
    }

    // Create RS encoder
    let rs = ReedSolomon::new(
        config::DATA_SYMBOLS_PER_CODEWORD,
        config::PARITY_SYMBOLS_PER_CODEWORD,
    )
    .map_err(|e| KontorPoRError::Cryptographic(format!("Reed-Solomon setup failed: {e}")))?;

    // Encode each codeword
    let mut all_symbols = Vec::new();

    for codeword_chunks in chunks.chunks(config::DATA_SYMBOLS_PER_CODEWORD) {
        // Create codeword with data + parity slots
        let mut codeword = codeword_chunks.to_vec();

        // Add parity symbol slots
        for _ in 0..config::PARITY_SYMBOLS_PER_CODEWORD {
            codeword.push(vec![0; config::CHUNK_SIZE_BYTES]);
        }

        // Pad partial last codeword to 255 symbols
        while codeword.len() < config::TOTAL_SYMBOLS_PER_CODEWORD {
            codeword.push(vec![0; config::CHUNK_SIZE_BYTES]);
        }

        // RS encode this codeword
        rs.encode(&mut codeword)
            .map_err(|e| KontorPoRError::Cryptographic(format!("RS encode failed: {e}")))?;

        all_symbols.extend(codeword);
    }

    Ok(all_symbols)
}

/// Reconstructs original file from erasure-coded symbols.
///
/// This function takes a vector of symbols (some possibly missing) and reconstructs
/// the original file data. Missing symbols are represented as `None`. The function
/// will fail if too many symbols are missing within any single codeword (> 24 missing).
///
/// # Arguments
///
/// * `symbols` - Vector of symbols where `None` represents missing symbols
/// * `num_codewords` - Number of RS codewords in the file
/// * `original_size` - Original file size in bytes (for truncation)
///
/// # Returns
///
/// Returns the reconstructed file data, or an error if too many symbols are missing.
///
/// # Example
///
/// ```rust,no_run
/// use kontor_crypto::erasure::{encode_file_symbols, decode_file_symbols};
///
/// let data = b"Test data";
/// let symbols = encode_file_symbols(data)?;
/// let num_codewords = 1;
///
/// // Simulate missing symbols
/// let mut damaged: Vec<Option<Vec<u8>>> = symbols.into_iter().map(Some).collect();
/// damaged[0] = None;
///
/// let reconstructed = decode_file_symbols(&mut damaged, num_codewords, data.len())?;
/// assert_eq!(reconstructed, data);
/// # Ok::<(), kontor_crypto::KontorPoRError>(())
/// ```
pub fn decode_file_symbols(
    symbols: &mut [Option<Vec<u8>>],
    num_codewords: usize,
    original_size: usize,
) -> Result<Vec<u8>> {
    let rs = ReedSolomon::new(
        config::DATA_SYMBOLS_PER_CODEWORD,
        config::PARITY_SYMBOLS_PER_CODEWORD,
    )
    .map_err(|e| KontorPoRError::Cryptographic(format!("Reed-Solomon setup failed: {e}")))?;

    let mut reconstructed = Vec::new();

    // Decode each codeword independently
    for cw_idx in 0..num_codewords {
        let start = cw_idx * config::TOTAL_SYMBOLS_PER_CODEWORD;
        let end = std::cmp::min(start + config::TOTAL_SYMBOLS_PER_CODEWORD, symbols.len());

        let mut codeword_symbols = symbols[start..end].to_vec();

        // Reconstruct this codeword
        rs.reconstruct(&mut codeword_symbols).map_err(|e| {
            KontorPoRError::Cryptographic(format!("RS decode failed for codeword {}: {e}", cw_idx))
        })?;

        // Extract data symbols (first 231)
        let data_end = std::cmp::min(config::DATA_SYMBOLS_PER_CODEWORD, codeword_symbols.len());
        for sym in codeword_symbols.iter().take(data_end).flatten() {
            reconstructed.extend_from_slice(sym);
        }
    }

    // Truncate to original size
    reconstructed.truncate(original_size);
    Ok(reconstructed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip_small() {
        let data = b"Hello, world! This is a test.";
        let symbols = encode_file_symbols(data).unwrap();

        // Should have 1 codeword (255 symbols)
        assert_eq!(symbols.len(), 255);

        // All present - reconstruct
        let mut full_symbols: Vec<Option<Vec<u8>>> = symbols.into_iter().map(Some).collect();
        let reconstructed = decode_file_symbols(&mut full_symbols, 1, data.len()).unwrap();

        assert_eq!(reconstructed, data);
    }

    #[test]
    fn test_encode_decode_with_missing_symbols() {
        let data = b"Test data for reconstruction.";
        let symbols = encode_file_symbols(data).unwrap();

        // Simulate losing 20 symbols (within 24 tolerance)
        let mut damaged: Vec<Option<Vec<u8>>> = symbols.into_iter().map(Some).collect();
        for item in damaged.iter_mut().take(20) {
            *item = None;
        }

        let reconstructed = decode_file_symbols(&mut damaged, 1, data.len()).unwrap();
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn test_too_many_missing_symbols() {
        let data = b"Test";
        let symbols = encode_file_symbols(data).unwrap();

        // Lose 25 symbols (exceeds tolerance of 24)
        let mut damaged: Vec<Option<Vec<u8>>> = symbols.into_iter().map(Some).collect();
        for item in damaged.iter_mut().take(25) {
            *item = None;
        }

        assert!(decode_file_symbols(&mut damaged, 1, data.len()).is_err());
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        assert!(encode_file_symbols(data).is_err());
    }

    #[test]
    fn test_multi_codeword_file() {
        // Create data that requires multiple codewords
        // 231 symbols * 31 bytes = 7161 bytes per codeword
        let data = vec![42u8; 15000]; // ~2.1 codewords

        let symbols = encode_file_symbols(&data).unwrap();

        // Should have 3 codewords (3 * 255 = 765 symbols)
        assert_eq!(symbols.len(), 765);

        // Test reconstruction with some missing symbols from each codeword
        let mut damaged: Vec<Option<Vec<u8>>> = symbols.into_iter().map(Some).collect();
        damaged[0] = None; // codeword 0
        damaged[255] = None; // codeword 1
        damaged[510] = None; // codeword 2

        let reconstructed = decode_file_symbols(&mut damaged, 3, data.len()).unwrap();
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn test_single_byte() {
        let data = b"A";
        let symbols = encode_file_symbols(data).unwrap();
        assert_eq!(symbols.len(), 255);

        let mut full: Vec<Option<Vec<u8>>> = symbols.into_iter().map(Some).collect();
        let reconstructed = decode_file_symbols(&mut full, 1, data.len()).unwrap();
        assert_eq!(reconstructed, data);
    }
}
