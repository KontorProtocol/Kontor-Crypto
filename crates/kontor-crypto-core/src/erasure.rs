//! Reed-Solomon erasure coding for Kontor PoR (31-byte symbols, multi-codeword).

use crate::config;
use crate::error::{CoreError, Result};
use reed_solomon_erasure::galois_8::ReedSolomon;

/// Encodes a file into 31-byte symbols using multi-codeword Reed-Solomon.
pub fn encode_file_symbols(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    if data.is_empty() {
        return Err(CoreError::EmptyData {
            operation: "encode_file_symbols".to_string(),
        });
    }

    let mut chunks = Vec::new();
    for chunk_start in (0..data.len()).step_by(config::CHUNK_SIZE_BYTES) {
        let chunk_end = std::cmp::min(chunk_start + config::CHUNK_SIZE_BYTES, data.len());
        let mut chunk = data[chunk_start..chunk_end].to_vec();
        chunk.resize(config::CHUNK_SIZE_BYTES, 0);
        chunks.push(chunk);
    }

    let rs = ReedSolomon::new(
        config::DATA_SYMBOLS_PER_CODEWORD,
        config::PARITY_SYMBOLS_PER_CODEWORD,
    )
    .map_err(|e| CoreError::Cryptographic(format!("Reed-Solomon setup failed: {e}")))?;

    let mut all_symbols = Vec::new();
    for codeword_chunks in chunks.chunks(config::DATA_SYMBOLS_PER_CODEWORD) {
        let mut codeword = codeword_chunks.to_vec();
        for _ in 0..config::PARITY_SYMBOLS_PER_CODEWORD {
            codeword.push(vec![0; config::CHUNK_SIZE_BYTES]);
        }
        while codeword.len() < config::TOTAL_SYMBOLS_PER_CODEWORD {
            codeword.push(vec![0; config::CHUNK_SIZE_BYTES]);
        }
        rs.encode(&mut codeword)
            .map_err(|e| CoreError::Cryptographic(format!("RS encode failed: {e}")))?;
        all_symbols.extend(codeword);
    }

    Ok(all_symbols)
}

/// Reconstructs original file from erasure-coded symbols.
pub fn decode_file_symbols(
    symbols: &mut [Option<Vec<u8>>],
    num_codewords: usize,
    original_size: usize,
) -> Result<Vec<u8>> {
    let rs = ReedSolomon::new(
        config::DATA_SYMBOLS_PER_CODEWORD,
        config::PARITY_SYMBOLS_PER_CODEWORD,
    )
    .map_err(|e| CoreError::Cryptographic(format!("Reed-Solomon setup failed: {e}")))?;

    let mut reconstructed = Vec::new();
    for cw_idx in 0..num_codewords {
        let start = cw_idx * config::TOTAL_SYMBOLS_PER_CODEWORD;
        let end = std::cmp::min(start + config::TOTAL_SYMBOLS_PER_CODEWORD, symbols.len());
        let mut codeword_symbols = symbols[start..end].to_vec();
        rs.reconstruct(&mut codeword_symbols).map_err(|e| {
            CoreError::Cryptographic(format!("RS decode failed for codeword {}: {e}", cw_idx))
        })?;
        let data_end = std::cmp::min(config::DATA_SYMBOLS_PER_CODEWORD, codeword_symbols.len());
        for sym in codeword_symbols.iter().take(data_end).flatten() {
            reconstructed.extend_from_slice(sym);
        }
    }
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
        assert_eq!(symbols.len(), 255);
        let mut full_symbols: Vec<Option<Vec<u8>>> = symbols.into_iter().map(Some).collect();
        let reconstructed = decode_file_symbols(&mut full_symbols, 1, data.len()).unwrap();
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn test_encode_decode_with_missing_symbols() {
        let data = b"Test data for reconstruction.";
        let symbols = encode_file_symbols(data).unwrap();
        let mut damaged: Vec<Option<Vec<u8>>> = symbols.into_iter().map(Some).collect();
        for item in damaged.iter_mut().take(20) {
            *item = None;
        }
        let reconstructed = decode_file_symbols(&mut damaged, 1, data.len()).unwrap();
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn test_empty_data() {
        assert!(encode_file_symbols(b"").is_err());
    }

    #[test]
    fn test_multi_codeword_file() {
        let data = vec![42u8; 15000];
        let symbols = encode_file_symbols(&data).unwrap();
        assert_eq!(symbols.len(), 765);
        let mut damaged: Vec<Option<Vec<u8>>> = symbols.into_iter().map(Some).collect();
        damaged[0] = None;
        damaged[255] = None;
        damaged[510] = None;
        let reconstructed = decode_file_symbols(&mut damaged, 3, data.len()).unwrap();
        assert_eq!(reconstructed, data);
    }
}
