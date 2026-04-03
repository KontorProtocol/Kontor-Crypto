//! prepare_file and reconstruct_file using core primitives.

use crate::config;
use crate::erasure::{decode_file_symbols, encode_file_symbols};
use crate::error::{CoreError, Result};
use crate::merkle;
use crate::types::{FileMetadata, PreparedFile};
use sha2::{Digest, Sha256};

/// Content-addressed object identifier: `obj_<SHA256(data)>`.
pub fn compute_object_id(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("obj_{:x}", h.finalize())
}

/// Unique file identifier: `file_<SHA256(domain || len(data) || data || len(nonce) || nonce)>`.
pub fn compute_file_id(data: &[u8], nonce: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"kontor.file_id.v1");
    h.update((data.len() as u64).to_le_bytes());
    h.update(data);
    h.update((nonce.len() as u64).to_le_bytes());
    h.update(nonce);
    format!("file_{:x}", h.finalize())
}

/// Intermediate result after input validation, erasure encoding, and
/// power-of-two padding — the shared pipeline used by both `prepare_file`
/// and the WASM `prepareLeaves` entry point.
pub struct EncodedFile {
    pub object_id: String,
    pub file_id: String,
    pub padded_symbols: Vec<Vec<u8>>,
    pub padded_len: usize,
    pub original_size: usize,
}

/// Validates inputs, computes content/file IDs, erasure-encodes data,
/// and pads to a power-of-two number of symbols.
pub fn validate_and_encode(data: &[u8], filename: &str, nonce: &[u8]) -> Result<EncodedFile> {
    if data.is_empty() {
        return Err(CoreError::EmptyData {
            operation: "prepare_file".to_string(),
        });
    }
    if data.len() > config::MAX_FILE_SIZE_BYTES {
        return Err(CoreError::InvalidInput(format!(
            "prepare_file input size {} exceeds maximum {}",
            data.len(),
            config::MAX_FILE_SIZE_BYTES
        )));
    }
    if filename.is_empty() {
        return Err(CoreError::InvalidInput(
            "prepare_file filename must be non-empty".to_string(),
        ));
    }
    if filename.len() > config::MAX_FILENAME_LEN_BYTES {
        return Err(CoreError::InvalidInput(format!(
            "prepare_file filename length {} exceeds maximum {}",
            filename.len(),
            config::MAX_FILENAME_LEN_BYTES
        )));
    }
    if nonce.len() > config::MAX_NONCE_LEN_BYTES {
        return Err(CoreError::InvalidInput(format!(
            "prepare_file nonce length {} exceeds maximum {}",
            nonce.len(),
            config::MAX_NONCE_LEN_BYTES
        )));
    }

    let object_id = compute_object_id(data);
    let file_id = compute_file_id(data, nonce);

    let all_symbols = encode_file_symbols(data)?;
    let padded_len = all_symbols.len().next_power_of_two();
    let mut padded_symbols = all_symbols;
    padded_symbols.resize(padded_len, vec![0; config::CHUNK_SIZE_BYTES]);

    Ok(EncodedFile {
        object_id,
        file_id,
        padded_symbols,
        padded_len,
        original_size: data.len(),
    })
}

/// Prepares raw data into PreparedFile and FileMetadata.
/// Algorithm: object_id = SHA256(data), file_id = SHA256(domain || len(data) || data || len(nonce) || nonce),
/// encode_file_symbols, pad to power of two, build_tree, build metadata and prepared file.
pub fn prepare_file(
    data: &[u8],
    filename: &str,
    nonce: &[u8],
) -> Result<(PreparedFile, FileMetadata)> {
    let encoded = validate_and_encode(data, filename, nonce)?;

    let (tree, root) = merkle::build_tree(&encoded.padded_symbols)?;

    let metadata = FileMetadata {
        root,
        object_id: encoded.object_id,
        file_id: encoded.file_id.clone(),
        nonce: nonce.to_vec(),
        padded_len: encoded.padded_len,
        original_size: encoded.original_size,
        filename: filename.to_string(),
    };
    metadata.validate()?;

    let prepared_file = PreparedFile {
        tree,
        file_id: encoded.file_id,
        root,
    };

    Ok((prepared_file, metadata))
}

/// Reconstructs the original file from erasure-coded symbols and metadata.
pub fn reconstruct_file(symbols: &[Option<Vec<u8>>], metadata: &FileMetadata) -> Result<Vec<u8>> {
    metadata.validate()?;
    let mut mutable = symbols.to_vec();
    decode_file_symbols(
        &mut mutable,
        metadata.num_codewords(),
        metadata.original_size,
    )
}
