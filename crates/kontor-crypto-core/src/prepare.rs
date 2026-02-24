//! prepare_file and reconstruct_file using core primitives.

use crate::config;
use crate::erasure::{decode_file_symbols, encode_file_symbols};
use crate::error::{CoreError, Result};
use crate::merkle;
use crate::types::{FileMetadata, PreparedFile};
use sha2::{Digest, Sha256};

/// Prepares raw data into PreparedFile and FileMetadata.
/// Algorithm: object_id = SHA256(data), file_id = SHA256(data||nonce),
/// encode_file_symbols, pad to power of two, build_tree, build metadata and prepared file.
pub fn prepare_file(
    data: &[u8],
    filename: &str,
    nonce: &[u8],
) -> Result<(PreparedFile, FileMetadata)> {
    if data.is_empty() {
        return Err(CoreError::EmptyData {
            operation: "prepare_file".to_string(),
        });
    }

    let mut object_hasher = Sha256::new();
    object_hasher.update(data);
    let object_id = format!("obj_{:x}", object_hasher.finalize());

    let mut file_hasher = Sha256::new();
    file_hasher.update(data);
    file_hasher.update(nonce);
    let file_id = format!("file_{:x}", file_hasher.finalize());

    let all_symbols = encode_file_symbols(data)?;
    let padded_len = all_symbols.len().next_power_of_two();
    let mut padded_symbols = all_symbols;
    padded_symbols.resize(padded_len, vec![0; config::CHUNK_SIZE_BYTES]);

    let (tree, root) = merkle::build_tree(&padded_symbols)?;

    let metadata = FileMetadata {
        root,
        object_id,
        file_id: file_id.clone(),
        nonce: nonce.to_vec(),
        padded_len,
        original_size: data.len(),
        filename: filename.to_string(),
    };

    let prepared_file = PreparedFile {
        tree,
        file_id,
        root,
    };

    Ok((prepared_file, metadata))
}

/// Reconstructs the original file from erasure-coded symbols and metadata.
pub fn reconstruct_file(
    symbols: &[Option<Vec<u8>>],
    metadata: &FileMetadata,
) -> Result<Vec<u8>> {
    let mut mutable = symbols.to_vec();
    decode_file_symbols(&mut mutable, metadata.num_codewords(), metadata.original_size)
}
