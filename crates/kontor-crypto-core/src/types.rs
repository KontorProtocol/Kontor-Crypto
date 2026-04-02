//! Core types for prepare_file: FileMetadata and PreparedFile.

use crate::config;
use crate::merkle::MerkleTree;
use crate::poseidon::FieldElement;
use serde::{Deserialize, Serialize};

/// Public commitment to a file (same shape as main crate api/types).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMetadata {
    pub root: FieldElement,
    pub object_id: String,
    pub file_id: String,
    pub nonce: Vec<u8>,
    pub padded_len: usize,
    pub original_size: usize,
    pub filename: String,
}

impl FileMetadata {
    pub fn num_data_symbols(&self) -> usize {
        self.original_size.div_ceil(config::CHUNK_SIZE_BYTES)
    }

    pub fn num_codewords(&self) -> usize {
        self.num_data_symbols()
            .div_ceil(config::DATA_SYMBOLS_PER_CODEWORD)
    }

    pub fn total_symbols(&self) -> usize {
        self.num_codewords() * config::TOTAL_SYMBOLS_PER_CODEWORD
    }

    pub fn depth(&self) -> usize {
        if self.padded_len == 0 {
            0
        } else {
            self.padded_len.trailing_zeros() as usize
        }
    }

    /// Validate metadata consistency and security bounds.
    pub fn validate(&self) -> crate::error::Result<()> {
        use crate::error::CoreError;

        if self.file_id.is_empty() {
            return Err(CoreError::InvalidInput(
                "FileMetadata.file_id must be non-empty".to_string(),
            ));
        }
        if self.object_id.is_empty() {
            return Err(CoreError::InvalidInput(
                "FileMetadata.object_id must be non-empty".to_string(),
            ));
        }
        if self.filename.is_empty() {
            return Err(CoreError::InvalidInput(
                "FileMetadata.filename must be non-empty".to_string(),
            ));
        }
        if self.file_id.len() > config::MAX_IDENTIFIER_LEN_BYTES {
            return Err(CoreError::InvalidInput(format!(
                "FileMetadata.file_id length {} exceeds maximum {}",
                self.file_id.len(),
                config::MAX_IDENTIFIER_LEN_BYTES
            )));
        }
        if self.object_id.len() > config::MAX_IDENTIFIER_LEN_BYTES {
            return Err(CoreError::InvalidInput(format!(
                "FileMetadata.object_id length {} exceeds maximum {}",
                self.object_id.len(),
                config::MAX_IDENTIFIER_LEN_BYTES
            )));
        }
        if self.filename.len() > config::MAX_FILENAME_LEN_BYTES {
            return Err(CoreError::InvalidInput(format!(
                "FileMetadata.filename length {} exceeds maximum {}",
                self.filename.len(),
                config::MAX_FILENAME_LEN_BYTES
            )));
        }
        if self.nonce.len() > config::MAX_NONCE_LEN_BYTES {
            return Err(CoreError::InvalidInput(format!(
                "FileMetadata.nonce length {} exceeds maximum {}",
                self.nonce.len(),
                config::MAX_NONCE_LEN_BYTES
            )));
        }
        if self.original_size == 0 {
            return Err(CoreError::InvalidInput(
                "FileMetadata.original_size must be > 0".to_string(),
            ));
        }
        if self.original_size > config::MAX_FILE_SIZE_BYTES {
            return Err(CoreError::InvalidInput(format!(
                "FileMetadata.original_size {} exceeds maximum {}",
                self.original_size,
                config::MAX_FILE_SIZE_BYTES
            )));
        }
        if self.padded_len == 0 {
            return Err(CoreError::InvalidInput(
                "FileMetadata.padded_len must be > 0".to_string(),
            ));
        }
        if !self.padded_len.is_power_of_two() {
            return Err(CoreError::InvalidInput(format!(
                "FileMetadata.padded_len {} must be a power of two",
                self.padded_len
            )));
        }

        let num_data_symbols = self.original_size.div_ceil(config::CHUNK_SIZE_BYTES);
        let num_codewords = num_data_symbols.div_ceil(config::DATA_SYMBOLS_PER_CODEWORD);
        let total_symbols = num_codewords
            .checked_mul(config::TOTAL_SYMBOLS_PER_CODEWORD)
            .ok_or_else(|| {
                CoreError::InvalidInput("FileMetadata symbol count overflow".to_string())
            })?;
        if total_symbols == 0 {
            return Err(CoreError::InvalidInput(
                "FileMetadata implied symbol count must be > 0".to_string(),
            ));
        }

        let expected_padded_len = total_symbols.next_power_of_two();
        if self.padded_len != expected_padded_len {
            return Err(CoreError::InvalidInput(format!(
                "FileMetadata.padded_len {} does not match expected {} for original_size {}",
                self.padded_len, expected_padded_len, self.original_size
            )));
        }

        let encoded_capacity = total_symbols
            .checked_mul(config::CHUNK_SIZE_BYTES)
            .ok_or_else(|| {
                CoreError::InvalidInput(
                    "FileMetadata encoded byte capacity overflow".to_string(),
                )
            })?;
        if self.original_size > encoded_capacity {
            return Err(CoreError::InvalidInput(format!(
                "FileMetadata.original_size {} exceeds encoded capacity {}",
                self.original_size, encoded_capacity
            )));
        }

        Ok(())
    }
}

/// Prover's representation of a file (full Merkle tree).
#[derive(Debug, Clone)]
pub struct PreparedFile {
    pub tree: MerkleTree,
    pub file_id: String,
    pub root: FieldElement,
}
