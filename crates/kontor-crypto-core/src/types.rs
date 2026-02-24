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
}

/// Prover's representation of a file (full Merkle tree).
#[derive(Debug, Clone)]
pub struct PreparedFile {
    pub tree: MerkleTree,
    pub file_id: String,
    pub root: FieldElement,
}
