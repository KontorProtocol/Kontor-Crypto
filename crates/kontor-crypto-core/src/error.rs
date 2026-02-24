//! Error types for prepare_file / encode / build_tree.

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// Empty data provided where non-empty data is required.
    #[error("Empty data: {operation} requires non-empty input data")]
    EmptyData { operation: String },

    /// Invalid input parameters.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Merkle tree construction or operations failed.
    #[error("Merkle tree error: {0}")]
    MerkleTree(String),

    /// Erasure coding validation or encoding failed.
    #[error("Erasure coding error: {details}")]
    ErasureCoding { details: String },

    /// Cryptographic operation failed.
    #[error("Cryptographic error: {0}")]
    Cryptographic(String),

    /// Index out of bounds.
    #[error("Index out of bounds: index {index}, length {length}")]
    IndexOutOfBounds { index: usize, length: usize },
}

pub type Result<T> = std::result::Result<T, CoreError>;
