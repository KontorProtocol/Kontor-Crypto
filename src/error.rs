//! Error types for the Kontor PoR library

/// Error types for the Kontor PoR library
#[derive(Debug, thiserror::Error)]
pub enum NovaPoRError {
    /// Merkle tree construction or operations failed
    #[error("Merkle tree error: {0}")]
    MerkleTree(String),

    /// Circuit construction or synthesis failed
    #[error("Circuit error: {0}")]
    Circuit(String),

    /// SNARK creation or verification failed
    #[error("SNARK error: {0}")]
    Snark(String),

    /// Invalid input parameters (generic fallback)
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Empty data provided where non-empty data is required
    #[error("Empty data: {operation} requires non-empty input data")]
    EmptyData { operation: String },

    /// Too many files requested
    #[error("Too many files: {got} exceeds limit of {max}")]
    TooManyFiles { got: usize, max: usize },

    /// File not found in collection
    #[error("File not found: {file_id}")]
    FileNotFound { file_id: String },

    /// File not found in ledger
    #[error("File not in ledger: {file_id} (possible depth spoofing)")]
    FileNotInLedger { file_id: String },

    /// Inconsistent challenge parameters
    #[error("Challenge mismatch: {field} values must be consistent across all challenges")]
    ChallengeMismatch { field: String },

    /// Invalid challenge count
    #[error("Invalid challenge count: {count} (must be > 0 and <= {max})", max = crate::config::MAX_NUM_CHALLENGES)]
    InvalidChallengeCount { count: usize },

    /// Chunk size validation failed
    #[error("Invalid chunk size: {size} bytes (must be > 0 and ≤ {max})")]
    InvalidChunkSize { size: usize, max: usize },

    /// File metadata mismatch
    #[error("Metadata mismatch: file root does not match expected value")]
    MetadataMismatch,

    /// Erasure coding validation failed
    #[error("Erasure coding error: {details}")]
    ErasureCoding { details: String },

    /// Ledger validation failed
    #[error("Ledger validation failed: {reason}")]
    LedgerValidation { reason: String },

    /// Cryptographic operation failed
    #[error("Cryptographic error: {0}")]
    Cryptographic(String),

    /// Serialization/deserialization failed
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// IO operation failed
    #[error("IO error: {0}")]
    IO(String),

    /// Index out of bounds
    #[error("Index out of bounds: index {index}, length {length}")]
    IndexOutOfBounds { index: usize, length: usize },

    /// Invalid chunk encoding (chunk too large for field)
    #[error("Invalid chunk encoding: chunk size {size} bytes exceeds maximum {max} bytes")]
    InvalidChunkEncoding { size: usize, max: usize },
}

/// Convenience Result type for Nova PoR operations
pub type Result<T> = std::result::Result<T, NovaPoRError>;
