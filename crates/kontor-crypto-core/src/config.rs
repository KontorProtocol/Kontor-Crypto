//! Shared configuration constants for prepare_file / encode / build_tree.

/// Chunk/symbol size in bytes (fits in Pallas scalar field).
pub const CHUNK_SIZE_BYTES: usize = 31;

/// Data symbols per Reed-Solomon codeword (GF(2^8): total ≤ 255).
pub const DATA_SYMBOLS_PER_CODEWORD: usize = 231;

/// Parity symbols per codeword.
pub const PARITY_SYMBOLS_PER_CODEWORD: usize = 24;

/// Total symbols per codeword (data + parity).
pub const TOTAL_SYMBOLS_PER_CODEWORD: usize = 255;

/// Maximum accepted raw file size for `prepare_file` (100 MB).
pub const MAX_FILE_SIZE_BYTES: usize = 100 * 1024 * 1024;

/// Maximum accepted filename length in bytes.
pub const MAX_FILENAME_LEN_BYTES: usize = 1024;

/// Maximum accepted file identifier / object identifier length in bytes.
pub const MAX_IDENTIFIER_LEN_BYTES: usize = 1024;

/// Maximum accepted nonce length in bytes.
pub const MAX_NONCE_LEN_BYTES: usize = 4096;
