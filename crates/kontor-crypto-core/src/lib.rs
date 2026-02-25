//! Shared cryptographic primitives for Kontor PoR (prepare_file, encode, Merkle).
//! No dependency on nova-snark; suitable for WASM and CLI.

pub mod config;
pub mod erasure;
pub mod error;
pub mod merkle;
pub mod poseidon;
pub mod prepare;
pub mod types;
pub mod utils;

pub use prepare::{prepare_file, reconstruct_file};
pub use types::{FileMetadata, PreparedFile};
