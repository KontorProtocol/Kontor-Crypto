//! Shared cryptographic primitives for Kontor PoR (prepare_file, encode, Merkle).
//! No dependency on nova-snark; suitable for WASM and CLI.

#![deny(unsafe_code)]

pub mod config;
pub mod erasure;
pub mod error;
pub mod merkle;
pub mod poseidon;
pub mod prepare;
pub mod types;
pub mod utils;

pub use prepare::{
    compute_file_id, compute_object_id, prepare_file, reconstruct_file, validate_and_encode,
    EncodedFile,
};
pub use types::{FileMetadata, PreparedFile};
