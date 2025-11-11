//! Circuit gadgets for Nova PoR.
//!
//! This module contains low-level circuit components used in the synthesis.

pub mod hash;
pub mod merkle;

// Re-export commonly used gadgets
pub use hash::{conditional_select, poseidon_hash_tagged_gadget};
pub use merkle::{verify_aggregation_path_gated, verify_merkle_path_gated};
