//! Circuit gadgets for Nova PoR.
//!
//! This module contains low-level circuit components used in the synthesis.

pub mod merkle;
pub mod poseidon;
pub mod select;

// Re-export commonly used gadgets
pub use merkle::{verify_aggregation_path_gated, verify_merkle_path_gated};
pub use poseidon::poseidon_hash_tagged_gadget;
pub use select::conditional_select;
