//! Common test utilities and shared infrastructure.
//!
//! This module provides all the shared functionality used across the test suite:
//! - `fixtures`: TestConfig struct and test scenario setup
//! - `assertions`: High-level assertion helpers for common test patterns

pub mod assertions;
pub mod fixtures;

// Re-export commonly used test helpers
#[allow(unused_imports)] // These are used across many test files
pub use fixtures::{create_multi_file_ledger, create_single_file_ledger};
