//! Fuzz target stubs for Kontor PoR.
//!
//! These are `#[ignore]`-d placeholder tests documenting intended fuzzing coverage.
//! Actual fuzz harnesses should be implemented using `cargo-fuzz` or `proptest`
//! before production deployment.
//!
//! Run with `cargo test --test fuzzing_targets -- --ignored` to list them.

/// FUZ-01: Fuzz build_tree + get_padded_proof_for_leaf + verify_merkle_proof_in_place
///
/// Properties to verify:
/// - Never panics regardless of input
/// - verify returns true IFF the proof was constructed from the same tree
/// - All indices < leaf_count should produce valid proofs
#[test]
#[ignore = "stub: implement with cargo-fuzz (merkle roundtrip)"]
fn fuz01_merkle_operations() {
    unimplemented!("implement with cargo-fuzz or proptest");
}

/// FUZ-02: Fuzz prepare_file with random bytes
///
/// Properties to verify:
/// - Never panics for any input data
/// - Metadata is always coherent (tree depth matches padded_len)
/// - object_id is deterministic for same file content
/// - file_id is deterministic for same input (content + nonce)
#[test]
#[ignore = "stub: implement with cargo-fuzz (prepare_file)"]
fn fuz02_prepare_file() {
    unimplemented!("implement with cargo-fuzz or proptest");
}

/// FUZ-03: Fuzz prove/verify cycle with small shapes
///
/// Properties to verify:
/// - verify(prove(x)) == true for all valid x
/// - No panics for any input combination
#[test]
#[ignore = "stub: implement with cargo-fuzz (prove/verify roundtrip)"]
fn fuz03_prove_verify_cycle() {
    unimplemented!("implement with cargo-fuzz or proptest");
}

/// FUZ-04: Property test for domain tag separation
///
/// Properties to verify:
/// - For random (x, y), all domain tags produce different hashes
/// - No collision between any pair of domain tags
#[test]
#[ignore = "stub: implement with proptest (domain tag separation)"]
fn fuz04_domain_tag_separation() {
    unimplemented!("implement with proptest");
}

/// FUZ-05: Property test for challenge index uniformity
///
/// Properties to verify:
/// - Challenge indices are uniformly distributed
/// - Chi-squared test passes for large sample
#[test]
#[ignore = "stub: implement with proptest (challenge index uniformity)"]
fn fuz05_challenge_uniformity() {
    unimplemented!("implement with proptest");
}
