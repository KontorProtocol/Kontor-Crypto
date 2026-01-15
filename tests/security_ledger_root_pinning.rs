//! Test that verifier properly rejects proofs when wrong aggregated root is provided.
//!
//! This test demonstrates the security improvement from pinning the ledger root:
//! a malicious prover cannot substitute a different ledger with a different root.

use kontor_crypto::{
    api::{self, Challenge, FieldElement, PorSystem},
    FileLedger,
};
use std::collections::BTreeMap;

mod common;

#[test]
fn test_wrong_aggregated_root_fails_verification() {
    println!("Testing that verification fails with wrong aggregated root");

    // Create two files for multi-file proof
    let data1 = b"First test file content for security test";
    let data2 = b"Second test file content for security test";

    // Prepare both files
    let (prepared1, metadata1) =
        api::prepare_file(data1, "test_file.dat", b"").expect("Should prepare first file");
    let (prepared2, metadata2) =
        api::prepare_file(data2, "test_file.dat", b"").expect("Should prepare second file");

    // Create legitimate ledger with both files
    let mut legitimate_ledger = FileLedger::new();
    legitimate_ledger
        .add_file(&metadata1)
        .expect("Should add file 1 to legitimate ledger");
    legitimate_ledger
        .add_file(&metadata2)
        .expect("Should add file 2 to legitimate ledger");

    // Create challenges for both files
    let seed = FieldElement::from(12345u64);
    let challenges = vec![
        Challenge::new_test(metadata1.clone(), 1000, 1, seed),
        Challenge::new_test(metadata2.clone(), 1000, 1, seed),
    ];

    // Create file map
    let mut files = BTreeMap::new();
    files.insert(metadata1.file_id.clone(), &prepared1);
    files.insert(metadata2.file_id.clone(), &prepared2);

    // Generate proof with legitimate ledger
    let system = PorSystem::new(&legitimate_ledger);
    let files_vec: Vec<&_> = files.values().copied().collect();
    let proof = system
        .prove(files_vec, &challenges)
        .expect("Should generate proof with legitimate ledger");

    // SECURITY TEST 1: Verify with correct aggregated root (should succeed)
    let correct_root = legitimate_ledger.tree.root();
    let valid_result = system
        .verify(&proof, &challenges)
        .expect("Verification with correct root should complete");
    assert!(
        valid_result,
        "Proof should verify with correct aggregated root"
    );

    println!("✓ Proof verifies with correct aggregated root");

    // SECURITY TEST 2: Create a malicious ledger with only one file (different root)
    let mut malicious_ledger = FileLedger::new();
    malicious_ledger
        .add_file(&metadata1)
        .expect("Should add file 1 to malicious ledger");
    // Note: deliberately omitting file 2, so malicious ledger has different root

    let malicious_root = malicious_ledger.tree.root();

    // Verify that the roots are actually different
    assert_ne!(
        correct_root, malicious_root,
        "Legitimate and malicious ledgers should have different roots"
    );

    // SECURITY TEST 3: Verification with wrong aggregated root should fail
    let malicious_system = api::PorSystem::new(&malicious_ledger);
    let malicious_result = malicious_system.verify(&proof, &challenges);

    match malicious_result {
        Ok(is_valid) => {
            assert!(
                !is_valid,
                "SECURITY VIOLATION: Proof should NOT verify with wrong aggregated root!"
            );
        }
        Err(_) => {
            // Error is also acceptable - the important thing is that it doesn't succeed
            println!("✓ Verification failed with error (acceptable)");
        }
    }

    println!("✓ Security test passed: wrong aggregated root prevented verification");
    println!("✓ All security tests passed: ledger root pinning is working correctly");
}
