//! High-level assertion helpers for common test patterns.

#![allow(dead_code)]
//!
//! This module provides declarative assertion functions that encapsulate
//! the most common test patterns: prove-and-verify-succeeds, prove-fails, etc.

use super::fixtures::{setup_test_scenario, TestConfig, TestSetup};
use kontor_crypto::api::{Challenge, FieldElement, PorSystem};
use kontor_crypto::ledger::FileLedger;

/// Helper function to determine the expected aggregated root for verification.
/// For single-file cases, uses the file root. For multi-file cases, uses the ledger root.
fn get_expected_aggregated_root(
    challenges: &[Challenge],
    ledger: Option<&FileLedger>,
) -> FieldElement {
    if let Some(ledger) = ledger {
        // Multi-file case: use ledger root
        ledger.tree.root()
    } else {
        // Single-file case: use the file root from the first (and only) challenge
        challenges[0].file_metadata.root
    }
}

/// Asserts that proof generation and verification both succeed.
pub fn assert_prove_and_verify_succeeds(setup: TestSetup) {
    let file_refs = setup.file_refs();
    let ledger_ref = setup.ledger_ref();

    // Generate proof
    let ledger = ledger_ref.expect("Ledger should be available for unified API");
    let system = PorSystem::new(ledger);
    let files_vec: Vec<&_> = file_refs.values().copied().collect();
    let proof = system
        .prove(files_vec, &setup.challenges)
        .expect("Proof generation should have succeeded");

    // Verify proof
    let is_valid = system
        .verify(&proof, &setup.challenges)
        .expect("Verification should have completed without error");

    assert!(is_valid, "Proof should have verified as valid");
}

/// Asserts that proof generation fails with an expected error message.
pub fn assert_prove_fails(setup: TestSetup, expected_error_substring: &str) {
    let file_refs = setup.file_refs();
    let ledger_ref = setup.ledger_ref();

    let ledger = ledger_ref.expect("Ledger should be available for unified API");
    let system = PorSystem::new(ledger);
    let files_vec: Vec<&_> = file_refs.values().copied().collect();
    let result = system.prove(files_vec, &setup.challenges);

    match result {
        Ok(_) => panic!("Expected proof generation to fail, but it succeeded"),
        Err(error) => {
            let error_msg = format!("{}", error);
            assert!(
                error_msg.contains(expected_error_substring),
                "Expected error message to contain '{}', but got: {}",
                expected_error_substring,
                error_msg
            );
        }
    }
}

/// Asserts that proof generation succeeds but verification fails.
pub fn assert_verify_fails(setup: TestSetup) {
    let file_refs = setup.file_refs();
    let ledger_ref = setup.ledger_ref();

    // Generate proof (should succeed)
    let ledger = ledger_ref.expect("Ledger should be available for unified API");
    let system = PorSystem::new(ledger);
    let files_vec: Vec<&_> = file_refs.values().copied().collect();
    let proof = system
        .prove(files_vec, &setup.challenges)
        .expect("Proof generation should have succeeded");

    // Verify proof (should fail)
    let result = system.verify(&proof, &setup.challenges);

    match result {
        Ok(is_valid) => {
            assert!(
                !is_valid,
                "Expected verification to return false, but it returned true"
            );
        }
        Err(_) => {
            // Verification error is also acceptable for this assertion
        }
    }
}

/// Asserts that verification fails with an expected error message.
pub fn assert_verify_fails_with_error(setup: TestSetup, expected_error_substring: &str) {
    let file_refs = setup.file_refs();
    let ledger_ref = setup.ledger_ref();

    // Generate proof (should succeed)
    let ledger = ledger_ref.expect("Ledger should be available for unified API");
    let system = PorSystem::new(ledger);
    let files_vec: Vec<&_> = file_refs.values().copied().collect();
    let proof = system
        .prove(files_vec, &setup.challenges)
        .expect("Proof generation should have succeeded");

    // Verify proof (should fail with specific error)
    let result = system.verify(&proof, &setup.challenges);

    match result {
        Ok(true) => panic!("Expected verification to fail, but it succeeded"),
        Ok(false) => {
            panic!("Expected verification to fail with error, but it returned false without error")
        }
        Err(error) => {
            let error_msg = format!("{}", error);
            assert!(
                error_msg.contains(expected_error_substring),
                "Expected error message to contain '{}', but got: {}",
                expected_error_substring,
                error_msg
            );
        }
    }
}

/// Asserts that the given TestSetup produces deterministic results.
/// Runs the same test multiple times and verifies identical outcomes.
pub fn assert_deterministic_behavior(setup_fn: impl Fn() -> TestSetup) {
    let setup1 = setup_fn();
    let setup2 = setup_fn();

    // Both setups should have the same number of files
    assert_eq!(setup1.files.len(), setup2.files.len());
    assert_eq!(setup1.challenges.len(), setup2.challenges.len());

    // Generate proofs
    let file_refs1 = setup1.file_refs();
    let file_refs2 = setup2.file_refs();
    let ledger_ref1 = setup1.ledger_ref();
    let ledger_ref2 = setup2.ledger_ref();

    let ledger1 = ledger_ref1.expect("First ledger should be available for unified API");
    let ledger2 = ledger_ref2.expect("Second ledger should be available for unified API");

    let system1 = PorSystem::new(ledger1);
    let files_vec1: Vec<&_> = file_refs1.values().copied().collect();
    let proof1 = system1
        .prove(files_vec1, &setup1.challenges)
        .expect("First proof generation should succeed");

    let system2 = PorSystem::new(ledger2);
    let files_vec2: Vec<&_> = file_refs2.values().copied().collect();
    let proof2 = system2
        .prove(files_vec2, &setup2.challenges)
        .expect("Second proof generation should succeed");

    // Verify both proofs
    let is_valid1 = system1
        .verify(&proof1, &setup1.challenges)
        .expect("First verification should complete");
    let is_valid2 = system2
        .verify(&proof2, &setup2.challenges)
        .expect("Second verification should complete");

    assert_eq!(
        is_valid1, is_valid2,
        "Both proofs should have the same validity"
    );
    assert!(
        is_valid1 && is_valid2,
        "Both proofs should be valid for deterministic test"
    );
}

/// Asserts that a proof generated with valid inputs fails when verified with tampered inputs.
/// This is a common security test pattern: generate a valid proof, then verify it with modified
/// challenges/ledger/etc to ensure the verification correctly rejects the tampered scenario.
pub fn assert_tampered_verify_fails<F>(
    setup: TestSetup,
    tamper_fn: F,
    expected_error_substring: Option<&str>,
) where
    F: FnOnce(Vec<Challenge>, Option<FileLedger>) -> (Vec<Challenge>, Option<FileLedger>),
{
    let file_refs = setup.file_refs();
    let ledger_ref = setup.ledger_ref();

    // Generate a valid proof with the original setup
    let ledger = ledger_ref.expect("Ledger should be available for unified API");
    let system = PorSystem::new(ledger);
    let files_vec: Vec<&_> = file_refs.values().copied().collect();
    let proof = system
        .prove(files_vec, &setup.challenges)
        .expect("Should generate valid proof with original setup");

    // Verify the proof works with original inputs (sanity check)
    let is_valid = system
        .verify(&proof, &setup.challenges)
        .expect("Original verification should complete");
    assert!(is_valid, "Original proof should verify successfully");

    // Apply the tampering function to get modified inputs
    let (tampered_challenges, tampered_ledger) =
        tamper_fn(setup.challenges.clone(), setup.ledger.clone());

    // Verify with tampered inputs - should fail
    let tampered_ledger_ref = tampered_ledger
        .as_ref()
        .expect("Tampered ledger should be available for unified API");
    let tampered_system = PorSystem::new(tampered_ledger_ref);
    let result = tampered_system.verify(&proof, &tampered_challenges);

    match result {
        Ok(is_valid) => {
            assert!(!is_valid, "Proof should not verify with tampered inputs");
        }
        Err(error) => {
            if let Some(expected_msg) = expected_error_substring {
                let error_msg = format!("{}", error);
                assert!(
                    error_msg.contains(expected_msg),
                    "Expected error to contain '{}', but got: {}",
                    expected_msg,
                    error_msg
                );
            }
            // Error is acceptable for tampered verification
        }
    }
}

/// Helper for testing multiple configurations that should all succeed.
/// This reduces boilerplate for the common "loop and assert succeeds" pattern.
pub fn assert_configs_succeed<I, F>(configs: I, config_to_setup: F)
where
    I: IntoIterator,
    I::Item: std::fmt::Debug,
    F: Fn(I::Item) -> TestConfig,
{
    for config_value in configs {
        let test_config = config_to_setup(config_value);
        let setup = setup_test_scenario(&test_config).expect("Setup should succeed");
        assert_prove_and_verify_succeeds(setup);
    }
}

/// Asserts that a result contains an error with a specific substring in the error message.
pub fn assert_error_contains<T, E: std::fmt::Display>(
    result: Result<T, E>,
    expected_substring: &str,
) {
    match result {
        Ok(_) => panic!(
            "Expected error containing '{}', but operation succeeded",
            expected_substring
        ),
        Err(error) => {
            let error_msg = format!("{}", error);
            assert!(
                error_msg.contains(expected_substring),
                "Expected error message to contain '{}', but got: {}",
                expected_substring,
                error_msg
            );
        }
    }
}

/// Asserts that a verification result is Ok(false) or contains an error with a specific substring.
pub fn assert_verify_fails_contains(
    result: Result<bool, impl std::fmt::Display>,
    expected_substring: Option<&str>,
) {
    match result {
        Ok(true) => panic!("Expected verification to fail, but it succeeded"),
        Ok(false) => {
            // Verification returned false - this is acceptable
        }
        Err(error) => {
            if let Some(expected_msg) = expected_substring {
                let error_msg = format!("{}", error);
                assert!(
                    error_msg.contains(expected_msg),
                    "Expected error to contain '{}', but got: {}",
                    expected_msg,
                    error_msg
                );
            }
            // Error is acceptable for failed verification
        }
    }
}
