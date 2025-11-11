//! Security tests against replay attacks on the recursive proof.

mod common;
use common::fixtures::{setup_test_scenario, TestConfig};
use kontor_crypto::api::FieldElement;

#[test]
fn test_proof_replay_with_wrong_step_count_is_rejected() {
    // This test ensures that a proof generated for N recursive steps cannot be
    // used to successfully verify a computation of M steps, where M != N.
    // This is a fundamental property of the recursive SNARK's integrity.
    println!("Testing rejection of proof with wrong step count...");

    // 1. Generate a valid proof for exactly 3 challenges (3 recursive steps).
    let num_challenges = 3;
    let setup = setup_test_scenario(&TestConfig::with_challenges(num_challenges)).unwrap();
    let file_refs = setup.file_refs();
    let ledger_ref = setup.ledger_ref();

    let ledger = ledger_ref.expect("Ledger should be available for unified API");
    let system = kontor_crypto::api::PorSystem::new(ledger);
    let files_vec: Vec<&_> = file_refs.values().copied().collect();
    let proof = system
        .prove(files_vec, &setup.challenges)
        .expect("Should generate a valid proof for 3 challenges");

    // 2. Sanity check: The proof should verify correctly with the original challenge count.
    assert!(
        system
            .verify(&proof, &setup.challenges)
            .expect("Verification should complete"),
        "Valid proof with correct step count should verify"
    );
    println!(
        "✓ Valid proof for {} steps verified correctly",
        num_challenges
    );

    // 3. Attack: Try to verify the same proof, but claim there were only 2 steps.
    let mut challenges_too_few = setup.challenges.clone();
    challenges_too_few[0].num_challenges = num_challenges - 1;

    let result_too_few = kontor_crypto::api::verify_raw(&challenges_too_few, &proof, ledger)
        .expect("Verification with fewer steps should complete without error");

    assert!(
        !result_too_few,
        "SECURITY VIOLATION: Proof for {} steps was accepted for {} steps!",
        num_challenges,
        num_challenges - 1
    );
    println!("✓ Proof correctly rejected when claiming fewer steps");

    // 4. Attack: Try to verify the same proof, but claim there were 4 steps.
    let mut challenges_too_many = setup.challenges.clone();
    challenges_too_many[0].num_challenges = num_challenges + 1;

    let result_too_many = kontor_crypto::api::verify_raw(&challenges_too_many, &proof, ledger)
        .expect("Verification with more steps should complete without error");

    assert!(
        !result_too_many,
        "SECURITY VIOLATION: Proof for {} steps was accepted for {} steps!",
        num_challenges,
        num_challenges + 1
    );
    println!("✓ Proof correctly rejected when claiming more steps");
}

#[test]
fn test_proof_replay_with_wrong_seed_is_rejected() {
    // This test ensures that a proof is cryptographically bound to the challenge
    // seed. A proof generated with seed A cannot be used to satisfy a verifier
    // expecting a proof for a challenge generated with seed B.
    println!("Testing rejection of proof with wrong challenge seed...");

    // 1. Generate a valid proof with a specific seed.
    let original_seed = 12345;
    let setup = setup_test_scenario(&TestConfig::with_seed(original_seed)).unwrap();
    let file_refs = setup.file_refs();
    let ledger_ref = setup.ledger_ref();

    let ledger = ledger_ref.expect("Ledger should be available for unified API");
    let system = kontor_crypto::api::PorSystem::new(ledger);
    let files_vec: Vec<&_> = file_refs.values().copied().collect();
    let proof = system
        .prove(files_vec, &setup.challenges)
        .expect("Should generate a valid proof");

    // 2. Sanity check: The proof should verify correctly with the original seed.
    assert!(
        system
            .verify(&proof, &setup.challenges)
            .expect("Verification should complete"),
        "Valid proof with original seed should verify"
    );
    println!(
        "✓ Valid proof with seed {} verified correctly",
        original_seed
    );

    // 3. Attack: Create a new challenge with a different seed.
    let tampered_seed = 54321;
    let mut tampered_challenges = setup.challenges.clone();
    tampered_challenges[0].seed = FieldElement::from(tampered_seed as u64);

    // 4. Try to verify the original proof against the challenge with the wrong seed.
    let result = kontor_crypto::api::verify_raw(&tampered_challenges, &proof, ledger)
        .expect("Verification with wrong seed should complete without error");

    assert!(
        !result,
        "SECURITY VIOLATION: Proof generated with seed {} was accepted for a challenge with seed {}!",
        original_seed,
        tampered_seed
    );
    println!("✓ Proof correctly rejected when using a different seed for verification");
}
