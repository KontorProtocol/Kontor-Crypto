//! Cryptography-focused regression tests discovered during audit.
//!
//! These tests are intentionally written as security expectations.
//! They should fail until the corresponding vulnerabilities are fixed.

use std::collections::BTreeMap;

use kontor_crypto::{
    api::{self, Challenge, ChallengeID, FieldElement, PorSystem, Proof},
    config,
    poseidon::domain_tags,
    poseidon::poseidon_hash_tagged,
    PorCircuit,
};
use nova_snark::nova::{CompressedSNARK, PublicParams, RecursiveSNARK};
use nova_snark::{
    provider::{ipa_pc, PallasEngine, VestaEngine},
    spartan::snark::RelaxedR1CSSNARK,
    traits::snark::RelaxedR1CSSNARKTrait,
};
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};

type E1 = PallasEngine;
type E2 = VestaEngine;
type EE1 = ipa_pc::EvaluationEngine<E1>;
type EE2 = ipa_pc::EvaluationEngine<E2>;
type S1 = RelaxedR1CSSNARK<E1, EE1>;
type S2 = RelaxedR1CSSNARK<E2, EE2>;
type C = PorCircuit<FieldElement>;
type NovaProof = RecursiveSNARK<E1, E2, C>;

fn deterministic_nonce(seed: u64) -> [u8; 16] {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    rng.gen()
}

fn derive_initial_state(challenges: &[Challenge]) -> FieldElement {
    const DOMAIN_V1: &[u8] = b"kontor.challenge_set.initial_state.v1";
    const DOMAIN_V1_EXPAND: &[u8] = b"kontor.challenge_set.initial_state.v1.expand";

    let mut sorted: Vec<Challenge> = challenges.to_vec();
    sorted.sort_by(
        |a, b| match a.file_metadata.file_id.cmp(&b.file_metadata.file_id) {
            std::cmp::Ordering::Equal => a.id().0.cmp(&b.id().0),
            other => other,
        },
    );

    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_V1);
    hasher.update((sorted.len() as u64).to_le_bytes());
    for challenge in &sorted {
        hasher.update(challenge.id().0);
    }
    let digest_a = hasher.finalize();

    let mut expander = Sha256::new();
    expander.update(DOMAIN_V1_EXPAND);
    expander.update(digest_a);
    let digest_b = expander.finalize();

    let mut uniform_bytes = [0u8; 64];
    uniform_bytes[..32].copy_from_slice(&digest_a);
    uniform_bytes[32..].copy_from_slice(&digest_b);
    kontor_crypto::field_from_uniform_bytes(&uniform_bytes)
}

fn build_single_file_proof_with_custom_witness_source(
    challenge: &Challenge,
    witness_file: &kontor_crypto::PreparedFile,
    statement_root: FieldElement,
    ledger: &kontor_crypto::FileLedger,
) -> Proof {
    let challenges = vec![challenge.clone()];
    let initial_state = derive_initial_state(&challenges);
    let depth = api::tree_depth_from_metadata(&challenge.file_metadata);
    let (files_per_step, file_tree_depth) = config::derive_shape(1, depth);
    let agg_depth = 0usize;
    let layout = config::PublicIOLayout::new(files_per_step);

    let mut forged_files = BTreeMap::new();
    forged_files.insert(challenge.file_metadata.file_id.clone(), witness_file);

    let ledger_index = ledger.lookup(&challenge.file_metadata.file_id).unwrap().0;
    let challenge_refs: Vec<&Challenge> = challenges.iter().collect();
    let (witness_step0, _state_after_step0) = api::generate_circuit_witness(
        &challenge_refs,
        Some(&forged_files),
        ledger,
        file_tree_depth,
        file_tree_depth,
        initial_state,
        agg_depth,
        0,
        &[ledger_index],
    )
    .unwrap();

    let circuit_first = C::new(
        files_per_step,
        file_tree_depth,
        agg_depth,
        Some(witness_step0.witnesses().to_vec()),
    );

    let pp = PublicParams::<E1, E2, C>::setup(&circuit_first, &*S1::ck_floor(), &*S2::ck_floor())
        .expect("public parameter setup should succeed");
    let (pk, _vk) = CompressedSNARK::setup(&pp).expect("compressed SNARK setup should succeed");

    let z0_primary = layout.build_z0_primary(
        statement_root,
        initial_state,
        &[ledger_index],
        &[depth],
        &[challenge.seed],
        &[kontor_crypto::poseidon::calculate_root_commitment(
            statement_root,
            FieldElement::from(depth as u64),
        )],
    );

    let mut recursive_snark =
        NovaProof::new(&pp, &circuit_first, &z0_primary).expect("new() should succeed");
    let dummy_step = C::new(files_per_step, file_tree_depth, agg_depth, None);
    recursive_snark
        .prove_step(&pp, &dummy_step)
        .expect("no-op prove_step should succeed");

    let compressed_snark =
        CompressedSNARK::prove(&pp, &pk, &recursive_snark).expect("compression should succeed");

    Proof {
        compressed_snark,
        ledger_root: statement_root,
        aggregated_tree_depth: agg_depth,
    }
}

#[test]
fn regression_single_file_verifier_must_bind_expected_file_root() {
    // SECURITY EXPECTATION:
    // A proof for file B must not verify against a challenge for file A.
    //
    // Attack model: malicious prover bypasses PorSystem::prove() and directly
    // builds RecursiveSNARK with witness data from another file of same depth.
    let data_a = vec![0x11u8; 4096];
    let data_b = vec![0x22u8; 4096];

    let (prepared_a, meta_a) =
        api::prepare_file(&data_a, "a.dat", &deterministic_nonce(1)).unwrap();
    let (prepared_b, meta_b) =
        api::prepare_file(&data_b, "b.dat", &deterministic_nonce(2)).unwrap();
    assert_ne!(
        meta_a.root, meta_b.root,
        "test precondition failed: roots must differ"
    );

    let mut ledger = kontor_crypto::FileLedger::new();
    ledger.add_file(&meta_a).unwrap();
    ledger.add_file(&meta_b).unwrap();

    let challenge = Challenge::new_test(meta_a.clone(), 1000, 1, FieldElement::from(42u64));
    let system = PorSystem::new(&ledger);

    // Baseline sanity check: custom constructor can build a valid honest proof.
    let honest_proof = build_single_file_proof_with_custom_witness_source(
        &challenge,
        &prepared_a,
        meta_a.root,
        &ledger,
    );
    let honest_verified = system
        .verify(&honest_proof, std::slice::from_ref(&challenge))
        .unwrap();
    assert!(
        honest_verified,
        "test harness sanity failed: honest custom proof did not verify"
    );

    // Attack: challenge metadata is for file A, but witness and statement root are for file B.
    let forged_proof = build_single_file_proof_with_custom_witness_source(
        &challenge,
        &prepared_b,
        meta_b.root,
        &ledger,
    );
    let verified = system.verify(&forged_proof, &[challenge]).unwrap();

    assert!(
        !verified,
        "SECURITY VIOLATION: verifier accepted proof for a different file root"
    );

    // Keep an explicit use of prepared_a to avoid accidental dead-code optimization
    // of setup assumptions in future edits.
    assert_eq!(prepared_a.root, meta_a.root);
}

#[test]
fn regression_file_id_must_not_allow_data_nonce_boundary_collisions() {
    // SECURITY EXPECTATION:
    // file_id should uniquely bind (data, nonce) as a tuple, not just data || nonce bytes.
    //
    // Construct `combined` deterministically, then split it in two different ways so that:
    // data1 || nonce1 == data2 || nonce2 == combined.
    let mut rng = rand::rngs::StdRng::seed_from_u64(999);
    let combined: [u8; 3] = rng.gen();
    let combined_vec = combined.to_vec();

    let data_1 = combined_vec[..2].to_vec();
    let nonce_1 = combined_vec[2..].to_vec();
    let data_2 = combined_vec[..1].to_vec();
    let nonce_2 = combined_vec[1..].to_vec();

    let (prepared_1, meta_1) = api::prepare_file(&data_1, "f1.dat", &nonce_1).unwrap();
    let (prepared_2, meta_2) = api::prepare_file(&data_2, "f2.dat", &nonce_2).unwrap();

    assert_ne!(
        (data_1.as_slice(), nonce_1.as_slice()),
        (data_2.as_slice(), nonce_2.as_slice())
    );
    assert_eq!(
        data_1
            .iter()
            .chain(nonce_1.iter())
            .copied()
            .collect::<Vec<_>>(),
        combined_vec
    );
    assert_eq!(
        data_2
            .iter()
            .chain(nonce_2.iter())
            .copied()
            .collect::<Vec<_>>(),
        combined_vec
    );

    assert_ne!(
        meta_1.file_id, meta_2.file_id,
        "SECURITY VIOLATION: file_id collided across distinct (data, nonce) tuples"
    );

    // Ensure these are genuinely different prepared files (different commitments).
    assert_ne!(prepared_1.root, prepared_2.root);
    let challenge_1 = Challenge::new_test(meta_1.clone(), 1000, 1, FieldElement::from(1u64));
    let challenge_2 = Challenge::new_test(meta_2.clone(), 1000, 1, FieldElement::from(1u64));
    let id_1: ChallengeID = challenge_1.id();
    let id_2: ChallengeID = challenge_2.id();
    assert_ne!(id_1, id_2);

    // Additional domain-separation sanity check for this test file:
    let h1 = poseidon_hash_tagged(
        domain_tags::challenge(),
        FieldElement::from(7u64),
        FieldElement::from(9u64),
    );
    let h2 = poseidon_hash_tagged(
        domain_tags::state_update(),
        FieldElement::from(7u64),
        FieldElement::from(9u64),
    );
    assert_ne!(h1, h2);
}
