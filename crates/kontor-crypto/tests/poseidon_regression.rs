//! Regression test: Poseidon in kontor-crypto-core must match Nova Poseidon in kontor-crypto
//! for the same inputs (tag=NODE, x=42, y=123 and hash2(left, right)).
//! Core uses the same field type (halo2curves::pasta::Fq) as Nova for identical constants.

use kontor_crypto::api::FieldElement;
use kontor_crypto::poseidon::{domain_tags, poseidon_hash_tagged, poseidon_hash2 as nova_hash2};

/// Regression: core Poseidon must match Nova (same round numbers and Grain LFSR as Nova).
#[test]
fn poseidon_hash_tagged_matches_core() {
    let tag = domain_tags::node();
    let x = FieldElement::from(42u64);
    let y = FieldElement::from(123u64);

    let nova_out = poseidon_hash_tagged(tag, x, y);
    let core_out = kontor_crypto_core::poseidon::poseidon_hash_tagged(tag, x, y);

    assert_eq!(
        nova_out, core_out,
        "poseidon_hash_tagged(NODE, 42, 123) must match between Nova and core"
    );
}

#[test]
fn poseidon_hash2_matches_core() {
    let left = FieldElement::from(100u64);
    let right = FieldElement::from(200u64);

    let nova_out = nova_hash2(left, right);
    let core_out = kontor_crypto_core::poseidon::poseidon_hash2(left, right);

    assert_eq!(
        nova_out, core_out,
        "poseidon_hash2(100, 200) must match between Nova and core"
    );
}
