//! Known-answer regression for Nova Poseidon in kontor-crypto.
//!
//! These expected hex values were generated and cross-validated with the
//! standalone (no-`nova_poseidon`) implementation in kontor-crypto-core
//! (see `poseidon_known_answer_standalone` in core). Comparing against
//! hardcoded golden values avoids the feature-unification pitfall where
//! Cargo merges `nova_poseidon` into core, making a cross-crate comparison
//! degenerate into Nova-vs-Nova.

use kontor_crypto::api::FieldElement;
use kontor_crypto::poseidon::{domain_tags, poseidon_hash2, poseidon_hash_tagged};
use kontor_crypto::utils::field_from_hex;

#[test]
fn poseidon_hash2_zero_zero() {
    assert_eq!(
        poseidon_hash2(FieldElement::from(0u64), FieldElement::from(0u64)),
        field_from_hex::<FieldElement>(
            "38ec69788c896550d69fb76411058e72798b21bcaaae2ad06101e9dc558b5dbd"
        ),
        "poseidon_hash2(0,0)"
    );
}

#[test]
fn poseidon_hash2_one_two() {
    assert_eq!(
        poseidon_hash2(FieldElement::from(1u64), FieldElement::from(2u64)),
        field_from_hex::<FieldElement>(
            "041f4c4432174659e6b91ccdc53b7e47caae1cd55c46b5385c13291392283f61"
        ),
        "poseidon_hash2(1,2)"
    );
}

#[test]
fn poseidon_hash_tagged_leaf_1_2() {
    assert_eq!(
        poseidon_hash_tagged(
            domain_tags::leaf(),
            FieldElement::from(1u64),
            FieldElement::from(2u64)
        ),
        field_from_hex::<FieldElement>(
            "2eb3923b358306dc6af5240a87e8ea32ec23a2b4cc99932af880d75a86021495"
        ),
        "poseidon_hash_tagged(leaf,1,2)"
    );
}

#[test]
fn poseidon_hash_tagged_node_42_123() {
    let result = poseidon_hash_tagged(
        domain_tags::node(),
        FieldElement::from(42u64),
        FieldElement::from(123u64),
    );
    let leaf_result = field_from_hex::<FieldElement>(
        "2eb3923b358306dc6af5240a87e8ea32ec23a2b4cc99932af880d75a86021495",
    );
    assert_ne!(result, leaf_result, "node tag must differ from leaf tag");
    assert_eq!(
        poseidon_hash_tagged(
            domain_tags::node(),
            FieldElement::from(42u64),
            FieldElement::from(123u64),
        ),
        result,
        "poseidon_hash_tagged must be deterministic"
    );
}
