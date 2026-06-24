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
            "bd5d8b55dce90161d02aaeaabc218b79728e051164b79fd65065898c7869ec38"
        )
        .unwrap(),
        "poseidon_hash2(0,0)"
    );
}

#[test]
fn poseidon_hash2_one_two() {
    assert_eq!(
        poseidon_hash2(FieldElement::from(1u64), FieldElement::from(2u64)),
        field_from_hex::<FieldElement>(
            "613f28921329135c38b5465cd51caeca477e3bc5cd1cb9e659461732444c1f04"
        )
        .unwrap(),
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
            "951402865ad780f82a9399ccb4a223ec32eae8870a24f56adc0683353b92b32e"
        )
        .unwrap(),
        "poseidon_hash_tagged(leaf,1,2)"
    );
}

#[test]
fn poseidon_hash_tagged_node_42_123() {
    assert_eq!(
        poseidon_hash_tagged(
            domain_tags::node(),
            FieldElement::from(42u64),
            FieldElement::from(123u64),
        ),
        field_from_hex::<FieldElement>(
            "2a77f2bbd4f43f29b224e5428492914ce9f27829cd9f4c13218a36b790b29237"
        )
        .unwrap(),
        "poseidon_hash_tagged(node,42,123)"
    );
}
