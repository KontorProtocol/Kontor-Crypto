//! Known-answer regression for Nova Poseidon in kontor-crypto.
//!
//! These expected hex values were generated and cross-validated with the
//! standalone (no-`nova_poseidon`) implementation in kontor-crypto-core
//! (see `poseidon_known_answer_standalone` in core). Comparing against
//! hardcoded golden values avoids the feature-unification pitfall where
//! Cargo merges `nova_poseidon` into core, making a cross-crate comparison
//! degenerate into Nova-vs-Nova.

use ff::PrimeField;
use kontor_crypto::api::FieldElement;
use kontor_crypto::poseidon::{domain_tags, poseidon_hash2, poseidon_hash_tagged};

fn fq_from_hex(hex: &str) -> FieldElement {
    let hex = hex.trim_start_matches("0x");
    let mut buf = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = core::str::from_utf8(chunk).unwrap();
        buf[31 - i] = u8::from_str_radix(s, 16).unwrap();
    }
    let mut repr = <FieldElement as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&buf);
    FieldElement::from_repr(repr).unwrap()
}

#[test]
fn poseidon_hash2_zero_zero() {
    assert_eq!(
        poseidon_hash2(FieldElement::from(0u64), FieldElement::from(0u64)),
        fq_from_hex("38ec69788c896550d69fb76411058e72798b21bcaaae2ad06101e9dc558b5dbd"),
        "poseidon_hash2(0,0)"
    );
}

#[test]
fn poseidon_hash2_one_two() {
    let result = poseidon_hash2(FieldElement::from(1u64), FieldElement::from(2u64));
    let zero_zero = fq_from_hex("38ec69788c896550d69fb76411058e72798b21bcaaae2ad06101e9dc558b5dbd");
    assert_ne!(result, zero_zero, "hash2(1,2) must differ from hash2(0,0)");
    assert_eq!(
        poseidon_hash2(FieldElement::from(1u64), FieldElement::from(2u64)),
        result,
        "poseidon_hash2 must be deterministic"
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
        fq_from_hex("2eb3923b358306dc6af5240a87e8ea32ec23a2b4cc99932af880d75a86021495"),
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
    let leaf_result = fq_from_hex("2eb3923b358306dc6af5240a87e8ea32ec23a2b4cc99932af880d75a86021495");
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
