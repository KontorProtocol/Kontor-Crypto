//! Property-based and statistical tests for Kontor PoR.
//!
//! Implements the FUZ-01..FUZ-05 coverage previously left as `#[ignore]`-d
//! stubs in `fuzzing_targets.rs`. Each test drives a large, fixed-seed random
//! sample (deterministic, non-flaky) over a primitive's public API and asserts
//! its invariant on every draw. The byte-oriented `cargo-fuzz` harnesses under
//! `fuzz/fuzz_targets/` remain the complementary deserialization-robustness
//! layer.
//!
//! Randomised loops (seeded `StdRng`) are used rather than `proptest` so the
//! suite has no extra dependency and builds offline; the trade-off is no
//! automatic shrinking. Each case prints its seed/index context on failure so
//! a counterexample is reproducible.
//!
//! Scope note: these exercise the stable core primitives (merkle, prepare,
//! poseidon domain tags, challenge-index derivation) plus a small bounded
//! prove/verify roundtrip — not circuit internals or proof wire-format, which
//! the dedicated circuit and e2e suites already cover.

use kontor_crypto::poseidon::{domain_tags, poseidon_hash_tagged};
use kontor_crypto::{
    build_tree, derive_index_from_bits, field_from_uniform_bytes, get_padded_proof_for_leaf,
    prepare_file, verify_merkle_proof_in_place, FieldElement,
};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

#[allow(dead_code)]
mod common;
use common::assertions::assert_prove_and_verify_succeeds;
use common::fixtures::{setup_test_scenario, TestConfig};

/// A uniformly-random field element drawn via the wide-reduction path used for
/// challenge seeds.
fn rand_field(rng: &mut StdRng) -> FieldElement {
    let mut buf = [0u8; 64];
    rng.fill_bytes(&mut buf);
    field_from_uniform_bytes(&buf)
}

/// A random chunk layout: 1..=24 chunks of 1..=31 bytes each (each chunk fits a
/// single 31-byte field leaf), then zero-padded to a power-of-two leaf count.
///
/// `build_tree` itself does not pad the leaf layer — production always feeds it
/// a power-of-two symbol count (see `validate_and_encode`, which resizes to
/// `next_power_of_two` with 31-zero-byte chunks). We mirror that here so the
/// roundtrip exercises the real code path.
fn rand_padded_chunks(rng: &mut StdRng) -> Vec<Vec<u8>> {
    let n = rng.gen_range(1..=24);
    let mut chunks: Vec<Vec<u8>> = (0..n)
        .map(|_| {
            let len = rng.gen_range(1..=31);
            let mut c = vec![0u8; len];
            rng.fill_bytes(&mut c);
            c
        })
        .collect();
    let padded_len = chunks.len().next_power_of_two();
    chunks.resize(padded_len, vec![0u8; 31]); // CHUNK_SIZE_BYTES
    chunks
}

/// FUZ-01: `build_tree` → `get_padded_proof_for_leaf` → `verify_merkle_proof_in_place`.
///
/// - Never panics for any chunk layout.
/// - A padded proof for leaf `i` verifies against its own tree's root for every
///   padded leaf index, and has exactly `depth` siblings.
/// - Only-if direction: a proof does not verify against an unrelated root.
#[test]
fn fuz01_merkle_roundtrip() {
    let mut rng = StdRng::seed_from_u64(0xF021_0001);
    for case in 0..256 {
        let chunks = rand_padded_chunks(&mut rng);
        let (tree, root) = build_tree(&chunks).unwrap();
        let depth = tree.layers.len().saturating_sub(1);
        let num_leaves = tree.layers[0].len();
        assert!(num_leaves.is_power_of_two(), "case {case}: leaves not 2^k");

        for i in 0..num_leaves {
            let proof = get_padded_proof_for_leaf(&tree, i, depth).unwrap();
            assert_eq!(proof.siblings.len(), depth, "case {case}, leaf {i}");
            assert!(
                verify_merkle_proof_in_place(root, &proof),
                "case {case}: valid proof for leaf {i} must verify"
            );
        }

        // Only-if direction: a proof from this tree must not verify against an
        // unrelated root. Skip the (astronomically rare) root collision.
        let (_tree_b, root_b) = build_tree(&rand_padded_chunks(&mut rng)).unwrap();
        if root_b != root {
            let proof0 = get_padded_proof_for_leaf(&tree, 0, depth).unwrap();
            assert!(
                !verify_merkle_proof_in_place(root_b, &proof0),
                "case {case}: proof must not verify against a foreign root"
            );
        }

        // Tamper direction: corrupting a single sibling must break verification
        // against the *correct* root — this catches a verifier that ignores the
        // path or mishandles sibling order (the foreign-root case alone wouldn't).
        if depth > 0 {
            let mut tampered = get_padded_proof_for_leaf(&tree, 0, depth).unwrap();
            let bogus = field_from_uniform_bytes(&[0xA5u8; 64]);
            if tampered.siblings[0] != bogus {
                tampered.siblings[0] = bogus;
                assert!(
                    !verify_merkle_proof_in_place(root, &tampered),
                    "case {case}: a corrupted sibling must fail verification"
                );
            }
        }
    }
}

/// FUZ-02: `prepare_file` on arbitrary content/nonce.
///
/// - Never panics; returns coherent metadata (padded_len is a power of two,
///   `depth == log2(padded_len)`, `original_size == data.len()`, `validate()`
///   passes).
/// - `file_id` / `object_id` / `root` are deterministic for identical input.
/// - `object_id` depends only on content, not on the nonce.
#[test]
fn fuz02_prepare_file_coherent_and_deterministic() {
    let mut rng = StdRng::seed_from_u64(0xF021_0002);
    for case in 0..128 {
        // Span several codewords (231×31 = 7161 data bytes each) so that
        // padded_len and depth actually vary across cases (one codeword → depth
        // 8, two→9, three→10) rather than pinning a single (depth, padded_len)
        // point. Bounded at ~16 KB to keep erasure-coding cost reasonable.
        let data_len = rng.gen_range(1..=16_000);
        let mut data = vec![0u8; data_len];
        rng.fill_bytes(&mut data);
        let nonce_len = rng.gen_range(0..=32);
        let mut nonce = vec![0u8; nonce_len];
        rng.fill_bytes(&mut nonce);

        let (_p1, m1) = prepare_file(&data, "f.dat", &nonce).unwrap();
        let (_p2, m2) = prepare_file(&data, "f.dat", &nonce).unwrap();

        // Determinism.
        assert_eq!(
            m1.file_id, m2.file_id,
            "case {case}: file_id non-deterministic"
        );
        assert_eq!(
            m1.object_id, m2.object_id,
            "case {case}: object_id non-deterministic"
        );
        assert_eq!(m1.root, m2.root, "case {case}: root non-deterministic");

        // Coherence.
        assert!(
            m1.padded_len.is_power_of_two(),
            "case {case}: padded_len not 2^k"
        );
        assert_eq!(
            1usize << m1.depth(),
            m1.padded_len,
            "case {case}: depth != log2(padded_len)"
        );
        assert_eq!(
            m1.original_size,
            data.len(),
            "case {case}: original_size mismatch"
        );
        assert!(
            m1.validate().is_ok(),
            "case {case}: metadata failed validate()"
        );

        // object_id is content-only: changing the nonce leaves it unchanged.
        let mut nonce2 = nonce.clone();
        nonce2.push(rng.gen());
        let (_p3, m3) = prepare_file(&data, "f.dat", &nonce2).unwrap();
        assert_eq!(
            m1.object_id, m3.object_id,
            "case {case}: object_id depends on nonce"
        );
    }
}

/// FUZ-04: domain-tag separation.
///
/// For any `(x, y)`, the tagged Poseidon hash under each of the seven protocol
/// domain tags is pairwise distinct — the tag genuinely separates hashing
/// contexts and no two contexts collide.
#[test]
fn fuz04_domain_tag_separation() {
    let mut rng = StdRng::seed_from_u64(0xF021_0004);
    for case in 0..512 {
        let x = rand_field(&mut rng);
        let y = rand_field(&mut rng);
        let tags = [
            ("leaf", domain_tags::leaf::<FieldElement>()),
            ("node", domain_tags::node::<FieldElement>()),
            ("challenge", domain_tags::challenge::<FieldElement>()),
            ("state_update", domain_tags::state_update::<FieldElement>()),
            (
                "root_commitment",
                domain_tags::root_commitment::<FieldElement>(),
            ),
            (
                "challenge_per_file",
                domain_tags::challenge_per_file::<FieldElement>(),
            ),
            ("challenge_id", domain_tags::challenge_id::<FieldElement>()),
        ];
        let hashes: Vec<(&str, FieldElement)> = tags
            .iter()
            .map(|(name, tag)| (*name, poseidon_hash_tagged(*tag, x, y)))
            .collect();

        for (i, (name_i, hi)) in hashes.iter().enumerate() {
            for (name_j, hj) in &hashes[i + 1..] {
                assert_ne!(
                    hi, hj,
                    "case {case}: domain tags {name_i} and {name_j} collided"
                );
            }
        }
    }
}

/// FUZ-03: prove/verify roundtrip over small random shapes.
///
/// `verify(prove(x))` holds for valid `x` across tree depths 0..=3 and 1..=3
/// challenges per file, for arbitrary seeds. Nova proving is expensive, so the
/// case count is small; the e2e suite covers the fixed representative shapes
/// exhaustively.
#[test]
fn fuz03_prove_verify_roundtrip() {
    let mut rng = StdRng::seed_from_u64(0xF021_0003);
    for _ in 0..6 {
        let depth = rng.gen_range(0..=3);
        let challenges = rng.gen_range(1..=3);
        let seed: u64 = rng.gen();

        let mut config = TestConfig::for_depth(depth);
        config.challenges_per_file = challenges;
        config.seed = seed;
        let setup = setup_test_scenario(&config).unwrap();
        assert_prove_and_verify_succeeds(setup);
    }
}

/// FUZ-05: challenge-index uniformity (seeded chi-squared).
///
/// `derive_index_from_bits` must spread challenge seeds uniformly across the
/// `2^depth` leaves so no leaf is over- or under-challenged. We draw a large
/// fixed-seed sample (deterministic, non-flaky) and require the chi-squared
/// statistic to stay below the p=0.999 critical value — failing only if the
/// distribution is *extremely* non-uniform.
#[test]
fn fuz05_challenge_index_uniformity() {
    use statrs::distribution::{ChiSquared, ContinuousCDF};

    const DEPTH: usize = 8;
    const BUCKETS: usize = 1 << DEPTH; // 256 leaves
    const SAMPLES: usize = BUCKETS * 600; // ~600 expected per bucket

    let mut counts = vec![0u64; BUCKETS];
    let mut rng = StdRng::seed_from_u64(0x00C0_FFEE);
    for _ in 0..SAMPLES {
        let f = rand_field(&mut rng);
        let idx = derive_index_from_bits(f, DEPTH);
        assert!(idx < BUCKETS, "index {idx} out of range");
        counts[idx] += 1;
    }

    let expected = SAMPLES as f64 / BUCKETS as f64;
    let chi2: f64 = counts
        .iter()
        .map(|&c| {
            let d = c as f64 - expected;
            d * d / expected
        })
        .sum();

    let df = (BUCKETS - 1) as f64;
    let critical = ChiSquared::new(df).unwrap().inverse_cdf(0.999);
    assert!(
        chi2 < critical,
        "challenge indices not uniform: chi2={chi2:.1} >= critical(p=0.999, df={df})={critical:.1}"
    );
}
