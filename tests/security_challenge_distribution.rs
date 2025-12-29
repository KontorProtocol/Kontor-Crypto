//! Test for the statistical uniformity of challenge derivation.

use ff::Field;
use kontor_crypto::{
    api::FieldElement,
    poseidon::{domain_tags, poseidon_hash_tagged},
    utils::{derive_index_from_bits, derive_index_unbiased},
};
use rand::{rngs::StdRng, SeedableRng};
use statrs::distribution::{ChiSquared, ContinuousCDF};

#[test]
fn test_challenge_distribution_is_uniform() {
    // Use a tree depth that's large enough for statistical significance
    // but small enough to run quickly. Depth 8 =
    const DEPTH: usize = 8;
    const NUM_LEAVES: usize = 1 << DEPTH;

    // Generate a large number of samples to get a good distribution.
    const SAMPLES_PER_LEAF: usize = 5;
    const TOTAL_SAMPLES: usize = NUM_LEAVES * SAMPLES_PER_LEAF;

    let mut histogram = vec![0usize; NUM_LEAVES];
    let mut rng = StdRng::seed_from_u64(42); // Deterministic seed for test reproducibility

    for _i in 0..TOTAL_SAMPLES {
        // Use the actual cryptographic hash function to generate challenges.
        // We simulate the seed and chained state with random field elements.
        let seed = FieldElement::random(&mut rng);
        let state = FieldElement::random(&mut rng);
        let random_hash = poseidon_hash_tagged(domain_tags::challenge(), seed, state);

        let leaf_index = derive_index_from_bits(random_hash, DEPTH);
        histogram[leaf_index] += 1;
    }

    // --- Statistical Validation ---
    // We will use the Chi-squared test for goodness-of-fit to determine if
    // the observed distribution of leaf indices is statistically consistent
    // with a uniform distribution.

    let expected_count = SAMPLES_PER_LEAF as f64;

    // Calculate the Chi-squared statistic: Σ [ (Observed - Expected)^2 / Expected ]
    let chi_squared_statistic: f64 = histogram
        .iter()
        .map(|&observed_count| {
            let observed = observed_count as f64;
            (observed - expected_count).powi(2) / expected_count
        })
        .sum();

    // The degrees of freedom for a goodness-of-fit test is k - 1,
    // where k is the number of categories (leaves).
    let degrees_of_freedom = (NUM_LEAVES - 1) as f64;

    // Create a Chi-squared distribution with our degrees of freedom.
    let chi_squared_dist =
        ChiSquared::new(degrees_of_freedom).expect("Failed to create Chi-squared distribution");

    // The p-value is the probability of observing a test statistic as extreme as,
    // or more extreme than, the one calculated, assuming the null hypothesis is true.
    // The null hypothesis is that the distribution is uniform.
    // We use the survival function (1 - CDF) to get this probability.
    let p_value = chi_squared_dist.sf(chi_squared_statistic);

    // Set a significance level (alpha). A common choice is 0.05 or 0.01.
    // If p-value > alpha, we do not reject the null hypothesis.
    let significance_level = 0.01;

    println!(
        "Chi-squared test results: statistic={:.2}, p-value={:.4}, df={}",
        chi_squared_statistic, p_value, degrees_of_freedom
    );

    assert!(
        p_value > significance_level,
        "p-value ({:.4}) is not greater than the significance level ({}). The distribution may not be uniform.",
        p_value,
        significance_level
    );

    println!(
        "✓ Challenge distribution is uniform (p-value {:.4} > {})",
        p_value, significance_level
    );
}

#[test]
fn test_unbiased_index_derivation_non_power_of_two() {
    println!("Testing unbiased index derivation for non-power-of-two leaf count...");

    const LEAF_COUNT: usize = 10; // Not a power of two
    const SAMPLES: usize = 2_000;

    let mut histogram = [0usize; LEAF_COUNT];
    let mut rng = StdRng::seed_from_u64(1337);

    for _ in 0..SAMPLES {
        let seed = FieldElement::random(&mut rng);
        let state = FieldElement::random(&mut rng);
        let h = poseidon_hash_tagged(domain_tags::challenge(), seed, state);
        let idx = derive_index_unbiased(h, LEAF_COUNT);
        assert!(idx < LEAF_COUNT);
        histogram[idx] += 1;
    }

    // Chi-squared goodness-of-fit against uniform distribution
    let expected = (SAMPLES as f64) / (LEAF_COUNT as f64);
    let chi2: f64 = histogram
        .iter()
        .map(|&obs| {
            let o = obs as f64;
            (o - expected) * (o - expected) / expected
        })
        .sum();

    let dof = (LEAF_COUNT - 1) as f64;
    let dist = ChiSquared::new(dof).expect("chi2");
    let p_value = dist.sf(chi2);
    let alpha = 0.01;

    println!(
        "Non-power-of-two chi2: stat={:.2}, p={:.4}, df={}",
        chi2, p_value, dof
    );
    assert!(
        p_value > alpha,
        "Distribution deviates from uniform (p <= {}).",
        alpha
    );
}
