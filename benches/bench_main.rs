use divan::{black_box, Bencher};
use kontor_crypto::{
    api::{self, Challenge, FieldElement, PorSystem},
    build_tree, config,
    erasure::encode_file_symbols,
    poseidon::{domain_tags, poseidon_hash_tagged},
    FileLedger,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};

fn main() {
    // Run benchmarks
    divan::main();
}

// --- Helpers ---

fn generate_test_data(size: usize, seed: u64) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut data = vec![0u8; size];
    rng.fill_bytes(&mut data);
    data
}

// --- Primitives ---

mod primitives {
    use super::*;

    #[cfg_attr(
        feature = "bench-smoke",
        divan::bench(sample_count = 1, sample_size = 1)
    )]
    #[cfg_attr(
        not(feature = "bench-smoke"),
        divan::bench(sample_count = 10, sample_size = 10)
    )]
    fn poseidon_hash() {
        let a = FieldElement::from(config::TEST_RANDOM_SEED);
        let b = FieldElement::from(123u64);
        black_box(poseidon_hash_tagged(
            domain_tags::node(),
            black_box(a),
            black_box(b),
        ));
    }

    #[cfg_attr(
        feature = "bench-smoke",
        divan::bench(sample_count = 1, sample_size = 1, args = [16])
    )]
    #[cfg_attr(
        not(feature = "bench-smoke"),
        divan::bench(sample_count = 10, sample_size = 10, args = [16, 1024])
    )]
    fn merkle_build(bencher: Bencher, num_leaves: usize) {
        bencher
            .with_inputs(|| {
                (0..num_leaves)
                    .map(|i| format!("leaf_{}", i).into_bytes())
                    .collect::<Vec<_>>()
            })
            .bench_values(|data| {
                build_tree(black_box(&data)).unwrap();
            });
    }

    #[cfg_attr(
        feature = "bench-smoke",
        divan::bench(sample_count = 1, sample_size = 1, args = [10])
    )]
    #[cfg_attr(
        not(feature = "bench-smoke"),
        divan::bench(sample_count = 1, sample_size = 1, args = [10, 1024])
    )]
    fn erasure_encode(bencher: Bencher, size_kb: usize) {
        bencher
            .with_inputs(|| generate_test_data(size_kb * 1024, 42))
            .bench_values(|data| {
                encode_file_symbols(black_box(&data)).unwrap();
            });
    }
}

// --- File Preparation ---

#[cfg_attr(
    feature = "bench-smoke",
    divan::bench(sample_count = 1, sample_size = 1, args = [10])
)]
#[cfg_attr(
    not(feature = "bench-smoke"),
    divan::bench(sample_count = 1, sample_size = 1, args = [10, 1024])
)]
fn file_preparation(bencher: Bencher, size_kb: usize) {
    bencher
        .with_inputs(|| generate_test_data(size_kb * 1024, 42))
        .bench_values(|data| {
            api::prepare_file(black_box(&data), "test.dat").unwrap();
        });
}

// --- Proving (Expensive!) ---

mod proving {
    use super::*;

    /// Pre-generate ledger, files, and challenges for proving benchmark.
    /// This avoids regenerating expensive fixtures on each iteration.
    fn setup_proving_fixture(
        size_kb: usize,
        num_files: usize,
        num_challenges: usize,
    ) -> (FileLedger, Vec<api::PreparedFile>, Vec<Challenge>) {
        let mut prepared_files = Vec::new();
        let mut challenges = Vec::new();
        let mut ledger = FileLedger::new();

        for i in 0..num_files {
            let data = generate_test_data(size_kb * 1024, 42 + i as u64);
            let (prepared, metadata) = api::prepare_file(&data, &format!("f{}", i)).unwrap();

            ledger.add_file(&metadata).unwrap();

            let challenge = Challenge::new(
                metadata,
                1000,
                num_challenges,
                FieldElement::from(config::TEST_RANDOM_SEED),
                String::from("bench"),
            );

            prepared_files.push(prepared);
            challenges.push(challenge);
        }

        (ledger, prepared_files, challenges)
    }

    #[cfg_attr(
        feature = "bench-smoke",
        divan::bench(sample_count = 1, sample_size = 1, args = [(10, 1, 2)]) // 10KB, 1 file, 2 challenges
    )]
    #[cfg_attr(
        not(feature = "bench-smoke"),
        divan::bench(
            sample_count = 1,
            sample_size = 1,
            args = [
                (10, 1, 10),   // 10KB, 1 file, 10 challenges
                (1024, 1, 10), // 1MB, 1 file, 10 challenges
                (10, 2, 10), // 10KB, 2 files, 10 challenges
                (1024, 2, 10), // 1MB, 2 files, 10 challenges
            ]
        )
    )]
    fn prove(bencher: Bencher, args: (usize, usize, usize)) {
        let (size_kb, num_files, num_challenges) = args;

        // Generate fixture once, outside the benchmark loop
        let (ledger, files, challenges) = setup_proving_fixture(size_kb, num_files, num_challenges);

        bencher.bench(|| {
            let system = PorSystem::new(&ledger);
            let files_ref: Vec<&_> = files.iter().collect();
            system
                .prove(black_box(files_ref), black_box(&challenges))
                .unwrap();
        });
    }
}

// --- Verification ---

mod verification {
    use super::*;

    /// Pre-generate proof and fixtures for verification benchmark.
    /// This avoids regenerating expensive proofs on each iteration.
    fn setup_verification_fixture(
        num_challenges: usize,
    ) -> (FileLedger, api::Proof, Vec<Challenge>) {
        let data = generate_test_data(16 * 1024, 42);
        let (prepared, metadata) = api::prepare_file(&data, "v.dat").unwrap();
        let mut ledger = FileLedger::new();
        ledger.add_file(&metadata).unwrap();

        let challenge = Challenge::new(
            metadata,
            1000,
            num_challenges,
            FieldElement::from(config::TEST_RANDOM_SEED),
            "v".into(),
        );

        let system = PorSystem::new(&ledger);
        let proof = system
            .prove(vec![&prepared], std::slice::from_ref(&challenge))
            .unwrap();

        (ledger, proof, vec![challenge])
    }

    #[cfg_attr(
        feature = "bench-smoke",
        divan::bench(sample_count = 1, sample_size = 1, args = [2])
    )]
    #[cfg_attr(
        not(feature = "bench-smoke"),
        divan::bench(sample_count = 10, sample_size = 10, args = [2, 100])
    )]
    fn verify_challenges(bencher: Bencher, num_challenges: usize) {
        // Generate proof once, outside the benchmark loop
        let (ledger, proof, challenges) = setup_verification_fixture(num_challenges);

        bencher.bench(|| {
            let system = PorSystem::new(&ledger);
            system
                .verify(black_box(&proof), black_box(&challenges))
                .unwrap();
        });
    }
}
