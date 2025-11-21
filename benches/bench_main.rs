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

#[cfg_attr(
    feature = "bench-smoke",
    divan::bench_group(sample_count = 1, sample_size = 1)
)]
#[cfg_attr(
    not(feature = "bench-smoke"),
    divan::bench_group(sample_count = 10, sample_size = 10)
)]
mod primitives {
    use super::*;

    #[divan::bench]
    fn poseidon_hash() {
        let a = FieldElement::from(config::TEST_RANDOM_SEED);
        let b = FieldElement::from(123u64);
        black_box(poseidon_hash_tagged(
            domain_tags::node(),
            black_box(a),
            black_box(b),
        ));
    }

    #[cfg_attr(feature = "bench-smoke", divan::bench(args = [16]))]
    #[cfg_attr(not(feature = "bench-smoke"), divan::bench(args = [16, 1024]))]
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

#[divan::bench_group(sample_count = 1, sample_size = 1)]
mod proving {
    use super::*;

    #[cfg_attr(
        feature = "bench-smoke",
        divan::bench(args = [(10, 1, 2)]) // 10KB, 1 file, 2 challenges
    )]
    #[cfg_attr(
        not(feature = "bench-smoke"),
        divan::bench(
            args = [
                (10, 1, 100),   // 10KB, 1 file, 100 challenges
                (1024, 1, 100), // 1MB, 1 file, 100 challenges
                (1024, 2, 100), // Multi-file: 2 files
            ]
        )
    )]
    fn prove(bencher: Bencher, args: (usize, usize, usize)) {
        let (size_kb, num_files, num_challenges) = args;

        bencher
            .with_inputs(|| {
                let mut prepared_files = Vec::new();
                let mut challenges = Vec::new();
                let mut ledger = FileLedger::new();

                for i in 0..num_files {
                    let data = generate_test_data(size_kb * 1024, 42 + i as u64);
                    let (prepared, metadata) =
                        api::prepare_file(&data, &format!("f{}", i)).unwrap();

                    ledger
                        .add_file(
                            metadata.file_id.clone(),
                            metadata.root,
                            api::tree_depth_from_metadata(&metadata),
                        )
                        .unwrap();

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
            })
            .bench_values(|(ledger, files, challenges)| {
                let system = PorSystem::new(&ledger);
                let files_ref: Vec<&_> = files.iter().collect();
                system
                    .prove(black_box(files_ref), black_box(&challenges))
                    .unwrap();
            });
    }
}

// --- Verification ---

#[cfg_attr(
    feature = "bench-smoke",
    divan::bench_group(sample_count = 1, sample_size = 1)
)]
#[cfg_attr(
    not(feature = "bench-smoke"),
    divan::bench_group(sample_count = 1, sample_size = 10)
)]
mod verification {
    use super::*;

    #[cfg_attr(feature = "bench-smoke", divan::bench(args = [2]))]
    #[cfg_attr(not(feature = "bench-smoke"), divan::bench(args = [2, 100]))]
    fn verify_challenges(bencher: Bencher, num_challenges: usize) {
        bencher
            .with_inputs(|| {
                let data = generate_test_data(16 * 1024, 42);
                let (prepared, metadata) = api::prepare_file(&data, "v.dat").unwrap();
                let mut ledger = FileLedger::new();
                ledger
                    .add_file(
                        metadata.file_id.clone(),
                        metadata.root,
                        api::tree_depth_from_metadata(&metadata),
                    )
                    .unwrap();

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

                // We can't return system because it borrows ledger.
                // Instead, return (ledger, proof, challenges) and recreate system in bench
                (ledger, proof, vec![challenge])
            })
            .bench_values(|(ledger, proof, challenges)| {
                let system = PorSystem::new(&ledger);
                system
                    .verify(black_box(&proof), black_box(&challenges))
                    .unwrap();
            });
    }
}
