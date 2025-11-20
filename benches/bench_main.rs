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

#[divan::bench_group(sample_count = 10, sample_size = 100)]
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

    #[divan::bench(args = [16, 1024])]
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

    #[divan::bench(args = [10, 1024])] // 10KB, 1MB
    fn erasure_encode(bencher: Bencher, size_kb: usize) {
        bencher
            .with_inputs(|| generate_test_data(size_kb * 1024, 42))
            .bench_values(|data| {
                encode_file_symbols(black_box(&data)).unwrap();
            });
    }
}

// --- File Preparation ---

#[divan::bench(
    sample_count = 10,
    args = [10, 1024] // 10KB, 1MB
)]
fn file_preparation(bencher: Bencher, size_kb: usize) {
    bencher
        .with_inputs(|| generate_test_data(size_kb * 1024, 42))
        .bench_values(|data| {
            api::prepare_file(black_box(&data), "test.dat").unwrap();
        });
}

// --- Proving (Expensive!) ---

#[divan::bench_group(sample_count = 1)] // Only 1 sample needed for expensive proofs
mod proving {
    use super::*;

    #[divan::bench(
        args = [
            (10, 2),    // 10KB, 2 challenges
            (1024, 2),  // 1MB, 2 challenges
            (10, 50),   // 10KB, 50 challenges
            (1024, 50)  // 1MB, 50 challenges
        ]
    )]
    fn single_file(bencher: Bencher, args: (usize, usize)) {
        let (size_kb, num_challenges) = args;

        bencher
            .with_inputs(|| {
                let data = generate_test_data(size_kb * 1024, 42);
                let (prepared_file, metadata) = api::prepare_file(&data, "bench.dat").unwrap();

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
                    String::from("bench_prover"),
                );

                (ledger, vec![prepared_file], vec![challenge])
            })
            .bench_values(|(ledger, files, challenges)| {
                let system = PorSystem::new(&ledger);
                let files_ref: Vec<&_> = files.iter().collect();
                system
                    .prove(black_box(files_ref), black_box(&challenges))
                    .unwrap();
            });
    }

    #[divan::bench(args = [2, 8])] // 2 files, 8 files
    fn multi_file_aggregation(bencher: Bencher, num_files: usize) {
        bencher
            .with_inputs(|| {
                let mut prepared_files = Vec::new();
                let mut challenges = Vec::new();
                let mut ledger = FileLedger::new();
                let size_kb = 16;

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
                        2, // Minimal challenges
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

#[divan::bench_group(sample_count = 10)]
mod verification {
    use super::*;

    #[divan::bench(args = [2, 50])]
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
                let proof = system.prove(vec![&prepared], &[challenge.clone()]).unwrap();

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
