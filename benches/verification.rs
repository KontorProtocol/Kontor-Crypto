//! Verification benchmarks across different file counts and challenge sizes

use codspeed_criterion_compat::criterion_group;
use criterion::{black_box, BenchmarkId, Criterion};
use kontor_crypto::{
    api::{self, Challenge, FieldElement, PorSystem},
    config, FileLedger,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};

fn generate_test_data(size: usize, seed: u64) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut data = vec![0u8; size];
    rng.fill_bytes(&mut data);
    data
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification");

    // Verification should be constant time regardless of challenge count
    // but test to confirm
    let file_size_kb = 16;

    for num_challenges in [2, 5, 10, 50] {
        let data = generate_test_data(file_size_kb * 1024, 42);
        let (prepared_file, metadata) = api::prepare_file(&data, "verify.dat").unwrap();

        let mut ledger = FileLedger::new();
        ledger
            .add_file(
                metadata.file_id.clone(),
                metadata.root,
                api::tree_depth_from_metadata(&metadata),
            )
            .unwrap();

        let seed = FieldElement::from(config::TEST_RANDOM_SEED);
        let challenge = Challenge::new(
            metadata.clone(),
            1000,
            num_challenges,
            seed,
            String::from("bench_prover"),
        );

        let challenges = vec![challenge.clone()];
        let system = PorSystem::new(&ledger);
        let proof = system.prove(vec![&prepared_file], &challenges).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_challenges", num_challenges)),
            &(system, proof, challenges),
            |bencher, (system, proof, challenges)| {
                bencher.iter(|| {
                    black_box(
                        system
                            .verify(black_box(proof), black_box(challenges))
                            .unwrap(),
                    )
                });
            },
        );
    }

    group.finish();
}

fn bench_verify_multi_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification_multi_file");

    // Verify constant-time across different file counts
    let file_size_kb = 16;
    let num_challenges_per_file = 5;

    for num_files in [1, 2, 4, 8] {
        let mut prepared_files = Vec::new();
        let mut metadatas = Vec::new();
        let mut ledger = FileLedger::new();

        for i in 0..num_files {
            let data = generate_test_data(file_size_kb * 1024, 42 + i as u64);
            let (prepared, metadata) =
                api::prepare_file(&data, &format!("file_{}.dat", i)).unwrap();

            ledger
                .add_file(
                    metadata.file_id.clone(),
                    metadata.root,
                    api::tree_depth_from_metadata(&metadata),
                )
                .unwrap();

            prepared_files.push(prepared);
            metadatas.push(metadata);
        }

        let mut challenges = Vec::new();
        for metadata in &metadatas {
            let seed = FieldElement::from(config::TEST_RANDOM_SEED);
            challenges.push(Challenge::new(
                metadata.clone(),
                1000,
                num_challenges_per_file,
                seed,
                String::from("bench_prover"),
            ));
        }

        let system = PorSystem::new(&ledger);
        let files_vec: Vec<&_> = prepared_files.iter().collect();
        let proof = system.prove(files_vec, &challenges).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_files", num_files)),
            &(system, proof, challenges),
            |bencher, (system, proof, challenges)| {
                bencher.iter(|| {
                    black_box(
                        system
                            .verify(black_box(proof), black_box(challenges))
                            .unwrap(),
                    )
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_verify, bench_verify_multi_file);
