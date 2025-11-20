//! Proving benchmarks for single-file and multi-file aggregation

use codspeed_criterion_compat::{black_box, criterion_group, BenchmarkId, Criterion, SamplingMode};
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

fn bench_prove_single_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("prove_single_file");
    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(2)
        .warmup_time(std::time::Duration::from_millis(10));

    // Test extremes: small and large files
    let file_sizes = [(10, "10KB"), (1024, "1MB")];
    let challenge_counts = [2, 50];

    for (size_kb, size_label) in file_sizes {
        for num_challenges in challenge_counts {
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

            let seed = FieldElement::from(config::TEST_RANDOM_SEED);
            let challenge = Challenge::new(
                metadata.clone(),
                1000,
                num_challenges,
                seed,
                String::from("bench_prover"),
            );

            let challenges = vec![challenge];
            let system = PorSystem::new(&ledger);

            group.bench_with_input(
                BenchmarkId::new(size_label, num_challenges),
                &(system, prepared_file, challenges),
                |bencher, (system, prepared_file, challenges)| {
                    bencher.iter(|| {
                        black_box(
                            system
                                .prove(vec![prepared_file], black_box(challenges))
                                .unwrap(),
                        )
                    });
                },
            );
        }
    }

    group.finish();
}

fn bench_prove_multi_file_aggregation(c: &mut Criterion) {
    let mut group = c.benchmark_group("multi_file_aggregation");
    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(2)
        .warmup_time(std::time::Duration::from_millis(10));

    // Test extremes: single file vs many files
    let file_counts = [1, 8];
    let num_challenges_per_file = 2;
    let file_size_kb = 10;

    for num_files in file_counts {
        // Prepare multiple files
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

        // Create challenges for all files
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

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_files", num_files)),
            &(system, files_vec, challenges),
            |bencher, (system, files, challenges)| {
                bencher.iter(|| {
                    black_box(
                        system
                            .prove(black_box(files.clone()), black_box(challenges))
                            .unwrap(),
                    )
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_prove_single_file,
    bench_prove_multi_file_aggregation
);
