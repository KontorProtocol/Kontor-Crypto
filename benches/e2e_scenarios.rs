//! End-to-end workflow benchmarks

use codspeed_criterion_compat::{black_box, criterion_group, BenchmarkId, Criterion, SamplingMode};
use kontor_crypto::{
    api::{self, Challenge, FieldElement, PorSystem},
    config, params, FileLedger,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};

fn generate_test_data(size: usize, seed: u64) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut data = vec![0u8; size];
    rng.fill_bytes(&mut data);
    data
}

fn bench_e2e_workflow(c: &mut Criterion) {
    let mut group = c.benchmark_group("e2e_workflow");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10);

    // Test full workflow for small and medium files
    for (size_kb, label) in [(10, "10KB"), (100, "100KB")] {
        for num_challenges in [2, 5, 10] {
            group.bench_with_input(
                BenchmarkId::new(label, num_challenges),
                &(size_kb, num_challenges),
                |bencher, (size_kb, num_challenges)| {
                    bencher.iter(|| {
                        // 1. Generate and prepare file
                        let data = generate_test_data(size_kb * 1024, 42);
                        let (prepared_file, metadata) =
                            api::prepare_file(&data, "e2e.dat").unwrap();

                        // 2. Generate parameters
                        let tree_depth = metadata.padded_len.trailing_zeros() as usize;
                        let (files_per_step, file_tree_depth) = config::derive_shape(1, tree_depth);
                        let _params =
                            params::load_or_generate_params(files_per_step, file_tree_depth, 0)
                                .unwrap();

                        // 3. Create challenge and ledger
                        let seed = FieldElement::from(config::TEST_RANDOM_SEED);
                        let challenge = Challenge::new(
                            metadata.clone(),
                            1000,
                            *num_challenges,
                            seed,
                            String::from("bench_prover"),
                        );

                        let mut ledger = FileLedger::new();
                        ledger
                            .add_file(
                                metadata.file_id.clone(),
                                metadata.root,
                                api::tree_depth_from_metadata(&metadata),
                            )
                            .unwrap();

                        // 4. Prove
                        let challenges = vec![challenge.clone()];
                        let system = PorSystem::new(&ledger);
                        let proof = system.prove(vec![&prepared_file], &challenges).unwrap();

                        // 5. Verify
                        black_box(system.verify(&proof, &challenges).unwrap())
                    });
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_e2e_workflow);
