//! Simple performance benchmarks for Kontor PoR
//!
//! Run with: cargo run --release --bin bench

use kontor_crypto::{
    api::{self, Challenge, FieldElement, PorSystem},
    build_tree, config, get_padded_proof_for_leaf, params,
    poseidon::{domain_tags, poseidon_hash_tagged},
    FileLedger,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

fn main() {
    println!("\nKontor PoR Performance Benchmarks");
    println!("================================\n");

    bench_microbenchmarks();
    bench_setup();
    bench_proving();
    bench_verifying();
    bench_e2e();

    println!("\n✅ All benchmarks completed\n");
}

/// Time a single operation and print the result
fn time_operation<F, R>(name: &str, mut f: F) -> (Duration, R)
where
    F: FnMut() -> R,
{
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();
    println!(
        "  {:<40} {:>12.3} ms",
        format!("{}:", name),
        duration.as_secs_f64() * 1000.0
    );
    (duration, result)
}

/// Time an operation multiple times and report average
fn time_operation_avg<F>(name: &str, iterations: usize, mut f: F) -> Duration
where
    F: FnMut(),
{
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let total = start.elapsed();
    let avg = total / iterations as u32;
    println!(
        "  {:<40} {:>12.3} ms (avg of {} runs)",
        format!("{}:", name),
        avg.as_secs_f64() * 1000.0,
        iterations
    );
    avg
}

fn bench_microbenchmarks() {
    println!("Microbenchmarks");
    println!("---------------");

    // Poseidon hash
    let a = FieldElement::from(config::TEST_RANDOM_SEED);
    let b = FieldElement::from(123u64);
    time_operation_avg(
        "Poseidon hash (domain-separated)",
        config::BENCHMARK_HASH_ITERATIONS,
        || {
            let _ = poseidon_hash_tagged(domain_tags::node(), a, b);
        },
    );

    // Tree building (256 leaves)
    let num_leaves = config::BENCHMARK_TREE_LEAVES;
    let data: Vec<Vec<u8>> = (0..num_leaves)
        .map(|i| format!("leaf_{}", i).into_bytes())
        .collect();
    let (_, (tree, _root)) =
        time_operation("Build tree (256 leaves)", || build_tree(&data).unwrap());

    // Merkle proof generation
    time_operation_avg(
        "Generate Merkle proof",
        config::BENCHMARK_PROOF_ITERATIONS,
        || {
            let _ = get_padded_proof_for_leaf(
                &tree,
                config::BENCHMARK_PROOF_LEAF_INDEX,
                config::BENCHMARK_TREE_DEPTH,
            );
        },
    );

    println!();
}

fn bench_setup() {
    println!("Setup API");
    println!("---------");

    // Generate test data
    let file_size_kb = config::BENCHMARK_FILE_SIZE_MEDIUM;
    let data = generate_test_data(file_size_kb * 1024);

    time_operation(&format!("Prepare {}KB file", file_size_kb), || {
        api::prepare_file(&data, "test_file.dat").unwrap()
    });

    println!();
}

fn bench_proving() {
    println!("Proving API");
    println!("----------------------------");

    // Small case: 16KB file, 2 challenges
    {
        let (_params, prepared_file, challenge) =
            setup_proof_scenario(config::BENCHMARK_FILE_SIZE_SMALL, 2);
        let mut files = BTreeMap::new();
        files.insert(challenge.file_metadata.file_id.clone(), &prepared_file);
        let mut ledger = FileLedger::new();
        ledger
            .add_file(
                challenge.file_metadata.file_id.clone(),
                challenge.file_metadata.root,
                api::tree_depth_from_metadata(&challenge.file_metadata),
            )
            .unwrap();
        let challenges = vec![challenge];
        let system = PorSystem::new(&ledger);
        time_operation("Prove 16KB/2 challenges", || {
            system.prove(vec![&prepared_file], &challenges).unwrap()
        });
    }

    // Medium case: 32KB file, 3 challenges
    {
        let (_params, prepared_file, challenge) =
            setup_proof_scenario(config::BENCHMARK_FILE_SIZE_MEDIUM, 3);
        let mut files = BTreeMap::new();
        files.insert(challenge.file_metadata.file_id.clone(), &prepared_file);
        let mut ledger = FileLedger::new();
        ledger
            .add_file(
                challenge.file_metadata.file_id.clone(),
                challenge.file_metadata.root,
                api::tree_depth_from_metadata(&challenge.file_metadata),
            )
            .unwrap();
        let challenges = vec![challenge];
        let system = PorSystem::new(&ledger);
        time_operation("Prove 32KB/3 challenges", || {
            system.prove(vec![&prepared_file], &challenges).unwrap()
        });
    }

    // More challenges: 16KB, 5 challenges
    {
        let (_params, prepared_file, challenge) =
            setup_proof_scenario(config::BENCHMARK_FILE_SIZE_SMALL, 5);
        let mut files = BTreeMap::new();
        files.insert(challenge.file_metadata.file_id.clone(), &prepared_file);
        let mut ledger = FileLedger::new();
        ledger
            .add_file(
                challenge.file_metadata.file_id.clone(),
                challenge.file_metadata.root,
                api::tree_depth_from_metadata(&challenge.file_metadata),
            )
            .unwrap();
        let challenges = vec![challenge];
        let system = PorSystem::new(&ledger);
        time_operation("Prove 16KB/5 challenges", || {
            system.prove(vec![&prepared_file], &challenges).unwrap()
        });
    }

    println!();
}

fn bench_verifying() {
    println!("Verification API");
    println!("----------------");

    // Generate a proof to verify (small for speed)
    let (_params, prepared_file, challenge) =
        setup_proof_scenario(config::BENCHMARK_FILE_SIZE_SMALL, 2);
    let mut files = BTreeMap::new();
    files.insert(challenge.file_metadata.file_id.clone(), &prepared_file);
    let mut ledger = FileLedger::new();
    ledger
        .add_file(
            challenge.file_metadata.file_id.clone(),
            challenge.file_metadata.root,
            api::tree_depth_from_metadata(&challenge.file_metadata),
        )
        .unwrap();
    let challenges = vec![challenge.clone()];
    let system = PorSystem::new(&ledger);
    let proof = system.prove(vec![&prepared_file], &challenges).unwrap();

    // Time verification (should be constant regardless of input)
    time_operation_avg("Verify proof", config::BENCHMARK_VERIFY_ITERATIONS, || {
        let result = system.verify(&proof, &challenges).unwrap();
        assert!(result, "Verification should succeed");
    });

    println!();
}

fn bench_e2e() {
    println!("End-to-End Workflow");
    println!("-------------------");

    let file_size_kb = config::BENCHMARK_FILE_SIZE_SMALL;
    let num_challenges = 2;

    time_operation(
        &format!(
            "Full workflow ({}KB/{} challenges)",
            file_size_kb, num_challenges
        ),
        || {
            // 1. Setup
            let data = generate_test_data(file_size_kb * 1024);

            let (prepared_file, metadata) = api::prepare_file(&data, "e2e_test.dat").unwrap();

            // 2. Generate parameters for exact shape
            let tree_depth = metadata.padded_len.trailing_zeros() as usize;
            let (files_per_step, file_tree_depth) = config::derive_shape(1, tree_depth);
            let _params =
                params::load_or_generate_params(files_per_step, file_tree_depth, 0).unwrap();

            // 3. Create challenge
            let seed = FieldElement::from(42u64);
            let challenge = Challenge::new(
                metadata.clone(),
                1000,
                num_challenges,
                seed,
                String::from("bench_prover"),
            );

            // 4. Create ledger
            let mut ledger = FileLedger::new();
            ledger
                .add_file(
                    metadata.file_id.clone(),
                    metadata.root,
                    api::tree_depth_from_metadata(&metadata),
                )
                .unwrap();

            // 5. Prove
            let mut files = BTreeMap::new();
            files.insert(metadata.file_id.clone(), &prepared_file);
            let challenges = vec![challenge.clone()];
            let system = PorSystem::new(&ledger);
            let proof = system.prove(vec![&prepared_file], &challenges).unwrap();

            // 6. Verify
            let result = system.verify(&proof, &challenges).unwrap();
            assert!(result, "E2E verification should succeed");
        },
    );

    println!();
}

// Helper functions

fn generate_test_data(size: usize) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(config::BENCHMARK_SEED);
    let mut data = vec![0u8; size];
    rng.fill_bytes(&mut data);
    data
}

fn setup_proof_scenario(
    file_size_kb: usize,
    num_challenges: usize,
) -> (api::PorParams, api::PreparedFile, Challenge) {
    // Generate data
    let data = generate_test_data(file_size_kb * 1024);

    // Prepare file
    let (prepared_file, metadata) = api::prepare_file(&data, "bench_test.dat").unwrap();

    // Generate parameters
    let tree_depth = metadata.padded_len.trailing_zeros() as usize;
    let (files_per_step, file_tree_depth) = config::derive_shape(1, tree_depth);
    let params = params::load_or_generate_params(files_per_step, file_tree_depth, 0).unwrap();

    // Create challenge
    let seed = FieldElement::from(config::TEST_RANDOM_SEED);
    let challenge = Challenge::new(
        metadata,
        1000,
        num_challenges,
        seed,
        String::from("bench_prover"),
    );

    (params, prepared_file, challenge)
}
