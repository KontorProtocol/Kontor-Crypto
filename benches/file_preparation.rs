//! File preparation benchmarks across protocol-specified file sizes

use codspeed_criterion_compat::{black_box, criterion_group, BenchmarkId, Criterion};
use kontor_crypto::api;
use rand::{rngs::StdRng, RngCore, SeedableRng};

fn generate_test_data(size: usize, seed: u64) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut data = vec![0u8; size];
    rng.fill_bytes(&mut data);
    data
}

fn bench_prepare_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_preparation");
    group.sample_size(3).warm_up_time(std::time::Duration::from_millis(10));

    // Test extremes: small and large files (skip 10MB - too slow)
    let sizes = [(10, "10KB"), (1024, "1MB")];

    for (size_kb, label) in sizes {
        let data = generate_test_data(size_kb * 1024, 42);

        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &data,
            |bencher, data| {
                bencher.iter(|| api::prepare_file(black_box(data), "test.dat").unwrap());
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_prepare_file);
