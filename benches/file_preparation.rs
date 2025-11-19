//! File preparation benchmarks across protocol-specified file sizes

use codspeed_criterion_compat::criterion_group;
use criterion::{black_box, BenchmarkId, Criterion};
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

    // Protocol-specified file sizes from spec table:
    // 10KB (depth 9), 100KB (depth 12), 1MB (depth 16), 10MB (depth 19)
    let sizes = [(10, "10KB"), (100, "100KB"), (1024, "1MB"), (10240, "10MB")];

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
