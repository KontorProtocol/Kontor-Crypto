//! Primitive operation benchmarks (Poseidon, Merkle, erasure coding)

use codspeed_criterion_compat::{black_box, criterion_group, BenchmarkId, Criterion};
use kontor_crypto::{
    build_tree, config, get_padded_proof_for_leaf,
    poseidon::{domain_tags, poseidon_hash_tagged},
    FieldElement,
};

fn bench_poseidon_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("poseidon");

    let a = FieldElement::from(config::TEST_RANDOM_SEED);
    let b = FieldElement::from(123u64);

    group.bench_function("hash_tagged", |bencher| {
        bencher.iter(|| {
            black_box(poseidon_hash_tagged(
                domain_tags::node(),
                black_box(a),
                black_box(b),
            ))
        });
    });

    group.finish();
}

fn bench_merkle_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle");

    // Test different tree sizes
    for num_leaves in [16, 64, 256, 1024] {
        let data: Vec<Vec<u8>> = (0..num_leaves)
            .map(|i| format!("leaf_{}", i).into_bytes())
            .collect();

        group.bench_with_input(
            BenchmarkId::new("build_tree", num_leaves),
            &data,
            |bencher, data| {
                bencher.iter(|| build_tree(black_box(data)).unwrap());
            },
        );
    }

    // Benchmark proof generation for depth 8 tree
    let num_leaves = 256;
    let data: Vec<Vec<u8>> = (0..num_leaves)
        .map(|i| format!("leaf_{}", i).into_bytes())
        .collect();
    let (tree, _) = build_tree(&data).unwrap();
    let depth = 8;

    group.bench_function("generate_proof_depth8", |bencher| {
        bencher.iter(|| {
            black_box(
                get_padded_proof_for_leaf(black_box(&tree), black_box(42), black_box(depth))
                    .unwrap(),
            )
        });
    });

    group.finish();
}

fn bench_erasure_coding(c: &mut Criterion) {
    use kontor_crypto::erasure::{decode_file_symbols, encode_file_symbols};

    let mut group = c.benchmark_group("erasure_coding");

    // Test different file sizes
    for size_kb in [10, 100, 1024] {
        let data = vec![42u8; size_kb * 1024];

        group.bench_with_input(
            BenchmarkId::new("encode", format!("{}KB", size_kb)),
            &data,
            |bencher, data| {
                bencher.iter(|| encode_file_symbols(black_box(data)).unwrap());
            },
        );

        // Benchmark decoding with some missing symbols
        let symbols = encode_file_symbols(&data).unwrap();
        let num_codewords = symbols.len() / config::TOTAL_SYMBOLS_PER_CODEWORD;
        let mut damaged: Vec<Option<Vec<u8>>> = symbols.into_iter().map(Some).collect();
        // Remove 10 symbols (within tolerance)
        for item in damaged.iter_mut().take(10) {
            *item = None;
        }

        group.bench_with_input(
            BenchmarkId::new("decode", format!("{}KB", size_kb)),
            &(damaged.clone(), num_codewords, data.len()),
            |bencher, (damaged, num_codewords, original_size)| {
                bencher.iter(|| {
                    let mut d = damaged.clone();
                    decode_file_symbols(black_box(&mut d), *num_codewords, *original_size).unwrap()
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_poseidon_hash,
    bench_merkle_operations,
    bench_erasure_coding
);
