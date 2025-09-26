//! Benchmarks for lib-q-random
//!
//! This module provides comprehensive benchmarks for the lib-q-random crate,
//! measuring performance across different RNG types and operations.

use std::hint::black_box;

use criterion::{
    BenchmarkId,
    Criterion,
    criterion_group,
    criterion_main,
};
use lib_q_random::entropy::{
    DeterministicEntropySource,
    UserEntropySource,
};
use lib_q_random::{
    EntropySource,
    LibQRng,
    SecureRng,
    new_deterministic_rng,
    new_secure_rng,
};
use rand_core::RngCore;

fn benchmark_deterministic_rng_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("deterministic_rng_creation");

    for size in [16, 32, 64, 128].iter() {
        group.bench_with_input(BenchmarkId::new("seed_size", size), size, |b, &size| {
            let seed = vec![0u8; size];
            b.iter(|| black_box(new_deterministic_rng(&seed)));
        });
    }

    group.finish();
}

fn benchmark_secure_rng_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("secure_rng_creation");

    group.bench_function("best_available", |b| {
        b.iter(|| black_box(new_secure_rng()));
    });

    group.finish();
}

fn benchmark_rng_fill_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("rng_fill_bytes");

    let seed = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut rng = new_deterministic_rng(&seed);

    for size in [16, 32, 64, 128, 256, 512, 1024].iter() {
        group.bench_with_input(BenchmarkId::new("deterministic", size), size, |b, &size| {
            b.iter(|| {
                let mut bytes = vec![0u8; size];
                rng.fill_bytes(&mut bytes);
                black_box(bytes)
            });
        });
    }

    group.finish();
}

fn benchmark_rng_next_u32(c: &mut Criterion) {
    let mut group = c.benchmark_group("rng_next_u32");

    let seed = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut rng = new_deterministic_rng(&seed);

    group.bench_function("deterministic", |b| {
        b.iter(|| black_box(rng.next_u32()));
    });

    group.finish();
}

fn benchmark_rng_next_u64(c: &mut Criterion) {
    let mut group = c.benchmark_group("rng_next_u64");

    let seed = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut rng = new_deterministic_rng(&seed);

    group.bench_function("deterministic", |b| {
        b.iter(|| black_box(rng.next_u64()));
    });

    group.finish();
}

fn benchmark_entropy_source_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("entropy_source_performance");

    // Benchmark deterministic entropy source
    let seed = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut det_source = DeterministicEntropySource::new(&seed);

    for size in [16, 32, 64, 128].iter() {
        group.bench_with_input(BenchmarkId::new("deterministic", size), size, |b, &size| {
            b.iter(|| {
                let mut bytes = vec![0u8; size];
                det_source.get_entropy(&mut bytes).unwrap();
                black_box(bytes)
            });
        });
    }

    // Benchmark user entropy source
    let entropy_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let mut user_source = UserEntropySource::new(entropy_data);

    for size in [16, 32, 64, 128].iter() {
        group.bench_with_input(BenchmarkId::new("user", size), size, |b, &size| {
            b.iter(|| {
                let mut bytes = vec![0u8; size];
                user_source.get_entropy(&mut bytes).unwrap();
                black_box(bytes)
            });
        });
    }

    group.finish();
}

fn benchmark_entropy_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("entropy_validation");

    use lib_q_random::EntropyValidator;
    use lib_q_random::validation::quick_entropy_check;

    let validator = EntropyValidator::new();

    // Generate test data
    let mut rng = new_deterministic_rng(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let mut test_data = vec![0u8; 1024];
    rng.fill_bytes(&mut test_data);

    group.bench_function("full_validation", |b| {
        b.iter(|| black_box(validator.validate_entropy(&test_data)));
    });

    group.bench_function("quick_check", |b| {
        b.iter(|| black_box(quick_entropy_check(&test_data)));
    });

    group.finish();
}

fn benchmark_rng_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("rng_operations");

    let seed = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut rng = new_deterministic_rng(&seed);

    group.bench_function("fill_bytes_32", |b| {
        b.iter(|| {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            black_box(bytes)
        });
    });

    group.bench_function("fill_bytes_64", |b| {
        b.iter(|| {
            let mut bytes = [0u8; 64];
            rng.fill_bytes(&mut bytes);
            black_box(bytes)
        });
    });

    group.bench_function("fill_bytes_128", |b| {
        b.iter(|| {
            let mut bytes = [0u8; 128];
            rng.fill_bytes(&mut bytes);
            black_box(bytes)
        });
    });

    group.bench_function("next_u32", |b| {
        b.iter(|| black_box(rng.next_u32()));
    });

    group.bench_function("next_u64", |b| {
        b.iter(|| black_box(rng.next_u64()));
    });

    group.finish();
}

fn benchmark_custom_rng_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("custom_rng_creation");

    let entropy_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    group.bench_function("user_entropy_source", |b| {
        b.iter(|| {
            let source = UserEntropySource::new(entropy_data.clone());
            black_box(LibQRng::new_custom(source))
        });
    });

    group.bench_function("deterministic_entropy_source", |b| {
        b.iter(|| {
            let seed = [1, 2, 3, 4, 5, 6, 7, 8];
            let source = DeterministicEntropySource::new(&seed);
            black_box(LibQRng::new_custom(source))
        });
    });

    group.finish();
}

fn benchmark_rng_initialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("rng_initialization");

    let seed = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut rng = new_deterministic_rng(&seed);

    group.bench_function("initialize", |b| {
        let entropy = [9, 10, 11, 12, 13, 14, 15, 16];
        b.iter(|| black_box(rng.initialize(&entropy)));
    });

    group.bench_function("reseed", |b| {
        b.iter(|| black_box(rng.reseed()));
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_deterministic_rng_creation,
    benchmark_secure_rng_creation,
    benchmark_rng_fill_bytes,
    benchmark_rng_next_u32,
    benchmark_rng_next_u64,
    benchmark_entropy_source_performance,
    benchmark_entropy_validation,
    benchmark_rng_operations,
    benchmark_custom_rng_creation,
    benchmark_rng_initialization
);

criterion_main!(benches);
