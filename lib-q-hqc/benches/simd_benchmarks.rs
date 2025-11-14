//! SIMD performance benchmarks for HQC operations
//!
//! This module provides comprehensive benchmarks to measure the performance improvements
//! from AVX2 SIMD optimizations compared to portable implementations.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use std::hint::black_box;

#[cfg(feature = "alloc")]
use criterion::{
    BenchmarkId,
    Criterion,
    Throughput,
    criterion_group,
    criterion_main,
};
#[cfg(all(feature = "alloc", feature = "simd-avx2", target_arch = "x86_64"))]
use lib_q_hqc::simd::Avx2;
#[cfg(feature = "alloc")]
use lib_q_hqc::simd::{
    Portable,
    traits::{
        PolynomialOps,
        SyndromeOps,
    },
};

/// Benchmark polynomial multiplication (sparse-dense)
#[cfg(feature = "alloc")]
fn benchmark_polynomial_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("polynomial_multiplication");

    // Test different buffer sizes
    let sizes = [64, 256, 1024, 4096];
    let weights = [10, 50, 100, 200];

    for &size in &sizes {
        for &weight in &weights {
            let sparse = vec![0xABu8; size / 2];
            let dense = vec![0xCDu8; size / 2];
            let mut output = vec![0u8; size];

            // Benchmark portable implementation
            group.bench_with_input(
                BenchmarkId::new("portable", format!("size_{}_weight_{}", size, weight)),
                &(size, weight),
                |b, &(_size, weight)| {
                    b.iter(|| {
                        Portable::sparse_dense_mul(
                            black_box(&mut output),
                            black_box(&sparse),
                            black_box(&dense),
                            black_box(weight),
                        );
                    });
                },
            );

            // Benchmark AVX2 implementation (if available)
            #[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
            {
                group.bench_with_input(
                    BenchmarkId::new("avx2", format!("size_{}_weight_{}", size, weight)),
                    &(size, weight),
                    |b, &(_size, weight)| {
                        b.iter(|| {
                            Avx2::sparse_dense_mul(
                                black_box(&mut output),
                                black_box(&sparse),
                                black_box(&dense),
                                black_box(weight),
                            );
                        });
                    },
                );
            }
        }
    }

    group.finish();
}

/// Benchmark vector addition (XOR)
#[cfg(feature = "alloc")]
fn benchmark_vector_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("vector_addition");

    let sizes = [64, 256, 1024, 4096];

    for &size in &sizes {
        let a = vec![0xAAu8; size];
        let b = vec![0x55u8; size];
        let mut output = vec![0u8; size];

        // Benchmark portable implementation
        group.bench_with_input(BenchmarkId::new("portable", size), &size, |bench, _| {
            bench.iter(|| {
                Portable::vect_add(black_box(&mut output), black_box(&a), black_box(&b));
            });
        });

        // Benchmark AVX2 implementation (if available)
        #[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
        {
            group.bench_with_input(BenchmarkId::new("avx2", size), &size, |bench, _| {
                bench.iter(|| {
                    Avx2::vect_add(black_box(&mut output), black_box(&a), black_box(&b));
                });
            });
        }
    }

    group.finish();
}

/// Benchmark shift and XOR operations
#[cfg(feature = "alloc")]
fn benchmark_shift_xor(c: &mut Criterion) {
    let mut group = c.benchmark_group("shift_xor");

    let sizes = [8, 32, 128, 512]; // u64 arrays
    let distances = [0, 1, 7, 8, 15, 16, 31, 32, 63, 64];

    for &size in &sizes {
        for &distance in &distances {
            let source = vec![0x123456789ABCDEF0u64; size];
            let mut dest = vec![0u64; size * 2]; // Larger destination for shifts

            // Benchmark portable implementation
            group.bench_with_input(
                BenchmarkId::new("portable", format!("size_{}_dist_{}", size, distance)),
                &(size, distance),
                |b, &(size, distance)| {
                    b.iter(|| {
                        Portable::shift_xor(
                            black_box(&mut dest[..size]),
                            black_box(&source),
                            black_box(distance),
                        );
                    });
                },
            );

            // Benchmark AVX2 implementation (if available)
            #[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
            {
                group.bench_with_input(
                    BenchmarkId::new("avx2", format!("size_{}_dist_{}", size, distance)),
                    &(size, distance),
                    |b, &(size, distance)| {
                        b.iter(|| {
                            Avx2::shift_xor(
                                black_box(&mut dest[..size]),
                                black_box(&source),
                                black_box(distance),
                            );
                        });
                    },
                );
            }
        }
    }

    group.finish();
}

/// Benchmark syndrome generation
#[cfg(feature = "alloc")]
fn benchmark_syndrome_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("syndrome_generation");

    let sizes = [64, 256, 1024, 4096];

    for &size in &sizes {
        let vector = vec![0x12u8; size];
        let parity = vec![0x34u8; size];
        let mut syndrome = vec![0u8; size];

        // Benchmark portable implementation
        group.bench_with_input(BenchmarkId::new("portable", size), &size, |b, _| {
            b.iter(|| {
                Portable::generate_syndrome(
                    black_box(&mut syndrome),
                    black_box(&vector),
                    black_box(&parity),
                );
            });
        });

        // Benchmark AVX2 implementation (if available)
        #[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
        {
            group.bench_with_input(BenchmarkId::new("avx2", size), &size, |b, _| {
                b.iter(|| {
                    Avx2::generate_syndrome(
                        black_box(&mut syndrome),
                        black_box(&vector),
                        black_box(&parity),
                    );
                });
            });
        }
    }

    group.finish();
}

/// Benchmark error correction
#[cfg(feature = "alloc")]
fn benchmark_error_correction(c: &mut Criterion) {
    let mut group = c.benchmark_group("error_correction");

    let sizes = [64, 256, 1024, 4096];

    for &size in &sizes {
        let received = vec![0x12u8; size];
        let syndrome = vec![0x34u8; size];
        let mut corrected = vec![0u8; size];

        // Benchmark portable implementation
        group.bench_with_input(BenchmarkId::new("portable", size), &size, |b, _| {
            b.iter(|| {
                let result = Portable::correct_errors(
                    black_box(&mut corrected),
                    black_box(&received),
                    black_box(&syndrome),
                );
                black_box(result);
            });
        });

        // Benchmark AVX2 implementation (if available)
        #[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
        {
            group.bench_with_input(BenchmarkId::new("avx2", size), &size, |b, _| {
                b.iter(|| {
                    let result = Avx2::correct_errors(
                        black_box(&mut corrected),
                        black_box(&received),
                        black_box(&syndrome),
                    );
                    black_box(result);
                });
            });
        }
    }

    group.finish();
}

/// Benchmark HQC parameter set operations
#[cfg(feature = "alloc")]
fn benchmark_hqc_parameter_sets(c: &mut Criterion) {
    use lib_q_hqc::params_correct::{
        Hqc1Params,
        Hqc3Params,
        Hqc5Params,
    };

    let mut group = c.benchmark_group("hqc_parameter_sets");

    // Test HQC-128
    benchmark_parameter_set::<Hqc1Params>(&mut group, "HQC-128");

    // Test HQC-192
    benchmark_parameter_set::<Hqc3Params>(&mut group, "HQC-192");

    // Test HQC-256
    benchmark_parameter_set::<Hqc5Params>(&mut group, "HQC-256");

    group.finish();
}

#[cfg(feature = "alloc")]
fn benchmark_parameter_set<P: lib_q_hqc::params_correct::HqcParams>(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    name: &str,
) {
    let n_bytes = P::N / 8;
    let sparse = vec![0xABu8; n_bytes / 2];
    let dense = vec![0xCDu8; n_bytes / 2];
    let mut output = vec![0u8; n_bytes];

    // Benchmark portable implementation
    group.bench_with_input(BenchmarkId::new("portable", name), &name, |b, _| {
        b.iter(|| {
            Portable::sparse_dense_mul(
                black_box(&mut output),
                black_box(&sparse),
                black_box(&dense),
                black_box(P::OMEGA as u32),
            );
        });
    });

    // Benchmark AVX2 implementation (if available)
    #[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
    {
        group.bench_with_input(BenchmarkId::new("avx2", name), &name, |b, _| {
            b.iter(|| {
                Avx2::sparse_dense_mul(
                    black_box(&mut output),
                    black_box(&sparse),
                    black_box(&dense),
                    black_box(P::OMEGA as u32),
                );
            });
        });
    }
}

/// Benchmark throughput measurements
#[cfg(feature = "alloc")]
fn benchmark_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");

    // Large buffer throughput test
    let size = 4096;
    let sparse = vec![0xABu8; size / 2];
    let dense = vec![0xCDu8; size / 2];
    let mut output = vec![0u8; size];

    group.throughput(Throughput::Bytes(size as u64));

    // Benchmark portable implementation
    group.bench_with_input(BenchmarkId::new("portable", "throughput"), &size, |b, _| {
        b.iter(|| {
            Portable::sparse_dense_mul(
                black_box(&mut output),
                black_box(&sparse),
                black_box(&dense),
                black_box(100),
            );
        });
    });

    // Benchmark AVX2 implementation (if available)
    #[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
    {
        group.bench_with_input(BenchmarkId::new("avx2", "throughput"), &size, |b, _| {
            b.iter(|| {
                Avx2::sparse_dense_mul(
                    black_box(&mut output),
                    black_box(&sparse),
                    black_box(&dense),
                    black_box(100),
                );
            });
        });
    }

    group.finish();
}

// All benchmarks require alloc feature
#[cfg(feature = "alloc")]
criterion_group!(
    benches,
    benchmark_polynomial_multiplication,
    benchmark_vector_addition,
    benchmark_shift_xor,
    benchmark_syndrome_generation,
    benchmark_error_correction,
    benchmark_hqc_parameter_sets,
    benchmark_throughput
);

#[cfg(feature = "alloc")]
criterion_main!(benches);

#[cfg(not(feature = "alloc"))]
fn main() {
    println!("SIMD benchmarks require the 'alloc' feature to be enabled");
    println!("Run with: cargo bench --features alloc,simd-avx2");
}
