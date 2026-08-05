//! SIMD performance benchmarks for HQC operations
//!
//! This module benchmarks the SIMD-dispatchable operations. Not every group below is a
//! meaningful AVX2-vs-portable comparison:
//!
//! - `polynomial_multiplication`, `hqc_parameter_sets`, and `throughput` benchmark
//!   `sparse_dense_mul`, which has **no AVX2 implementation** — `Avx2::sparse_dense_mul`
//!   delegates to the portable code in every configuration (see
//!   `src/simd/avx2/mod.rs`'s `impl PolynomialOps for Avx2`). These groups therefore only run
//!   the portable implementation; there used to be a second "avx2" arm here that timed the same
//!   function under a different label, which made these groups look like an avx2-vs-portable
//!   comparison when they were actually the same code path timed twice. That arm has been
//!   removed.
//! - `vector_addition`, `syndrome_generation`, and `error_correction` are real comparisons —
//!   their AVX2 arms use genuine intrinsics above a 32-byte-chunk threshold, and all tested sizes
//!   here (64/256/1024/4096) exceed it.
//! - `shift_xor`'s AVX2 arm is real, but only reaches the intrinsic path for the word-aligned
//!   distances in its distance list (see the comment on `benchmark_shift_xor`).
//! - `vect_mul_avx2_vs_schoolbook` is the one comparison that corresponds to what the HQC KEM
//!   actually calls: `simd::avx2::gf2x::avx2_vect_mul_mod_xnm1` (Toom-3 + Karatsuba + PCLMUL)
//!   versus its schoolbook fallback in `hqc_pke.rs`.
//!
//! No speedup percentage is published from these benchmarks; see
//! `benches/performance_benchmarks.rs` for keygen/encapsulate/decapsulate comparisons and
//! `docs/simd-architecture.md` for the reproducible procedure.

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

/// Benchmark polynomial multiplication (sparse-dense).
///
/// `sparse_dense_mul` has no AVX2 implementation (see module doc above), so this only measures
/// the portable implementation. There is intentionally no "avx2" arm here — timing
/// `Avx2::sparse_dense_mul` against `Portable::sparse_dense_mul` would time the same underlying
/// code path twice, since the former delegates to the latter in every configuration.
#[cfg(feature = "alloc")]
fn benchmark_polynomial_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("polynomial_multiplication");

    // Test different buffer sizes
    let sizes = [64, 256, 1024, 4096];
    let weights = [10, 50, 100, 200];

    for &size in &sizes {
        for &weight in &weights {
            let sparse = vec![0xABu8; size];
            let dense = vec![0xCDu8; size];
            let mut output = vec![0u8; size];
            let n_bits = size * 8;

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
                            black_box(n_bits),
                        );
                    });
                },
            );
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

/// Benchmark shift and XOR operations.
///
/// Of the distances below, only `0` and `64` are multiples of 64 and take the AVX2 chunk-loop
/// branch of `shift_xor_avx2`; all other distances (`1, 7, 8, 15, 16, 31, 32, 63`) run the scalar
/// branch even in the "avx2" arm, by design (see `polynomial::shift_xor_avx2`'s doc comment).
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

/// `sparse_dense_mul` has no AVX2 implementation (see module doc above), so this only measures
/// the portable implementation — no "avx2" arm here, for the same reason as
/// `benchmark_polynomial_multiplication`.
#[cfg(feature = "alloc")]
fn benchmark_parameter_set<P: lib_q_hqc::params_correct::HqcParams>(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    name: &str,
) {
    let n_bytes = P::VEC_N_SIZE_BYTES;
    let sparse = vec![0xABu8; n_bytes];
    let dense = vec![0xCDu8; n_bytes];
    let mut output = vec![0u8; n_bytes];

    group.bench_with_input(BenchmarkId::new("portable", name), &name, |b, _| {
        b.iter(|| {
            Portable::sparse_dense_mul(
                black_box(&mut output),
                black_box(&sparse),
                black_box(&dense),
                black_box(P::OMEGA as u32),
                black_box(P::N),
            );
        });
    });
}

/// Benchmark throughput measurements.
///
/// `sparse_dense_mul` has no AVX2 implementation (see module doc above), so this only measures
/// the portable implementation — no "avx2" arm here, for the same reason as
/// `benchmark_polynomial_multiplication`.
#[cfg(feature = "alloc")]
fn benchmark_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");

    // Large buffer throughput test
    let size = 4096;
    let sparse = vec![0xABu8; size];
    let dense = vec![0xCDu8; size];
    let mut output = vec![0u8; size];
    let n_bits = size * 8;

    group.throughput(Throughput::Bytes(size as u64));

    group.bench_with_input(BenchmarkId::new("portable", "throughput"), &size, |b, _| {
        b.iter(|| {
            Portable::sparse_dense_mul(
                black_box(&mut output),
                black_box(&sparse),
                black_box(&dense),
                black_box(100),
                black_box(n_bits),
            );
        });
    });

    group.finish();
}

/// Benchmark the AVX2 `gf2x` Toom-3/Karatsuba/PCLMUL multiply against its schoolbook fallback,
/// at true HQC-128 sizes. Unlike the `sparse_dense_mul`-based groups above, this is the one
/// comparison in this file that corresponds to what the KEM's `vect_mul` actually calls
/// (`hqc_pke.rs:735-747`): `avx2_vect_mul_mod_xnm1` and `schoolbook_vect_mul_mod_xnm1` are two
/// genuinely different implementations of the same ring product, not the same code path timed
/// twice.
#[cfg(all(feature = "simd-avx2", feature = "alloc", target_arch = "x86_64"))]
fn benchmark_vect_mul_avx2_vs_schoolbook(c: &mut Criterion) {
    use lib_q_hqc::hqc_pke::schoolbook_vect_mul_mod_xnm1;
    use lib_q_hqc::params_correct::{
        Hqc1Params,
        HqcParams,
    };
    use lib_q_hqc::simd::avx2::gf2x::avx2_vect_mul_mod_xnm1;

    let n = Hqc1Params::VEC_N_SIZE_64;
    let a: Vec<u64> = (0..n)
        .map(|i| (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15))
        .collect();
    let b: Vec<u64> = (0..n)
        .map(|i| {
            (i as u64)
                .wrapping_mul(0xC2B2_AE3D_27D4_EB4F)
                .wrapping_add(1)
        })
        .collect();
    let mut output = vec![0u64; n];

    let mut group = c.benchmark_group("vect_mul");

    group.bench_with_input(BenchmarkId::new("avx2", "HQC-128"), &n, |bch, _| {
        bch.iter(|| {
            let _ = avx2_vect_mul_mod_xnm1::<Hqc1Params>(
                black_box(&mut output),
                black_box(&a),
                black_box(&b),
            );
        });
    });

    group.bench_with_input(BenchmarkId::new("schoolbook", "HQC-128"), &n, |bch, _| {
        bch.iter(|| {
            let _ = schoolbook_vect_mul_mod_xnm1(
                black_box(&mut output),
                black_box(&a),
                black_box(&b),
                Hqc1Params::VEC_N_SIZE_64,
                Hqc1Params::N,
            );
        });
    });

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

#[cfg(all(feature = "alloc", feature = "simd-avx2", target_arch = "x86_64"))]
criterion_group!(vect_mul_benches, benchmark_vect_mul_avx2_vs_schoolbook);

#[cfg(all(
    feature = "alloc",
    not(all(feature = "simd-avx2", target_arch = "x86_64"))
))]
criterion_main!(benches);

#[cfg(all(feature = "alloc", feature = "simd-avx2", target_arch = "x86_64"))]
criterion_main!(benches, vect_mul_benches);

#[cfg(not(feature = "alloc"))]
fn main() {
    println!("SIMD benchmarks require the 'alloc' feature to be enabled");
    println!("Run with: cargo bench --features alloc,simd-avx2");
}
