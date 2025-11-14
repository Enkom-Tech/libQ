//! Performance benchmarks for HQC operations
//!
//! This module provides benchmarks to measure the performance improvements
//! from FFT/NTT optimizations and other performance enhancements.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use std::hint::black_box;

#[cfg(feature = "alloc")]
use criterion::{
    Criterion,
    criterion_group,
    criterion_main,
};
#[cfg(feature = "alloc")]
use lib_q_hqc::params_correct::{
    Hqc1Params,
    Hqc3Params,
    Hqc5Params,
};

/// Benchmark HQC KEM operations for different security levels
#[cfg(feature = "alloc")]
fn benchmark_hqc_kem_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("hqc_kem_operations");

    // Test HQC-128
    group.bench_function("HQC-128_keygen", |b| {
        b.iter(|| {
            use lib_q_hqc::hqc_correct::Hqc128Kem;
            use lib_q_random::LibQRng;
            let mut rng = LibQRng::new_secure().unwrap();
            let kem = Hqc128Kem::new().unwrap();
            black_box(kem.keygen(&mut rng))
        })
    });

    // Test HQC-192
    group.bench_function("HQC-192_keygen", |b| {
        b.iter(|| {
            use lib_q_hqc::hqc_correct::Hqc192Kem;
            use lib_q_random::LibQRng;
            let mut rng = LibQRng::new_secure().unwrap();
            let kem = Hqc192Kem::new().unwrap();
            black_box(kem.keygen(&mut rng))
        })
    });

    // Test HQC-256
    group.bench_function("HQC-256_keygen", |b| {
        b.iter(|| {
            use lib_q_hqc::hqc_correct::Hqc256Kem;
            use lib_q_random::LibQRng;
            let mut rng = LibQRng::new_secure().unwrap();
            let kem = Hqc256Kem::new().unwrap();
            black_box(kem.keygen(&mut rng))
        })
    });

    group.finish();
}

/// Benchmark HQC encapsulation/decapsulation
#[cfg(feature = "alloc")]
fn benchmark_hqc_encapsulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("hqc_encapsulation");

    // Test HQC-128 encapsulation
    group.bench_function("HQC-128_encapsulate", |b| {
        b.iter(|| {
            use lib_q_hqc::hqc_correct::Hqc128Kem;
            use lib_q_random::LibQRng;
            let mut rng = LibQRng::new_secure().unwrap();
            let kem = Hqc128Kem::new().unwrap();
            let (public_key, _) = kem.keygen(&mut rng).unwrap();
            black_box(kem.encapsulate(&public_key, &mut rng))
        })
    });

    group.finish();
}

/// Benchmark memory usage patterns
#[cfg(feature = "alloc")]
fn benchmark_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage");

    group.bench_function("hqc_parameter_sizes", |b| {
        b.iter(|| {
            use lib_q_hqc::params_correct::HqcParams;
            let hqc1_n = Hqc1Params::N;
            let hqc3_n = Hqc3Params::N;
            let hqc5_n = Hqc5Params::N;
            black_box((hqc1_n, hqc3_n, hqc5_n))
        })
    });

    group.finish();
}

// All benchmarks require alloc feature
#[cfg(feature = "alloc")]
criterion_group!(
    benches,
    benchmark_hqc_kem_operations,
    benchmark_hqc_encapsulation,
    benchmark_memory_usage
);

#[cfg(feature = "alloc")]
criterion_main!(benches);

#[cfg(not(feature = "alloc"))]
fn main() {
    println!("Benchmarks require the 'alloc' feature to be enabled");
    println!("Run with: cargo bench --features alloc");
}
