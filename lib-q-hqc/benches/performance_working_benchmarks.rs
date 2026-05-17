//! Working performance benchmarks

#[cfg(feature = "alloc")]
use std::hint::black_box;

#[cfg(feature = "alloc")]
use criterion::{
    Criterion,
    criterion_group,
    criterion_main,
};
#[cfg(feature = "alloc")]
use lib_q_hqc::hqc_correct::{
    Hqc128Kem,
    Hqc192Kem,
    Hqc256Kem,
};
#[cfg(feature = "alloc")]
use lib_q_random::LibQRng;

/// Benchmark HQC key generation
#[cfg(feature = "alloc")]
fn benchmark_hqc_keygen(c: &mut Criterion) {
    c.bench_function("HQC-128_keygen", |b| {
        b.iter(|| {
            let mut rng = LibQRng::new_secure().unwrap();
            let kem = Hqc128Kem::new().unwrap();
            black_box(kem.keygen(&mut rng))
        })
    });
}

/// Benchmark HQC encapsulation
#[cfg(feature = "alloc")]
fn benchmark_hqc_encapsulation(c: &mut Criterion) {
    c.bench_function("HQC-128_encapsulate", |b| {
        b.iter(|| {
            let mut rng = LibQRng::new_secure().unwrap();
            let kem = Hqc128Kem::new().unwrap();
            let (public_key, _) = kem.keygen(&mut rng).unwrap();
            black_box(kem.encapsulate(&public_key, &mut rng))
        })
    });
}

/// Benchmark different security levels
#[cfg(feature = "alloc")]
fn benchmark_security_levels(c: &mut Criterion) {
    c.bench_function("HQC-192_keygen", |b| {
        b.iter(|| {
            let mut rng = LibQRng::new_secure().unwrap();
            let kem = Hqc192Kem::new().unwrap();
            black_box(kem.keygen(&mut rng))
        })
    });

    c.bench_function("HQC-256_keygen", |b| {
        b.iter(|| {
            let mut rng = LibQRng::new_secure().unwrap();
            let kem = Hqc256Kem::new().unwrap();
            black_box(kem.keygen(&mut rng))
        })
    });
}

/// Benchmark memory usage
#[cfg(feature = "alloc")]
fn benchmark_memory_usage(c: &mut Criterion) {
    c.bench_function("hqc_memory_usage", |b| {
        b.iter(|| {
            let mut rng = LibQRng::new_secure().unwrap();
            let kem = Hqc256Kem::new().unwrap();
            let (public_key, secret_key) = kem.keygen(&mut rng).unwrap();
            let (ciphertext, shared_secret) = kem.encapsulate(&public_key, &mut rng).unwrap();
            black_box((secret_key, public_key, ciphertext, shared_secret))
        })
    });
}

#[cfg(feature = "alloc")]
criterion_group!(
    benches,
    benchmark_hqc_keygen,
    benchmark_hqc_encapsulation,
    benchmark_security_levels,
    benchmark_memory_usage
);

#[cfg(feature = "alloc")]
criterion_main!(benches);

/// Fallback main function for no_alloc builds
#[cfg(not(feature = "alloc"))]
fn main() {
    println!("Benchmarks require the 'alloc' feature to be enabled");
}
