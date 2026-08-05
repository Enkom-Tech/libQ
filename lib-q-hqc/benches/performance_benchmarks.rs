//! Performance benchmarks for HQC operations
//!
//! This module benchmarks keygen/encapsulate/decapsulate for each HQC security level. The
//! benchmark group name is suffixed with the backend string reported by
//! `simd::runtime::get_best_implementation()` (`"avx2"` or `"portable"`), so a `simd-avx2` build
//! and a default build land in differently-named groups and cannot be silently compared as if
//! they were the same run. See `docs/simd-architecture.md` for the reproducible
//! `simd-avx2`-vs-default procedure this is designed to support; no percentage speedup is
//! hard-coded or asserted here.

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

/// Benchmark HQC KEM operations for different security levels.
///
/// Setup (RNG/KEM construction, keygen for the encapsulate/decapsulate benches) happens once per
/// `bench_function` call, outside the timed `b.iter` closure — an earlier revision of this file
/// ran a full `keygen()` inside the timed closure for `HQC-128_encapsulate`, so the reported
/// number was keygen + encapsulate, not encapsulate alone.
#[cfg(feature = "alloc")]
fn benchmark_hqc_kem_operations(c: &mut Criterion) {
    let backend = lib_q_hqc::simd::runtime::get_best_implementation();
    let mut group = c.benchmark_group(format!("hqc_kem_operations/{backend}"));

    // --- Key generation ---

    group.bench_function("HQC-128_keygen", |b| {
        use lib_q_hqc::hqc_correct::Hqc128Kem;
        use lib_q_random::LibQRng;
        let mut rng = LibQRng::new_secure().unwrap();
        let kem = Hqc128Kem::new().unwrap();
        b.iter(|| black_box(kem.keygen(&mut rng)))
    });

    group.bench_function("HQC-192_keygen", |b| {
        use lib_q_hqc::hqc_correct::Hqc192Kem;
        use lib_q_random::LibQRng;
        let mut rng = LibQRng::new_secure().unwrap();
        let kem = Hqc192Kem::new().unwrap();
        b.iter(|| black_box(kem.keygen(&mut rng)))
    });

    group.bench_function("HQC-256_keygen", |b| {
        use lib_q_hqc::hqc_correct::Hqc256Kem;
        use lib_q_random::LibQRng;
        let mut rng = LibQRng::new_secure().unwrap();
        let kem = Hqc256Kem::new().unwrap();
        b.iter(|| black_box(kem.keygen(&mut rng)))
    });

    // --- Encapsulation (keypair built once, outside the timed closure) ---

    group.bench_function("HQC-128_encapsulate", |b| {
        use lib_q_hqc::hqc_correct::Hqc128Kem;
        use lib_q_random::LibQRng;
        let mut rng = LibQRng::new_secure().unwrap();
        let kem = Hqc128Kem::new().unwrap();
        let (public_key, _secret_key) = kem.keygen(&mut rng).unwrap();
        b.iter(|| black_box(kem.encapsulate(&public_key, &mut rng)))
    });

    // --- Decapsulation (keypair + one ciphertext built once, outside the timed closure) ---
    // Previously unbenchmarked, despite decapsulation exercising `vect_mul` just like
    // encapsulation.

    group.bench_function("HQC-128_decapsulate", |b| {
        use lib_q_hqc::hqc_correct::Hqc128Kem;
        use lib_q_random::LibQRng;
        let mut rng = LibQRng::new_secure().unwrap();
        let kem = Hqc128Kem::new().unwrap();
        let (public_key, secret_key) = kem.keygen(&mut rng).unwrap();
        let (ciphertext, _shared_secret) = kem.encapsulate(&public_key, &mut rng).unwrap();
        b.iter(|| black_box(kem.decapsulate(&secret_key, &ciphertext)))
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
    benchmark_memory_usage
);

#[cfg(feature = "alloc")]
criterion_main!(benches);

#[cfg(not(feature = "alloc"))]
fn main() {
    println!("Benchmarks require the 'alloc' feature to be enabled");
    println!("Run with: cargo bench --features alloc");
}
