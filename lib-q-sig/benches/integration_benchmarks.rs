//! Integration benchmarks for lib-q-sig provider pattern
//!
//! These benchmarks measure the performance of the lib-q signature provider
//! including security validation, provider routing, and cross-algorithm
//! comparison through the unified interface.

use std::hint::black_box;

#[cfg(feature = "slh-dsa")]
use criterion::BenchmarkId;
use criterion::{
    Criterion,
    criterion_group,
    criterion_main,
};
#[cfg(feature = "slh-dsa")]
use lib_q_core::SigSecretKey;
use lib_q_core::{
    Algorithm,
    SignatureOperations,
};
use lib_q_sig::LibQSignatureProvider;

/// Benchmark provider pattern key generation across all algorithms
fn benchmark_provider_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("provider_key_generation");

    let provider = LibQSignatureProvider::new().expect("Failed to create provider");

    // SLH-DSA benchmarks
    #[cfg(feature = "slh-dsa")]
    {
        let slh_dsa_algorithms = [
            Algorithm::SlhDsaSha256128fRobust,
            Algorithm::SlhDsaSha256192fRobust,
            Algorithm::SlhDsaSha256256fRobust,
            Algorithm::SlhDsaShake256128fRobust,
            Algorithm::SlhDsaShake256192fRobust,
            Algorithm::SlhDsaShake256256fRobust,
        ];

        for algorithm in slh_dsa_algorithms {
            group.bench_function(format!("{:?}", algorithm), |b| {
                b.iter(|| {
                    let keypair = provider
                        .generate_keypair(algorithm, None)
                        .expect("Key generation should succeed");
                    black_box(keypair)
                })
            });
        }
    }

    // ML-DSA benchmarks
    #[cfg(feature = "ml-dsa")]
    {
        let ml_dsa_algorithms = [Algorithm::MlDsa44, Algorithm::MlDsa65, Algorithm::MlDsa87];

        for algorithm in ml_dsa_algorithms {
            group.bench_function(format!("{:?}", algorithm), |b| {
                b.iter(|| {
                    let keypair = provider
                        .generate_keypair(algorithm, None)
                        .expect("Key generation should succeed");
                    black_box(keypair)
                })
            });
        }
    }

    // FN-DSA benchmarks
    #[cfg(feature = "fn-dsa")]
    {
        let fn_dsa_algorithms = [Algorithm::FnDsa512, Algorithm::FnDsa1024];

        for algorithm in fn_dsa_algorithms {
            group.bench_function(format!("{:?}", algorithm), |b| {
                b.iter(|| {
                    let keypair = provider
                        .generate_keypair(algorithm, None)
                        .expect("Key generation should succeed");
                    black_box(keypair)
                })
            });
        }
    }

    group.finish();
}

/// Benchmark provider pattern signing across different message sizes
fn benchmark_provider_signing(c: &mut Criterion) {
    #[cfg(feature = "slh-dsa")]
    let mut group = c.benchmark_group("provider_signing");
    #[cfg(not(feature = "slh-dsa"))]
    let group = c.benchmark_group("provider_signing");

    // Use SLH-DSA for signing benchmarks
    #[cfg(feature = "slh-dsa")]
    {
        let provider = LibQSignatureProvider::new().expect("Failed to create provider");
        let algorithm = Algorithm::SlhDsaShake256128fRobust;
        let keypair = provider
            .generate_keypair(algorithm, None)
            .expect("Key generation should succeed");

        let message_sizes = [64, 256, 1024, 4096, 16384];

        for size in message_sizes {
            let message = vec![0u8; size];
            group.bench_with_input(BenchmarkId::new("SLH-DSA", size), &message, |b, msg| {
                b.iter(|| {
                    let signature = provider
                        .sign(algorithm, keypair.secret_key(), msg, None)
                        .expect("Signing should succeed");
                    black_box(signature)
                })
            });
        }
    }

    group.finish();
}

/// Benchmark provider pattern verification across different message sizes
fn benchmark_provider_verification(c: &mut Criterion) {
    #[cfg(feature = "slh-dsa")]
    let mut group = c.benchmark_group("provider_verification");
    #[cfg(not(feature = "slh-dsa"))]
    let group = c.benchmark_group("provider_verification");

    // Use SLH-DSA for verification benchmarks
    #[cfg(feature = "slh-dsa")]
    {
        let provider = LibQSignatureProvider::new().expect("Failed to create provider");
        let algorithm = Algorithm::SlhDsaShake256128fRobust;
        let keypair = provider
            .generate_keypair(algorithm, None)
            .expect("Key generation should succeed");

        let message_sizes = [64, 256, 1024, 4096, 16384];

        for size in message_sizes {
            let message = vec![0u8; size];
            let signature = provider
                .sign(algorithm, keypair.secret_key(), &message, None)
                .expect("Signing should succeed");

            group.bench_with_input(BenchmarkId::new("SLH-DSA", size), &message, |b, msg| {
                b.iter(|| {
                    let is_valid = provider
                        .verify(algorithm, keypair.public_key(), msg, &signature)
                        .expect("Verification should succeed");
                    black_box(is_valid)
                })
            });
        }
    }

    group.finish();
}

/// Benchmark cross-algorithm comparison through provider
fn benchmark_cross_algorithm_comparison(c: &mut Criterion) {
    #[cfg(feature = "slh-dsa")]
    let mut group = c.benchmark_group("cross_algorithm_comparison");
    #[cfg(not(feature = "slh-dsa"))]
    let group = c.benchmark_group("cross_algorithm_comparison");

    // Compare SLH-DSA parameter sets
    #[cfg(feature = "slh-dsa")]
    {
        let provider = LibQSignatureProvider::new().expect("Failed to create provider");
        let message = b"Cross-algorithm comparison benchmark";
        let slh_dsa_algorithms = [
            Algorithm::SlhDsaShake256128fRobust,
            Algorithm::SlhDsaShake256192fRobust,
            Algorithm::SlhDsaShake256256fRobust,
        ];

        for algorithm in slh_dsa_algorithms {
            let keypair = provider
                .generate_keypair(algorithm, None)
                .expect("Key generation should succeed");

            group.bench_function(format!("{:?}_full_workflow", algorithm), |b| {
                b.iter(|| {
                    let signature = provider
                        .sign(algorithm, keypair.secret_key(), message, None)
                        .expect("Signing should succeed");
                    let is_valid = provider
                        .verify(algorithm, keypair.public_key(), message, &signature)
                        .expect("Verification should succeed");
                    black_box((signature, is_valid))
                })
            });
        }
    }

    group.finish();
}

/// Benchmark security validation overhead
fn benchmark_security_validation_overhead(c: &mut Criterion) {
    #[cfg(feature = "slh-dsa")]
    let mut group = c.benchmark_group("security_validation_overhead");
    #[cfg(not(feature = "slh-dsa"))]
    let group = c.benchmark_group("security_validation_overhead");

    #[cfg(feature = "slh-dsa")]
    {
        let provider = LibQSignatureProvider::new().expect("Failed to create provider");
        let algorithm = Algorithm::SlhDsaShake256128fRobust;

        // Benchmark with valid randomness (includes security validation)
        let mut valid_randomness = [0u8; 32];
        for (i, item) in valid_randomness.iter_mut().enumerate() {
            *item = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }

        group.bench_function("with_security_validation", |b| {
            b.iter(|| {
                let keypair = provider
                    .generate_keypair(algorithm, Some(&valid_randomness))
                    .expect("Key generation should succeed");
                black_box(keypair)
            })
        });

        // Benchmark with system RNG (bypasses some validation)
        group.bench_function("with_system_rng", |b| {
            b.iter(|| {
                let keypair = provider
                    .generate_keypair(algorithm, None)
                    .expect("Key generation should succeed");
                black_box(keypair)
            })
        });
    }

    group.finish();
}

/// Benchmark provider error handling performance
fn benchmark_provider_error_handling(c: &mut Criterion) {
    #[cfg(feature = "slh-dsa")]
    let mut group = c.benchmark_group("provider_error_handling");
    #[cfg(not(feature = "slh-dsa"))]
    let group = c.benchmark_group("provider_error_handling");

    #[cfg(feature = "slh-dsa")]
    {
        let provider = LibQSignatureProvider::new().expect("Failed to create provider");
        let algorithm = Algorithm::SlhDsaShake256128fRobust;

        // Benchmark error handling for invalid algorithm
        group.bench_function("invalid_algorithm_error", |b| {
            b.iter(|| {
                let result = provider.generate_keypair(Algorithm::Sha3_256, None);
                black_box(result)
            })
        });

        // Benchmark error handling for invalid key
        let invalid_key = SigSecretKey::new(vec![0; 16]); // Too small
        group.bench_function("invalid_key_error", |b| {
            b.iter(|| {
                let result = provider.sign(algorithm, &invalid_key, b"test", None);
                black_box(result)
            })
        });

        // Benchmark error handling for all-zero randomness
        let zero_randomness = [0u8; 32];
        group.bench_function("zero_randomness_error", |b| {
            b.iter(|| {
                let result = provider.generate_keypair(algorithm, Some(&zero_randomness));
                black_box(result)
            })
        });
    }

    group.finish();
}

/// Benchmark provider memory usage patterns
fn benchmark_provider_memory_usage(c: &mut Criterion) {
    #[cfg(feature = "slh-dsa")]
    let mut group = c.benchmark_group("provider_memory_usage");
    #[cfg(not(feature = "slh-dsa"))]
    let group = c.benchmark_group("provider_memory_usage");

    #[cfg(feature = "slh-dsa")]
    {
        let provider = LibQSignatureProvider::new().expect("Failed to create provider");
        let algorithm = Algorithm::SlhDsaShake256128fRobust;

        // Benchmark key generation memory usage
        group.bench_function("key_generation_memory", |b| {
            b.iter(|| {
                let keypair = provider
                    .generate_keypair(algorithm, None)
                    .expect("Key generation should succeed");
                let public_key_size = keypair.public_key().as_bytes().len();
                let secret_key_size = keypair.secret_key().as_bytes().len();
                black_box((public_key_size, secret_key_size))
            })
        });

        // Benchmark signing memory usage
        let keypair = provider
            .generate_keypair(algorithm, None)
            .expect("Key generation should succeed");
        let message = b"Memory usage benchmark message";

        group.bench_function("signing_memory", |b| {
            b.iter(|| {
                let signature = provider
                    .sign(algorithm, keypair.secret_key(), message, None)
                    .expect("Signing should succeed");
                let signature_size = signature.len();
                black_box(signature_size)
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_provider_key_generation,
    benchmark_provider_signing,
    benchmark_provider_verification,
    benchmark_cross_algorithm_comparison,
    benchmark_security_validation_overhead,
    benchmark_provider_error_handling,
    benchmark_provider_memory_usage
);
criterion_main!(benches);
