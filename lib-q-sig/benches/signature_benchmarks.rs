//! Performance benchmarks for lib-q-sig signature operations
//!
//! This module provides comprehensive benchmarks for:
//! - Key generation performance
//! - Signing performance
//! - Verification performance
//! - Memory usage patterns
//! - Algorithm comparison

use std::hint::black_box;

use criterion::{
    BenchmarkId,
    Criterion,
    criterion_group,
    criterion_main,
};
use lib_q_core::{
    Algorithm,
    Signature,
    SignatureOperations,
};
#[cfg(feature = "fn-dsa")]
use lib_q_fn_dsa::{
    FnDsa512,
    FnDsa1024,
};
use lib_q_sig::LibQSignatureProvider;
use lib_q_sig::ml_dsa::MlDsa;

/// Benchmark key generation for different algorithms
fn benchmark_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation");

    // ML-DSA benchmarks
    #[cfg(feature = "ml-dsa")]
    {
        group.bench_function("ML-DSA-44", |b| {
            let ml_dsa = MlDsa::ml_dsa_44();
            b.iter(|| black_box(ml_dsa.generate_keypair().unwrap()))
        });

        group.bench_function("ML-DSA-65", |b| {
            let ml_dsa = MlDsa::ml_dsa_65();
            b.iter(|| black_box(ml_dsa.generate_keypair().unwrap()))
        });

        group.bench_function("ML-DSA-87", |b| {
            let ml_dsa = MlDsa::ml_dsa_87();
            b.iter(|| black_box(ml_dsa.generate_keypair().unwrap()))
        });
    }

    // FN-DSA benchmarks
    #[cfg(feature = "fn-dsa")]
    {
        group.bench_function("FN-DSA-512", |b| {
            let fn_dsa = FnDsa512::new();
            b.iter(|| black_box(fn_dsa.generate_keypair().unwrap()))
        });

        group.bench_function("FN-DSA-1024", |b| {
            let fn_dsa = FnDsa1024::new();
            b.iter(|| black_box(fn_dsa.generate_keypair().unwrap()))
        });
    }

    group.finish();
}

/// Benchmark signing operations for different algorithms and message sizes
fn benchmark_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("signing");

    // Test different message sizes
    let message_sizes = vec![
        ("empty", b"".as_slice()),
        ("short", b"Hello, lib-Q!".as_slice()),
        ("medium", b"The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.".as_slice()),
        ("long", &[0u8; 1024]),
        ("very_long", &[0u8; 10240]),
    ];

    // ML-DSA signing benchmarks
    #[cfg(feature = "ml-dsa")]
    {
        let ml_dsa = MlDsa::ml_dsa_65();
        let keypair = ml_dsa.generate_keypair().unwrap();

        for (size_name, message) in message_sizes.iter() {
            group.bench_with_input(
                BenchmarkId::new("ML-DSA-65", size_name),
                message,
                |b, message| {
                    b.iter(|| black_box(ml_dsa.sign(keypair.secret_key(), *message).unwrap()))
                },
            );
        }
    }

    // FN-DSA signing benchmarks
    #[cfg(feature = "fn-dsa")]
    {
        let fn_dsa = FnDsa512::new();
        let keypair = fn_dsa.generate_keypair().unwrap();

        for (size_name, message) in message_sizes.iter() {
            group.bench_with_input(
                BenchmarkId::new("FN-DSA-512", size_name),
                message,
                |b, message| {
                    b.iter(|| black_box(fn_dsa.sign(keypair.secret_key(), *message).unwrap()))
                },
            );
        }
    }

    group.finish();
}

/// Benchmark verification operations for different algorithms
fn benchmark_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification");

    // Test different message sizes
    let message_sizes = vec![
        ("empty", b"".as_slice()),
        ("short", b"Hello, lib-Q!".as_slice()),
        ("medium", b"The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.".as_slice()),
        ("long", &[0u8; 1024]),
        ("very_long", &[0u8; 10240]),
    ];

    // ML-DSA verification benchmarks
    #[cfg(feature = "ml-dsa")]
    {
        let ml_dsa = MlDsa::ml_dsa_65();
        let keypair = ml_dsa.generate_keypair().unwrap();

        for (size_name, message) in message_sizes.iter() {
            let signature = ml_dsa.sign(keypair.secret_key(), message).unwrap();

            group.bench_with_input(
                BenchmarkId::new("ML-DSA-65", size_name),
                message,
                |b, message| {
                    b.iter(|| {
                        black_box(
                            ml_dsa
                                .verify(keypair.public_key(), *message, &signature)
                                .unwrap(),
                        )
                    })
                },
            );
        }
    }

    // FN-DSA verification benchmarks
    #[cfg(feature = "fn-dsa")]
    {
        let fn_dsa = FnDsa512::new();
        let keypair = fn_dsa.generate_keypair().unwrap();

        for (size_name, message) in message_sizes.iter() {
            let signature = fn_dsa.sign(keypair.secret_key(), message).unwrap();

            group.bench_with_input(
                BenchmarkId::new("FN-DSA-512", size_name),
                message,
                |b, message| {
                    b.iter(|| {
                        black_box(
                            fn_dsa
                                .verify(keypair.public_key(), *message, &signature)
                                .unwrap(),
                        )
                    })
                },
            );
        }
    }

    group.finish();
}

/// Benchmark provider operations
fn benchmark_provider_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("provider_operations");

    let provider = LibQSignatureProvider::new().unwrap();
    let message = b"Provider benchmark message";

    // ML-DSA provider benchmarks
    #[cfg(feature = "ml-dsa")]
    {
        group.bench_function("Provider-ML-DSA-65-KeyGen", |b| {
            b.iter(|| black_box(provider.generate_keypair(Algorithm::MlDsa65, None).unwrap()))
        });

        let keypair = provider.generate_keypair(Algorithm::MlDsa65, None).unwrap();

        group.bench_function("Provider-ML-DSA-65-Sign", |b| {
            b.iter(|| {
                black_box(
                    provider
                        .sign(Algorithm::MlDsa65, keypair.secret_key(), message, None)
                        .unwrap(),
                )
            })
        });

        let signature = provider
            .sign(Algorithm::MlDsa65, keypair.secret_key(), message, None)
            .unwrap();

        group.bench_function("Provider-ML-DSA-65-Verify", |b| {
            b.iter(|| {
                black_box(
                    provider
                        .verify(
                            Algorithm::MlDsa65,
                            keypair.public_key(),
                            message,
                            &signature,
                        )
                        .unwrap(),
                )
            })
        });
    }

    // FN-DSA provider benchmarks
    #[cfg(feature = "fn-dsa")]
    {
        group.bench_function("Provider-FN-DSA-512-KeyGen", |b| {
            b.iter(|| {
                black_box(
                    provider
                        .generate_keypair(Algorithm::FnDsa512, None)
                        .unwrap(),
                )
            })
        });

        let keypair = provider
            .generate_keypair(Algorithm::FnDsa512, None)
            .unwrap();

        group.bench_function("Provider-FN-DSA-512-Sign", |b| {
            b.iter(|| {
                black_box(
                    provider
                        .sign(Algorithm::FnDsa512, keypair.secret_key(), message, None)
                        .unwrap(),
                )
            })
        });

        let signature = provider
            .sign(Algorithm::FnDsa512, keypair.secret_key(), message, None)
            .unwrap();

        group.bench_function("Provider-FN-DSA-512-Verify", |b| {
            b.iter(|| {
                black_box(
                    provider
                        .verify(
                            Algorithm::FnDsa512,
                            keypair.public_key(),
                            message,
                            &signature,
                        )
                        .unwrap(),
                )
            })
        });
    }

    group.finish();
}

/// Benchmark algorithm comparison
fn benchmark_algorithm_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("algorithm_comparison");

    let message = b"Algorithm comparison benchmark message";

    // Compare key generation
    #[cfg(feature = "ml-dsa")]
    {
        let ml_dsa = MlDsa::ml_dsa_65();
        group.bench_function("ML-DSA-65-KeyGen", |b| {
            b.iter(|| black_box(ml_dsa.generate_keypair().unwrap()))
        });
    }

    #[cfg(feature = "fn-dsa")]
    {
        let fn_dsa = FnDsa512::new();
        group.bench_function("FN-DSA-512-KeyGen", |b| {
            b.iter(|| black_box(fn_dsa.generate_keypair().unwrap()))
        });
    }

    // Compare signing
    #[cfg(feature = "ml-dsa")]
    {
        let ml_dsa = MlDsa::ml_dsa_65();
        let keypair = ml_dsa.generate_keypair().unwrap();
        group.bench_function("ML-DSA-65-Sign", |b| {
            b.iter(|| black_box(ml_dsa.sign(keypair.secret_key(), message).unwrap()))
        });
    }

    #[cfg(feature = "fn-dsa")]
    {
        let fn_dsa = FnDsa512::new();
        let keypair = fn_dsa.generate_keypair().unwrap();
        group.bench_function("FN-DSA-512-Sign", |b| {
            b.iter(|| black_box(fn_dsa.sign(keypair.secret_key(), message).unwrap()))
        });
    }

    // Compare verification
    #[cfg(feature = "ml-dsa")]
    {
        let ml_dsa = MlDsa::ml_dsa_65();
        let keypair = ml_dsa.generate_keypair().unwrap();
        let signature = ml_dsa.sign(keypair.secret_key(), message).unwrap();
        group.bench_function("ML-DSA-65-Verify", |b| {
            b.iter(|| {
                black_box(
                    ml_dsa
                        .verify(keypair.public_key(), message, &signature)
                        .unwrap(),
                )
            })
        });
    }

    #[cfg(feature = "fn-dsa")]
    {
        let fn_dsa = FnDsa512::new();
        let keypair = fn_dsa.generate_keypair().unwrap();
        let signature = fn_dsa.sign(keypair.secret_key(), message).unwrap();
        group.bench_function("FN-DSA-512-Verify", |b| {
            b.iter(|| {
                black_box(
                    fn_dsa
                        .verify(keypair.public_key(), message, &signature)
                        .unwrap(),
                )
            })
        });
    }

    group.finish();
}

/// Benchmark memory usage patterns
fn benchmark_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage");

    // Benchmark key sizes
    #[cfg(feature = "ml-dsa")]
    {
        let ml_dsa_44 = MlDsa::ml_dsa_44();
        let ml_dsa_65 = MlDsa::ml_dsa_65();
        let ml_dsa_87 = MlDsa::ml_dsa_87();

        group.bench_function("ML-DSA-44-KeySize", |b| {
            b.iter(|| {
                let keypair = ml_dsa_44.generate_keypair().unwrap();
                black_box(
                    keypair.public_key().as_bytes().len() + keypair.secret_key().as_bytes().len(),
                )
            })
        });

        group.bench_function("ML-DSA-65-KeySize", |b| {
            b.iter(|| {
                let keypair = ml_dsa_65.generate_keypair().unwrap();
                black_box(
                    keypair.public_key().as_bytes().len() + keypair.secret_key().as_bytes().len(),
                )
            })
        });

        group.bench_function("ML-DSA-87-KeySize", |b| {
            b.iter(|| {
                let keypair = ml_dsa_87.generate_keypair().unwrap();
                black_box(
                    keypair.public_key().as_bytes().len() + keypair.secret_key().as_bytes().len(),
                )
            })
        });
    }

    // Benchmark signature sizes
    #[cfg(feature = "ml-dsa")]
    {
        let ml_dsa_65 = MlDsa::ml_dsa_65();
        let keypair = ml_dsa_65.generate_keypair().unwrap();
        let message = b"Memory usage benchmark";

        group.bench_function("ML-DSA-65-SignatureSize", |b| {
            b.iter(|| {
                let signature = ml_dsa_65.sign(keypair.secret_key(), message).unwrap();
                black_box(signature.len())
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_key_generation,
    benchmark_signing,
    benchmark_verification,
    benchmark_provider_operations,
    benchmark_algorithm_comparison,
    benchmark_memory_usage
);

criterion_main!(benches);
