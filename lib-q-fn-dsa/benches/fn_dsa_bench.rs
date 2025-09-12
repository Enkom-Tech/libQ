//! FN-DSA Performance Benchmarks
//!
//! This benchmark suite measures the performance characteristics of FN-DSA
//! implementations, including key generation, signing, and verification.

use std::hint::black_box;

use criterion::{
    BenchmarkId,
    Criterion,
    criterion_group,
    criterion_main,
};
use lib_q_fn_dsa::*;

fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation");

    // Benchmark FN-DSA Level 1 key generation
    group.bench_function("fn_dsa_512", |b| {
        let fn_dsa = FnDsa512::new();
        b.iter(|| black_box(fn_dsa.generate_keypair().unwrap()))
    });

    // Benchmark FN-DSA Level 5 key generation
    group.bench_function("fn_dsa_1024", |b| {
        let fn_dsa = FnDsa1024::new();
        b.iter(|| black_box(fn_dsa.generate_keypair().unwrap()))
    });

    group.finish();
}

fn bench_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("signing");

    // Prepare test data
    let fn_dsa512 = FnDsa512::new();
    let fn_dsa1024 = FnDsa1024::new();

    let keypair512 = fn_dsa512.generate_keypair().unwrap();
    let keypair1024 = fn_dsa1024.generate_keypair().unwrap();

    let message = b"Benchmark test message for FN-DSA signing performance";

    // Benchmark FN-DSA Level 1 signing
    group.bench_function("fn_dsa_512", |b| {
        b.iter(|| {
            black_box(
                fn_dsa512
                    .sign(&keypair512.secret_key, black_box(message))
                    .unwrap(),
            )
        })
    });

    // Benchmark FN-DSA Level 5 signing
    group.bench_function("fn_dsa_1024", |b| {
        b.iter(|| {
            black_box(
                fn_dsa1024
                    .sign(&keypair1024.secret_key, black_box(message))
                    .unwrap(),
            )
        })
    });

    group.finish();
}

fn bench_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification");

    // Prepare test data
    let fn_dsa512 = FnDsa512::new();
    let fn_dsa1024 = FnDsa1024::new();

    let keypair512 = fn_dsa512.generate_keypair().unwrap();
    let keypair1024 = fn_dsa1024.generate_keypair().unwrap();

    let message = b"Benchmark test message for FN-DSA verification performance";

    let signature512 = fn_dsa512.sign(&keypair512.secret_key, message).unwrap();
    let signature1024 = fn_dsa1024.sign(&keypair1024.secret_key, message).unwrap();

    // Benchmark FN-DSA Level 1 verification
    group.bench_function("fn_dsa_512", |b| {
        b.iter(|| {
            black_box(
                fn_dsa512
                    .verify(&keypair512.public_key, black_box(message), &signature512)
                    .unwrap(),
            )
        })
    });

    // Benchmark FN-DSA Level 5 verification
    group.bench_function("fn_dsa_1024", |b| {
        b.iter(|| {
            black_box(
                fn_dsa1024
                    .verify(&keypair1024.public_key, black_box(message), &signature1024)
                    .unwrap(),
            )
        })
    });

    group.finish();
}

fn bench_different_message_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_sizes");

    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa.generate_keypair().unwrap();

    let message_sizes = [1, 64, 256, 1024, 4096, 16384];

    for size in message_sizes.iter() {
        let message = vec![0u8; *size];
        let signature = fn_dsa.sign(&keypair.secret_key, &message).unwrap();

        group.bench_with_input(BenchmarkId::new("signing", size), size, |b, &size| {
            let message = vec![0u8; size];
            b.iter(|| {
                black_box(
                    fn_dsa
                        .sign(&keypair.secret_key, black_box(&message))
                        .unwrap(),
                )
            })
        });

        group.bench_with_input(BenchmarkId::new("verification", size), size, |b, &size| {
            let message = vec![0u8; size];
            b.iter(|| {
                black_box(
                    fn_dsa
                        .verify(&keypair.public_key, black_box(&message), &signature)
                        .unwrap(),
                )
            })
        });
    }

    group.finish();
}

fn bench_security_level_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("security_level_comparison");

    let fn_dsa512 = FnDsa512::new();
    let fn_dsa1024 = FnDsa1024::new();

    let keypair512 = fn_dsa512.generate_keypair().unwrap();
    let keypair1024 = fn_dsa1024.generate_keypair().unwrap();

    let message = b"Security level comparison benchmark";

    // Compare key generation performance
    group.bench_function("keygen_512", |b| {
        b.iter(|| black_box(fn_dsa512.generate_keypair().unwrap()))
    });

    group.bench_function("keygen_1024", |b| {
        b.iter(|| black_box(fn_dsa1024.generate_keypair().unwrap()))
    });

    // Compare signing performance
    group.bench_function("sign_512", |b| {
        b.iter(|| {
            black_box(
                fn_dsa512
                    .sign(&keypair512.secret_key, black_box(message))
                    .unwrap(),
            )
        })
    });

    group.bench_function("sign_1024", |b| {
        b.iter(|| {
            black_box(
                fn_dsa1024
                    .sign(&keypair1024.secret_key, black_box(message))
                    .unwrap(),
            )
        })
    });

    // Compare verification performance
    let sig512 = fn_dsa512.sign(&keypair512.secret_key, message).unwrap();
    let sig1024 = fn_dsa1024.sign(&keypair1024.secret_key, message).unwrap();

    group.bench_function("verify_512", |b| {
        b.iter(|| {
            black_box(
                fn_dsa512
                    .verify(&keypair512.public_key, black_box(message), &sig512)
                    .unwrap(),
            )
        })
    });

    group.bench_function("verify_1024", |b| {
        b.iter(|| {
            black_box(
                fn_dsa1024
                    .verify(&keypair1024.public_key, black_box(message), &sig1024)
                    .unwrap(),
            )
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_signing,
    bench_verification,
    bench_different_message_sizes,
    bench_security_level_comparison
);

criterion_main!(benches);
