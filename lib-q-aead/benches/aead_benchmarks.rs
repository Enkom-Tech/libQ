//! Performance Benchmarks for lib-q-aead
//!
//! This module provides comprehensive performance benchmarks for all AEAD implementations
//! to ensure they meet libQ's performance goals.

use std::hint::black_box;

use criterion::{
    BenchmarkId,
    Criterion,
    criterion_group,
    criterion_main,
};
use lib_q_aead::security::timing::protect_timing;
use lib_q_aead::{
    AeadKey,
    Algorithm,
    Nonce,
    create_aead,
};

/// Generate test data for benchmarks
fn generate_test_data() -> (AeadKey, Nonce, Vec<u8>, Vec<u8>) {
    let key_data = vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x00,
    ];

    let nonce_data = vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];

    let key = AeadKey::new(key_data);
    let nonce = Nonce::new(nonce_data);

    // Test with different message sizes
    let plaintext = vec![0x42u8; 1024]; // 1KB message
    let associated_data = b"benchmark metadata";

    (key, nonce, plaintext, associated_data.to_vec())
}

/// Benchmark encryption operations
fn bench_encrypt(c: &mut Criterion) {
    let (key, nonce, plaintext, associated_data) = generate_test_data();

    let mut group = c.benchmark_group("encrypt");

    // SHAKE256 AEAD
    if let Ok(aead) = create_aead(Algorithm::Shake256Aead) {
        group.bench_function("shake256", |b| {
            b.iter(|| {
                let result = aead.encrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&plaintext),
                    Some(black_box(&associated_data)),
                );
                black_box(result)
            })
        });
    }

    // Saturnin AEAD
    if let Ok(aead) = create_aead(Algorithm::KemAead) {
        group.bench_function("saturnin", |b| {
            b.iter(|| {
                let result = aead.encrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&plaintext),
                    Some(black_box(&associated_data)),
                );
                black_box(result)
            })
        });
    }

    group.finish();
}

/// Benchmark decryption operations
fn bench_decrypt(c: &mut Criterion) {
    let (key, nonce, plaintext, associated_data) = generate_test_data();

    let mut group = c.benchmark_group("decrypt");

    // SHAKE256 AEAD
    if let Ok(aead) = create_aead(Algorithm::Shake256Aead) {
        let ciphertext = aead
            .encrypt(&key, &nonce, &plaintext, Some(&associated_data))
            .expect("Encryption failed");

        group.bench_function("shake256", |b| {
            b.iter(|| {
                let result = aead.decrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&ciphertext),
                    Some(black_box(&associated_data)),
                );
                black_box(result)
            })
        });
    }

    // Saturnin AEAD
    if let Ok(aead) = create_aead(Algorithm::KemAead) {
        let ciphertext = aead
            .encrypt(&key, &nonce, &plaintext, Some(&associated_data))
            .expect("Encryption failed");

        group.bench_function("saturnin", |b| {
            b.iter(|| {
                let result = aead.decrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&ciphertext),
                    Some(black_box(&associated_data)),
                );
                black_box(result)
            })
        });
    }

    group.finish();
}

/// Benchmark encrypt-decrypt round trip
fn bench_round_trip(c: &mut Criterion) {
    let (key, nonce, plaintext, associated_data) = generate_test_data();

    let mut group = c.benchmark_group("round_trip");

    // SHAKE256 AEAD
    if let Ok(aead) = create_aead(Algorithm::Shake256Aead) {
        group.bench_function("shake256", |b| {
            b.iter(|| {
                let ciphertext = aead
                    .encrypt(
                        black_box(&key),
                        black_box(&nonce),
                        black_box(&plaintext),
                        Some(black_box(&associated_data)),
                    )
                    .expect("Encryption failed");

                let result = aead.decrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&ciphertext),
                    Some(black_box(&associated_data)),
                );
                black_box(result)
            })
        });
    }

    // Saturnin AEAD
    if let Ok(aead) = create_aead(Algorithm::KemAead) {
        group.bench_function("saturnin", |b| {
            b.iter(|| {
                let ciphertext = aead
                    .encrypt(
                        black_box(&key),
                        black_box(&nonce),
                        black_box(&plaintext),
                        Some(black_box(&associated_data)),
                    )
                    .expect("Encryption failed");

                let result = aead.decrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&ciphertext),
                    Some(black_box(&associated_data)),
                );
                black_box(result)
            })
        });
    }

    group.finish();
}

/// Benchmark with timing protection
fn bench_with_timing_protection(c: &mut Criterion) {
    let (key, nonce, plaintext, associated_data) = generate_test_data();

    let mut group = c.benchmark_group("with_timing_protection");

    // SHAKE256 AEAD with timing protection
    if let Ok(aead) = create_aead(Algorithm::Shake256Aead) {
        group.bench_function("shake256", |b| {
            b.iter(|| {
                let result = protect_timing(|| {
                    aead.encrypt(
                        black_box(&key),
                        black_box(&nonce),
                        black_box(&plaintext),
                        Some(black_box(&associated_data)),
                    )
                });
                black_box(result)
            })
        });
    }

    // Saturnin AEAD with timing protection
    if let Ok(aead) = create_aead(Algorithm::KemAead) {
        group.bench_function("saturnin", |b| {
            b.iter(|| {
                let result = protect_timing(|| {
                    aead.encrypt(
                        black_box(&key),
                        black_box(&nonce),
                        black_box(&plaintext),
                        Some(black_box(&associated_data)),
                    )
                });
                black_box(result)
            })
        });
    }

    group.finish();
}

/// Benchmark different message sizes
fn bench_message_sizes(c: &mut Criterion) {
    let (key, nonce, _, associated_data) = generate_test_data();

    let message_sizes = [64, 256, 1024, 4096, 16384]; // bytes

    let mut group = c.benchmark_group("message_sizes");

    for size in message_sizes.iter() {
        let _plaintext = vec![0x42u8; *size];

        if let Ok(aead) = create_aead(Algorithm::Shake256Aead) {
            group.bench_with_input(BenchmarkId::new("shake256", size), size, |b, &size| {
                let plaintext = vec![0x42u8; size];
                b.iter(|| {
                    let result = aead.encrypt(
                        black_box(&key),
                        black_box(&nonce),
                        black_box(&plaintext),
                        Some(black_box(&associated_data)),
                    );
                    black_box(result)
                })
            });
        }
    }

    group.finish();
}

/// Benchmark throughput (operations per second)
fn bench_throughput(c: &mut Criterion) {
    let (key, nonce, plaintext, associated_data) = generate_test_data();

    let mut group = c.benchmark_group("throughput");
    group.throughput(criterion::Throughput::Bytes(plaintext.len() as u64));

    if let Ok(aead) = create_aead(Algorithm::Shake256Aead) {
        group.bench_function("shake256", |b| {
            b.iter(|| {
                let result = aead.encrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&plaintext),
                    Some(black_box(&associated_data)),
                );
                black_box(result)
            })
        });
    }

    if let Ok(aead) = create_aead(Algorithm::KemAead) {
        group.bench_function("saturnin", |b| {
            b.iter(|| {
                let result = aead.encrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&plaintext),
                    Some(black_box(&associated_data)),
                );
                black_box(result)
            })
        });
    }

    group.finish();
}

/// Benchmark memory usage
fn bench_memory_usage(c: &mut Criterion) {
    let (key, nonce, plaintext, associated_data) = generate_test_data();

    let mut group = c.benchmark_group("memory_usage");

    if let Ok(aead) = create_aead(Algorithm::Shake256Aead) {
        group.bench_function("shake256", |b| {
            b.iter(|| {
                // Measure memory allocation
                let ciphertext = aead
                    .encrypt(
                        black_box(&key),
                        black_box(&nonce),
                        black_box(&plaintext),
                        Some(black_box(&associated_data)),
                    )
                    .expect("Encryption failed");

                // Measure memory deallocation
                drop(ciphertext);
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_encrypt,
    bench_decrypt,
    bench_round_trip,
    bench_with_timing_protection,
    bench_message_sizes,
    bench_throughput,
    bench_memory_usage
);

criterion_main!(benches);
