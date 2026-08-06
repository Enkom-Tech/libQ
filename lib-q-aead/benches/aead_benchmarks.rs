//! Performance Benchmarks for lib-q-aead
//!
//! This module provides comprehensive performance benchmarks for all AEAD implementations
//! to ensure they meet libQ's performance goals.
//!
//! # Feature gating — read this before trusting a `cargo bench -p lib-q-aead` run
//!
//! `lib-q-aead`'s `default` feature set only enables `Shake256Aead`; `Saturnin`,
//! `DuplexSpongeAead`, `TweakAead`, `RomulusN`/`RomulusM`, and `RoccaS` are all off by default.
//! This bench target has no `required-features` (giving it one would make cargo skip the whole
//! target silently, which is worse), so `create_aead` for those six returns `Err` under
//! default features and this file prints a visible `SKIPPED` line for each — rather than
//! silently only ever measuring SHAKE256, which is what the previous version of this file did
//! (`grep -c "Algorithm::Shake256Aead"` was 7 of 7 `Algorithm::` occurrences at HEAD 62f52a8; no
//! other variant appeared anywhere in the file). To measure the full suite:
//!
//! ```text
//! CARGO_INCREMENTAL=0 cargo bench -p lib-q-aead \
//!     --features saturnin,duplex-sponge-aead,tweak-aead,romulus,rocca-s
//! ```
//!
//! Key/nonce sizes are taken from each algorithm's [`AeadWithMetadata::key_size`] /
//! [`AeadWithMetadata::nonce_size`] at runtime, not hard-coded — `RomulusN`/`RomulusM` use a
//! 16-byte key where the other five use 32, and a fixed 32-byte key (the previous shape of this
//! file) would fail `Aead::encrypt` for those two the moment they are enabled.

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
    AeadWithMetadata,
    Algorithm,
    Nonce,
    create_aead,
};

/// All AEAD algorithms in the registry (`lib_q_aead::registry`'s own list, `Algorithm::Aead`
/// category). Every bench group below loops over this instead of hard-coding `Shake256Aead`.
fn algorithms() -> &'static [Algorithm] {
    &[
        Algorithm::Shake256Aead,
        Algorithm::Saturnin,
        Algorithm::DuplexSpongeAead,
        Algorithm::TweakAead,
        Algorithm::RomulusN,
        Algorithm::RomulusM,
        Algorithm::RoccaS,
    ]
}

/// Create an algorithm's AEAD instance, or print a visible skip notice and return `None`.
/// (`create_aead` returning `Err` for a not-compiled-in algorithm is expected under default
/// features — see the module doc — but it must never be silent.)
fn try_create(algorithm: Algorithm) -> Option<Box<dyn AeadWithMetadata>> {
    match create_aead(algorithm) {
        Ok(aead) => Some(aead),
        Err(_) => {
            eprintln!(
                "SKIPPED {algorithm:?}: feature not enabled — run with \
                 --features saturnin,duplex-sponge-aead,tweak-aead,romulus,rocca-s to include it"
            );
            None
        }
    }
}

/// Build a key/nonce pair sized correctly for `aead` (sizes come from its own metadata, not a
/// hard-coded constant — see the module doc).
fn key_nonce_for(aead: &dyn AeadWithMetadata) -> (AeadKey, Nonce) {
    let key = AeadKey::new((0..aead.key_size() as u8).collect());
    let nonce = Nonce::new((0..aead.nonce_size() as u8).collect());
    (key, nonce)
}

fn associated_data() -> Vec<u8> {
    b"benchmark metadata".to_vec()
}

/// Benchmark encryption operations, across the full algorithm suite.
fn bench_encrypt(c: &mut Criterion) {
    let plaintext = vec![0x42u8; 1024]; // 1 KiB message
    let ad = associated_data();

    let mut group = c.benchmark_group("encrypt");
    for &algorithm in algorithms() {
        let Some(aead) = try_create(algorithm) else {
            continue;
        };
        let (key, nonce) = key_nonce_for(&*aead);
        let name = aead.metadata().name;
        group.bench_function(BenchmarkId::new(name, "1024B"), |b| {
            b.iter(|| {
                let result = aead.encrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&plaintext),
                    Some(black_box(&ad)),
                );
                black_box(result)
            })
        });
    }
    group.finish();
}

/// Benchmark decryption operations, across the full algorithm suite.
fn bench_decrypt(c: &mut Criterion) {
    let plaintext = vec![0x42u8; 1024];
    let ad = associated_data();

    let mut group = c.benchmark_group("decrypt");
    for &algorithm in algorithms() {
        let Some(aead) = try_create(algorithm) else {
            continue;
        };
        let (key, nonce) = key_nonce_for(&*aead);
        let ciphertext = aead
            .encrypt(&key, &nonce, &plaintext, Some(&ad))
            .expect("Encryption failed");
        let name = aead.metadata().name;
        group.bench_function(BenchmarkId::new(name, "1024B"), |b| {
            b.iter(|| {
                let result = aead.decrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&ciphertext),
                    Some(black_box(&ad)),
                );
                black_box(result)
            })
        });
    }
    group.finish();
}

/// Benchmark encrypt-decrypt round trip, across the full algorithm suite.
fn bench_round_trip(c: &mut Criterion) {
    let plaintext = vec![0x42u8; 1024];
    let ad = associated_data();

    let mut group = c.benchmark_group("round_trip");
    for &algorithm in algorithms() {
        let Some(aead) = try_create(algorithm) else {
            continue;
        };
        let (key, nonce) = key_nonce_for(&*aead);
        let name = aead.metadata().name;
        group.bench_function(BenchmarkId::new(name, "1024B"), |b| {
            b.iter(|| {
                let ciphertext = aead
                    .encrypt(
                        black_box(&key),
                        black_box(&nonce),
                        black_box(&plaintext),
                        Some(black_box(&ad)),
                    )
                    .expect("Encryption failed");

                let result = aead.decrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&ciphertext),
                    Some(black_box(&ad)),
                );
                black_box(result)
            })
        });
    }
    group.finish();
}

/// Benchmark with timing protection, across the full algorithm suite.
fn bench_with_timing_protection(c: &mut Criterion) {
    let plaintext = vec![0x42u8; 1024];
    let ad = associated_data();

    let mut group = c.benchmark_group("with_timing_protection");
    for &algorithm in algorithms() {
        let Some(aead) = try_create(algorithm) else {
            continue;
        };
        let (key, nonce) = key_nonce_for(&*aead);
        let name = aead.metadata().name;
        group.bench_function(BenchmarkId::new(name, "1024B"), |b| {
            b.iter(|| {
                let result = protect_timing(|| {
                    aead.encrypt(
                        black_box(&key),
                        black_box(&nonce),
                        black_box(&plaintext),
                        Some(black_box(&ad)),
                    )
                });
                black_box(result)
            })
        });
    }
    group.finish();
}

/// Benchmark different message sizes, across the full algorithm suite.
fn bench_message_sizes(c: &mut Criterion) {
    let ad = associated_data();
    let message_sizes = [64, 256, 1024, 4096, 16384]; // bytes

    let mut group = c.benchmark_group("message_sizes");
    for &algorithm in algorithms() {
        let Some(aead) = try_create(algorithm) else {
            continue;
        };
        let (key, nonce) = key_nonce_for(&*aead);
        let name = aead.metadata().name;
        for size in message_sizes.iter() {
            group.bench_with_input(BenchmarkId::new(name, size), size, |b, &size| {
                let plaintext = vec![0x42u8; size];
                b.iter(|| {
                    let result = aead.encrypt(
                        black_box(&key),
                        black_box(&nonce),
                        black_box(&plaintext),
                        Some(black_box(&ad)),
                    );
                    black_box(result)
                })
            });
        }
    }
    group.finish();
}

/// Benchmark throughput (bytes/sec), across the full algorithm suite.
fn bench_throughput(c: &mut Criterion) {
    let plaintext = vec![0x42u8; 1024];
    let ad = associated_data();

    let mut group = c.benchmark_group("throughput");
    group.throughput(criterion::Throughput::Bytes(plaintext.len() as u64));
    for &algorithm in algorithms() {
        let Some(aead) = try_create(algorithm) else {
            continue;
        };
        let (key, nonce) = key_nonce_for(&*aead);
        let name = aead.metadata().name;
        group.bench_function(BenchmarkId::new(name, "1024B"), |b| {
            b.iter(|| {
                let result = aead.encrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&plaintext),
                    Some(black_box(&ad)),
                );
                black_box(result)
            })
        });
    }
    group.finish();
}

/// Benchmark memory allocation/deallocation cost, across the full algorithm suite.
fn bench_memory_usage(c: &mut Criterion) {
    let plaintext = vec![0x42u8; 1024];
    let ad = associated_data();

    let mut group = c.benchmark_group("memory_usage");
    for &algorithm in algorithms() {
        let Some(aead) = try_create(algorithm) else {
            continue;
        };
        let (key, nonce) = key_nonce_for(&*aead);
        let name = aead.metadata().name;
        group.bench_function(BenchmarkId::new(name, "1024B"), |b| {
            b.iter(|| {
                let ciphertext = aead
                    .encrypt(
                        black_box(&key),
                        black_box(&nonce),
                        black_box(&plaintext),
                        Some(black_box(&ad)),
                    )
                    .expect("Encryption failed");
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
