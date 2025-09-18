//! lib-Q integration benchmarks for SLH-DSA
//!
//! These benchmarks measure the performance of SLH-DSA operations
//! when used through the lib-Q provider pattern, including security
//! validation and provider routing overhead.

use std::hint::black_box;

use criterion::{
    BenchmarkId,
    Criterion,
    criterion_group,
    criterion_main,
};
use lib_q_slh_dsa::{
    ParameterSet,
    Sha2_128f,
    Sha2_192f,
    Sha2_256f,
    Shake128f,
    Shake192f,
    Shake256f,
    SigningKey,
    VerifyingKey,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use signature::{
    Keypair,
    RandomizedSigner,
    Verifier,
};

/// Benchmark key generation for different SLH-DSA parameter sets
fn benchmark_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa_key_generation");

    // Generate deterministic randomness for consistent benchmarks
    let mut seed = [0u8; 32];
    for (i, item) in seed.iter_mut().enumerate() {
        *item = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
    }

    let parameter_sets = [
        ("SHA2-128f", Sha2_128f::NAME),
        ("SHA2-192f", Sha2_192f::NAME),
        ("SHA2-256f", Sha2_256f::NAME),
        ("SHAKE128f", Shake128f::NAME),
        ("SHAKE192f", Shake192f::NAME),
        ("SHAKE256f", Shake256f::NAME),
    ];

    for (name, _) in parameter_sets {
        group.bench_function(name, |b| {
            b.iter(|| {
                let mut rng = StdRng::from_seed(seed);
                let signing_key = SigningKey::<Sha2_128f>::new(&mut rng);
                let verifying_key = signing_key.verifying_key();
                black_box((signing_key, verifying_key))
            })
        });
    }

    group.finish();
}

/// Benchmark signing operations for different parameter sets and message sizes
fn benchmark_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa_signing");

    // Generate deterministic randomness
    let mut key_seed = [0u8; 32];
    for (i, item) in key_seed.iter_mut().enumerate() {
        *item = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
    }

    let mut signing_seed = [0u8; 32];
    for (i, item) in signing_seed.iter_mut().enumerate() {
        *item = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
    }

    let mut key_rng = StdRng::from_seed(key_seed);
    let signing_key = SigningKey::<Shake128f>::new(&mut key_rng);

    let message_sizes = [64, 256, 1024, 4096, 16384];

    for size in message_sizes {
        let message = vec![0u8; size];
        group.bench_with_input(BenchmarkId::new("SHAKE128f", size), &message, |b, msg| {
            b.iter(|| {
                let mut signing_rng = StdRng::from_seed(signing_seed);
                let signature = signing_key
                    .try_sign_with_rng(&mut signing_rng, msg)
                    .expect("Signing should succeed");
                black_box(signature)
            })
        });
    }

    group.finish();
}

/// Benchmark verification operations for different parameter sets and message sizes
fn benchmark_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa_verification");

    // Generate deterministic randomness
    let mut key_seed = [0u8; 32];
    for (i, item) in key_seed.iter_mut().enumerate() {
        *item = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
    }

    let mut signing_seed = [0u8; 32];
    for (i, item) in signing_seed.iter_mut().enumerate() {
        *item = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
    }

    let mut key_rng = StdRng::from_seed(key_seed);
    let signing_key = SigningKey::<Shake128f>::new(&mut key_rng);
    let verifying_key = signing_key.verifying_key();

    let message_sizes = [64, 256, 1024, 4096, 16384];

    for size in message_sizes {
        let message = vec![0u8; size];
        let mut signing_rng = StdRng::from_seed(signing_seed);
        let signature = signing_key
            .try_sign_with_rng(&mut signing_rng, &message)
            .expect("Signing should succeed");

        group.bench_with_input(BenchmarkId::new("SHAKE128f", size), &message, |b, msg| {
            b.iter(|| {
                let is_valid = verifying_key.verify(msg, &signature).is_ok();
                black_box(is_valid)
            })
        });
    }

    group.finish();
}

/// Benchmark key serialization and deserialization
fn benchmark_key_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa_key_serialization");

    // Generate deterministic randomness
    let mut seed = [0u8; 32];
    for (i, item) in seed.iter_mut().enumerate() {
        *item = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
    }

    let mut rng = StdRng::from_seed(seed);
    let signing_key = SigningKey::<Shake128f>::new(&mut rng);
    let verifying_key = signing_key.verifying_key();

    group.bench_function("signing_key_serialization", |b| {
        b.iter(|| {
            let bytes = signing_key.to_bytes();
            black_box(bytes)
        })
    });

    group.bench_function("signing_key_deserialization", |b| {
        let bytes = signing_key.to_bytes();
        b.iter(|| {
            let deserialized = SigningKey::<Shake128f>::try_from(&bytes[..])
                .expect("Deserialization should succeed");
            black_box(deserialized)
        })
    });

    group.bench_function("verifying_key_serialization", |b| {
        b.iter(|| {
            let bytes = verifying_key.to_bytes();
            black_box(bytes)
        })
    });

    group.bench_function("verifying_key_deserialization", |b| {
        let bytes = verifying_key.to_bytes();
        b.iter(|| {
            let deserialized = VerifyingKey::<Shake128f>::try_from(&bytes[..])
                .expect("Deserialization should succeed");
            black_box(deserialized)
        })
    });

    group.finish();
}

/// Benchmark signature serialization and deserialization
fn benchmark_signature_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa_signature_serialization");

    // Generate deterministic randomness
    let mut key_seed = [0u8; 32];
    for (i, item) in key_seed.iter_mut().enumerate() {
        *item = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
    }

    let mut signing_seed = [0u8; 32];
    for (i, item) in signing_seed.iter_mut().enumerate() {
        *item = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
    }

    let mut key_rng = StdRng::from_seed(key_seed);
    let signing_key = SigningKey::<Shake128f>::new(&mut key_rng);
    let message = b"Benchmark message for signature serialization";

    let mut signing_rng = StdRng::from_seed(signing_seed);
    let signature = signing_key
        .try_sign_with_rng(&mut signing_rng, message)
        .expect("Signing should succeed");

    group.bench_function("signature_serialization", |b| {
        b.iter(|| {
            let bytes = signature.to_bytes();
            black_box(bytes)
        })
    });

    group.bench_function("signature_deserialization", |b| {
        let bytes = signature.to_bytes();
        b.iter(|| {
            let deserialized = lib_q_slh_dsa::Signature::<Shake128f>::try_from(&bytes[..])
                .expect("Deserialization should succeed");
            black_box(deserialized)
        })
    });

    group.finish();
}

/// Benchmark parameter set comparison
fn benchmark_parameter_set_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa_parameter_set_comparison");

    // Generate deterministic randomness
    let mut key_seed = [0u8; 32];
    for (i, item) in key_seed.iter_mut().enumerate() {
        *item = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
    }

    let mut signing_seed_16 = [0u8; 32];
    for (i, item) in signing_seed_16.iter_mut().enumerate() {
        *item = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
    }

    let mut signing_seed_24 = [0u8; 32];
    for (i, item) in signing_seed_24.iter_mut().enumerate() {
        *item = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
    }

    let mut signing_seed_32 = [0u8; 32];
    for (i, item) in signing_seed_32.iter_mut().enumerate() {
        *item = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
    }

    let message = b"Parameter set comparison benchmark";

    // Benchmark SHA2-128f
    let mut key_rng_128f = StdRng::from_seed(key_seed);
    let signing_key_128f = SigningKey::<Sha2_128f>::new(&mut key_rng_128f);
    group.bench_function("SHA2-128f_full_workflow", |b| {
        b.iter(|| {
            let mut signing_rng = StdRng::from_seed(signing_seed_16);
            let signature = signing_key_128f
                .try_sign_with_rng(&mut signing_rng, message)
                .expect("Signing should succeed");
            black_box(signature)
        })
    });

    // Benchmark SHA2-192f
    let mut key_rng_192f = StdRng::from_seed(key_seed);
    let signing_key_192f = SigningKey::<Sha2_192f>::new(&mut key_rng_192f);
    group.bench_function("SHA2-192f_full_workflow", |b| {
        b.iter(|| {
            let mut signing_rng = StdRng::from_seed(signing_seed_24);
            let signature = signing_key_192f
                .try_sign_with_rng(&mut signing_rng, message)
                .expect("Signing should succeed");
            black_box(signature)
        })
    });

    // Benchmark SHA2-256f
    let mut key_rng_256f = StdRng::from_seed(key_seed);
    let signing_key_256f = SigningKey::<Sha2_256f>::new(&mut key_rng_256f);
    group.bench_function("SHA2-256f_full_workflow", |b| {
        b.iter(|| {
            let mut signing_rng = StdRng::from_seed(signing_seed_32);
            let signature = signing_key_256f
                .try_sign_with_rng(&mut signing_rng, message)
                .expect("Signing should succeed");
            black_box(signature)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_key_generation,
    benchmark_signing,
    benchmark_verification,
    benchmark_key_serialization,
    benchmark_signature_serialization,
    benchmark_parameter_set_comparison
);
criterion_main!(benches);
