#[allow(unused_imports)]
use std::hint::black_box;

use criterion::{
    Criterion,
    criterion_group,
    criterion_main,
};
// These imports are used within conditional compilation blocks
#[allow(unused_imports)]
use libq::{
    Algorithm,
    KemContext,
    SignatureContext,
};

fn bench_key_generation(c: &mut Criterion) {
    let group = c.benchmark_group("key_generation");

    #[cfg(feature = "ml-dsa")]
    {
        let context = SignatureContext::new(Algorithm::MlDsa65).unwrap();

        group.bench_function("ml-dsa-65", |b| {
            b.iter(|| {
                let _keypair = context.generate_keypair().unwrap();
            });
        });
    }

    #[cfg(feature = "ml-kem")]
    {
        let context = KemContext::new(Algorithm::MlKem768).unwrap();

        group.bench_function("ml-kem-768", |b| {
            b.iter(|| {
                let _keypair = context.generate_keypair().unwrap();
            });
        });
    }

    group.finish();
}

fn bench_signing(c: &mut Criterion) {
    let group = c.benchmark_group("signing");

    #[cfg(feature = "ml-dsa")]
    {
        let context = SignatureContext::new(Algorithm::MlDsa65).unwrap();
        let keypair = context.generate_keypair().unwrap();
        let message = black_box(b"Hello, world! This is a test message for benchmarking.");

        group.bench_function("ml-dsa-65", |b| {
            b.iter(|| {
                let _signature = context.sign(&keypair.secret_key, message).unwrap();
            });
        });
    }

    group.finish();
}

fn bench_verification(c: &mut Criterion) {
    let group = c.benchmark_group("verification");

    #[cfg(feature = "ml-dsa")]
    {
        let context = SignatureContext::new(Algorithm::MlDsa65).unwrap();
        let keypair = context.generate_keypair().unwrap();
        let message = black_box(b"Hello, world! This is a test message for benchmarking.");
        let signature = context.sign(&keypair.secret_key, message).unwrap();

        group.bench_function("ml-dsa-65", |b| {
            b.iter(|| {
                let _is_valid = context
                    .verify(&keypair.public_key, message, &signature)
                    .unwrap();
            });
        });
    }

    group.finish();
}

fn bench_encapsulation(c: &mut Criterion) {
    let group = c.benchmark_group("encapsulation");

    #[cfg(feature = "ml-kem")]
    {
        let context = KemContext::new(Algorithm::MlKem768).unwrap();
        let public_key = context.generate_keypair().unwrap().public_key;

        group.bench_function("ml-kem-768", |b| {
            b.iter(|| {
                let _ciphertext = context.encapsulate(&public_key).unwrap();
            });
        });
    }

    group.finish();
}

fn bench_decapsulation(c: &mut Criterion) {
    let group = c.benchmark_group("decapsulation");

    #[cfg(feature = "ml-kem")]
    {
        let context = KemContext::new(Algorithm::MlKem768).unwrap();
        let keypair = context.generate_keypair().unwrap();
        let (ciphertext, _shared_secret) = context.encapsulate(&keypair.public_key).unwrap();

        group.bench_function("ml-kem-768", |b| {
            b.iter(|| {
                let _shared_secret = context
                    .decapsulate(&keypair.secret_key, &ciphertext)
                    .unwrap();
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_signing,
    bench_verification,
    bench_encapsulation,
    bench_decapsulation
);
criterion_main!(benches);
