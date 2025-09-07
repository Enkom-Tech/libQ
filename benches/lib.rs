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
    LibQCryptoProvider,
    SignatureContext,
};

fn bench_key_generation(c: &mut Criterion) {
    let group = c.benchmark_group("key_generation");

    #[cfg(feature = "ml-dsa")]
    {
        let provider = Box::new(LibQCryptoProvider);
        let mut context = SignatureContext::with_provider(provider);

        group.bench_function("ml-dsa-65", |b| {
            b.iter(|| {
                let _keypair = context.generate_keypair(Algorithm::MlDsa65).unwrap();
            });
        });
    }

    #[cfg(feature = "ml-kem")]
    {
        let provider = Box::new(LibQCryptoProvider);
        let mut context = KemContext::with_provider(provider);

        group.bench_function("ml-kem-768", |b| {
            b.iter(|| {
                let _keypair = context.generate_keypair(Algorithm::MlKem768).unwrap();
            });
        });
    }

    group.finish();
}

fn bench_signing(c: &mut Criterion) {
    let group = c.benchmark_group("signing");

    #[cfg(feature = "ml-dsa")]
    {
        let provider = Box::new(LibQCryptoProvider);
        let mut context = SignatureContext::with_provider(provider);
        let keypair = context.generate_keypair(Algorithm::MlDsa65).unwrap();
        let message = black_box(b"Hello, world! This is a test message for benchmarking.");

        group.bench_function("ml-dsa-65", |b| {
            b.iter(|| {
                let _signature = context
                    .sign(Algorithm::MlDsa65, &keypair.secret_key, message)
                    .unwrap();
            });
        });
    }

    group.finish();
}

fn bench_verification(c: &mut Criterion) {
    let group = c.benchmark_group("verification");

    #[cfg(feature = "ml-dsa")]
    {
        let provider = Box::new(LibQCryptoProvider);
        let mut context = SignatureContext::with_provider(provider);
        let keypair = context.generate_keypair(Algorithm::MlDsa65).unwrap();
        let message = black_box(b"Hello, world! This is a test message for benchmarking.");
        let signature = context
            .sign(Algorithm::MlDsa65, &keypair.secret_key, message)
            .unwrap();

        group.bench_function("ml-dsa-65", |b| {
            b.iter(|| {
                let _is_valid = context
                    .verify(Algorithm::MlDsa65, &keypair.public_key, message, &signature)
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
        let provider = Box::new(LibQCryptoProvider);
        let mut context = KemContext::with_provider(provider);
        let public_key = context
            .generate_keypair(Algorithm::MlKem768)
            .unwrap()
            .public_key;

        group.bench_function("ml-kem-768", |b| {
            b.iter(|| {
                let _ciphertext = context
                    .encapsulate(Algorithm::MlKem768, &public_key)
                    .unwrap();
            });
        });
    }

    group.finish();
}

fn bench_decapsulation(c: &mut Criterion) {
    let group = c.benchmark_group("decapsulation");

    #[cfg(feature = "ml-kem")]
    {
        let provider = Box::new(LibQCryptoProvider);
        let mut context = KemContext::with_provider(provider);
        let keypair = context.generate_keypair(Algorithm::MlKem768).unwrap();
        let (ciphertext, _shared_secret) = context
            .encapsulate(Algorithm::MlKem768, &keypair.public_key)
            .unwrap();

        group.bench_function("ml-kem-768", |b| {
            b.iter(|| {
                let _shared_secret = context
                    .decapsulate(Algorithm::MlKem768, &keypair.secret_key, &ciphertext)
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
