use std::time::Duration;

use criterion::{
    Criterion,
    criterion_group,
    criterion_main,
};
use fips204::traits::{
    Signer,
    Verifier,
};
use lib_q_ml_dsa::ml_dsa_65;
use lib_q_random::new_secure_rng;
use rand_core::Rng;

pub fn comparisons_key_generation(c: &mut Criterion) {
    let mut rng = new_secure_rng().expect("Failed to create RNG");
    let mut group = c.benchmark_group("ML-DSA-65 Key Generation");
    group.measurement_time(Duration::from_secs(10));

    let mut randomness = [0; 32];
    rng.fill_bytes(&mut randomness);

    group.bench_function("lib-q (external random)", move |b| {
        b.iter(|| {
            let _ = ml_dsa_65::generate_key_pair(randomness);
        })
    });

    group.bench_function("fips204 (OS RNG)", move |b| {
        b.iter(|| {
            let _ = fips204::ml_dsa_65::try_keygen().expect("fips204 keygen");
        })
    });
}

pub fn comparisons_signing(c: &mut Criterion) {
    let mut rng = new_secure_rng().expect("Failed to create RNG");
    let mut group = c.benchmark_group("ML-DSA-65 Signing");
    group.measurement_time(Duration::from_secs(10));

    let mut message = [0u8; 511];
    rng.fill_bytes(&mut message);

    let mut randomness = [0; 32];
    rng.fill_bytes(&mut randomness);
    let keypair = ml_dsa_65::generate_key_pair(randomness);

    rng.fill_bytes(&mut randomness);

    group.bench_function("lib-q (external random)", move |b| {
        b.iter(|| {
            let _ = ml_dsa_65::sign(&keypair.signing_key, &message, b"", randomness);
        })
    });

    let (_pk_f, sk_f) = fips204::ml_dsa_65::try_keygen().expect("fips204 keygen");
    group.bench_function("fips204 (OS RNG)", move |b| {
        b.iter(|| {
            let _ = sk_f.try_sign(&message, &[]).expect("fips204 sign");
        })
    });
}

pub fn comparisons_verification(c: &mut Criterion) {
    let mut rng = new_secure_rng().expect("Failed to create RNG");
    let mut group = c.benchmark_group("ML-DSA-65 Verification");
    group.measurement_time(Duration::from_secs(10));

    let mut message = [0u8; 511];
    rng.fill_bytes(&mut message);

    let mut randomness = [0; 32];
    rng.fill_bytes(&mut randomness);
    let keypair = ml_dsa_65::generate_key_pair(randomness);

    rng.fill_bytes(&mut randomness);
    let signature = ml_dsa_65::sign(&keypair.signing_key, &message, b"", randomness).unwrap();

    group.bench_function("lib-q", move |b| {
        b.iter(|| {
            ml_dsa_65::verify(&keypair.verification_key, &message, b"", &signature).unwrap();
        })
    });

    let (pk_f, sk_f) = fips204::ml_dsa_65::try_keygen().expect("fips204 keygen");
    let sig_f = sk_f.try_sign(&message, &[]).expect("fips204 sign");

    group.bench_function("fips204", move |b| {
        b.iter(|| {
            assert!(pk_f.verify(&message, &sig_f, &[]));
        })
    });
}

pub fn comparisons(c: &mut Criterion) {
    comparisons_key_generation(c);
    comparisons_signing(c);
    comparisons_verification(c);
}

criterion_group!(benches, comparisons);
criterion_main!(benches);
