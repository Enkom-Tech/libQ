use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use lib_q_ml_dsa::{Zeroizing, ml_dsa_65};
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
            let _ = ml_dsa_65::generate_key_pair_from_seed(&Zeroizing::new(randomness));
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
    let keypair = ml_dsa_65::generate_key_pair_from_seed(&Zeroizing::new(randomness));

    rng.fill_bytes(&mut randomness);

    group.bench_function("lib-q (external random)", move |b| {
        b.iter(|| {
            let _ = ml_dsa_65::sign(&keypair.signing_key, &message, b"", randomness);
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
    let keypair = ml_dsa_65::generate_key_pair_from_seed(&Zeroizing::new(randomness));

    rng.fill_bytes(&mut randomness);
    let signature = ml_dsa_65::sign(&keypair.signing_key, &message, b"", randomness).unwrap();

    group.bench_function("lib-q", move |b| {
        b.iter(|| {
            ml_dsa_65::verify(&keypair.verification_key, &message, b"", &signature).unwrap();
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
