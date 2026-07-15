//! MAYO_2 keygen / sign / verify benchmarks.

use std::hint::black_box;

use criterion::{
    Criterion,
    criterion_group,
    criterion_main,
};
use lib_q_mayo::mayo_2;

fn bench_mayo2(c: &mut Criterion) {
    let keypair = mayo_2::generate_key_pair([7u8; 24]);
    let message = [0xA5u8; 59];
    let signature = mayo_2::sign(&keypair.signing_key, &message, [3u8; 24]).unwrap();

    c.bench_function("mayo2_keygen", |b| {
        b.iter(|| mayo_2::generate_key_pair(black_box([7u8; 24])))
    });
    c.bench_function("mayo2_sign", |b| {
        b.iter(|| mayo_2::sign(&keypair.signing_key, black_box(&message), [3u8; 24]).unwrap())
    });
    c.bench_function("mayo2_verify", |b| {
        b.iter(|| mayo_2::verify(&keypair.verification_key, black_box(&message), &signature))
    });
}

criterion_group!(benches, bench_mayo2);
criterion_main!(benches);
