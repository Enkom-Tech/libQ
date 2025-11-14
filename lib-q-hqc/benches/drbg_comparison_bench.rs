use std::hint::black_box;

use criterion::{
    Criterion,
    criterion_group,
    criterion_main,
};
#[cfg(feature = "aes-drbg")]
use lib_q_hqc::aes_ctr_drbg::Aes256CtrDrbg;
#[cfg(feature = "bearssl-aes")]
use lib_q_hqc::bearssl_aes_ctr_drbg::BearSslAes256CtrDrbg;
use rand_core::RngCore;

fn benchmark_drbg_output(c: &mut Criterion) {
    let seed = [0x06u8; 48];

    #[cfg(feature = "aes-drbg")]
    c.bench_function("rust_aes_drbg_32_bytes", |b| {
        b.iter(|| {
            let mut rng = Aes256CtrDrbg::instantiate(&seed);
            let mut output = [0u8; 32];
            rng.fill_bytes(black_box(&mut output));
        });
    });

    #[cfg(feature = "bearssl-aes")]
    c.bench_function("bearssl_aes_drbg_32_bytes", |b| {
        b.iter(|| {
            let mut rng = BearSslAes256CtrDrbg::instantiate(&seed);
            let mut output = [0u8; 32];
            rng.fill_bytes(black_box(&mut output));
        });
    });
}

criterion_group!(benches, benchmark_drbg_output);
criterion_main!(benches);
