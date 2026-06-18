//! Criterion throughput benchmarks for Rocca-S AEAD.

use criterion::{
    BenchmarkId,
    Criterion,
    Throughput,
    criterion_group,
    criterion_main,
};
use lib_q_rocca_s::{
    Aead,
    AeadKey,
    Nonce,
    RoccaSAead,
};

fn bench_encrypt(c: &mut Criterion) {
    let aead = RoccaSAead::new();
    let key = AeadKey::new(vec![0x24; 32]);
    let nonce = Nonce::new(vec![0x42; 16]);
    let ad = b"associated-data";

    let mut group = c.benchmark_group("rocca_s_encrypt");
    for &size in &[64usize, 1024, 16384, 65536] {
        let pt = vec![0xA5u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &pt, |b, pt| {
            b.iter(|| {
                aead.encrypt(&key, &nonce, std::hint::black_box(pt), Some(ad))
                    .unwrap()
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_encrypt);
criterion_main!(benches);
