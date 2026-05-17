//! Criterion benchmarks for duplex-sponge AEAD.
use criterion::{
    BenchmarkId,
    Criterion,
    Throughput,
    criterion_group,
    criterion_main,
};
use lib_q_core::{
    Aead,
    AeadKey,
    Nonce,
};
use lib_q_duplex_aead::{
    DuplexSpongeAead,
    KEY_BYTES,
    NONCE_BYTES,
};

fn bench_encrypt(c: &mut Criterion) {
    let aead = DuplexSpongeAead::new();
    let key = AeadKey::new(vec![0u8; KEY_BYTES]);
    let nonce = Nonce::new(vec![0u8; NONCE_BYTES]);
    let pt = vec![7u8; 4096];
    let ad = b"bench-ad";

    let mut group = c.benchmark_group("duplex_sponge_aead_encrypt");
    group.throughput(Throughput::Bytes(pt.len() as u64));
    group.bench_function(BenchmarkId::new("len", pt.len()), |b| {
        b.iter(|| {
            let _ = aead.encrypt(&key, &nonce, &pt, Some(ad.as_slice()));
        });
    });
    group.finish();
}

criterion_group!(benches, bench_encrypt);
criterion_main!(benches);
