//! Throughput/latency benchmarks for S-A-H-256 (PLAN Part 7).
//!
//! Workloads span libQ-relevant sizes: short control records, MTU-ish, record
//! ceiling, and bulk. Compare against lib-q-saturnin / lib-q-duplex-aead /
//! lib-q-romulus via lib-q-aead/benches for the cross-algorithm picture.

use criterion::{
    BenchmarkId,
    Criterion,
    Throughput,
    criterion_group,
    criterion_main,
};
use lib_q_sah::{
    Sah256,
    Sah256Key,
    Sah256Nonce,
};

fn bench_seal(c: &mut Criterion) {
    let key = Sah256Key::new([0x42; 32]);
    let nonce = Sah256Nonce::new([0x17; 16]);
    let mut group = c.benchmark_group("sah256_seal");

    for &len in &[32usize, 64, 256, 1500, 16384, 1 << 20] {
        let pt = vec![0xABu8; len];
        let mut ct = vec![0u8; len];
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(len), &len, |b, _| {
            b.iter(|| {
                let _ = Sah256::seal_detached(&key, &nonce, b"", &pt, &mut ct).unwrap();
            });
        });
    }
    group.finish();
}

fn bench_aad_heavy(c: &mut Criterion) {
    // libQ headers ride in AAD: 1 KiB AAD, 64 B payload.
    let key = Sah256Key::new([0x42; 32]);
    let nonce = Sah256Nonce::new([0x17; 16]);
    let aad = vec![0x5Au8; 1024];
    let pt = vec![0xABu8; 64];
    let mut ct = vec![0u8; 64];
    c.bench_function("sah256_seal_aad1k_pt64", |b| {
        b.iter(|| {
            let _ = Sah256::seal_detached(&key, &nonce, &aad, &pt, &mut ct).unwrap();
        });
    });
}

criterion_group!(benches, bench_seal, bench_aad_heavy);
criterion_main!(benches);
