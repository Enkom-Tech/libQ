//! Criterion benchmarks for SHA-3 and SHAKE algorithms.
//! Throughput is reported in bytes so Criterion can show MB/s.

use std::hint::black_box;

use criterion::{
    BenchmarkId,
    Criterion,
    Throughput,
    criterion_group,
    criterion_main,
};
use digest::{
    Digest,
    ExtendableOutput,
    Update,
};
use lib_q_sha3::{
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shake128,
    Shake256,
};

const INPUT_SIZES: &[usize] = &[10, 100, 1_000, 10_000];

fn bench_fixed<H: Digest + Default>(c: &mut Criterion, name: &str) {
    let mut group = c.benchmark_group(name);
    for &size in INPUT_SIZES {
        let data = vec![0x42u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let mut h = H::default();
                h.update(black_box(data.as_slice()));
                black_box(h.finalize())
            })
        });
    }
    group.finish();
}

fn bench_xof<H: ExtendableOutput + Update + Default>(c: &mut Criterion, name: &str) {
    let mut group = c.benchmark_group(name);
    for &size in INPUT_SIZES {
        let data = vec![0x42u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let mut h = H::default();
                h.update(black_box(data.as_slice()));
                let mut out = [0u8; 32];
                h.finalize_xof_into(&mut out);
                black_box(out)
            })
        });
    }
    group.finish();
}

fn sha3_224(c: &mut Criterion) {
    bench_fixed::<Sha3_224>(c, "sha3_224");
}
fn sha3_256(c: &mut Criterion) {
    bench_fixed::<Sha3_256>(c, "sha3_256");
}
fn sha3_384(c: &mut Criterion) {
    bench_fixed::<Sha3_384>(c, "sha3_384");
}
fn sha3_512(c: &mut Criterion) {
    bench_fixed::<Sha3_512>(c, "sha3_512");
}
fn shake128(c: &mut Criterion) {
    bench_xof::<Shake128>(c, "shake128");
}
fn shake256(c: &mut Criterion) {
    bench_xof::<Shake256>(c, "shake256");
}

criterion_group!(
    benches, sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256
);
criterion_main!(benches);
