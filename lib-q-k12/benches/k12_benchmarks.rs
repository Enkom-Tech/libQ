//! Criterion benchmarks for KangarooTwelve.
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
    ExtendableOutput,
    Update,
};

const INPUT_SIZES: &[usize] = &[10, 100, 1_000, 10_000];

fn kangarootwelve(c: &mut Criterion) {
    let mut group = c.benchmark_group("kangarootwelve");
    for &size in INPUT_SIZES {
        let data = vec![0x42u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let mut h = lib_q_k12::KangarooTwelve::default();
                h.update(black_box(data.as_slice()));
                let mut out = [0u8; 32];
                h.finalize_xof_into(&mut out);
                black_box(out)
            })
        });
    }
    group.finish();
}

criterion_group!(benches, kangarootwelve);
criterion_main!(benches);
