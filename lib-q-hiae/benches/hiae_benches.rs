//! Criterion throughput: HiAE in place (detached tag), dispatched backend, plus the
//! portable constant-time backend for reference.

use criterion::{
    BenchmarkId,
    Criterion,
    Throughput,
    criterion_group,
    criterion_main,
};
use lib_q_hiae::{
    _internals,
    Hiae,
};

const SIZES: &[usize] = &[64, 1200, 16384];

fn bench(c: &mut Criterion) {
    let key = [0x24u8; 32];
    let nonce = [0x42u8; 16];
    let ad = [0u8; 41];
    let mut g = c.benchmark_group("hiae");
    for &size in SIZES {
        let mut buf = vec![0xA5u8; size];
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_function(BenchmarkId::new("seal", size), |b| {
            b.iter(|| Hiae::encrypt_in_place_detached(&key, &nonce, &ad, &mut buf).unwrap())
        });
        g.bench_function(BenchmarkId::new("seal-soft", size), |b| {
            b.iter(|| _internals::hiae_seal_soft(&key, &nonce, &ad, &mut buf))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
