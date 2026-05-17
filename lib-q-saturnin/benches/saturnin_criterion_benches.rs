use core::time::Duration;

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
#[cfg(feature = "aead")]
use lib_q_saturnin::SaturninAead;
#[cfg(feature = "block-cipher")]
use lib_q_saturnin::SaturninBlockCipher;
#[cfg(feature = "hash")]
use lib_q_saturnin::SaturninHash;
#[cfg(feature = "stream")]
use lib_q_saturnin::SaturninStream;
use lib_q_saturnin::core::SaturninCore;
#[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
use lib_q_saturnin::simd::SimdOptimizedCore;

fn data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i & 0xFF) as u8).collect()
}

fn bench_block_core(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_core_encrypt");
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(6));
    group.sample_size(100);
    group.throughput(Throughput::Bytes(32));

    let key = [0x11u8; 32];
    let core = SaturninCore::new(10, 1).expect("valid");
    group.bench_function(BenchmarkId::new("scalar", "core"), |b| {
        b.iter(|| {
            let mut block = [0x22u8; 32];
            core.encrypt_block(&key, &mut block).expect("encrypt");
        });
    });

    #[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
    {
        let simd = SimdOptimizedCore::new(10, 1).expect("valid");
        group.bench_function(BenchmarkId::new("simd_dispatch", "core"), |b| {
            b.iter(|| {
                let mut block = [0x22u8; 32];
                simd.encrypt_block(&key, &mut block).expect("encrypt");
            });
        });
    }

    group.finish();
}

fn bench_block_cipher_api(c: &mut Criterion) {
    #[cfg(not(feature = "block-cipher"))]
    {
        let _ = c;
        return;
    }
    #[cfg(feature = "block-cipher")]
    {
        let mut group = c.benchmark_group("block_cipher_api");
        group.warm_up_time(Duration::from_secs(2));
        group.measurement_time(Duration::from_secs(6));
        group.sample_size(100);
        let cipher = SaturninBlockCipher::new();
        let key = vec![0x11u8; 32];
        let block = vec![0x22u8; 32];

        group.throughput(Throughput::Bytes(32));
        group.bench_function("encrypt_block", |b| {
            b.iter(|| {
                let _ = cipher.encrypt_block(&key, &block).expect("encrypt");
            });
        });
        group.finish();
    }
}

fn bench_stream(c: &mut Criterion) {
    #[cfg(not(feature = "stream"))]
    {
        let _ = c;
        return;
    }
    #[cfg(feature = "stream")]
    {
        let mut group = c.benchmark_group("stream_throughput");
        group.warm_up_time(Duration::from_secs(2));
        group.measurement_time(Duration::from_secs(6));
        group.sample_size(60);
        let stream = SaturninStream::new();
        let key = vec![0x11u8; 32];
        let nonce = vec![0x33u8; 16];
        for size in [64usize, 1024, 10 * 1024, 100 * 1024] {
            let plaintext = data(size);
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(BenchmarkId::new("encrypt", size), &plaintext, |b, p| {
                b.iter(|| {
                    let _ = stream.encrypt(&key, &nonce, p).expect("stream encrypt");
                });
            });
        }
        group.finish();
    }
}

fn bench_hash(c: &mut Criterion) {
    #[cfg(not(feature = "hash"))]
    {
        let _ = c;
        return;
    }
    #[cfg(feature = "hash")]
    {
        let mut group = c.benchmark_group("hash_throughput");
        group.warm_up_time(Duration::from_secs(2));
        group.measurement_time(Duration::from_secs(6));
        group.sample_size(60);
        let hash = SaturninHash::new();
        for size in [64usize, 1024, 10 * 1024, 100 * 1024, 1024 * 1024] {
            let input = data(size);
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(BenchmarkId::new("hash", size), &input, |b, v| {
                b.iter(|| {
                    let _ = hash.hash(v).expect("hash");
                });
            });
        }
        group.finish();
    }
}

fn bench_aead(c: &mut Criterion) {
    #[cfg(not(feature = "aead"))]
    {
        let _ = c;
        return;
    }
    #[cfg(feature = "aead")]
    {
        let mut group = c.benchmark_group("aead_throughput");
        group.warm_up_time(Duration::from_secs(2));
        group.measurement_time(Duration::from_secs(6));
        group.sample_size(60);
        let aead = SaturninAead::new();
        let key = AeadKey::new(vec![0x11u8; 32]);
        let nonce = Nonce::new(vec![0x22u8; 16]);
        for size in [64usize, 1024, 10 * 1024] {
            let input = data(size);
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(BenchmarkId::new("encrypt", size), &input, |b, v| {
                b.iter(|| {
                    let _ = aead.encrypt(&key, &nonce, v, None).expect("encrypt");
                });
            });
        }
        group.finish();
    }
}

criterion_group!(
    benches,
    bench_block_core,
    bench_block_cipher_api,
    bench_stream,
    bench_hash,
    bench_aead
);
criterion_main!(benches);
