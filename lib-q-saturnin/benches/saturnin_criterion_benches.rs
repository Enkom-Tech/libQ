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
        // Short-message sizes (0/16/64/256/1024 bytes) are the point of this sweep: `hash()`
        // does a fixed amount of per-call setup work (see `src/hash.rs::SaturninHash::hash`)
        // before it ever touches a byte of input, and that fixed cost is invisible at large
        // message sizes but dominates at these small ones. Card t_ae63f1ec's SUSPECTED-by-
        // operation-counting estimate (~2 block-encryptions of fixed overhead per call) must be
        // measured here, not assumed.
        for size in [0usize, 16, 64, 256, 1024] {
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
        // AD = 16 bytes, fixed: no real caller passes `None` here (every AEAD consumer in this
        // workspace binds at least a header/context to the ciphertext), and 16 B is the
        // networking-header shape used elsewhere in this bench suite. Numbers from before this
        // change (which measured `AD = None`) are not comparable to numbers measured after it.
        let ad = data(16);
        for size in [64usize, 1024, 10 * 1024] {
            let input = data(size);
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(BenchmarkId::new("encrypt", size), &input, |b, v| {
                b.iter(|| {
                    let _ = aead
                        .encrypt(&key, &nonce, v, Some(ad.as_slice()))
                        .expect("encrypt");
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
