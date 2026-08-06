//! Measures the CTX committing-AEAD transform's real cost on Saturnin-QCB, and QCB's cost
//! against the default Saturnin-CTR-Cascade mode ([`SaturninAead`]).
//!
//! Every number this bench replaces was previously unreproducible: `SaturninQcb` had no way to
//! turn CTX off, so the README's overhead table came from a disclaimed single-run scratch
//! harness that could not be checked against the shipped code. This bench compares, in the same
//! process, [`Aead::encrypt`]/[`Aead::decrypt`] (CTX on, the only production behavior) against
//! the `#[doc(hidden)]` `__bench_only_*_uncommitted` affordance on [`SaturninQcb`] (CTX off, the
//! raw QCB Algorithm-1 tag). See `src/qcb.rs` for why that affordance is not a public feature.
//!
//! Two independent sweeps, because the whole point of measuring is that CTX's cost tracks the
//! associated-data length `|A|` (one extra `SaturninHash` call over `104 + |A|` bytes per
//! operation) while QCB's own cost tracks the message length `|M|`:
//! - `qcb_msg_sweep` varies `|M|` at fixed `|A| = 16`. Hypothesis (NOT confirmed by the runs
//!   taken so far): the ctx/raw delta stays roughly constant in absolute time as `|M|` grows,
//!   since CTX never touches the message. At single-run sample sizes only the 64 B and 16 KiB
//!   points separated at all, and they disagreed by more than an order of magnitude — treat
//!   this group as an open question, not as a measured result.
//! - `qcb_ad_sweep` varies `|A|` at fixed `|M| = 64` — the ctx/raw delta should grow with `|A|`.
//!
//! Run with `CARGO_INCREMENTAL=0 cargo bench -p lib-q-saturnin --bench qcb_ctx_overhead`.
//!
//! # How to read the output — do not publish a percentage from a single run
//!
//! Criterion's per-benchmark confidence interval describes variance *inside one measurement
//! window*. It says nothing about drift *between* windows, and this bench times the `ctx` and
//! the `raw` arm in two consecutive windows, so any change in machine load (or CPU frequency)
//! between them lands directly in the ratio. Observed on the development host: five runs of
//! `qcb_shapes/*/networking_64B_ad16` put the encrypt overhead anywhere from about +37 % to
//! about +103 % and the decrypt overhead from about +28 % to about +123 %, while every single
//! run reported tight, cleanly non-overlapping CIs for the two arms.
//!
//! What is robust, and what this bench is for: **the two arms separate in every run** — the
//! `ctx` CI's lower bound stayed above the `raw` CI's upper bound in all five — so at the 64 B
//! networking shape CTX's cost is real, large and always positive. The *magnitude* is only
//! trustworthy from several runs on an otherwise idle machine; report it as a range across
//! those runs, never as one run's percentage.

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
use lib_q_saturnin::{
    SaturninAead,
    SaturninQcb,
};

fn data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i & 0xFF) as u8).collect()
}

fn key32() -> AeadKey {
    AeadKey::new(vec![0x11u8; 32])
}

fn nonce16() -> Nonce {
    Nonce::new(vec![0x22u8; 16])
}

/// Message-size sweep at a fixed, small AD size. CTX overhead should be roughly constant in
/// absolute time across this sweep (it depends on `|A|`, not `|M|`).
fn qcb_msg_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("qcb_msg_sweep");
    let qcb = SaturninQcb::new();
    let key = key32();
    let nonce = nonce16();
    let ad = data(16);

    for size in [64usize, 1024, 16 * 1024, 1024 * 1024] {
        let pt = data(size);
        group.throughput(Throughput::Bytes(size as u64));
        // 1 MiB QCB is ~37 MB/s by prior external measurement (~28 ms/op): keep the sample
        // count and measurement window bounded so the sweep finishes in reasonable time.
        if size >= 1024 * 1024 {
            group.sample_size(10);
            group.measurement_time(Duration::from_secs(8));
        } else {
            group.sample_size(60);
            group.measurement_time(Duration::from_secs(4));
        }

        let ct_ctx = qcb.encrypt(&key, &nonce, &pt, Some(&ad)).expect("encrypt");
        let ct_raw = qcb
            .__bench_only_encrypt_uncommitted(&key, &nonce, &pt, Some(&ad))
            .expect("encrypt");

        group.bench_with_input(BenchmarkId::new("encrypt_ctx", size), &pt, |b, v| {
            b.iter(|| qcb.encrypt(&key, &nonce, v, Some(&ad)).expect("encrypt"));
        });
        group.bench_with_input(BenchmarkId::new("encrypt_raw", size), &pt, |b, v| {
            b.iter(|| {
                qcb.__bench_only_encrypt_uncommitted(&key, &nonce, v, Some(&ad))
                    .expect("encrypt")
            });
        });
        group.bench_with_input(BenchmarkId::new("decrypt_ctx", size), &ct_ctx, |b, v| {
            b.iter(|| qcb.decrypt(&key, &nonce, v, Some(&ad)).expect("decrypt"));
        });
        group.bench_with_input(BenchmarkId::new("decrypt_raw", size), &ct_raw, |b, v| {
            b.iter(|| {
                qcb.__bench_only_decrypt_uncommitted(&key, &nonce, v, Some(&ad))
                    .expect("decrypt")
            });
        });
    }
    group.finish();
}

/// Associated-data-size sweep at a fixed, small message size. This is the axis CTX's own cost
/// actually tracks: the ctx/raw delta must grow with `|A|`.
fn qcb_ad_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("qcb_ad_sweep");
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(4));
    group.sample_size(60);
    let qcb = SaturninQcb::new();
    let key = key32();
    let nonce = nonce16();
    let pt = data(64);

    for ad_size in [0usize, 16, 32, 256, 1024, 4096, 16 * 1024] {
        let ad = data(ad_size);
        // Deliberately no `group.throughput` here. `|M|` is pinned at 64 B across the whole
        // sweep, so a message-bytes throughput would be a constant carrying no information,
        // and an AD-bytes throughput reads as a meaningless `0 B/s` at the `|A| = 0` point.
        // Wall-clock time per operation is the quantity this group is measuring.
        let ad_opt = if ad.is_empty() {
            None
        } else {
            Some(ad.as_slice())
        };

        let ct_ctx = qcb.encrypt(&key, &nonce, &pt, ad_opt).expect("encrypt");
        let ct_raw = qcb
            .__bench_only_encrypt_uncommitted(&key, &nonce, &pt, ad_opt)
            .expect("encrypt");

        group.bench_with_input(BenchmarkId::new("encrypt_ctx", ad_size), &ad, |b, _| {
            b.iter(|| qcb.encrypt(&key, &nonce, &pt, ad_opt).expect("encrypt"));
        });
        group.bench_with_input(BenchmarkId::new("encrypt_raw", ad_size), &ad, |b, _| {
            b.iter(|| {
                qcb.__bench_only_encrypt_uncommitted(&key, &nonce, &pt, ad_opt)
                    .expect("encrypt")
            });
        });
        group.bench_with_input(BenchmarkId::new("decrypt_ctx", ad_size), &ct_ctx, |b, v| {
            b.iter(|| qcb.decrypt(&key, &nonce, v, ad_opt).expect("decrypt"));
        });
        group.bench_with_input(BenchmarkId::new("decrypt_raw", ad_size), &ct_raw, |b, v| {
            b.iter(|| {
                qcb.__bench_only_decrypt_uncommitted(&key, &nonce, v, ad_opt)
                    .expect("decrypt")
            });
        });
    }
    group.finish();
}

/// The two deliverable shapes: (a) networking — 64 B message, 16 B AD; (b) data at rest — 1 MiB
/// message, 32 B AD. Reported to the orchestrator as criterion's own means/CIs, not re-derived.
fn qcb_shapes(c: &mut Criterion) {
    let mut group = c.benchmark_group("qcb_shapes");
    let qcb = SaturninQcb::new();
    let key = key32();
    let nonce = nonce16();

    let shapes: &[(&str, usize, usize)] = &[
        ("networking_64B_ad16", 64, 16),
        ("at_rest_1MiB_ad32", 1024 * 1024, 32),
    ];

    for (label, msg_size, ad_size) in shapes {
        let pt = data(*msg_size);
        let ad = data(*ad_size);
        group.throughput(Throughput::Bytes(*msg_size as u64));
        if *msg_size >= 1024 * 1024 {
            group.sample_size(10);
            group.measurement_time(Duration::from_secs(8));
        } else {
            group.sample_size(60);
            group.measurement_time(Duration::from_secs(4));
        }

        let ct_ctx = qcb.encrypt(&key, &nonce, &pt, Some(&ad)).expect("encrypt");
        let ct_raw = qcb
            .__bench_only_encrypt_uncommitted(&key, &nonce, &pt, Some(&ad))
            .expect("encrypt");

        group.bench_function(BenchmarkId::new("encrypt_ctx", *label), |b| {
            b.iter(|| qcb.encrypt(&key, &nonce, &pt, Some(&ad)).expect("encrypt"));
        });
        group.bench_function(BenchmarkId::new("encrypt_raw", *label), |b| {
            b.iter(|| {
                qcb.__bench_only_encrypt_uncommitted(&key, &nonce, &pt, Some(&ad))
                    .expect("encrypt")
            });
        });
        group.bench_function(BenchmarkId::new("decrypt_ctx", *label), |b| {
            b.iter(|| {
                qcb.decrypt(&key, &nonce, &ct_ctx, Some(&ad))
                    .expect("decrypt")
            });
        });
        group.bench_function(BenchmarkId::new("decrypt_raw", *label), |b| {
            b.iter(|| {
                qcb.__bench_only_decrypt_uncommitted(&key, &nonce, &ct_raw, Some(&ad))
                    .expect("decrypt")
            });
        });
    }
    group.finish();
}

/// Production `SaturninQcb` (CTX on, the only shipped behavior) vs production `SaturninAead`
/// (CTR-Cascade, the default AEAD everywhere in this workspace) — the mode-choice comparison
/// load-bearing for D3 in the decision brief: is QCB faster than CTR-Cascade at these sizes?
fn mode_compare(c: &mut Criterion) {
    let mut group = c.benchmark_group("mode_compare");
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(60);
    let qcb = SaturninQcb::new();
    let cascade = SaturninAead::new();
    let key = key32();
    let nonce = nonce16();
    let ad = data(16);

    for size in [64usize, 1024, 16 * 1024] {
        let pt = data(size);
        group.throughput(Throughput::Bytes(size as u64));

        let ct_qcb = qcb.encrypt(&key, &nonce, &pt, Some(&ad)).expect("encrypt");
        let ct_cascade = cascade
            .encrypt(&key, &nonce, &pt, Some(&ad))
            .expect("encrypt");

        group.bench_with_input(BenchmarkId::new("qcb_encrypt", size), &pt, |b, v| {
            b.iter(|| qcb.encrypt(&key, &nonce, v, Some(&ad)).expect("encrypt"));
        });
        group.bench_with_input(BenchmarkId::new("cascade_encrypt", size), &pt, |b, v| {
            b.iter(|| {
                cascade
                    .encrypt(&key, &nonce, v, Some(&ad))
                    .expect("encrypt")
            });
        });
        group.bench_with_input(BenchmarkId::new("qcb_decrypt", size), &ct_qcb, |b, v| {
            b.iter(|| qcb.decrypt(&key, &nonce, v, Some(&ad)).expect("decrypt"));
        });
        group.bench_with_input(
            BenchmarkId::new("cascade_decrypt", size),
            &ct_cascade,
            |b, v| {
                b.iter(|| {
                    cascade
                        .decrypt(&key, &nonce, v, Some(&ad))
                        .expect("decrypt")
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    qcb_msg_sweep,
    qcb_ad_sweep,
    qcb_shapes,
    mode_compare
);
criterion_main!(benches);
