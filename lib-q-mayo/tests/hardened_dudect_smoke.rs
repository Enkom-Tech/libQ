#![cfg(all(
    feature = "hardened",
    feature = "mayo2",
    feature = "dudect-smoke-tests"
))]

//! Wall-clock timing-variance smoke for MAYO_2 signing: two fixed keys with
//! different secret material signing the same message must not show a large
//! timing separation. Loose CI gate, not instrumented dudect.
//!
//! The two classes (key A, key B) are collected as two separate vectors and passed to the
//! two-class `dudect` API as such — never interleaved into one sequence and re-split by
//! position. An earlier version of this test interleaved `[A, B, A, B, ...]` into a single
//! `Vec` and handed it to a single-slice API that inferred class membership from
//! `split_at(len / 2)`; with a 50/50 interleave that split puts half of each class in each
//! half, so the statistic measured first-half-vs-second-half drift instead of key A vs key B.
//! The `dudect` crate's signature now requires two labeled slices, which makes that mistake
//! impossible to express.
//!
//! Single-decision rule: one measurement at a fixed sample size against the unchanged loose
//! threshold, no best-of-N retry. A previous version retried up to 5 times and returned on the
//! first success, which converts any residual measurement noise into a pass; if CI flakiness is
//! observed here, the documented fallback is an aggregate decision (e.g. median-of-5 full runs),
//! never first-success.
//!
//! # Sensitivity — what a pass here does and does not mean
//!
//! This is a wall-clock measurement, so its resolving power is bounded by scheduler and cache
//! noise on the host, not by the gate constant. Measured on one loaded Windows dev box, the
//! per-class standard error at 200 samples/class was ~14 µs against a ~950 µs mean signing time,
//! i.e. an injected key-dependent slowdown of ~90 µs (~9 %) scored |t| = 6.2 and *passed* the 8.0
//! gate. `SMOKE_ITERS` is therefore set well above the minimum: the standard error falls as
//! `1/sqrt(SMOKE_ITERS)`, so the same box resolves roughly a 4 % separation at the current value
//! (measured standard error ~4-6 µs).
//! A pass is evidence that no *gross* key-dependent timing difference was introduced; it is not
//! evidence of constant-time behaviour, and it does not replace instrumented dudect or TVLA with
//! cycle counters. Treat this as a regression tripwire only.

use lib_q_mayo::mayo_2::{
    SIGNING_RANDOMNESS_SIZE,
    generate_key_pair,
    sign,
};
use lib_q_sca_test::dudect::timing_passes_loose;

/// Samples per class. Sensitivity scales as `sqrt(SMOKE_ITERS)`; see the sensitivity note in the
/// module docs for what this buys and what it does not.
const SMOKE_ITERS: usize = 1000;
/// Loose CI gate: wall-clock smoke only, not instrumented dudect.
const SMOKE_THRESHOLD: f64 = 8.0;

fn collect_sign_timing_samples() -> (Vec<f64>, Vec<f64>) {
    let kp_a = generate_key_pair([0x42u8; 24]);
    let kp_b = generate_key_pair([0xA5u8; 24]);
    let message = b"libq-hardened-mayo-smoke";

    let mut class_a = Vec::with_capacity(SMOKE_ITERS);
    let mut class_b = Vec::with_capacity(SMOKE_ITERS);
    for i in 0..SMOKE_ITERS {
        let mut randomness = [0u8; SIGNING_RANDOMNESS_SIZE];
        randomness[0] = i as u8;

        let start = std::time::Instant::now();
        let r = sign(&kp_a.signing_key, message, randomness);
        let _ = std::hint::black_box(r);
        class_a.push(start.elapsed().as_secs_f64());

        let start = std::time::Instant::now();
        let r = sign(&kp_b.signing_key, message, randomness);
        let _ = std::hint::black_box(r);
        class_b.push(start.elapsed().as_secs_f64());
    }
    (class_a, class_b)
}

#[test]
fn hardened_dudect_smoke_sign() {
    let (class_a, class_b) = collect_sign_timing_samples();
    let t = lib_q_sca_test::dudect::timing_t_statistic(&class_a, &class_b);
    assert!(
        timing_passes_loose(SMOKE_THRESHOLD, &class_a, &class_b),
        "hardened MAYO sign timing smoke exceeded the loose gate (t = {t:?}, \
         threshold = {SMOKE_THRESHOLD})"
    );
}
