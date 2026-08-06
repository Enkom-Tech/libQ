#![cfg(all(
    feature = "hardened",
    feature = "mldsa44",
    feature = "dudect-smoke-tests"
))]

//! Wall-clock timing-variance smoke for ML-DSA-44 verification: a valid signature and a
//! corrupted signature over the same message/key must not show a large timing separation.
//! Loose CI gate, not instrumented dudect.
//!
//! The two classes (valid signature, corrupted signature) differ only in a **public** input
//! (the signature bytes), so this is a robustness/timing-uniformity signal rather than a
//! secret-dependent leak probe; see `lib-q-mayo/tests/hardened_dudect_smoke.rs` for the
//! secret-key-dependent variant of this harness.
//!
//! The two classes are collected as two separate vectors and passed to the two-class `dudect`
//! API as such — never interleaved into one sequence and re-split by position. An earlier
//! version of this test interleaved `[A, B, A, B, ...]` into a single `Vec` and handed it to a
//! single-slice API that inferred class membership from `split_at(len / 2)`; with a 50/50
//! interleave that split puts half of each class in each half, so the statistic measured
//! first-half-vs-second-half drift instead of valid vs corrupted. The `dudect` crate's
//! signature now requires two labeled slices, which makes that mistake impossible to express.
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
//! per-class standard error at 200 samples/class was ~3 µs against a ~180 µs mean verification
//! time, so a separation had to exceed roughly 13 % of the runtime before it could reach the 8.0
//! gate at all. The standard error falls as `1/sqrt(SMOKE_ITERS)`, so the current sample count
//! resolves roughly a 5 % separation on the same box (measured standard error ~1.2-1.5 µs). A pass is evidence that no *gross*
//! input-dependent timing difference was introduced; it is not evidence of constant-time
//! behaviour, and it does not replace instrumented dudect or TVLA with cycle counters. Treat this
//! as a regression tripwire only.

use lib_q_ml_dsa::constants::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};
use lib_q_ml_dsa::ml_dsa_44::{
    MLDSA44Signature,
    MLDSA44VerificationKey,
    generate_key_pair,
    sign,
    verify,
};
use lib_q_sca_test::dudect::timing_passes_loose;

/// Samples per class. Sensitivity scales as `sqrt(SMOKE_ITERS)`; see the sensitivity note in the
/// module docs. Deliberately a `usize`, not a `u8`: the previous `u8` counter silently capped this
/// harness at 255 samples per class, which is a hard ceiling on how small a timing separation it
/// can ever resolve.
const SMOKE_ITERS: usize = 2000;
/// Loose CI gate: wall-clock smoke only, not instrumented dudect.
const SMOKE_THRESHOLD: f64 = 8.0;

fn collect_verify_timing_samples(
    vk: &MLDSA44VerificationKey,
    message: &[u8],
    sig: &MLDSA44Signature,
) -> (Vec<f64>, Vec<f64>) {
    let mut valid_class = Vec::with_capacity(SMOKE_ITERS);
    let mut corrupted_class = Vec::with_capacity(SMOKE_ITERS);
    for i in 0..SMOKE_ITERS {
        let start = std::time::Instant::now();
        let r = verify(vk, message, b"", sig);
        let _ = std::hint::black_box(r);
        valid_class.push(start.elapsed().as_secs_f64());

        let mut bad = *sig.as_ref();
        // `% 255` then `+1` keeps the flip mask in 1..=255: a mask of 0 would leave the
        // "corrupted" signature valid and quietly contaminate the second class.
        bad[0] ^= ((i % 255) as u8).wrapping_add(1);
        let bad_sig = MLDSA44Signature::new(bad);
        let start = std::time::Instant::now();
        let r = verify(vk, message, b"", &bad_sig);
        let _ = std::hint::black_box(r);
        corrupted_class.push(start.elapsed().as_secs_f64());
    }
    (valid_class, corrupted_class)
}

#[test]
fn hardened_dudect_smoke_verify() {
    let kp = generate_key_pair([0x42u8; KEY_GENERATION_RANDOMNESS_SIZE]);
    let message = b"libq-hardened-ml-dsa-smoke";
    let sig = sign(
        &kp.signing_key,
        message,
        b"",
        [0x11u8; SIGNING_RANDOMNESS_SIZE],
    )
    .expect("sign");

    let (valid_class, corrupted_class) =
        collect_verify_timing_samples(&kp.verification_key, message, &sig);
    let t = lib_q_sca_test::dudect::timing_t_statistic(&valid_class, &corrupted_class);
    assert!(
        timing_passes_loose(SMOKE_THRESHOLD, &valid_class, &corrupted_class),
        "hardened ML-DSA verify timing smoke exceeded the loose gate (t = {t:?}, \
         threshold = {SMOKE_THRESHOLD})"
    );
}
