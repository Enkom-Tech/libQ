//! Controls for the `dudect` two-class timing API.
//!
//! History: the previous single-slice API (`fn(samples: &[f64]) -> Option<f64>`) inferred class
//! membership from position via `samples.split_at(samples.len() / 2)`. Two in-workspace callers
//! (`lib-q-mayo` and `lib-q-ml-dsa` hardened dudect smoke tests) built their sample vector by
//! *interleaving* class A and class B timings (`[A, B, A, B, ...]`) instead of blocking them
//! (`[A, ..., B, ...]`). Interleaved data handed to a midpoint split puts exactly half of each
//! class in each half, so the resulting statistic measures first-half-vs-second-half drift, not
//! class A vs class B — a dataset with 100% key-dependent timing separation reported *no leak*.
//!
//! RED evidence (captured against the single-slice API at HEAD before this fix, same fabricated
//! data as below, alternating layout):
//!
//! ```text
//! thread 'interleaved_perfect_separation_must_not_pass_the_gate' panicked at
//! lib-q-sca-test\tests\detector_controls.rs:35:5:
//! BUG REPRODUCED: interleaved 100% class-separated data passed the loose gate
//! (t = Some(-0.0002814245685951151), threshold = 8) — the midpoint split is measuring
//! first-half-vs-second-half drift, not class A vs class B
//! ```
//!
//! The fix changes the signature to `fn(class_a: &[f64], class_b: &[f64])`, which makes that
//! specific misuse impossible to express: there is no shared sequence for the callee to
//! mis-split, because the caller must already hand over two separately-labeled slices. The tests
//! below are the permanent positive/negative controls for the two-class API — a leak detector
//! with no positive control is the same defect one level up.
use lib_q_sca_test::dudect::{
    timing_passes_loose,
    timing_t_statistic,
};

const THRESHOLD: f64 = 8.0;

/// The exact per-sample values the old code interleaved into one `Vec`, now expressed the only
/// way the two-class API allows: as two separately-labeled classes.
fn perfectly_separated_classes() -> (Vec<f64>, Vec<f64>) {
    let class_a: Vec<f64> = (0..100u32)
        .map(|i| 1.0e-6 + (i % 3) as f64 * 1e-9)
        .collect();
    let class_b: Vec<f64> = (0..100u32)
        .map(|i| 2.0e-6 + (i % 3) as f64 * 1e-9)
        .collect();
    (class_a, class_b)
}

/// Positive control: a real, unmistakable timing separation between the two classes must fire
/// the gate (large |t|, `timing_passes_loose` returns `false`).
#[test]
fn separated_classes_fire_the_gate() {
    let (class_a, class_b) = perfectly_separated_classes();
    let t = timing_t_statistic(&class_a, &class_b).expect("well-formed classes yield a statistic");
    assert!(
        t.abs() > THRESHOLD,
        "expected the two-class API to detect the fabricated leak, got t={t}"
    );
    assert!(!timing_passes_loose(THRESHOLD, &class_a, &class_b));
}

/// Negative control: classes differing only by sub-nanosecond deterministic jitter must pass the
/// loose gate (no leak).
#[test]
fn near_identical_classes_pass_the_gate() {
    let class_a: Vec<f64> = (0..100u32)
        .map(|i| 1.0e-6 + (i % 3) as f64 * 1e-9)
        .collect();
    let class_b: Vec<f64> = (0..100u32)
        .map(|i| 1.0e-6 + (i % 3) as f64 * 1e-9 + 1e-13)
        .collect();
    assert!(timing_passes_loose(THRESHOLD, &class_a, &class_b));
}

/// Fail-closed: a class with fewer than 2 samples cannot yield a statistic, and the gate must
/// treat that as a failure, never a pass.
#[test]
fn fail_closed_on_undersized_class() {
    let class_a = [1.0e-6];
    let class_b = [1.0e-6, 1.0000001e-6];
    assert_eq!(timing_t_statistic(&class_a, &class_b), None);
    assert!(!timing_passes_loose(THRESHOLD, &class_a, &class_b));
}

/// Fail-closed: identical (zero-variance) classes yield a zero pooled standard error, which
/// `welch_t_statistic` reports as `None`, and the gate must treat that as a failure too.
#[test]
fn fail_closed_on_zero_variance() {
    let class_a = [1.0e-6, 1.0e-6, 1.0e-6, 1.0e-6];
    let class_b = [1.0e-6, 1.0e-6, 1.0e-6, 1.0e-6];
    assert_eq!(timing_t_statistic(&class_a, &class_b), None);
    assert!(!timing_passes_loose(THRESHOLD, &class_a, &class_b));
}
