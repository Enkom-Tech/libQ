//! Wall-clock timing harness in the spirit of dudect (software timing leakage probes).
//!
//! This is **not** a substitute for instrumented power traces or a calibrated dudect build; it
//! provides a cheap regression hook that secret-dependent branches or allocations often perturb.
//!
//! # Class separation is the caller's job, and it is load-bearing
//!
//! Both entry points below take the two classes **as two separate slices**. There used to be a
//! single-slice `&[f64]` API that inferred class membership from position
//! (`samples.split_at(samples.len() / 2)`) — it was removed because that inference is silently
//! wrong the moment a caller interleaves the two classes (`[A, B, A, B, ...]`) instead of
//! blocking them (`[A, A, ..., B, B, ...]`): a 50/50 interleave puts exactly half of each class in
//! each half of the split, so the resulting Welch statistic measures first-half-vs-second-half
//! drift, not class A vs class B, and a 100%-key-dependent timing leak reports as no leak at all.
//! Two callers in this workspace shipped exactly that bug (see git history around the
//! `dudect-gate` fix). Taking two slices makes that specific mistake impossible to express: there
//! is no position for the callee to get wrong, because the caller must already know which sample
//! belongs to which class.

/// Welch *t*-statistic between two labeled timing classes.
///
/// `class_a` and `class_b` must each already contain only that class's samples — do not
/// interleave and then split; collect (or filter) into two vectors up front.
pub fn timing_t_statistic(class_a: &[f64], class_b: &[f64]) -> Option<f64> {
    crate::welch_t_statistic(class_a, class_b)
}

/// Returns true if \\(|t| < \\) `threshold` (loose CI default: large timing noise dominates).
///
/// Fails closed (`false`) whenever [`timing_t_statistic`] cannot compute a statistic (too few
/// samples in either class, or zero pooled variance) — an inconclusive measurement is not a pass.
pub fn timing_passes_loose(threshold: f64, class_a: &[f64], class_b: &[f64]) -> bool {
    match timing_t_statistic(class_a, class_b) {
        Some(t) => t.abs() < threshold,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two classes differing only by deterministic sub-microsecond jitter must pass the loose
    /// gate (no leak).
    #[test]
    fn near_identical_classes_pass_loose_gate() {
        let a: Vec<f64> = (0..200).map(|i| 1e-6 + (i % 3) as f64 * 1e-9).collect();
        let b: Vec<f64> = (0..200)
            .map(|i| 1e-6 + (i % 3) as f64 * 1e-9 + 1e-12)
            .collect();
        assert!(timing_passes_loose(4.5, &a, &b));
    }

    /// Positive control: two classes with a real, order-of-magnitude timing separation must fire
    /// the gate. A leak detector with no positive control is the same defect one level up — see
    /// `tests/detector_controls.rs` for the full interleaved-vs-labeled comparison this guards.
    #[test]
    fn separated_classes_fail_loose_gate() {
        let a: Vec<f64> = (0..100).map(|i| 1.0e-6 + (i % 3) as f64 * 1e-9).collect();
        let b: Vec<f64> = (0..100).map(|i| 2.0e-6 + (i % 3) as f64 * 1e-9).collect();
        let t = timing_t_statistic(&a, &b).expect("well-formed classes yield a statistic");
        assert!(t.abs() > 8.0, "expected the gate to fire, got t={t}");
        assert!(!timing_passes_loose(8.0, &a, &b));
    }

    /// Fail-closed: fewer than 2 samples in a class yields `None`, which `timing_passes_loose`
    /// must treat as a failure, never a pass.
    #[test]
    fn fail_closed_on_too_few_samples() {
        let a = [1.0e-6];
        let b = [1.0e-6, 1.0000001e-6];
        assert_eq!(timing_t_statistic(&a, &b), None);
        assert!(!timing_passes_loose(8.0, &a, &b));
    }

    /// Fail-closed: identical (zero-variance) classes yield `None` (Welch's SE is 0), which must
    /// also be treated as a failure, never a pass.
    #[test]
    fn fail_closed_on_zero_variance() {
        let a = [1.0e-6, 1.0e-6, 1.0e-6];
        let b = [1.0e-6, 1.0e-6, 1.0e-6];
        assert_eq!(timing_t_statistic(&a, &b), None);
        assert!(!timing_passes_loose(8.0, &a, &b));
    }
}
