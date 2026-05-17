//! Wall-clock timing harness in the spirit of dudect (software timing leakage probes).
//!
//! This is **not** a substitute for instrumented power traces or a calibrated dudect build; it
//! provides a cheap regression hook that secret-dependent branches or allocations often perturb.

/// Split `samples` into two halves and run a Welch *t*-test on the means (same helper semantics as
/// TVLA fixed-vs-random with scalar outputs).
pub fn timing_t_statistic(samples: &[f64]) -> Option<f64> {
    if samples.len() < 4 {
        return None;
    }
    let mid = samples.len() / 2;
    let (a, b) = samples.split_at(mid);
    crate::welch_t_statistic(a, b)
}

/// Returns true if \\(|t| < \\) `threshold` (loose CI default: large timing noise dominates).
pub fn timing_passes_loose(threshold: f64, samples: &[f64]) -> bool {
    match timing_t_statistic(samples) {
        Some(t) => t.abs() < threshold,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_noise_passes_loose_gate() {
        let mut v: Vec<f64> = (0..200).map(|i| 1e-6 + (i % 3) as f64 * 1e-9).collect();
        assert!(timing_passes_loose(4.5, &v));
        // Shift second half — still small effect if any
        for x in v.iter_mut().skip(100) {
            *x += 1e-12;
        }
        assert!(timing_passes_loose(4.5, &v));
    }
}
