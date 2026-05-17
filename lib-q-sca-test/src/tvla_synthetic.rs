//! Synthetic “trace” vectors for TVLA harness smoke tests (no acquisition hardware).
//!
//! Real TVLA requires aligned traces from a DUT; here we only validate that the statistics plumbing
//! behaves on controlled inputs.

/// Build two synthetic trace populations with a controllable mean separation (for unit tests).
pub fn synthetic_fixed_vs_random(
    traces_per_group: usize,
    fixed_mean: f64,
    random_mean: f64,
    noise: f64,
) -> (Vec<f64>, Vec<f64>) {
    let fixed: Vec<f64> = (0..traces_per_group)
        .map(|i| fixed_mean + noise * (i as f64 * 0.001).sin())
        .collect();
    let random: Vec<f64> = (0..traces_per_group)
        .map(|i| random_mean + noise * (i as f64 * 0.001).cos())
        .collect();
    (fixed, random)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TvlaConfig,
        tvla_passes,
    };

    #[test]
    fn nearly_identical_groups_pass_tvla() {
        let cfg = TvlaConfig::default();
        // Same construction as `tests::welch_near_identical_means_small_t`: means differ by ~1e-12.
        let f: Vec<f64> = (0..200).map(|i| i as f64 * 1e-9).collect();
        let r: Vec<f64> = (0..200).map(|i| i as f64 * 1e-9 + 1e-12).collect();
        assert!(tvla_passes(&cfg, &f, &r));
    }

    #[test]
    fn synthetic_trace_shapes() {
        let (a, b) = synthetic_fixed_vs_random(40, 1.0, 2.0, 0.01);
        assert_eq!(a.len(), b.len());
    }
}
