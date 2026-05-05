//! Trace acquisition hooks for TVLA-style screening (first-order Welch *t*-test).
//!
//! Real evaluations require a DUT, a scope or EM probe, trace alignment, and preprocessing. This
//! module documents the acceptance criterion and exposes **numeric** helpers only; it does not
//! implement hardware drivers.

/// Recommended first-order leakage screening threshold on \\(|t|\\) (NIST-style TVLA literature).
pub const DEFAULT_TVLA_ABS_T: f64 = 4.5;

/// Suggested minimum trace count per class for exploratory screening (public labs often use 10⁶+).
pub const SUGGESTED_TRACES_PER_CLASS: u64 = 1_000_000;

/// Returns `true` if \\(|t| < \\) [`DEFAULT_TVLA_ABS_T`].
#[must_use]
pub fn first_order_screen_passes(t_statistic: f64) -> bool {
    t_statistic.abs() < DEFAULT_TVLA_ABS_T
}

/// Map a fixed-vs-random experiment to pass/fail using [`crate::welch_t_statistic`].
#[must_use]
pub fn screen_fixed_vs_random(fixed: &[f64], random: &[f64]) -> Option<bool> {
    crate::welch_t_statistic(fixed, random).map(first_order_screen_passes)
}

#[cfg(feature = "mldsa")]
use lib_q_ml_dsa::ml_dsa_44::portable;
#[cfg(feature = "mlkem")]
use lib_q_ml_kem::{
    Decapsulate,
    Encapsulate,
    KemCore,
    MlKem768,
};

/// Collect fixed-vs-random wall-clock timings for ML-KEM decapsulation (TVLA-style smoke harness).
///
/// The `fixed` class reuses one `(dk, ct)` pair. The `random` class rotates across independently
/// generated `(dk, ct)` pairs so the secret key material varies per sample.
#[cfg(feature = "mlkem")]
pub fn mlkem_decaps_tvla_timings(samples: usize) -> (Vec<f64>, Vec<f64>) {
    let mut rng = lib_q_random::LibQRng::new_secure().expect("secure rng");
    let (fixed_dk, fixed_ek) = MlKem768::generate(&mut rng);
    let (fixed_ct, _fixed_ss) = fixed_ek.encapsulate(&mut rng).expect("encap");

    let mut random_pairs = Vec::with_capacity(samples);
    for _ in 0..samples {
        let (dk, ek) = MlKem768::generate(&mut rng);
        let (ct, _ss) = ek.encapsulate(&mut rng).expect("encap");
        random_pairs.push((dk, ct));
    }

    let fixed = crate::sample_wall_times(
        || {
            let ss = fixed_dk.decapsulate(&fixed_ct).expect("decap");
            std::hint::black_box(ss);
        },
        samples,
    );
    let mut random_idx = 0usize;
    let random = crate::sample_wall_times(
        || {
            let (dk, ct) = &random_pairs[random_idx];
            let ss = dk.decapsulate(ct).expect("decap");
            std::hint::black_box(ss);
            random_idx = (random_idx + 1) % random_pairs.len();
        },
        samples,
    );

    (fixed, random)
}

/// Collect fixed-vs-random wall-clock timings for ML-DSA signing (TVLA-style smoke harness).
///
/// The `fixed` class signs with one fixed signing key. The `random` class rotates signing keys.
#[cfg(feature = "mldsa")]
pub fn mldsa_sign_tvla_timings(samples: usize) -> (Vec<f64>, Vec<f64>) {
    let msg = b"lib-q-sca-tvla";
    let ctx = b"";
    let rnd = [0x42u8; 32];

    let fixed_kp = portable::generate_key_pair([0x11u8; 32]);
    let random_kps: Vec<_> = (0..samples)
        .map(|i| portable::generate_key_pair([i as u8; 32]))
        .collect();

    let fixed = crate::sample_wall_times(
        || {
            let sig = portable::sign(&fixed_kp.signing_key, msg, ctx, rnd).expect("sign");
            std::hint::black_box(sig);
        },
        samples,
    );
    let mut random_idx = 0usize;
    let random = crate::sample_wall_times(
        || {
            let sig =
                portable::sign(&random_kps[random_idx].signing_key, msg, ctx, rnd).expect("sign");
            std::hint::black_box(sig);
            random_idx = (random_idx + 1) % random_kps.len();
        },
        samples,
    );
    (fixed, random)
}

/// CI-friendly first-order TVLA screen for ML-KEM decapsulation.
#[cfg(feature = "mlkem")]
pub fn mlkem_decaps_tvla_screen(samples: usize) -> Option<bool> {
    let (fixed, random) = mlkem_decaps_tvla_timings(samples);
    screen_fixed_vs_random(&fixed, &random)
}

/// CI-friendly first-order TVLA screen for ML-DSA signing.
#[cfg(feature = "mldsa")]
pub fn mldsa_sign_tvla_screen(samples: usize) -> Option<bool> {
    let (fixed, random) = mldsa_sign_tvla_timings(samples);
    screen_fixed_vs_random(&fixed, &random)
}

/// CI-friendly dudect-style timing screen for ML-KEM decapsulation.
#[cfg(feature = "mlkem")]
pub fn mlkem_decaps_dudect_screen(samples: usize, threshold: f64) -> bool {
    let (fixed, random) = mlkem_decaps_tvla_timings(samples);
    let mut joined = fixed;
    joined.extend(random);
    crate::dudect::timing_passes_loose(threshold, &joined)
}

/// CI-friendly dudect-style timing screen for ML-DSA signing.
#[cfg(feature = "mldsa")]
pub fn mldsa_sign_dudect_screen(samples: usize, threshold: f64) -> bool {
    let (fixed, random) = mldsa_sign_tvla_timings(samples);
    let mut joined = fixed;
    joined.extend(random);
    crate::dudect::timing_passes_loose(threshold, &joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_sanity() {
        assert!(first_order_screen_passes(0.1));
        assert!(!first_order_screen_passes(10.0));
    }

    #[cfg(feature = "mlkem")]
    #[test]
    fn mlkem_tvla_and_dudect_smoke() {
        let _ = mlkem_decaps_tvla_screen(32).expect("t-stat");
        let _ = mlkem_decaps_dudect_screen(32, DEFAULT_TVLA_ABS_T);
    }

    #[cfg(feature = "mldsa")]
    #[test]
    fn mldsa_tvla_and_dudect_smoke() {
        let _ = mldsa_sign_tvla_screen(32).expect("t-stat");
        let _ = mldsa_sign_dudect_screen(32, DEFAULT_TVLA_ABS_T);
    }

    /// Wall-clock TVLA at scale (slow). Run: `cargo test -p lib-q-sca-test -- --ignored --nocapture`.
    ///
    /// Prints Welch *t* for manual review. The |*t*| < 4.5 gate targets **instrumented** traces; OS
    /// scheduling noise routinely violates it for `std::time::Instant` wall times, so we do not assert
    /// that threshold here.
    #[cfg(feature = "mldsa")]
    #[test]
    #[ignore = "slow: ~10k sign timings per class; for harness scale only"]
    fn mldsa_sign_tvla_screen_10k_welch_report() {
        const SAMPLES: usize = 10_000;
        let (fixed, random) = mldsa_sign_tvla_timings(SAMPLES);
        let t = crate::welch_t_statistic(&fixed, &random).expect("welch t-statistic");
        eprintln!(
            "ML-DSA Sign wall-clock Welch t (n={SAMPLES} per class): {t:.6} (first-order EM/TVLA gate is |t| < {DEFAULT_TVLA_ABS_T})"
        );
        assert!(t.is_finite(), "t-statistic must be finite");
    }
}
