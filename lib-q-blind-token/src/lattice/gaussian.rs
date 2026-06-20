//! Discrete Gaussian sampler `D_{Z,s,c}` over the integers.
//!
//! Convention: `ρ_s(x) = exp(-π (x - c)² / s²)`, so `s` is the Gaussian *width* parameter and the
//! standard deviation is `σ = s / √(2π)`. Sampling is rejection-based over a tail-cut window; this
//! is **research-grade and not constant-time** (the accept/reject branch and the `exp` are
//! data-dependent). It is adequate for the provisional, non-load-bearing blind-signature prototype;
//! a production instantiation must use a constant-time base sampler (e.g. a CDT or Karney sampler).

use rand_core::{
    CryptoRng,
    Rng,
};

/// Tail cut: samples are confined to `c ± TAIL_CUT·s`. `ρ_s(TAIL_CUT·s) = exp(-π·TAIL_CUT²)` is
/// `< 2^-650` at `TAIL_CUT = 12`, far below any statistical-distance budget we rely on.
const TAIL_CUT: f64 = 12.0;

/// Draw a fresh `u64` from the RNG.
#[inline]
fn next_u64<R: Rng>(rng: &mut R) -> u64 {
    let mut b = [0u8; 8];
    rng.fill_bytes(&mut b);
    u64::from_le_bytes(b)
}

/// Uniform integer in `[0, n)` (`n > 0`) by rejection (no modulo bias).
#[inline]
fn uniform_below<R: Rng>(rng: &mut R, n: u64) -> u64 {
    debug_assert!(n > 0);
    if n == 1 {
        return 0;
    }
    // Largest multiple of `n` that fits in u64; reject the remainder zone.
    let zone = u64::MAX - (u64::MAX % n);
    loop {
        let r = next_u64(rng);
        if r < zone {
            return r % n;
        }
    }
}

/// Uniform `f64` in `[0, 1)` with 53 bits of entropy.
#[inline]
fn uniform_unit<R: Rng>(rng: &mut R) -> f64 {
    // Top 53 bits → exact multiples of 2^-53 in [0,1).
    ((next_u64(rng) >> 11) as f64) * (1.0_f64 / ((1u64 << 53) as f64))
}

/// Above this width the discrete Gaussian is statistically indistinguishable from a rounded
/// continuous Gaussian (the per-step discretization error is far below any distance budget we use),
/// so we take the fast non-rejection path. Small widths use the exact rejection sampler.
const FAST_PATH_WIDTH: f64 = 50.0;

/// Sample `x ∈ Z` from the discrete Gaussian `D_{Z,s,c}` with `ρ_s(x) = exp(-π (x-c)²/s²)`.
///
/// Panics in debug if `s <= 0`. For small `s` the result lies in
/// `[⌊c - TAIL_CUT·s⌋, ⌈c + TAIL_CUT·s⌉]`; for large `s` it is a rounded continuous sample.
pub fn sample_discrete_gaussian<R: CryptoRng + Rng>(rng: &mut R, s: f64, c: f64) -> i64 {
    debug_assert!(s > 0.0 && s.is_finite() && c.is_finite());
    if s >= FAST_PATH_WIDTH {
        // σ = s/√(2π); round a continuous N(c, σ²) sample.
        let sigma = s / (2.0 * core::f64::consts::PI).sqrt();
        return (c + sigma * std_normal(rng)).round() as i64;
    }
    let lo = (c - TAIL_CUT * s).floor() as i64;
    let hi = (c + TAIL_CUT * s).ceil() as i64;
    let span = (hi - lo + 1) as u64;
    let inv_s2 = 1.0 / (s * s);
    loop {
        let x = lo + uniform_below(rng, span) as i64;
        let diff = (x as f64) - c;
        let rho = (-core::f64::consts::PI * diff * diff * inv_s2).exp();
        if uniform_unit(rng) < rho {
            return x;
        }
    }
}

/// Standard normal `N(0,1)` via Box–Muller.
fn std_normal<R: CryptoRng + Rng>(rng: &mut R) -> f64 {
    let u1 = uniform_unit(rng).max(f64::MIN_POSITIVE);
    let u2 = uniform_unit(rng);
    (-2.0 * u1.ln()).sqrt() * (2.0 * core::f64::consts::PI * u2).cos()
}

/// Standard deviation `σ = s / √(2π)` for the width parameter `s`.
#[must_use]
pub fn sigma_of(s: f64) -> f64 {
    s / (2.0 * core::f64::consts::PI).sqrt()
}

#[cfg(test)]
mod tests {
    use lib_q_random::new_deterministic_rng;

    use super::*;

    /// Empirical mean and variance match `c` and `σ² = s²/(2π)` within tolerance.
    #[test]
    #[ignore = "statistical (60k samples); run with: cargo test --release -- --ignored"]
    fn moments_match_parameters() {
        let mut rng = new_deterministic_rng([0x37; 32]);
        let s = 12.0_f64;
        let c = 0.0_f64;
        let n = 60_000usize;
        let mut sum = 0.0_f64;
        let mut sum_sq = 0.0_f64;
        let mut max_abs = 0i64;
        for _ in 0..n {
            let x = sample_discrete_gaussian(&mut rng, s, c);
            sum += x as f64;
            sum_sq += (x as f64) * (x as f64);
            max_abs = max_abs.max(x.abs());
        }
        let mean = sum / n as f64;
        let var = sum_sq / n as f64 - mean * mean;
        let expected_var = sigma_of(s).powi(2);
        assert!(mean.abs() < 0.1, "mean {mean} not ≈ 0");
        assert!(
            (var - expected_var).abs() / expected_var < 0.05,
            "var {var} vs expected {expected_var}",
        );
        // Tail cut respected.
        assert!(
            (max_abs as f64) <= TAIL_CUT * s,
            "sample {max_abs} beyond tail cut"
        );
    }

    /// A non-zero center shifts the distribution.
    #[test]
    #[ignore = "statistical (30k samples); run with: cargo test --release -- --ignored"]
    fn nonzero_center_shifts_mean() {
        let mut rng = new_deterministic_rng([0x42; 32]);
        let s = 8.0_f64;
        let c = 5.3_f64;
        let n = 30_000usize;
        let mut sum = 0.0_f64;
        for _ in 0..n {
            sum += sample_discrete_gaussian(&mut rng, s, c) as f64;
        }
        let mean = sum / n as f64;
        assert!((mean - c).abs() < 0.1, "mean {mean} not ≈ {c}");
    }
}
