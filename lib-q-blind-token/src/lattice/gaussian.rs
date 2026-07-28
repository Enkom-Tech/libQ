//! Discrete Gaussian sampler `D_{Z,s,c}` over the integers.
//!
//! Convention: `ρ_s(x) = exp(-π (x - c)² / s²)`, so `s` is the Gaussian *width* parameter and the
//! standard deviation is `σ = s / √(2π)`.
//!
//! Two paths:
//! * **small `σ`** (`s < FAST_PATH_WIDTH`) — routed to the isochronous constant-time sampler
//!   [`super::gaussian_ct::SamplerZ`]; timing is independent of the secret center and output.
//! * **large `σ`** (`s ≥ FAST_PATH_WIDTH`) — rounding of a continuous `N(c, σ²)` sample, which is
//!   branchless (no rejection) and thus already isochronous. A CDT of size `≈12σ` is impractical
//!   here, and the discrete/continuous statistical distance is negligible at these widths.
//!
//! Hot loops that draw many samples at one fixed width should build a [`super::gaussian_ct::SamplerZ`]
//! once and reuse it (this free function rebuilds the base table per call).

use rand_core::{
    CryptoRng,
    Rng,
};

/// Draw a fresh `u64` from the RNG.
#[inline]
fn next_u64<R: Rng>(rng: &mut R) -> u64 {
    let mut b = [0u8; 8];
    rng.fill_bytes(&mut b);
    u64::from_le_bytes(b)
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
pub const FAST_PATH_WIDTH: f64 = 50.0;

/// Sample `x ∈ Z` from the discrete Gaussian `D_{Z,s,c}` with `ρ_s(x) = exp(-π (x-c)²/s²)`.
///
/// Panics in debug if `s <= 0`. For small `s` the result lies in
/// `[⌊c - TAIL_CUT·s⌋, ⌈c + TAIL_CUT·s⌉]`; for large `s` it is a rounded continuous sample.
pub fn sample_discrete_gaussian<R: CryptoRng + Rng>(rng: &mut R, s: f64, c: f64) -> i64 {
    debug_assert!(s > 0.0 && s.is_finite() && c.is_finite());
    if s >= FAST_PATH_WIDTH {
        // σ = s/√(2π); round a continuous N(c, σ²) sample. Branchless (no rejection).
        let sigma = s / (2.0 * core::f64::consts::PI).sqrt();
        return (c + sigma * std_normal(rng)).round() as i64;
    }
    // Small width: isochronous constant-time sampler. Rebuilds the base table per call — callers in
    // hot loops should hold a `SamplerZ` instead (see `sample_gaussian_poly`, `perturb`, `gadget`).
    super::gaussian_ct::SamplerZ::new(s).sample(rng, c)
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
        // Tail cut respected (the isochronous sampler truncates the base at ≈13σ ≈ 5.2·s).
        assert!(
            (max_abs as f64) <= 12.0 * s,
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
