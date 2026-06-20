//! Discrete Gaussian sampler `D_{Z,s,c}` over the integers.
//!
//! Convention: `ρ_s(x) = exp(-π (x - c)² / s²)`, so `s` is the Gaussian *width* parameter and the
//! standard deviation is `σ = s / √(2π)`.
//!
//! Two samplers live here, with different constant-time postures (see `SECURITY_ANALYSIS.md` §8):
//!
//! * [`sample_secret_coeff_ct`] — a **constant-time CDT** sampler at the fixed secret width
//!   [`CT_SECRET_WIDTH`]. This is the load-bearing path (it samples the secret key `a₀`): a uniform
//!   `u64` is compared against a precomputed cumulative table with a **branchless** scan (no
//!   data-dependent control flow, no `exp` in the hot path, fixed iteration count). Table precision
//!   is `f64` (≈53-bit), giving a statistical distance to the ideal `D_{Z,s}` of `≲ 2⁻⁴³` over a
//!   whole polynomial — adequate for this research-grade instance; a production build would widen the
//!   table to 128-bit fixed point.
//! * [`sample_discrete_gaussian`] — the general rejection sampler for **mask** widths (the FS mask
//!   `y` and the signing mask `y_r`). It is **not constant-time** (data-dependent accept/reject and
//!   `exp`). For masks this is acceptable in the *distributed* (rejection-free aggregation) path; the
//!   single-signer rejection path must not be used against a timing adversary for secret keys.

use std::sync::OnceLock;

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
    ((next_u64(rng) >> 11) as f64) * (1.0_f64 / ((1u64 << 53) as f64))
}

/// Above this width the discrete Gaussian is statistically indistinguishable from a rounded
/// continuous Gaussian, so we take the fast non-rejection path. Small widths use the exact sampler.
const FAST_PATH_WIDTH: f64 = 50.0;

/// Sample `x ∈ Z` from the discrete Gaussian `D_{Z,s,c}` with `ρ_s(x) = exp(-π (x-c)²/s²)`.
pub fn sample_discrete_gaussian<R: CryptoRng + Rng>(rng: &mut R, s: f64, c: f64) -> i64 {
    debug_assert!(s > 0.0 && s.is_finite() && c.is_finite());
    if s >= FAST_PATH_WIDTH {
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

// ---------------------------------------------------------------------------
// Constant-time CDT sampler for the fixed secret width
// ---------------------------------------------------------------------------

/// Fixed Gaussian width for the constant-time secret sampler (must equal `dkg::SECRET_KEY_WIDTH`).
pub const CT_SECRET_WIDTH: f64 = 8.0;

/// Magnitude cap of the CDT. `ρ_s(x) < 2⁻⁸⁰` beyond `x ≈ 34` at `s = 8`, so 40 covers the full
/// `u64`-representable support with margin.
const CDT_ZMAX: usize = 40;

/// Branchless `u64` less-than: returns `1` iff `a < b`, else `0`. The borrow out of the 128-bit
/// subtraction lands in bit 64; no branch, no data-dependent timing.
#[inline]
fn ct_lt_u64(a: u64, b: u64) -> i64 {
    (((a as u128).wrapping_sub(b as u128) >> 64) & 1) as i64
}

/// Cumulative tail table `cdt[m] = ⌊2⁶⁴ · Pr[|X| ≥ m+1]⌋` for the magnitude of `X ~ D_{Z, s}` at
/// `s = CT_SECRET_WIDTH`. Magnitude `= Σ_m [r < cdt[m]]` for a uniform `r`, so the deeper the tail,
/// the larger the magnitude — computed with a branchless count.
fn secret_cdt() -> &'static [u64; CDT_ZMAX] {
    static T: OnceLock<[u64; CDT_ZMAX]> = OnceLock::new();
    T.get_or_init(|| {
        let s = CT_SECRET_WIDTH;
        let inv_s2 = 1.0 / (s * s);
        let rho = |x: i64| (-core::f64::consts::PI * (x * x) as f64 * inv_s2).exp();
        // a[0] = ρ(0); a[x] = 2·ρ(x) for x ≥ 1 (combine ±x into one magnitude).
        let mut z = rho(0);
        for x in 1..=(CDT_ZMAX as i64) {
            z += 2.0 * rho(x);
        }
        let two64 = 2.0_f64.powi(64);
        let mut table = [0u64; CDT_ZMAX];
        for (m, slot) in table.iter_mut().enumerate() {
            // tail = Pr[mag ≥ m+1] = (Σ_{x≥m+1} 2·ρ(x)) / Z.
            let mut tail = 0.0;
            for x in (m as i64 + 1)..=(CDT_ZMAX as i64) {
                tail += 2.0 * rho(x);
            }
            let scaled = (tail / z) * two64;
            *slot = if scaled >= two64 {
                u64::MAX
            } else {
                scaled as u64
            };
        }
        table
    })
}

/// Sample one secret coefficient from `D_{Z, CT_SECRET_WIDTH, 0}` in **constant time**: a branchless
/// scan of the CDT yields the magnitude, then a uniform sign. The iteration count is fixed
/// (`CDT_ZMAX`) and independent of the sampled value. `mag = 0` maps to `0` regardless of the sign
/// bit, so no branch is needed.
pub fn sample_secret_coeff_ct<R: CryptoRng + Rng>(rng: &mut R) -> i64 {
    let table = secret_cdt();
    let r = next_u64(rng);
    let mut mag: i64 = 0;
    for &t in table.iter() {
        mag += ct_lt_u64(r, t);
    }
    let sign_bit = (next_u64(rng) & 1) as i64;
    mag * (1 - 2 * sign_bit)
}

#[cfg(test)]
mod ct_tests {
    use lib_q_random::new_deterministic_rng;

    use super::*;

    #[test]
    fn ct_lt_matches_naive() {
        let cases = [
            (0u64, 0u64),
            (0, 1),
            (1, 0),
            (u64::MAX, 0),
            (0, u64::MAX),
            (1 << 63, 1 << 63),
            (5, 7),
            (7, 5),
        ];
        for (a, b) in cases {
            assert_eq!(ct_lt_u64(a, b), i64::from(a < b), "ct_lt({a},{b})");
        }
    }

    #[test]
    fn secret_cdt_sampler_matches_target_moments() {
        // Empirical mean ≈ 0 and variance ≈ σ² = (s/√(2π))² for s = CT_SECRET_WIDTH.
        let mut rng = new_deterministic_rng([0x9Cu8; 32]);
        let n = 200_000;
        let (mut sum, mut sumsq, mut maxabs) = (0i64, 0i128, 0i64);
        for _ in 0..n {
            let x = sample_secret_coeff_ct(&mut rng);
            sum += x;
            sumsq += i128::from(x) * i128::from(x);
            maxabs = maxabs.max(x.abs());
        }
        let mean = sum as f64 / n as f64;
        let var = sumsq as f64 / n as f64 - mean * mean;
        let sigma = sigma_of(CT_SECRET_WIDTH);
        assert!(mean.abs() < 0.05, "mean {mean} should be ≈ 0");
        assert!(
            (var.sqrt() - sigma).abs() < 0.15,
            "stddev {} ≈ σ {sigma}",
            var.sqrt()
        );
        assert!(
            maxabs < CDT_ZMAX as i64,
            "samples stay within the table support"
        );
    }
}
