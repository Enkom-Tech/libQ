//! Isochronous (constant-time) discrete Gaussian sampler `D_{Z,s,c}`.
//!
//! This replaces the naive accept/reject sampler for the **small-width** sites (trapdoor `R`,
//! attribute, gadget coset, perturbation rounding), whose running time and branch pattern leaked
//! the secret center and the sampled value. The construction is the Howe–Prest–Ricosset–Rossi
//! isochronous sampler (the one used in Falcon):
//!
//! * a **constant-time base sampler** for the one-sided `D_{Z⁺,σ}` via a reverse-CDT that is
//!   scanned in full every draw (no early exit, no data-dependent index), and
//! * a **branchless `BerExp`** — a Bernoulli trial of probability `exp(-x)` computed with a
//!   fixed-degree polynomial (no `libm` `exp`, no branch), so per-trial time is constant.
//!
//! The accept/reject loop still runs a variable number of iterations, but that count depends only
//! on the **public** width `σ` — never on the secret center `c` or the output `z` (each trial has
//! the same constant cost and the acceptance probability `exp(-x)` is realised in constant time).
//! That is the isochrony property: timing is independent of secret inputs at a fixed call site.
//!
//! Large-width sites (`S_SIGN`, `S_Y`; `σ ≳ 2·10³`) keep the branchless continuous-rounding fast
//! path in [`super::gaussian`]: rounding a continuous sample has no secret-dependent branch, so it
//! is already isochronous, and a CDT table of size `≈ 12σ` would be impractical there.
//!
//! Scope / honesty: this removes the *algorithmic* (control-flow / branch / loop-count) leak. It
//! does not claim protection against f64 micro-architectural timing of the polynomial arithmetic
//! itself (the mul/add sequence is fixed and data-oblivious, but IEEE-754 subnormal handling can
//! vary by platform); the perturbation/GSO float linear algebra upstream is likewise not audited
//! for constant-time. This is a research-grade hardening of the dominant leak, not a certified
//! constant-time implementation. See `LIBQ_API.md` §7.

use rand_core::{
    CryptoRng,
    Rng,
};

/// Tail cut for the base sampler support, in units of `σ`. `exp(-13²/2) < 2^-122`, so truncating
/// `D_{Z⁺,σ}` at `⌈TAIL_SIGMA·σ⌉` loses statistical distance far below any budget we rely on.
const TAIL_SIGMA: f64 = 13.0;

/// `1 / ln 2`, for range reduction `x = k·ln2 + r`.
const LOG2_E: f64 = core::f64::consts::LOG2_E;
/// `ln 2`.
const LN2: f64 = core::f64::consts::LN_2;

/// Draw a fresh `u64` from the RNG.
#[inline]
fn next_u64<R: Rng>(rng: &mut R) -> u64 {
    let mut b = [0u8; 8];
    rng.fill_bytes(&mut b);
    u64::from_le_bytes(b)
}

/// Branchless `exp(-r)` for `r ∈ [0, ln2]`, returning a value in `(0.5, 1]`.
///
/// Degree-10 Taylor series of `e^{-r}` evaluated by Horner. Over `[0, ln2]` the truncation error is
/// `< r^11/11! < (ln2)^11/11! ≈ 3·10^-11 ≈ 2^-35`. This is a per-trial acceptance bias, not a formal
/// statistical-distance bound at the 128-bit level (Falcon uses a ≈2^-47 minimax polynomial + a Rényi
/// argument); it is adequate for this crate's PROVISIONAL unlinkability, and the degree can be raised
/// to Falcon's minimax coefficients drop-in (same branchless structure) if a formal bound is needed.
/// It is a fixed sequence of `f64` fused multiply-adds with **no branch and no table index**, so it
/// runs in data-oblivious time (unlike a `libm` `exp` call, whose latency is argument-dependent).
#[inline]
fn exp_neg_reduced(r: f64) -> f64 {
    // Coefficients 1/k! for k = 10..0, applied by Horner on (-r).
    const INV_FACT: [f64; 11] = [
        1.0,
        1.0,
        1.0 / 2.0,
        1.0 / 6.0,
        1.0 / 24.0,
        1.0 / 120.0,
        1.0 / 720.0,
        1.0 / 5040.0,
        1.0 / 40320.0,
        1.0 / 362880.0,
        1.0 / 3628800.0,
    ];
    let x = -r;
    let mut acc = INV_FACT[10];
    // Horner: Σ x^k / k!   (indices 9..0)
    let mut k = 9usize;
    loop {
        acc = acc * x + INV_FACT[k];
        if k == 0 {
            break;
        }
        k -= 1;
    }
    acc
}

/// Constant-time Bernoulli trial returning `1` with probability `exp(-x)` for `x ≥ 0`.
///
/// Range-reduce `x = k·ln2 + r`, `r ∈ [0, ln2)`, so `exp(-x) = exp(-r)·2^-k` with
/// `exp(-r) ∈ (0.5, 1]`. We form the 64-bit fixed-point mantissa `p = exp(-r)·2^64`, shift right by
/// `k` (branchlessly clamped to `[0,63]`), and compare against a fresh uniform `u64`. The only
/// data-dependent quantity is the *value* of the shift/compare operands, not the control flow.
#[inline]
fn ber_exp<R: CryptoRng + Rng>(rng: &mut R, x: f64) -> bool {
    // Range reduction. x ≥ 0 by construction of the caller.
    let kf = (x * LOG2_E).floor();
    let r = x - kf * LN2; // r ∈ [0, ln2)
    // Work in 63-bit fixed point so nothing can overflow: exp(-r) ∈ (0.5, 1] maps to
    // mantissa = exp(-r)·2^63 ∈ (2^62, 2^63], and 2^63 is exactly representable as f64/u64.
    let mantissa = (exp_neg_reduced(r) * ((1u64 << 63) as f64)) as u64; // ≤ 2^63
    // Branchless clamp of the shift amount to [0, 63]. For k ≥ 64, exp(-x) ≈ 0, and a shift of 63
    // drives the accept probability below 2^-63 (indistinguishable from 0 for our budgets). k ≥ 0.
    let k = kf as i64;
    let over = ((63 - k) >> 63) & 1; // 1 when k > 63, else 0
    let shift = ((k & (over - 1)) | (63 & (-over))) as u32 & 63; // k when in-range, else 63
    // p = exp(-x)·2^63 = mantissa >> k. Compare against a 63-bit uniform; accept iff u < p. When
    // exp(-r) == 1 and k == 0, p == 2^63 and every 63-bit u < 2^63, so acceptance is certain.
    let p = mantissa >> shift;
    let u = next_u64(rng) >> 1; // 63-bit uniform in [0, 2^63)
    u < p
}

/// A constant-time discrete-Gaussian sampler for a **fixed public width** `s`.
///
/// Holds the reverse-CDT of the one-sided base distribution `D_{Z⁺,σ}` (`σ = s/√(2π)`). Reused
/// across many draws that share the same width (e.g. all `N` coefficients of a polynomial, or all
/// draws at one gadget GSO level) so the table is built once.
pub struct SamplerZ {
    /// Standard deviation `σ = s/√(2π)`.
    sigma: f64,
    /// `rcdt[i] = round(2^64 · P[X ≥ i+1])` for the base `D_{Z⁺,σ}`, `X ∈ {0,…,cap}`.
    /// Scanned in full every draw; `rcdt.len() == cap`.
    rcdt: alloc::vec::Vec<u64>,
    /// `1 / (2σ²)`, the exponent scale for `BerExp`.
    inv_two_sigma_sq: f64,
}

impl SamplerZ {
    /// Build a sampler for width parameter `s` (`ρ_s(x)=exp(-π x²/s²)`, so `σ = s/√(2π)`).
    pub fn new(s: f64) -> Self {
        debug_assert!(s > 0.0 && s.is_finite());
        let sigma = s / (2.0 * core::f64::consts::PI).sqrt();
        let cap = (TAIL_SIGMA * sigma).ceil() as usize + 1;
        // Un-normalised base weights ρ(k) = exp(-k²/2σ²), k = 0..=cap.
        let inv_two_sigma_sq = 1.0 / (2.0 * sigma * sigma);
        let mut weights = alloc::vec![0.0f64; cap + 1];
        let mut total = 0.0f64;
        for (k, w) in weights.iter_mut().enumerate() {
            let kk = k as f64;
            *w = (-kk * kk * inv_two_sigma_sq).exp();
            total += *w;
        }
        // Reverse CDT: rcdt[i] = P[X ≥ i+1] scaled to 2^64. Tail sum from the top for accuracy.
        let scale = (1u64 << 63) as f64 * 2.0; // 2^64 as f64 (exact)
        let mut rcdt = alloc::vec![0u64; cap];
        let mut tail = 0.0f64;
        for i in (0..cap).rev() {
            tail += weights[i + 1] / total; // P[X ≥ i+1]
            // Fixed point in [0, 2^64). `scale - 1.0` rounds back to 2^64 in f64 so the `min` never
            // bites; correctness rests on Rust's saturating float→int cast pinning any 2^64 value to
            // u64::MAX (so rcdt[0] = u64::MAX ⇒ accept-prob 1 − 2^-64, negligible).
            let v = (tail * scale).min(scale - 1.0);
            rcdt[i] = v as u64;
        }
        Self {
            sigma,
            rcdt,
            inv_two_sigma_sq,
        }
    }

    /// Constant-time base draw of `z0 ~ D_{Z⁺,σ}`: full scan of the reverse-CDT, no early exit.
    #[inline]
    fn base_sample<R: CryptoRng + Rng>(&self, rng: &mut R) -> i64 {
        let u = next_u64(rng);
        let mut z0: i64 = 0;
        for &threshold in &self.rcdt {
            // Add 1 for every level whose tail probability still exceeds u. Branchless: the
            // comparison is turned into 0/1 and accumulated for the *whole* table every time.
            z0 += i64::from(u < threshold);
        }
        z0
    }

    /// Sample `v ~ D_{Z,s,c}` in isochronous time (timing independent of the secret center `c`).
    pub fn sample<R: CryptoRng + Rng>(&self, rng: &mut R, c: f64) -> i64 {
        let ci = c.floor();
        let r = c - ci; // fractional center ∈ [0,1)
        loop {
            let z0 = self.base_sample(rng);
            let b = (next_u64(rng) & 1) as i64; // sign/fold bit
            // Fold the one-sided base to a full-line candidate centred near r:
            //   b = 0 -> z = -z0   (covers z ≤ 0)
            //   b = 1 -> z =  z0+1 (covers z ≥ 1)
            let z = (2 * b - 1) * z0 + b;
            // Acceptance exponent x = ((z - r)² - z0²) / (2σ²) ≥ 0, giving output law ∝ exp(-(z-r)²/2σ²).
            let dz = z as f64 - r;
            let x = (dz * dz - (z0 * z0) as f64) * self.inv_two_sigma_sq;
            if ber_exp(rng, x) {
                return z + ci as i64;
            }
        }
    }

    /// Width's standard deviation (test/introspection helper).
    #[must_use]
    pub fn sigma(&self) -> f64 {
        self.sigma
    }
}

#[cfg(test)]
mod tests {
    use lib_q_random::new_deterministic_rng;

    use super::*;

    /// Base + fold + BerExp reproduce the target mean/variance at center 0.
    #[test]
    #[ignore = "statistical (80k samples); run with: cargo test --release -- --ignored"]
    fn centered_moments_match() {
        let mut rng = new_deterministic_rng([0x51; 32]);
        let s = 8.0_f64;
        let sampler = SamplerZ::new(s);
        let n = 80_000usize;
        let (mut sum, mut sum_sq) = (0.0f64, 0.0f64);
        for _ in 0..n {
            let x = sampler.sample(&mut rng, 0.0) as f64;
            sum += x;
            sum_sq += x * x;
        }
        let mean = sum / n as f64;
        let var = sum_sq / n as f64 - mean * mean;
        let expected_var = (s / (2.0 * core::f64::consts::PI).sqrt()).powi(2);
        assert!(mean.abs() < 0.1, "mean {mean} not ≈ 0");
        assert!(
            (var - expected_var).abs() / expected_var < 0.06,
            "var {var} vs expected {expected_var}"
        );
    }

    /// A non-integer center shifts the mean to `c` (exercises the fractional-center path).
    #[test]
    #[ignore = "statistical (60k samples); run with: cargo test --release -- --ignored"]
    fn fractional_center_shifts_mean() {
        let mut rng = new_deterministic_rng([0x52; 32]);
        let s = 6.0_f64;
        let c = 3.7_f64;
        let sampler = SamplerZ::new(s);
        let n = 60_000usize;
        let mut sum = 0.0f64;
        for _ in 0..n {
            sum += sampler.sample(&mut rng, c) as f64;
        }
        let mean = sum / n as f64;
        assert!((mean - c).abs() < 0.1, "mean {mean} not ≈ {c}");
    }

    /// `exp_neg_reduced` matches `libm` `exp` to high accuracy over the reduced range.
    #[test]
    fn exp_poly_accuracy() {
        let mut r = 0.0f64;
        while r <= core::f64::consts::LN_2 {
            let approx = exp_neg_reduced(r);
            let exact = (-r).exp();
            assert!((approx - exact).abs() < 1e-9, "exp poly off at r={r}");
            r += 0.0001;
        }
    }

    /// Regression guard for the isochrony property: the amount of randomness consumed (a proxy for
    /// running time / loop iterations) must not depend on the *secret* center. An early-exit or a
    /// center-dependent branch reintroduced into the hot path would show up as diverging draw counts
    /// between a zero center and an adversarially chosen fractional center.
    #[test]
    #[ignore = "statistical timing proxy (2x40k samples); run with: cargo test --release -- --ignored"]
    fn rng_consumption_independent_of_center() {
        use core::cell::Cell;
        use core::convert::Infallible;

        use rand_core::{
            TryCryptoRng,
            TryRng,
        };

        /// RNG wrapper counting `try_fill_bytes` calls (each sampler word-draw is one such call).
        /// `Rng`/`CryptoRng` follow for free via rand_core's blanket impls over `TryRng`.
        struct Counting<'a, R> {
            inner: R,
            draws: &'a Cell<u64>,
        }
        impl<R: TryRng<Error = Infallible>> TryRng for Counting<'_, R> {
            type Error = Infallible;
            fn try_next_u32(&mut self) -> Result<u32, Infallible> {
                self.draws.set(self.draws.get() + 1);
                self.inner.try_next_u32()
            }
            fn try_next_u64(&mut self) -> Result<u64, Infallible> {
                self.draws.set(self.draws.get() + 1);
                self.inner.try_next_u64()
            }
            fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
                self.draws.set(self.draws.get() + 1);
                self.inner.try_fill_bytes(dst)
            }
        }
        impl<R: TryCryptoRng<Error = Infallible>> TryCryptoRng for Counting<'_, R> {}

        let s = 6.0_f64;
        let sampler = SamplerZ::new(s);
        let n = 40_000usize;

        let measure = |center: f64, seed: [u8; 32]| -> f64 {
            let draws = Cell::new(0u64);
            let mut rng = Counting {
                inner: new_deterministic_rng(seed),
                draws: &draws,
            };
            for _ in 0..n {
                let _ = sampler.sample(&mut rng, center);
            }
            draws.get() as f64 / n as f64
        };

        let at_zero = measure(0.0, [0x60; 32]);
        // A "worst-case" secret center at the fractional midpoint, plus a large integer part (which
        // must be irrelevant — only the fractional part enters the acceptance test).
        let at_secret = measure(123.5, [0x61; 32]);
        let rel = (at_zero - at_secret).abs() / at_zero;
        assert!(
            rel < 0.05,
            "per-sample RNG draws differ by {:.1}% between centers ({at_zero} vs {at_secret}) — \
             possible timing leak",
            rel * 100.0
        );
    }

    /// `BerExp(0)` always accepts; `BerExp(large)` essentially never does.
    #[test]
    fn ber_exp_endpoints() {
        let mut rng = new_deterministic_rng([0x53; 32]);
        let mut accept0 = 0usize;
        let mut accept_big = 0usize;
        for _ in 0..2000 {
            if ber_exp(&mut rng, 0.0) {
                accept0 += 1;
            }
            if ber_exp(&mut rng, 40.0) {
                accept_big += 1;
            }
        }
        assert_eq!(accept0, 2000, "exp(-0)=1 must always accept");
        assert_eq!(accept_big, 0, "exp(-40) must (almost) never accept");
    }
}
