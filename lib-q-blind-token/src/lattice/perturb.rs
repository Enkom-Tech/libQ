//! Micciancio–Peikert perturbation sampler (Peikert convolution, canonical-embedding variant).
//!
//! To make a gadget preimage `x = p + [R;I]·z` a *spherical* discrete Gaussian of width `s` whose
//! distribution is independent of the trapdoor `R`, the perturbation `p` must have covariance
//! `Σ = s²·I − s_g²·[R;I][R;I]^*` (`^*` = ring/Hermitian conjugate). We sample `p` by Peikert's
//! convolution: sample a continuous Gaussian `z = L·g` with `L L^* = Σ − r²·I` (ring Cholesky), then
//! round each coordinate with a width-`r` discrete Gaussian.
//!
//! The ring Cholesky is computed per canonical-embedding slot (`X^1024+1` evaluated at its complex
//! roots), where ring multiplication is pointwise. Feeding a **real** `g` through the embedding keeps
//! the conjugate symmetry automatic, so the output is real without manual pairing bookkeeping.
//!
//! Convention: widths are `ρ_s` parameters (real variance `s²/2π`). Correctness is validated by the
//! spherical-covariance test in [`crate::lattice::trapdoor`] / this module — a wrong scaling or a
//! wrong Cholesky makes the empirical covariance of `x` non-spherical or `R`-dependent.

use alloc::vec::Vec;

use rand_core::{
    CryptoRng,
    Rng,
};

use super::gadget::GADGET_LEN;
use super::gaussian::sample_discrete_gaussian;
use super::ring::{
    N,
    Rq,
    centered_coeffs,
    poly_from_i64,
};

/// Rounding width for the convolution (must exceed the smoothing parameter of `Z`).
pub const ROUND_WIDTH: f64 = 3.0;

const DIM: usize = super::trapdoor::MBAR + GADGET_LEN;

#[derive(Clone, Copy)]
struct Cpx {
    re: f64,
    im: f64,
}

impl Cpx {
    const ZERO: Cpx = Cpx { re: 0.0, im: 0.0 };
    #[inline]
    fn new(re: f64, im: f64) -> Self {
        Self { re, im }
    }
    #[inline]
    fn add(self, o: Cpx) -> Cpx {
        Cpx::new(self.re + o.re, self.im + o.im)
    }
    #[inline]
    fn sub(self, o: Cpx) -> Cpx {
        Cpx::new(self.re - o.re, self.im - o.im)
    }
    #[inline]
    fn mul(self, o: Cpx) -> Cpx {
        Cpx::new(
            self.re * o.re - self.im * o.im,
            self.re * o.im + self.im * o.re,
        )
    }
    #[inline]
    fn conj(self) -> Cpx {
        Cpx::new(self.re, -self.im)
    }
    #[inline]
    fn scale(self, k: f64) -> Cpx {
        Cpx::new(self.re * k, self.im * k)
    }
}

/// Roots `exp(iπ m / N)` for `m in 0..2N`, so `ζ_j^t = roots[((2j+1)·t) mod 2N]`.
fn make_roots() -> Vec<Cpx> {
    let mut v = Vec::with_capacity(2 * N);
    for m in 0..2 * N {
        let theta = core::f64::consts::PI * (m as f64) / (N as f64);
        v.push(Cpx::new(theta.cos(), theta.sin()));
    }
    v
}

/// In-place radix-2 iterative FFT computing `A[j] = Σ_t a[t]·exp(sign·i2π j t / n)` (`sign = ±1`,
/// unnormalized). `n` must be a power of two.
fn fft(a: &mut [Cpx], sign: f64) {
    let n = a.len();
    // Bit-reversal permutation.
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j |= bit;
        if i < j {
            a.swap(i, j);
        }
    }
    let mut len = 2usize;
    while len <= n {
        let ang = sign * 2.0 * core::f64::consts::PI / (len as f64);
        let wlen = Cpx::new(ang.cos(), ang.sin());
        let mut i = 0usize;
        while i < n {
            let mut w = Cpx::new(1.0, 0.0);
            for k in 0..len / 2 {
                let u = a[i + k];
                let v = a[i + k + len / 2].mul(w);
                a[i + k] = u.add(v);
                a[i + k + len / 2] = u.sub(v);
                w = w.mul(wlen);
            }
            i += len;
        }
        len <<= 1;
    }
}

/// Canonical embedding of real coefficients: `out[j] = Σ_t c[t]·ζ_j^t`, `ζ_j = exp(iπ(2j+1)/N)`.
/// Computed as `out = FFT₊(c ⊙ ψ)` with `ψ[t] = exp(iπ t/N) = roots[t]` — an O(N log N) negacyclic
/// transform equivalent to the naive sum at the odd roots of `X^N + 1`.
fn embed(c: &[f64; N], roots: &[Cpx]) -> Vec<Cpx> {
    let mut d: Vec<Cpx> = (0..N).map(|t| roots[t].scale(c[t])).collect();
    fft(&mut d, 1.0);
    d
}

/// Inverse embedding: `out[t] = Re( (1/N)·conj(ψ[t])·Σ_j slots[j]·exp(-i2π j t/N) )`.
fn inverse_embed(slots: &[Cpx], roots: &[Cpx]) -> [f64; N] {
    let mut tmp = slots.to_vec();
    fft(&mut tmp, -1.0);
    let inv_n = 1.0 / (N as f64);
    let mut out = [0.0f64; N];
    for (t, ot) in out.iter_mut().enumerate() {
        *ot = roots[t].conj().mul(tmp[t]).re * inv_n;
    }
    out
}

/// Lower-triangular complex Cholesky `M = L L^H` of a Hermitian PSD matrix; `None` if not PSD.
fn cholesky(m: &[[Cpx; DIM]; DIM]) -> Option<[[Cpx; DIM]; DIM]> {
    let mut l = [[Cpx::ZERO; DIM]; DIM];
    for i in 0..DIM {
        for j in 0..=i {
            // s = M[i][j] - Σ_{k<j} L[i][k] conj(L[j][k]).
            let mut s = m[i][j];
            for k in 0..j {
                s = s.sub(l[i][k].mul(l[j][k].conj()));
            }
            if i == j {
                // Diagonal must be real positive.
                if s.re <= 0.0 || s.re.is_nan() {
                    return None;
                }
                l[i][j] = Cpx::new(s.re.sqrt(), 0.0);
            } else {
                let denom = l[j][j].re;
                if denom == 0.0 {
                    return None;
                }
                l[i][j] = s.scale(1.0 / denom);
            }
        }
    }
    Some(l)
}

/// Precomputed per-slot Cholesky factors of `Σ − r²I` for one trapdoor.
pub struct PerturbSampler {
    roots: Vec<Cpx>,
    /// `l[slot]` is the lower-triangular factor of `Ĉ_slot`.
    l: Vec<[[Cpx; DIM]; DIM]>,
}

impl PerturbSampler {
    /// Build the sampler for output width `s` and gadget width `s_g` given the trapdoor `R`. The
    /// covariance `Σ = s²I − s_g²[R;I][R;I]^*` depends only on `R`, not on `Ā`.
    ///
    /// Returns `None` if `Σ − r²I` is not positive definite in some slot (the `R` draw was too
    /// large for the chosen output width `s`); the caller should resample `R`.
    #[must_use]
    pub fn new(r: &[Vec<Rq>], s: f64, s_g: f64) -> Option<Self> {
        let roots = make_roots();
        let mbar = super::trapdoor::MBAR;
        let gl = GADGET_LEN;

        // `T = [R; I]` (DIM × GADGET_LEN). The bottom `GADGET_LEN` rows embed to the *exact*
        // identity (a constant-1 entry embeds to 1 in every slot), so only the `R̂` block carries
        // real structure. Embed just the `R` rows, transposed to per-slot contiguous storage
        // (`rslot[slot][a·gl + l] = R̂[a][l][slot]`) for cache-friendly covariance assembly.
        let mut rhat: Vec<Vec<Cpx>> = Vec::with_capacity(mbar * gl);
        for a in 0..mbar {
            for l in 0..gl {
                let c = centered_coeffs(&r[a][l]);
                let coeffs: [f64; N] = core::array::from_fn(|t| c[t] as f64);
                rhat.push(embed(&coeffs, &roots));
            }
        }
        let mut rslot: Vec<Vec<Cpx>> = (0..N).map(|_| alloc::vec![Cpx::ZERO; mbar * gl]).collect();
        for idx in 0..mbar * gl {
            let v = &rhat[idx];
            for slot in 0..N {
                rslot[slot][idx] = v[slot];
            }
        }

        let r2 = ROUND_WIDTH * ROUND_WIDTH;
        let diag = s * s - r2;
        let sg2 = s_g * s_g;

        let mut l_factors = Vec::with_capacity(N);
        for slot in 0..N {
            let rs = &rslot[slot];
            // Ĉ = diag·I − s_g²·[R;I][R;I]^* with the block structure
            //   [ [R̂R̂^*, R̂], [R̂^*, I] ].
            let mut mat = [[Cpx::ZERO; DIM]; DIM];
            // top-left (R̂R̂^*): mbar × mbar.
            for a in 0..mbar {
                for b in 0..mbar {
                    let mut acc = Cpx::ZERO;
                    for l in 0..gl {
                        acc = acc.add(rs[a * gl + l].mul(rs[b * gl + l].conj()));
                    }
                    let mut entry = acc.scale(-sg2);
                    if a == b {
                        entry = entry.add(Cpx::new(diag, 0.0));
                    }
                    mat[a][b] = entry;
                }
            }
            // top-right / bottom-left (±R̂): Ĉ[a][mbar+m] = −s_g²·R̂[a][m].
            for a in 0..mbar {
                for m in 0..gl {
                    let e = rs[a * gl + m].scale(-sg2);
                    mat[a][mbar + m] = e;
                    mat[mbar + m][a] = e.conj();
                }
            }
            // bottom-right (diag − s_g²)·I on the gadget block (identity·identity^* = I).
            for m in 0..gl {
                mat[mbar + m][mbar + m] = Cpx::new(diag - sg2, 0.0);
            }
            let l = cholesky(&mat)?;
            l_factors.push(l);
        }

        Some(Self {
            roots,
            l: l_factors,
        })
    }

    /// Sample a perturbation `p` (DIM ring elements) with covariance `Σ = s²I − s_g²[R;I][R;I]^*`.
    pub fn sample<R: CryptoRng + Rng>(&self, rng: &mut R) -> Vec<Rq> {
        // Continuous standard `g`: DIM ring elements, each coefficient ~ N(0, 1/2π).
        let std = 1.0 / (2.0 * core::f64::consts::PI).sqrt();
        let mut g_hat: Vec<Vec<Cpx>> = Vec::with_capacity(DIM);
        for _ in 0..DIM {
            let coeffs: [f64; N] = core::array::from_fn(|_| std_normal(rng) * std);
            g_hat.push(embed(&coeffs, &self.roots));
        }

        // z_a[slot] = Σ_b L_slot[a][b] · ĝ_b[slot]; then inverse-embed and round with width r.
        let mut out = Vec::with_capacity(DIM);
        for a_idx in 0..DIM {
            let mut z_slots = alloc::vec![Cpx::ZERO; N];
            for (slot, zs) in z_slots.iter_mut().enumerate() {
                let mut acc = Cpx::ZERO;
                for b_idx in 0..=a_idx {
                    acc = acc.add(self.l[slot][a_idx][b_idx].mul(g_hat[b_idx][slot]));
                }
                *zs = acc;
            }
            let z_real = inverse_embed(&z_slots, &self.roots);
            let rounded: [i64; N] =
                core::array::from_fn(|t| sample_discrete_gaussian(rng, ROUND_WIDTH, z_real[t]));
            out.push(poly_from_i64(&rounded));
        }
        out
    }
}

/// Standard normal via Box–Muller.
fn std_normal<R: CryptoRng + Rng>(rng: &mut R) -> f64 {
    let mut b = [0u8; 16];
    rng.fill_bytes(&mut b);
    let u1 = ((u64::from_le_bytes(b[0..8].try_into().unwrap()) >> 11) as f64) *
        (1.0 / ((1u64 << 53) as f64));
    let u2 = ((u64::from_le_bytes(b[8..16].try_into().unwrap()) >> 11) as f64) *
        (1.0 / ((1u64 << 53) as f64));
    let u1 = u1.max(f64::MIN_POSITIVE);
    (-2.0 * u1.ln()).sqrt() * (2.0 * core::f64::consts::PI * u2).cos()
}

#[cfg(test)]
mod tests {
    use lib_q_random::new_deterministic_rng;

    use super::*;
    use crate::lattice::ring::ring_mul;

    fn approx_eq_coeffs(a: &[f64; N], b: &[f64; N], tol: f64) -> bool {
        a.iter().zip(b.iter()).all(|(x, y)| (x - y).abs() < tol)
    }

    #[test]
    fn embed_inverse_roundtrip() {
        let roots = make_roots();
        let mut rng = new_deterministic_rng([0x90u8; 32]);
        // embed is only ever applied to *small* values (trapdoor entries, continuous Gaussians);
        // a uniform poly (coeffs ~ q ≈ 2^46) would lose the 1e-3 tolerance to f64 rounding.
        let p = crate::lattice::ring::sample_gaussian_poly(&mut rng, 50.0);
        let c = centered_coeffs(&p);
        let cf: [f64; N] = core::array::from_fn(|t| c[t] as f64);
        let back = inverse_embed(&embed(&cf, &roots), &roots);
        assert!(approx_eq_coeffs(&cf, &back, 1e-3), "embed∘inverse ≠ id");
    }

    #[test]
    fn embed_is_multiplicative() {
        let roots = make_roots();
        let mut rng = new_deterministic_rng([0x91u8; 32]);
        // Use small polys so the product coefficients stay exact in f64.
        let a = crate::lattice::ring::sample_gaussian_poly(&mut rng, 5.0);
        let b = crate::lattice::ring::sample_gaussian_poly(&mut rng, 5.0);
        let prod = ring_mul(&a, &b);
        let ca = centered_coeffs(&a);
        let cb = centered_coeffs(&b);
        let cp = centered_coeffs(&prod);
        let fa: [f64; N] = core::array::from_fn(|t| ca[t] as f64);
        let fb: [f64; N] = core::array::from_fn(|t| cb[t] as f64);
        let fp: [f64; N] = core::array::from_fn(|t| cp[t] as f64);
        let ea = embed(&fa, &roots);
        let eb = embed(&fb, &roots);
        let prod_hat: Vec<Cpx> = ea.iter().zip(eb.iter()).map(|(x, y)| x.mul(*y)).collect();
        let back = inverse_embed(&prod_hat, &roots);
        // back ≈ fp (mod q, but products are small enough to compare centered directly).
        assert!(
            approx_eq_coeffs(&fp, &back, 1e-1),
            "embed not multiplicative"
        );
    }
}
