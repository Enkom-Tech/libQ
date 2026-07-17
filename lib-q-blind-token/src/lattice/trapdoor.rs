//! Micciancio–Peikert gadget trapdoor over `R_q` and GPV preimage sampling.
//!
//! Module rank `n = 1`. The public matrix is a row of `MBAR + GADGET_LEN` ring elements
//! `A = [Ā | G − Ā·R]` with `Ā = [1, a_1, …, a_{m̄-1}]` (`MBAR = m̄`) and gadget
//! `G = (1, 2, …, 2^{k-1})`. The trapdoor is the short Gaussian matrix `R ∈ R_q^{m̄×k}`. The defining
//! identity `A·[R; I_k] = G` lets the holder map any syndrome to a short preimage via the gadget
//! sampler.
//!
//! `m̄` is chosen so that `[Ā | Ā·R]` is statistically close to uniform (leftover-hash trapdoor
//! hiding), so the issuer matrix `A` is indistinguishable from uniform *without* a Module-LWE
//! assumption — see `LIBQ_API.md` §3. For `q ≈ 2^51`, `s_r = 4`, this needs `m̄ = 18`.
//!
//! Preimage sampling ([`Trapdoor::sample_preimage`]) uses the Micciancio–Peikert perturbation
//! method (see [`super::perturb`]) so the output `x` is a spherical discrete Gaussian whose
//! distribution does **not** depend on `R` — this is what protects the trapdoor (one-more
//! unforgeability) and is validated empirically by the covariance test.

use alloc::vec::Vec;

use rand_core::{
    CryptoRng,
    Rng,
};

use super::gadget::{
    GADGET_LEN,
    GadgetSampler,
};
use super::perturb::PerturbSampler;
use super::ring::{
    Rq,
    const_poly,
    ring_add,
    ring_mul,
    ring_sub,
    sample_gaussian_poly,
    sample_uniform_poly,
};

/// Width of the `Ā = [1, a_1, …, a_{m̄-1}]` part. Chosen for statistical trapdoor hiding at
/// `q ≈ 2^51`, `s_r = 4` (leftover-hash leftover `≥ 2λ`).
pub const MBAR: usize = 18;

/// Total number of ring elements in `A` and in a preimage `x`.
pub const PREIMAGE_LEN: usize = MBAR + GADGET_LEN;

/// Public matrix `A` (row of [`PREIMAGE_LEN`] ring elements).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicMatrix {
    /// `A[0..PREIMAGE_LEN]`.
    pub cols: Vec<Rq>,
}

impl PublicMatrix {
    /// `A · x = Σ_i A[i] · x[i]` (a single ring element).
    #[must_use]
    pub fn apply(&self, x: &[Rq]) -> Rq {
        assert_eq!(x.len(), self.cols.len());
        let mut acc = Rq::zero();
        for (a, xi) in self.cols.iter().zip(x.iter()) {
            acc = ring_add(&acc, &ring_mul(a, xi));
        }
        acc
    }
}

/// Gadget trapdoor secret `R ∈ R_q^{MBAR × GADGET_LEN}` plus the cached preimage sampler state.
pub struct Trapdoor {
    /// `R[i][j]`, short Gaussian (`MBAR × GADGET_LEN`, heap-allocated: at `N = 1024` each `Rq` is
    /// 8 KiB, so the full matrix is multi-MiB and must not live on the stack).
    pub r: Vec<Vec<Rq>>,
    /// Output Gaussian width `s` for preimages.
    pub width: f64,
    gadget: GadgetSampler,
    perturb: PerturbSampler,
}

/// `g_j = 2^j` as a constant ring element.
#[must_use]
pub fn gadget_poly(j: usize) -> Rq {
    const_poly(1i64 << j)
}

/// Generate `(A, trapdoor)`. `s_r` is the trapdoor Gaussian width; `width` is the output preimage
/// width `s` (must satisfy the perturbation PSD condition `s² I ⪰ s_g² · [R;I][R;I]^*`, which
/// [`PerturbSampler::new`] verifies).
pub fn trapdoor_gen<R: CryptoRng + Rng>(
    rng: &mut R,
    s_r: f64,
    width: f64,
    gadget_width: f64,
) -> (PublicMatrix, Trapdoor) {
    // Buffer the RNG: keygen draws millions of small values (Gaussian R), so per-call CSPRNG
    // overhead dominates without buffering.
    let mut br = super::rngbuf::BufRng::new(rng);
    let rng = &mut br;

    // Ā = [1, a_1, …, a_{m̄-1}] with the a_i uniform.
    let a_vec: Vec<Rq> = (0..MBAR - 1).map(|_| sample_uniform_poly(rng)).collect();

    // R: MBAR × k short Gaussian (heap). Resample if the perturbation covariance is not PD for
    // `width` (a rare large draw); the trapdoor is valid for any short R that admits the sampler.
    let (r, perturb) = loop {
        let mut r: Vec<Vec<Rq>> = Vec::with_capacity(MBAR);
        for _ in 0..MBAR {
            let mut row = Vec::with_capacity(GADGET_LEN);
            for _ in 0..GADGET_LEN {
                row.push(sample_gaussian_poly(rng, s_r));
            }
            r.push(row);
        }
        if let Some(perturb) = PerturbSampler::new(&r, width, gadget_width) {
            break (r, perturb);
        }
    };

    // A = [Ā | (g_j − Ā·R[·][j])_j], with Ā·R[·][j] = r[0][j] + Σ_i a_i·r[i+1][j].
    let mut cols = Vec::with_capacity(PREIMAGE_LEN);
    cols.push(const_poly(1));
    for ai in &a_vec {
        cols.push(ai.clone());
    }
    for j in 0..GADGET_LEN {
        let mut a_r = r[0][j].clone();
        for (i, ai) in a_vec.iter().enumerate() {
            a_r = ring_add(&a_r, &ring_mul(ai, &r[i + 1][j]));
        }
        cols.push(ring_sub(&gadget_poly(j), &a_r));
    }

    let gadget = GadgetSampler::new(gadget_width);
    (
        PublicMatrix { cols },
        Trapdoor {
            r,
            width,
            gadget,
            perturb,
        },
    )
}

impl Trapdoor {
    /// `[R; I_k] · z` — the `PREIMAGE_LEN`-vector whose top `MBAR` entries are `R·z` and whose
    /// bottom `k` entries are `z`.
    #[must_use]
    fn apply_r_stack(&self, z: &[Rq]) -> Vec<Rq> {
        let mut out = Vec::with_capacity(PREIMAGE_LEN);
        for ri in &self.r {
            let mut acc = Rq::zero();
            for (rij, zj) in ri.iter().zip(z.iter()) {
                acc = ring_add(&acc, &ring_mul(rij, zj));
            }
            out.push(acc);
        }
        out.extend(z.iter().cloned());
        out
    }

    /// Sample a short preimage `x` with `A·x = u` (`A` is the matrix returned alongside this
    /// trapdoor). The distribution of `x` is a spherical discrete Gaussian of width `self.width`,
    /// independent of `R`.
    pub fn sample_preimage<R: CryptoRng + Rng>(
        &self,
        rng: &mut R,
        public: &PublicMatrix,
        u: &Rq,
    ) -> Vec<Rq> {
        let mut br = super::rngbuf::BufRng::new(rng);
        let rng = &mut br;
        // 1. Perturbation p (covariance s²I − s_g²[R;I][R;I]^*).
        let p = self.perturb.sample(rng);
        // 2. Coset target v = u − A·p.
        let ap = public.apply(&p);
        let v = ring_sub(u, &ap);
        // 3. Gadget preimage z with g·z = v (per coefficient).
        let z = self.gadget_preimage(rng, &v);
        // 4. x = p + [R;I]·z.
        let stack = self.apply_r_stack(&z);
        p.iter()
            .zip(stack.iter())
            .map(|(pi, si)| ring_add(pi, si))
            .collect()
    }

    /// Sample `z ∈ R_q^k` with `g·z = v` by sampling each of the `N` coefficient cosets. Returns a
    /// `GADGET_LEN`-vector of ring elements (heap-allocated — the digit table is multi-MiB at
    /// `N = 1024`).
    fn gadget_preimage<R: CryptoRng + Rng>(&self, rng: &mut R, v: &Rq) -> Vec<Rq> {
        use super::ring::{
            N,
            poly_from_i64,
        };

        // For each ring coefficient position, sample a k-vector; assemble k ring elements.
        let mut digits: Vec<[i64; N]> = alloc::vec![[0i64; N]; GADGET_LEN];
        let v_coeffs = super::ring::centered_coeffs(v);
        for (coeff_idx, &vc) in v_coeffs.iter().enumerate() {
            let z = self.gadget.sample_coset(rng, vc);
            for (g_idx, &zi) in z.iter().enumerate() {
                digits[g_idx][coeff_idx] = zi;
            }
        }
        digits.iter().map(poly_from_i64).collect()
    }
}

#[cfg(test)]
mod tests {
    use lib_q_random::new_deterministic_rng;

    use super::*;
    use crate::lattice::ring::ring_infinity_norm;

    /// `A·[R;I] = G` holds exactly for every gadget column.
    #[test]
    fn trapdoor_identity_holds() {
        let mut rng = new_deterministic_rng([0x01u8; 32]);
        let (public, td) = trapdoor_gen(
            &mut rng,
            4.0,
            5248.0,
            super::super::gadget::GADGET_GAUSSIAN_WIDTH,
        );
        for j in 0..GADGET_LEN {
            // Column j of [R;I]: (r[0][j], …, r[MBAR-1][j], e_j).
            let mut col: Vec<Rq> = (0..MBAR).map(|row| td.r[row][j].clone()).collect();
            for i in 0..GADGET_LEN {
                col.push(if i == j { const_poly(1) } else { Rq::zero() });
            }
            let got = public.apply(&col);
            assert_eq!(
                super::super::ring::centered_coeffs(&got),
                super::super::ring::centered_coeffs(&gadget_poly(j)),
                "A·[R;I] column {j} ≠ g_{j}",
            );
        }
    }

    /// Constant-time regression guard: the persistent secret f64 operands of the online
    /// perturbation apply (the Cholesky factors) are never subnormal, so no denormal-assist timing
    /// channel exists on the `L·ĝ` mul-add chain. Runs in release (debug_asserts are compiled out
    /// there); pairs with the `debug_assert`s covering the transient FFT/accumulation intermediates.
    #[test]
    fn perturb_factors_are_never_subnormal() {
        for seed in [0x01u8, 0x5A, 0xC3] {
            let mut rng = new_deterministic_rng([seed; 32]);
            let (_public, td) = trapdoor_gen(
                &mut rng,
                4.0,
                5248.0,
                super::super::gadget::GADGET_GAUSSIAN_WIDTH,
            );
            assert!(
                td.perturb.all_factors_normal(),
                "Cholesky factor held a subnormal f64 (seed {seed:#x}) — CT range argument broken",
            );
        }
    }

    /// Security validator: the preimage `x` must be a *spherical* discrete Gaussian of width `s`
    /// (per-coefficient variance `s²/2π`, no cross-coordinate correlation), independent of `R`. A
    /// broken perturbation (wrong covariance/scaling) makes the variance wrong or the coordinates
    /// `R`-correlated. This is the empirical analogue of "the sampler does not leak the trapdoor".
    #[test]
    #[ignore = "statistical (300 preimages); run with: cargo test --release -- --ignored"]
    fn preimage_covariance_is_spherical() {
        use super::super::ring::N;

        let mut rng = new_deterministic_rng([0x33u8; 32]);
        let s = 5248.0_f64;
        let (public, td) = trapdoor_gen(
            &mut rng,
            4.0,
            s,
            super::super::gadget::GADGET_GAUSSIAN_WIDTH,
        );
        let u = sample_uniform_poly(&mut rng);

        let m = 300usize;
        // Pool over all N coefficients of two coordinates for variance, plus their cross product.
        let (a_idx, b_idx) = (0usize, 1usize);
        let mut sum_a = 0.0;
        let mut sum_sq_a = 0.0;
        let mut sum_cross = 0.0;
        let mut count = 0.0;
        for _ in 0..m {
            let x = td.sample_preimage(&mut rng, &public, &u);
            let ca = super::super::ring::centered_coeffs(&x[a_idx]);
            let cb = super::super::ring::centered_coeffs(&x[b_idx]);
            for t in 0..N {
                let va = ca[t] as f64;
                let vb = cb[t] as f64;
                sum_a += va;
                sum_sq_a += va * va;
                sum_cross += va * vb;
                count += 1.0;
            }
        }
        let mean_a = sum_a / count;
        let var_a = sum_sq_a / count - mean_a * mean_a;
        let cross = sum_cross / count;
        let expected_var = s * s / (2.0 * core::f64::consts::PI);
        // Absolute scaling correct within 12%.
        assert!(
            (var_a - expected_var).abs() / expected_var < 0.12,
            "variance {var_a} vs expected {expected_var} (scaling off)",
        );
        // No R-leakage: cross-correlation small relative to variance.
        assert!(
            cross.abs() / expected_var < 0.08,
            "cross-covariance {cross} too large vs var {expected_var} (R leaks into x)",
        );
    }

    /// `sample_preimage` yields `A·x = u` exactly and a short `x`.
    #[test]
    fn preimage_is_exact_and_short() {
        let mut rng = new_deterministic_rng([0x02u8; 32]);
        let (public, td) = trapdoor_gen(
            &mut rng,
            4.0,
            5248.0,
            super::super::gadget::GADGET_GAUSSIAN_WIDTH,
        );
        for _ in 0..3 {
            let u = sample_uniform_poly(&mut rng);
            let x = td.sample_preimage(&mut rng, &public, &u);
            assert_eq!(x.len(), PREIMAGE_LEN);
            let ax = public.apply(&x);
            assert_eq!(
                super::super::ring::centered_coeffs(&ax),
                super::super::ring::centered_coeffs(&u),
                "A·x ≠ u",
            );
            let max = x.iter().map(ring_infinity_norm).max().unwrap();
            // s = 1800 ⇒ σ ≈ 718 ⇒ tail ~ 12σ·… but ∞-norm stays well below q/2.
            assert!(
                max < (super::super::ring::Q / 4),
                "preimage not short: {max}"
            );
        }
    }
}
