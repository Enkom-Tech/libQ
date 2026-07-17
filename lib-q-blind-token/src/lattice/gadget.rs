//! Binary gadget `g = (1, 2, 4, …, 2^{k-1})` over `Z_q` and its coset preimage sampler.
//!
//! `k = GADGET_LEN` is chosen so `2^{k-1} ≤ q < 2^k`, i.e. the gadget spans `[0, 2^k) ⊇ [0, q)`.
//! Two operations are provided:
//!
//! * [`decompose_bits`] — exact binary decomposition: `Σ_i 2^i · bits[i] = u` for `u ∈ [0, q)`.
//! * [`GadgetSampler::sample_coset`] — sample a short `z ∈ Z^k` from a discrete Gaussian over the
//!   coset `{ z : Σ_i 2^i z_i ≡ u (mod q) }`, via Klein/GPV nearest-plane sampling on the canonical
//!   basis of `Λ^⊥_q(g^T)`. This is the scalar `SampleG` used coefficient-wise by the ring trapdoor.
//!
//! Correctness (`g·z ≡ u`) is exact and unit-tested; the Gaussian distribution is what the security
//! argument relies on and is the part that needs RED-zone scrutiny.

use rand_core::{
    CryptoRng,
    Rng,
};

use super::gaussian::sample_discrete_gaussian;

/// Modulus `q` as an `i64` (from the self-contained ring).
pub const Q: i64 = super::ring::Q;

/// Gadget length `k` such that `2^{k-1} ≤ q < 2^k`. For `q ≈ 2^51`, `k = 51`.
pub const GADGET_LEN: usize = 51;

/// Default Gaussian width for the coset `G`-sampler. Must exceed `‖B̃‖ · η_ε(Z)`; the canonical
/// `Λ^⊥_q(g^T)` basis has Gram–Schmidt norms `≤ √5 ≈ 2.236`, so `6.0` leaves comfortable margin.
pub const GADGET_GAUSSIAN_WIDTH: f64 = 6.0;

/// `g_i = 2^i` for `i in 0..GADGET_LEN`.
#[must_use]
pub fn gadget_vector() -> [i64; GADGET_LEN] {
    let mut g = [0i64; GADGET_LEN];
    for (i, gi) in g.iter_mut().enumerate() {
        *gi = 1i64 << i;
    }
    g
}

/// Exact binary decomposition of `u ∈ [0, q)`: returns bits `b` with `Σ_i 2^i b_i = u`.
#[must_use]
pub fn decompose_bits(u: i64) -> [i64; GADGET_LEN] {
    debug_assert!((0..Q).contains(&u));
    let mut bits = [0i64; GADGET_LEN];
    let mut v = u;
    for b in &mut bits {
        *b = v & 1;
        v >>= 1;
    }
    debug_assert_eq!(v, 0, "u did not fit in GADGET_LEN bits");
    bits
}

/// `Σ_i 2^i z_i mod q`, normalized to `[0, q)`. Accepts arbitrary integer `z_i`.
#[must_use]
pub fn gadget_inner(z: &[i64; GADGET_LEN]) -> i64 {
    let mut acc: i128 = 0;
    for (i, &zi) in z.iter().enumerate() {
        acc += (1i128 << i) * zi as i128;
    }
    acc.rem_euclid(Q as i128) as i64
}

/// Coset `G`-preimage sampler holding the precomputed Gram–Schmidt data of the `Λ^⊥_q(g^T)` basis.
///
/// Basis columns (canonical for `g = (1,2,…,2^{k-1})`, modulus `q` with bits `q_i`):
/// * `b_j = 2·e_j − e_{j+1}` for `j = 0..k-2`  (so `g·b_j = 2·2^j − 2^{j+1} = 0`),
/// * `b_{k-1} = (q_0, q_1, …, q_{k-1})`        (so `g·b_{k-1} = q ≡ 0`).
pub struct GadgetSampler {
    /// Basis columns, integer (`basis[j][i]` = row `i` of column `j`).
    basis: [[f64; GADGET_LEN]; GADGET_LEN],
    /// Integer copy of the basis for exact lattice-point reconstruction.
    basis_int: [[i64; GADGET_LEN]; GADGET_LEN],
    /// Gram–Schmidt vectors `b̃_j`.
    gso: [[f64; GADGET_LEN]; GADGET_LEN],
    /// `‖b̃_j‖²`.
    gso_sq_norm: [f64; GADGET_LEN],
    /// Width parameter `s`.
    width: f64,
}

impl GadgetSampler {
    /// Build the sampler for width `s` (use [`GADGET_GAUSSIAN_WIDTH`] unless overriding for tests).
    #[must_use]
    pub fn new(width: f64) -> Self {
        let k = GADGET_LEN;
        let mut basis_int = [[0i64; GADGET_LEN]; GADGET_LEN];
        // Bidiagonal columns 0..k-2.
        for j in 0..k - 1 {
            basis_int[j][j] = 2;
            basis_int[j + 1][j] = -1;
        }
        // Last column = bits of q.
        let mut qv = Q;
        for i in 0..k {
            basis_int[i][k - 1] = qv & 1;
            qv >>= 1;
        }

        let mut basis = [[0.0f64; GADGET_LEN]; GADGET_LEN];
        for j in 0..k {
            for i in 0..k {
                basis[j][i] = basis_int[i][j] as f64;
            }
        }

        // Classical Gram–Schmidt over columns b_0..b_{k-1}.
        let mut gso = [[0.0f64; GADGET_LEN]; GADGET_LEN];
        let mut gso_sq_norm = [0.0f64; GADGET_LEN];
        for j in 0..k {
            let mut v = basis[j];
            for p in 0..j {
                let mu = dot(&basis[j], &gso[p]) / gso_sq_norm[p];
                for i in 0..k {
                    v[i] -= mu * gso[p][i];
                }
            }
            gso[j] = v;
            gso_sq_norm[j] = dot(&v, &v);
        }

        Self {
            basis,
            basis_int,
            gso,
            gso_sq_norm,
            width,
        }
    }

    /// Sample a short `z ∈ Z^k` from `D_{coset(u), s}` with `Σ_i 2^i z_i ≡ u (mod q)`.
    pub fn sample_coset<R: CryptoRng + Rng>(&self, rng: &mut R, u: i64) -> [i64; GADGET_LEN] {
        let k = GADGET_LEN;
        let u = u.rem_euclid(Q);
        // Deterministic coset representative z0 (bits), g·z0 = u exactly.
        let z0 = decompose_bits(u);
        let target: [f64; GADGET_LEN] = core::array::from_fn(|i| z0[i] as f64);

        // Klein/GPV: sample lattice point w ∈ Λ(B) ~ D_{Λ, s, target}, then z = z0 − w.
        let mut c = target;
        let mut coeffs = [0i64; GADGET_LEN];
        for j in (0..k).rev() {
            let cprime = dot(&c, &self.gso[j]) / self.gso_sq_norm[j];
            let sprime = self.width / self.gso_sq_norm[j].sqrt();
            let zj = sample_discrete_gaussian(rng, sprime, cprime);
            coeffs[j] = zj;
            // c := c − zj · b_j.
            for i in 0..k {
                c[i] -= zj as f64 * self.basis[j][i];
            }
        }
        // Lattice point w = Σ_j coeffs_j · b_j (exact integer), then z = z0 − w.
        let mut z = z0;
        for j in 0..k {
            if coeffs[j] == 0 {
                continue;
            }
            for i in 0..k {
                z[i] -= coeffs[j] * self.basis_int[i][j];
            }
        }
        z
    }
}

#[inline]
fn dot(a: &[f64; GADGET_LEN], b: &[f64; GADGET_LEN]) -> f64 {
    let mut s = 0.0;
    for i in 0..GADGET_LEN {
        s += a[i] * b[i];
    }
    s
}

#[cfg(test)]
mod tests {
    use lib_q_random::new_deterministic_rng;

    use super::*;

    #[test]
    fn gadget_spans_modulus() {
        // 2^{k-1} ≤ q < 2^k.
        const { assert!((1i64 << (GADGET_LEN - 1)) <= Q) };
        const { assert!(Q < (1i64 << GADGET_LEN)) };
    }

    #[test]
    fn decompose_is_exact() {
        for &u in &[0i64, 1, 2, 255, 4_194_303, Q - 1, 1234567] {
            let bits = decompose_bits(u);
            assert!(bits.iter().all(|&b| b == 0 || b == 1));
            assert_eq!(gadget_inner(&bits), u, "decompose({u})");
        }
    }

    #[test]
    fn coset_sampler_is_exact_and_short() {
        let sampler = GadgetSampler::new(GADGET_GAUSSIAN_WIDTH);
        let mut rng = new_deterministic_rng([0x5A; 32]);
        let mut max_abs = 0i64;
        for trial in 0..300u64 {
            let u = (trial.wrapping_mul(2_654_435_761) % Q as u64) as i64;
            let z = sampler.sample_coset(&mut rng, u);
            // Exact coset membership.
            assert_eq!(gadget_inner(&z), u, "g·z ≢ u for u={u}");
            for &zi in &z {
                max_abs = max_abs.max(zi.abs());
            }
        }
        // Short: Klein on a √5-GSO basis with width 6 keeps |z_i| well under, say, 80.
        assert!(max_abs < 80, "coset sample too large: {max_abs}");
    }
}
