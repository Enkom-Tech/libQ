//! Sampling of `A`, of the key/randomness distribution `B` and of the scalar noise `D`.
//!
//! Table 5 fixes `B = B_4` (centered binomial, eta = 4) and `D = D_64` (a "Gaussian-like
//! distribution of standard deviation sigma", §5.3: "`D_sigma` a Gaussian-like distribution of
//! standard deviation `sigma`, encompassing centered binomials, sums of uniforms, and discrete
//! Gaussians").
//!
//! ## Which `D_64` this crate instantiates, and why that one
//!
//! `D_64` here is a **sum of uniforms**, the middle option the paper explicitly permits:
//!
//! ```text
//! f = (u_1 + ... + u_6) - (v_1 + ... + v_6),   each u_i, v_i uniform on {0, ..., 63}
//! ```
//!
//! `Var(u_i - v_i) = 2 * (2^12 - 1)/12 = (2^12 - 1)/6`, so `Var(f) = 6 * (2^12 - 1)/6 = 4095`
//! and `sigma = sqrt(4095) = 63.9922`. That is `D_64` to within 0.012%.
//!
//! The alternative readings are both worse here. A centered binomial with `Var = eta/2 = 4096`
//! needs `eta = 8192`, i.e. 2 KB of XOF per coefficient (1 MB per encapsulation). A discrete
//! Gaussian needs rejection sampling, which is the classic side-channel foothold in lattice
//! signatures. The sum-of-uniforms form draws from power-of-two ranges, so it needs no rejection,
//! has no secret-dependent branch, and consumes a fixed 9 bytes per coefficient (twelve 6-bit
//! fields). Constant-time by construction.

use alloc::vec::Vec;

use crate::arith::Modulus;
use crate::hash;
use crate::params::{
    N,
    ParamSet,
    Poly,
};

/// Bytes of XOF consumed per coefficient of a `B_eta` sample (`2*eta` bits, eta = 4 -> 1 byte).
#[must_use]
pub const fn cbd_bytes_per_poly(eta: u32) -> usize {
    N * (2 * eta as usize) / 8
}

/// Bytes of XOF consumed per polynomial of a `D_64` sample: twelve 6-bit fields per coefficient.
pub const D_BYTES_PER_POLY: usize = N * 9;

/// Number of `(u - v)` terms summed to build one `D_64` coefficient.
const D_REPS: usize = 6;
/// Bit width of each uniform draw in the `D_64` sum.
const D_UNIFORM_BITS: u32 = 6;

/// Exact variance of the instantiated `D_64`: `D_REPS * (2^(2b) - 1) / 6` with `b = 6`.
pub const D_VARIANCE: u32 = 4095;

/// Centered binomial `B_eta` over one polynomial. `buf` must be [`cbd_bytes_per_poly`] long.
#[must_use]
pub fn cbd(buf: &[u8], eta: u32, m: &Modulus) -> Poly {
    assert_eq!(buf.len(), cbd_bytes_per_poly(eta), "cbd: wrong buffer size");
    assert_eq!(eta, 4, "cbd: only eta = 4 (Table 5's B_4) is implemented");
    let mut out = [0i32; N];
    for (i, &b) in buf.iter().enumerate() {
        let a = i64::from((b & 0x0F).count_ones());
        let c = i64::from((b >> 4).count_ones());
        out[i] = m.reduce(a - c);
    }
    out
}

/// `D_64` over one polynomial. `buf` must be [`D_BYTES_PER_POLY`] long.
#[must_use]
pub fn sample_d(buf: &[u8], m: &Modulus) -> Poly {
    assert_eq!(buf.len(), D_BYTES_PER_POLY, "sample_d: wrong buffer size");
    let mask = (1u128 << D_UNIFORM_BITS) - 1;
    let mut out = [0i32; N];
    for i in 0..N {
        let mut word = [0u8; 16];
        word[..9].copy_from_slice(&buf[i * 9..i * 9 + 9]);
        let bits = u128::from_le_bytes(word);
        let mut acc: i64 = 0;
        for j in 0..D_REPS {
            let u =
                ((bits >> (u32::try_from(j).expect("D_REPS fits") * D_UNIFORM_BITS)) & mask) as i64;
            let v = ((bits >> (u32::try_from(j + D_REPS).expect("D_REPS fits") * D_UNIFORM_BITS)) &
                mask) as i64;
            acc += u - v;
        }
        out[i] = m.reduce(acc);
    }
    out
}

/// Expand the public matrix `A` (k x k, row-major) from the public-parameter seed.
///
/// Rejection sampling on a **public** value: the rejection pattern depends only on `rho`, which
/// is public by definition, so its non-constant-time behaviour leaks nothing secret. This is the
/// same argument ML-KEM's `SampleNTT` relies on.
#[must_use]
pub fn expand_a(p: &ParamSet, rho: &[u8; 32]) -> Vec<Vec<Poly>> {
    let bits = p.pk_bits;
    let mask = (1u32 << bits) - 1;
    let mut mat = Vec::with_capacity(p.k);
    for i in 0..p.k {
        let mut row = Vec::with_capacity(p.k);
        for j in 0..p.k {
            let mut poly = [0i32; N];
            let mut filled = 0usize;
            let mut chunk = 1usize;
            // Grow the squeeze if a run of rejections exhausts it. Acceptance is 93.8% at
            // q = 7681 (13 bits) and 57.8% at q = 9473 (14 bits), so 4x is ample first time.
            while filled < N {
                let want = 4 * N * 2 * chunk;
                let stream = hash::matrix_xof(
                    p,
                    rho,
                    u32::try_from(i).expect("k fits in u32"),
                    u32::try_from(j).expect("k fits in u32"),
                    want,
                );
                filled = 0;
                poly = [0i32; N];
                for pair in stream.as_chunks::<2>().0 {
                    if filled == N {
                        break;
                    }
                    let val = (u32::from(pair[0]) | (u32::from(pair[1]) << 8)) & mask;
                    if val < p.q.cast_unsigned() {
                        poly[filled] = val.cast_signed();
                        filled += 1;
                    }
                }
                chunk *= 2;
            }
            row.push(poly);
        }
        mat.push(row);
    }
    mat
}

/// Sample the key-generation pair `(s, e) <-$ B^{2k}` from a 32-byte seed.
#[must_use]
pub fn keygen_noise(p: &ParamSet, seed: &[u8; 32], m: &Modulus) -> (Vec<Poly>, Vec<Poly>) {
    let per = cbd_bytes_per_poly(p.eta);
    let stream = hash::keygen_noise_xof(p, seed, 2 * p.k * per);
    let mut s = Vec::with_capacity(p.k);
    let mut e = Vec::with_capacity(p.k);
    for idx in 0..p.k {
        s.push(cbd(&stream[idx * per..(idx + 1) * per], p.eta, m));
    }
    for idx in p.k..2 * p.k {
        e.push(cbd(&stream[idx * per..(idx + 1) * per], p.eta, m));
    }
    (s, e)
}

/// Sample the shared encryption randomness `(s_C, e_C) <-$ B^{2k}` from `r_C`.
#[must_use]
pub fn rc_noise(p: &ParamSet, rc: &[u8; 32], m: &Modulus) -> (Vec<Poly>, Vec<Poly>) {
    let per = cbd_bytes_per_poly(p.eta);
    let stream = hash::rc_noise_xof(p, rc, 2 * p.k * per);
    let mut s = Vec::with_capacity(p.k);
    let mut e = Vec::with_capacity(p.k);
    for idx in 0..p.k {
        s.push(cbd(&stream[idx * per..(idx + 1) * per], p.eta, m));
    }
    for idx in p.k..2 * p.k {
        e.push(cbd(&stream[idx * per..(idx + 1) * per], p.eta, m));
    }
    (s, e)
}

/// Sample the scalar noise `f <-$ D_64` from `r_L` (`side = 0`) or `r_R` (`side = 1`).
#[must_use]
pub fn f_noise(p: &ParamSet, r: &[u8; 32], side: u8, m: &Modulus) -> Poly {
    let stream = hash::f_noise_xof(p, r, side, D_BYTES_PER_POLY);
    sample_d(&stream, m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{
        ALL,
        MAUL768,
    };

    #[test]
    fn d64_has_the_variance_the_paper_asks_for() {
        // Empirical check that the instantiated sum-of-uniforms really is sigma ~= 64, not just
        // documented as such. 40 polynomials = 10240 samples.
        let p = &MAUL768;
        let m = Modulus::new(p);
        let mut sum_sq: i64 = 0;
        let mut sum: i64 = 0;
        let mut count: i64 = 0;
        for i in 0..40u8 {
            let f = f_noise(p, &[i; 32], i % 2, &m);
            for c in f {
                let v = m.center(c);
                sum += v;
                sum_sq += v * v;
                count += 1;
            }
        }
        let var = sum_sq / count - (sum / count) * (sum / count);
        // True variance is exactly D_VARIANCE = 4095 (sigma = 63.99). Allow +/-12% sampling error
        // on 10240 draws.
        let lo = i64::from(D_VARIANCE) * 88 / 100;
        let hi = i64::from(D_VARIANCE) * 112 / 100;
        assert!(
            var > lo && var < hi,
            "D_64 empirical variance {var} outside [{lo}, {hi}] (target {D_VARIANCE})"
        );
        assert!(sum.abs() < 4 * 64 * 101, "D_64 is not centered: sum {sum}");
    }

    #[test]
    fn d64_range_is_the_sum_of_uniforms_range() {
        let p = &MAUL768;
        let m = Modulus::new(p);
        for i in 0..8u8 {
            let f = f_noise(p, &[i; 32], 0, &m);
            for c in f {
                let v = m.center(c);
                assert!(
                    (-378..=378).contains(&v),
                    "D_64 coefficient {v} out of range"
                );
            }
        }
    }

    #[test]
    fn cbd_stays_in_the_b4_range_and_is_centered() {
        let p = &MAUL768;
        let m = Modulus::new(p);
        let (s, e) = keygen_noise(p, &[9u8; 32], &m);
        let mut sum: i64 = 0;
        let mut n = 0i64;
        for poly in s.iter().chain(e.iter()) {
            for c in poly {
                let v = m.center(*c);
                assert!((-4..=4).contains(&v), "B_4 coefficient {v} out of range");
                sum += v;
                n += 1;
            }
        }
        assert_eq!(n, 2 * (p.k as i64) * (N as i64));
        assert!(sum.abs() < 200, "B_4 is not centered: sum {sum}");
    }

    #[test]
    fn expand_a_is_deterministic_and_in_range() {
        for p in ALL {
            let a = expand_a(p, &[3u8; 32]);
            let b = expand_a(p, &[3u8; 32]);
            assert_eq!(a, b, "{}: expand_a not deterministic", p.name);
            assert_eq!(a.len(), p.k);
            for row in &a {
                assert_eq!(row.len(), p.k);
                for poly in row {
                    for c in poly {
                        assert!(*c >= 0 && *c < p.q, "{}: A coefficient {c} >= q", p.name);
                    }
                }
            }
            let c = expand_a(p, &[4u8; 32]);
            assert_ne!(a, c, "{}: expand_a ignores the seed", p.name);
        }
    }

    #[test]
    fn noise_sampling_is_seed_dependent() {
        let p = &MAUL768;
        let m = Modulus::new(p);
        let (s1, _) = keygen_noise(p, &[1u8; 32], &m);
        let (s2, _) = keygen_noise(p, &[2u8; 32], &m);
        assert_ne!(s1, s2, "keygen noise ignores the seed");
        assert_ne!(
            f_noise(p, &[1u8; 32], 0, &m),
            f_noise(p, &[2u8; 32], 0, &m),
            "f noise ignores the seed"
        );
    }
}
