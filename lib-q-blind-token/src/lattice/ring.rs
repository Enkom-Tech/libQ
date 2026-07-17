//! Self-contained ring `R_q = Z_q[X]/(X^N + 1)` for the secure blind-token instance.
//!
//! Unlike the q ≈ 2^23 prototype (which borrowed `lib_q_ring`'s ML-DSA ring), the cryptographic-
//! strength instance needs a *larger* modulus and ring dimension so that, simultaneously:
//!
//! * the Fiat–Shamir masked response `z` fits below `q/2` even with a heavy challenge (128-bit
//!   knowledge soundness, `τ = 16`), and
//! * Module-SIS on the issuer matrix `A` (the binding / one-more-unforgeability assumption) clears
//!   a **128-bit quantum** floor against the BKZ core-SVP cost model — see `LIBQ_API.md` §3/§7.
//!
//! Parameters: `N = 1024`, `q = 2 251 799 813 640 193` (prime, `q ≡ 1 (mod 2N)`, `q < 2^51`). The
//! modulus was raised from the `q ≈ 2^48` profile-1 instance (≈119-bit quantum) to this `q ≈ 2^51`
//! profile-2 instance so the quantum core-SVP margin clears 128-bit (≈130-bit; ≈143-bit classical).
//! The ring is implemented from scratch here (negacyclic NTT, validated against the schoolbook
//! product) so the crate does not depend on a fixed external modulus.

use std::sync::OnceLock;

use lib_q_sha3::{
    ExtendableOutput,
    Update,
    XofReader,
};
use rand_core::{
    CryptoRng,
    Rng,
};

use super::gaussian::sample_discrete_gaussian;

/// Ring dimension `N` (negacyclic, `X^N + 1`).
pub const N: usize = 1024;

/// Modulus `q` (prime, `q ≡ 1 (mod 2N)`, `q < 2^51`).
pub const Q: i64 = 2_251_799_813_640_193;

/// Primitive `2N`-th root of unity mod `q` (`ζ^N = -1`).
const ZETA: i64 = 833_963_715_377_153;

/// `N^{-1} mod q` (for the inverse NTT scaling).
const N_INV: i64 = 2_249_600_790_384_685;

const LOG_N: u32 = 10; // log2(N)

/// `-q^{-1} mod 2^64` (Montgomery).
const QINV: u64 = 1_645_692_721_173_581_823;
/// `(2^64)^2 mod q` (Montgomery `R²`).
const R2: u64 = 1_119_852_662_702_020;

/// An element of `R_q`, coefficients in `[0, q)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rq {
    /// Coefficients in `[0, q)`, low degree first.
    pub coeffs: [i64; N],
}

impl Rq {
    /// The zero polynomial.
    #[must_use]
    pub fn zero() -> Self {
        Self { coeffs: [0i64; N] }
    }

    /// Build from coefficients already reduced into `[0, q)`.
    #[must_use]
    pub fn from_coeffs(coeffs: [i64; N]) -> Self {
        Self { coeffs }
    }
}

/// Montgomery reduction: `t·R^{-1} mod q` for `t < q·R` (`R = 2^64`). No division.
#[inline]
fn mont_reduce(t: u128) -> i64 {
    let m = (t as u64).wrapping_mul(QINV);
    let r = ((t + (m as u128) * (Q as u128)) >> 64) as u64;
    let r = if r >= Q as u64 { r - Q as u64 } else { r };
    r as i64
}

/// `a·b mod q` for `a, b ∈ [0, q)`, via two Montgomery reductions (division-free; far faster than
/// 128-bit `%` in debug). Equivalent to `a·b mod q`: `mont(a·b) = a·b·R^{-1}`, then `·R²` undoes it.
#[inline]
fn modmul(a: i64, b: i64) -> i64 {
    let ab = mont_reduce(a as u128 * b as u128);
    mont_reduce(ab as u128 * R2 as u128)
}

#[inline]
fn modadd(a: i64, b: i64) -> i64 {
    let s = a + b;
    if s >= Q { s - Q } else { s }
}

#[inline]
fn modsub(a: i64, b: i64) -> i64 {
    let s = a - b;
    if s < 0 { s + Q } else { s }
}

#[inline]
fn bitrev(mut x: usize, bits: u32) -> usize {
    let mut r = 0usize;
    for _ in 0..bits {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}

/// Bit-reversed powers of `ζ`: `z[i] = ζ^{bitrev(i)} mod q`.
fn zetas() -> &'static [i64; N] {
    static T: OnceLock<[i64; N]> = OnceLock::new();
    T.get_or_init(|| {
        let mut pw = [0i64; N];
        let mut acc = 1i64;
        for p in pw.iter_mut() {
            *p = acc;
            acc = modmul(acc, ZETA);
        }
        let mut t = [0i64; N];
        for (i, ti) in t.iter_mut().enumerate() {
            *ti = pw[bitrev(i, LOG_N)];
        }
        t
    })
}

/// In-place forward negacyclic NTT (Cooley–Tukey butterflies).
fn ntt(a: &mut [i64; N]) {
    let z = zetas();
    let mut k = 0usize;
    let mut len = N / 2;
    while len >= 1 {
        let mut start = 0usize;
        while start < N {
            k += 1;
            let zeta = z[k];
            for j in start..start + len {
                let t = modmul(zeta, a[j + len]);
                a[j + len] = modsub(a[j], t);
                a[j] = modadd(a[j], t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// In-place inverse negacyclic NTT (Gentleman–Sande butterflies + `N^{-1}` scaling).
fn intt(a: &mut [i64; N]) {
    let z = zetas();
    let mut k = N;
    let mut len = 1usize;
    while len < N {
        let mut start = 0usize;
        while start < N {
            k -= 1;
            let zeta = Q - z[k]; // -ζ^{...} mod q
            for j in start..start + len {
                let t = a[j];
                a[j] = modadd(t, a[j + len]);
                a[j + len] = modmul(zeta, modsub(t, a[j + len]));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for x in a.iter_mut() {
        *x = modmul(*x, N_INV);
    }
}

/// Negacyclic product `a · b` in `R_q` via the NTT.
#[must_use]
pub fn ring_mul(a: &Rq, b: &Rq) -> Rq {
    let mut fa = a.coeffs;
    let mut fb = b.coeffs;
    ntt(&mut fa);
    ntt(&mut fb);
    let mut fc = [0i64; N];
    for i in 0..N {
        fc[i] = modmul(fa[i], fb[i]);
    }
    intt(&mut fc);
    Rq { coeffs: fc }
}

/// Schoolbook negacyclic product (reference for testing `ring_mul`).
#[must_use]
pub fn mul_negacyclic(a: &Rq, b: &Rq) -> Rq {
    let mut acc = [0i128; N];
    for i in 0..N {
        for j in 0..N {
            let prod = a.coeffs[i] as i128 * b.coeffs[j] as i128;
            let k = i + j;
            if k < N {
                acc[k] += prod;
            } else {
                acc[k - N] -= prod; // X^N = -1
            }
        }
    }
    let mut out = [0i64; N];
    for i in 0..N {
        out[i] = acc[i].rem_euclid(Q as i128) as i64;
    }
    Rq { coeffs: out }
}

/// `a + b` in `R_q`.
#[must_use]
pub fn ring_add(a: &Rq, b: &Rq) -> Rq {
    let mut out = [0i64; N];
    for i in 0..N {
        out[i] = modadd(a.coeffs[i], b.coeffs[i]);
    }
    Rq { coeffs: out }
}

/// `a - b` in `R_q`.
#[must_use]
pub fn ring_sub(a: &Rq, b: &Rq) -> Rq {
    let mut out = [0i64; N];
    for i in 0..N {
        out[i] = modsub(a.coeffs[i], b.coeffs[i]);
    }
    Rq { coeffs: out }
}

/// Constant polynomial `c` (reduced mod `q`).
#[must_use]
pub fn const_poly(c: i64) -> Rq {
    let mut coeffs = [0i64; N];
    coeffs[0] = c.rem_euclid(Q);
    Rq { coeffs }
}

/// Build an `Rq` from integer coefficients, each reduced into `[0, q)`.
#[must_use]
pub fn poly_from_i64(coeffs: &[i64; N]) -> Rq {
    let mut out = [0i64; N];
    for (o, &c) in out.iter_mut().zip(coeffs.iter()) {
        *o = c.rem_euclid(Q);
    }
    Rq { coeffs: out }
}

/// Centered representatives in `(-q/2, q/2]` of each coefficient.
#[must_use]
pub fn centered_coeffs(p: &Rq) -> [i64; N] {
    let half = Q / 2;
    let mut out = [0i64; N];
    for (o, &c) in out.iter_mut().zip(p.coeffs.iter()) {
        let mut v = c.rem_euclid(Q);
        if v > half {
            v -= Q;
        }
        *o = v;
    }
    out
}

/// Infinity norm on centered representatives.
#[must_use]
pub fn ring_infinity_norm(p: &Rq) -> i64 {
    centered_coeffs(p)
        .into_iter()
        .map(i64::abs)
        .max()
        .unwrap_or(0)
}

/// Sample a ring element with i.i.d. `D_{Z,s,0}` coefficients (short Gaussian).
pub fn sample_gaussian_poly<R: CryptoRng + Rng>(rng: &mut R, s: f64) -> Rq {
    let mut coeffs = [0i64; N];
    for c in &mut coeffs {
        *c = sample_discrete_gaussian(rng, s, 0.0);
    }
    poly_from_i64(&coeffs)
}

/// Sample a uniformly random ring element in `R_q`.
pub fn sample_uniform_poly<R: CryptoRng + Rng>(rng: &mut R) -> Rq {
    let q = Q as u64;
    let zone = u64::MAX - (u64::MAX % q);
    let mut coeffs = [0i64; N];
    for c in &mut coeffs {
        let mut b = [0u8; 8];
        let v = loop {
            rng.fill_bytes(&mut b);
            let r = u64::from_le_bytes(b);
            if r < zone {
                break r % q;
            }
        };
        *c = v as i64;
    }
    Rq { coeffs }
}

/// Deterministic sparse challenge: a polynomial with exactly `tau` non-zero `±1` coefficients,
/// positions and signs derived from `seed` via SHAKE-256 (Fisher–Yates from the top, à la ML-DSA).
#[must_use]
pub fn sample_in_ball(seed: &[u8; 32], tau: usize) -> Rq {
    debug_assert!(tau <= 64); // ≤ 64 fits the single sign word; also ≤ N since N = 1024
    let mut h = lib_q_sha3::Shake256::default();
    h.update(seed);
    let mut rd = h.finalize_xof();

    let mut sign_buf = [0u8; 8];
    XofReader::read(&mut rd, &mut sign_buf);
    let mut signs = u64::from_le_bytes(sign_buf);

    let mut coeffs = [0i64; N];
    for i in (N - tau)..N {
        // Uniform j in [0, i] via 10-bit rejection (acceptance ≥ i/N, here ≥ ~98%).
        let j = loop {
            let mut b = [0u8; 2];
            XofReader::read(&mut rd, &mut b);
            let cand = ((b[0] as usize) | ((b[1] as usize) << 8)) & (N - 1);
            if cand <= i {
                break cand;
            }
        };
        coeffs[i] = coeffs[j];
        coeffs[j] = if signs & 1 == 1 { -1 } else { 1 };
        signs >>= 1;
    }
    poly_from_i64(&coeffs)
}

#[cfg(test)]
mod tests {
    use lib_q_random::new_deterministic_rng;

    use super::*;

    #[test]
    fn ntt_mul_matches_schoolbook() {
        let mut rng = new_deterministic_rng([0x7Cu8; 32]);
        for _ in 0..10 {
            let a = sample_uniform_poly(&mut rng);
            let b = sample_uniform_poly(&mut rng);
            let got = ring_mul(&a, &b);
            let want = mul_negacyclic(&a, &b);
            assert_eq!(centered_coeffs(&got), centered_coeffs(&want));
        }
    }

    #[test]
    fn ntt_roundtrip_is_identity() {
        let mut rng = new_deterministic_rng([0x7Du8; 32]);
        let a = sample_uniform_poly(&mut rng);
        let mut f = a.coeffs;
        ntt(&mut f);
        intt(&mut f);
        assert_eq!(f, a.coeffs);
    }

    #[test]
    fn mul_by_one_is_identity() {
        let mut rng = new_deterministic_rng([0x7Eu8; 32]);
        let a = sample_uniform_poly(&mut rng);
        let one = const_poly(1);
        assert_eq!(centered_coeffs(&ring_mul(&a, &one)), centered_coeffs(&a));
    }

    #[test]
    fn add_sub_roundtrip() {
        let mut rng = new_deterministic_rng([0x11u8; 32]);
        let a = sample_uniform_poly(&mut rng);
        let b = sample_uniform_poly(&mut rng);
        let back = ring_sub(&ring_add(&a, &b), &b);
        assert_eq!(centered_coeffs(&back), centered_coeffs(&a));
    }

    #[test]
    fn gaussian_poly_is_short() {
        let mut rng = new_deterministic_rng([0x22u8; 32]);
        let p = sample_gaussian_poly(&mut rng, 6.0);
        assert!(ring_infinity_norm(&p) <= 72);
    }

    #[test]
    fn sample_in_ball_is_sparse_signed() {
        let seed = [0x5Bu8; 32];
        let tau = 16usize;
        let c = sample_in_ball(&seed, tau);
        let centered = centered_coeffs(&c);
        let nonzero = centered.iter().filter(|&&v| v != 0).count();
        assert_eq!(nonzero, tau, "challenge must have exactly tau nonzeros");
        assert!(
            centered.iter().all(|&v| v == 0 || v == 1 || v == -1),
            "coeffs must be ±1"
        );
        // Deterministic in the seed.
        assert_eq!(centered, centered_coeffs(&sample_in_ball(&seed, tau)));
    }
}
