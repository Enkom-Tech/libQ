//! Self-contained ring `R_q = Z_q[X]/(X^N + 1)` for the binding DKG commitments.
//!
//! The dealerless DKG verifies Shamir evaluations `f(j) = Σ jⁱ·cᵢ`, which are **non-short**
//! (`jⁱ` spans `Z_q`). To bind such a value, the commitment must bind an *arbitrary* `R_q` message
//! under short randomness only (BDLOP / Baum style). Over a small modulus there is no room to fit
//! both the BDLOP hiding and binding margins, so this ring uses a *large* modulus:
//!
//! Parameters: `N = 1024`, `q = 281 474 976 694 273` (prime, `q ≡ 1 (mod 2N)`, `q < 2^48`). At these
//! parameters the BDLOP commitment is **statistically binding** (the shortest nonzero kernel vector
//! of `B0` is far longer than any extractable opening — see [`super::bdlop`] / `LIBQ_API.md` §3), so
//! the kernel-injection attack on the legacy bare-Ajtai check is defeated unconditionally.
//!
//! The ring (negacyclic NTT, Montgomery `modmul`) is validated against the schoolbook product so the
//! crate depends on no fixed external modulus.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use lib_q_sha3::{
    ExtendableOutput,
    Update,
    XofReader,
};
use rand_core::{
    CryptoRng,
    Rng,
};

use super::gaussian::{
    sample_discrete_gaussian,
    sample_secret_coeff_ct,
};

/// Ring dimension `N` (negacyclic, `X^N + 1`).
pub const N: usize = 1024;

/// Modulus `q` (prime, `q ≡ 1 (mod 2N)`, `q < 2^48`).
pub const Q: i64 = 281_474_976_694_273;

/// Primitive `2N`-th root of unity mod `q` (`ζ^N = -1`).
const ZETA: i64 = 223_324_776_709_556;

/// `N^{-1} mod q` (for the inverse NTT scaling).
const N_INV: i64 = 281_200_098_787_345;

const LOG_N: u32 = 10; // log2(N)

/// `-q^{-1} mod 2^64` (Montgomery).
const QINV: u64 = 9_151_591_519_478_595_583;
/// `(2^64)^2 mod q` (Montgomery `R²`).
const R2: u64 = 140_741_850_411_009;

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

impl zeroize::Zeroize for Rq {
    fn zeroize(&mut self) {
        self.coeffs.zeroize();
    }
}

/// An element of `R_q` in the NTT (evaluation) domain.
///
/// Sums and pointwise products in this domain commute exactly with the coefficient domain
/// (`intt` is `Z_q`-linear and the NTT round-trip is the identity — see the
/// `ntt_roundtrip_is_identity` / `ntt_inner_matches_per_pair_products` tests), so accumulating
/// many products before a single inverse transform gives **bit-identical** results to summing
/// individual [`ring_mul`]s while skipping the redundant per-product transforms.
#[derive(Clone, Debug)]
pub struct RqNtt {
    evals: [i64; N],
}

impl RqNtt {
    /// The zero element (also zero in the evaluation domain).
    #[must_use]
    pub fn zero() -> Self {
        Self { evals: [0i64; N] }
    }
}

impl zeroize::Zeroize for RqNtt {
    fn zeroize(&mut self) {
        self.evals.zeroize();
    }
}

/// Forward transform into the NTT domain.
#[must_use]
pub fn to_ntt(p: &Rq) -> RqNtt {
    let mut evals = p.coeffs;
    ntt(&mut evals);
    RqNtt { evals }
}

/// Inverse transform back to the coefficient domain.
#[must_use]
pub fn from_ntt(p: &RqNtt) -> Rq {
    let mut coeffs = p.evals;
    intt(&mut coeffs);
    Rq { coeffs }
}

/// `acc += a ∘ b` (pointwise product) in the NTT domain — the accumulation step of an NTT-domain
/// inner product (`Σ_i a_i·b_i` costs one `intt` total instead of one per term).
pub fn ntt_mul_acc(acc: &mut RqNtt, a: &RqNtt, b: &RqNtt) {
    for i in 0..N {
        acc.evals[i] = modadd(acc.evals[i], modmul(a.evals[i], b.evals[i]));
    }
}

/// Constant-time conditional subtract of `q` from `r ∈ [0, 2q)`: returns `r mod q` with **no
/// secret-dependent branch**. `d = r − q` underflows (sets bit 63) iff `r < q`; the all-ones/all-zero
/// mask then conditionally adds `q` back. Used by the Montgomery reduction (operates on secret·public
/// products), so it must be branchless. See `SECURITY_ANALYSIS.md` §8.
#[inline]
fn csub_q_u64(r: u64) -> u64 {
    let q = Q as u64;
    let d = r.wrapping_sub(q); // r-q if r>=q, else wraps (bit 63 set)
    let mask = 0u64.wrapping_sub(d >> 63); // all-ones iff r<q, else 0
    d.wrapping_add(q & mask)
}

/// Montgomery reduction: `t·R^{-1} mod q` for `t < q·R` (`R = 2^64`). No division, **branchless**.
#[inline]
fn mont_reduce(t: u128) -> i64 {
    let m = (t as u64).wrapping_mul(QINV);
    let r = ((t + (m as u128) * (Q as u128)) >> 64) as u64;
    csub_q_u64(r) as i64
}

/// `a·b mod q` for `a, b ∈ [0, q)`, via two Montgomery reductions (division-free, branchless).
#[inline]
fn modmul(a: i64, b: i64) -> i64 {
    let ab = mont_reduce(a as u128 * b as u128);
    mont_reduce(ab as u128 * R2 as u128)
}

/// `a + b mod q` for `a, b ∈ [0, q)` — **branchless** conditional subtract.
#[inline]
fn modadd(a: i64, b: i64) -> i64 {
    csub_q_u64((a + b) as u64) as i64
}

/// `a − b mod q` for `a, b ∈ [0, q)` — **branchless** (arithmetic-shift sign mask).
#[inline]
fn modsub(a: i64, b: i64) -> i64 {
    let s = a - b; // in (-q, q)
    s + (Q & (s >> 63)) // s>>63 = -1 if s<0 (add q) else 0
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

/// Bit-reversed powers of `ζ`: `z[i] = ζ^{bitrev(i)} mod q`. Cached process-wide with a lock-free
/// racy init (`once_cell::race`) so the table works without `std` (a lost racer recomputes the same
/// deterministic table and is dropped).
fn zetas() -> &'static [i64; N] {
    static T: once_cell::race::OnceBox<[i64; N]> = once_cell::race::OnceBox::new();
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
        Box::new(t)
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
///
/// **Branchless**: the decapsulation path calls this on the secret decode input `w`, so the
/// conditional subtract of `q` must not branch on the coefficient value (same discipline as
/// [`csub_q_u64`]). `rem_euclid` by the constant `Q` compiles to a multiply-shift, not a division.
#[must_use]
pub fn centered_coeffs(p: &Rq) -> [i64; N] {
    let half = Q / 2;
    let mut out = [0i64; N];
    for (o, &c) in out.iter_mut().zip(p.coeffs.iter()) {
        let v = c.rem_euclid(Q);
        let mask = (half - v) >> 63; // all-ones iff v > half, else 0
        *o = v - (Q & mask);
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

/// Multiply a ring element by an integer scalar `k` (mod `q`); `k` may be any `i64`.
#[must_use]
pub fn scalar_mul(p: &Rq, k: i64) -> Rq {
    let km = k.rem_euclid(Q);
    let mut out = [0i64; N];
    for (o, &c) in out.iter_mut().zip(p.coeffs.iter()) {
        *o = modmul(c, km);
    }
    Rq { coeffs: out }
}

/// Sample the **secret** ring element with i.i.d. `D_{Z,s,0}` coefficients at the fixed secret width,
/// using the **constant-time** CDT base sampler (see [`super::gaussian::sample_secret_coeff_ct`]).
/// This is the sampler the DKG uses for the secret constant term `a₀`.
pub fn sample_secret_poly<R: CryptoRng + Rng>(rng: &mut R) -> Rq {
    let mut coeffs = [0i64; N];
    for c in &mut coeffs {
        *c = sample_secret_coeff_ct(rng);
    }
    poly_from_i64(&coeffs)
}

/// Sample a ring element with i.i.d. `D_{Z,s,0}` coefficients (short Gaussian). General (mask) widths
/// only — **not constant-time**; for the secret use [`sample_secret_poly`].
pub fn sample_gaussian_poly<R: CryptoRng + Rng>(rng: &mut R, s: f64) -> Rq {
    let mut coeffs = [0i64; N];
    for c in &mut coeffs {
        *c = sample_discrete_gaussian(rng, s, 0.0);
    }
    poly_from_i64(&coeffs)
}

/// Sample a block of `K` Gaussian ring elements (the FS-proof mask `y`).
pub fn sample_discrete_gaussian_block<R: CryptoRng + Rng, const K: usize>(
    rng: &mut R,
    s: f64,
) -> [Rq; K] {
    core::array::from_fn(|_| sample_gaussian_poly(rng, s))
}

/// Sample a ternary ring element (coefficients i.i.d. uniform in `{-1, 0, +1}`).
pub fn sample_ternary_poly<R: CryptoRng + Rng>(rng: &mut R) -> Rq {
    let mut coeffs = [0i64; N];
    for c in &mut coeffs {
        // 2-bit rejection: 0,1,2 → -1,0,+1 ; 3 rejected (unbiased).
        let v = loop {
            let mut b = [0u8; 1];
            rng.fill_bytes(&mut b);
            let two = b[0] & 0b11;
            if two < 3 {
                break two as i64 - 1;
            }
        };
        *c = v;
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

/// Bytes per coefficient in the canonical wire encoding (`q < 2^48` ⇒ 6 bytes suffice).
pub const COEFF_BYTES: usize = 6;

/// Encoded size of one ring element.
pub const RQ_BYTES: usize = N * COEFF_BYTES;

/// Serialize a ring element: each coefficient (canonical `[0, q)`) as `COEFF_BYTES` little-endian
/// bytes. Coefficients are normalized into `[0, q)` first.
#[must_use]
pub fn rq_to_le_bytes(p: &Rq) -> Vec<u8> {
    let mut out = Vec::with_capacity(RQ_BYTES);
    rq_write_le_bytes(p, &mut out);
    out
}

/// Append the canonical serialization of `p` to `out` — same bytes as [`rq_to_le_bytes`] without
/// the intermediate allocation (for callers assembling multi-element encodings).
pub fn rq_write_le_bytes(p: &Rq, out: &mut Vec<u8>) {
    out.reserve(RQ_BYTES);
    for &c in &p.coeffs {
        let v = c.rem_euclid(Q) as u64;
        out.extend_from_slice(&v.to_le_bytes()[..COEFF_BYTES]);
    }
}

/// Parse a ring element from exactly [`RQ_BYTES`] bytes; rejects non-canonical coefficients (`≥ q`).
#[must_use]
pub fn rq_from_le_bytes(bytes: &[u8]) -> Option<Rq> {
    if bytes.len() != RQ_BYTES {
        return None;
    }
    let mut coeffs = [0i64; N];
    for (i, c) in coeffs.iter_mut().enumerate() {
        let mut buf = [0u8; 8];
        buf[..COEFF_BYTES].copy_from_slice(&bytes[i * COEFF_BYTES..i * COEFF_BYTES + COEFF_BYTES]);
        let v = u64::from_le_bytes(buf);
        if v >= Q as u64 {
            return None;
        }
        *c = v as i64;
    }
    Some(Rq { coeffs })
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
    fn branchless_reduction_matches_reference() {
        // modadd/modsub branchless results must equal the naive conditional versions over [0,q).
        let mut rng = new_deterministic_rng([0x4Du8; 32]);
        for _ in 0..100_000 {
            let mut b = [0u8; 16];
            rng.fill_bytes(&mut b);
            let a = (u64::from_le_bytes(b[..8].try_into().unwrap()) % Q as u64) as i64;
            let c = (u64::from_le_bytes(b[8..].try_into().unwrap()) % Q as u64) as i64;
            let add_ref = {
                let s = a + c;
                if s >= Q { s - Q } else { s }
            };
            let sub_ref = {
                let s = a - c;
                if s < 0 { s + Q } else { s }
            };
            assert_eq!(modadd(a, c), add_ref);
            assert_eq!(modsub(a, c), sub_ref);
            // csub on [0,2q).
            let r = (a as u64).wrapping_add(c as u64); // in [0, 2q)
            let csub_ref = if r >= Q as u64 { r - Q as u64 } else { r };
            assert_eq!(csub_q_u64(r), csub_ref);
        }
    }

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
    fn ntt_inner_matches_per_pair_products() {
        // NTT-domain accumulation (one intt total) must be bit-identical to summing individual
        // ring_muls — the identity every NTT-domain inner-product caller relies on.
        let mut rng = new_deterministic_rng([0x7Eu8; 32]);
        let a: Vec<Rq> = (0..5).map(|_| sample_uniform_poly(&mut rng)).collect();
        let b: Vec<Rq> = (0..5).map(|_| sample_uniform_poly(&mut rng)).collect();
        let mut acc = RqNtt::zero();
        for (ai, bi) in a.iter().zip(b.iter()) {
            ntt_mul_acc(&mut acc, &to_ntt(ai), &to_ntt(bi));
        }
        let got = from_ntt(&acc);
        let mut want = Rq::zero();
        for (ai, bi) in a.iter().zip(b.iter()) {
            want = ring_add(&want, &ring_mul(ai, bi));
        }
        assert_eq!(got, want);
    }

    #[test]
    fn centered_coeffs_branchless_matches_reference() {
        let mut rng = new_deterministic_rng([0x7Bu8; 32]);
        let half = Q / 2;
        for _ in 0..10 {
            let a = sample_uniform_poly(&mut rng);
            let got = centered_coeffs(&a);
            for (g, &c) in got.iter().zip(a.coeffs.iter()) {
                let mut v = c.rem_euclid(Q);
                if v > half {
                    v -= Q;
                }
                assert_eq!(*g, v);
            }
        }
        // Boundary values: 0, half, half+1, Q-1 must center to 0, half, -(half), -1.
        let mut coeffs = [0i64; N];
        coeffs[0] = 0;
        coeffs[1] = half;
        coeffs[2] = half + 1;
        coeffs[3] = Q - 1;
        let c = centered_coeffs(&Rq::from_coeffs(coeffs));
        assert_eq!(c[0], 0);
        assert_eq!(c[1], half);
        assert_eq!(c[2], half + 1 - Q);
        assert_eq!(c[3], -1);
    }

    #[test]
    fn scalar_mul_matches_const_ring_mul() {
        let mut rng = new_deterministic_rng([0x7Fu8; 32]);
        let a = sample_uniform_poly(&mut rng);
        let k = 1234567i64;
        let got = scalar_mul(&a, k);
        let want = ring_mul(&a, &const_poly(k));
        assert_eq!(centered_coeffs(&got), centered_coeffs(&want));
    }

    #[test]
    fn ternary_poly_is_short() {
        let mut rng = new_deterministic_rng([0x23u8; 32]);
        let p = sample_ternary_poly(&mut rng);
        assert!(ring_infinity_norm(&p) <= 1);
    }

    #[test]
    fn sample_in_ball_is_sparse_signed() {
        let seed = [0x5Bu8; 32];
        let tau = 22usize;
        let c = sample_in_ball(&seed, tau);
        let centered = centered_coeffs(&c);
        let nonzero = centered.iter().filter(|&&v| v != 0).count();
        assert_eq!(nonzero, tau, "challenge must have exactly tau nonzeros");
        assert!(
            centered.iter().all(|&v| v == 0 || v == 1 || v == -1),
            "coeffs must be ±1"
        );
        assert_eq!(centered, centered_coeffs(&sample_in_ball(&seed, tau)));
    }
}
