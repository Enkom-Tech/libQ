use core::ops::{
    Add,
    Mul,
    Sub,
};

use hybrid_array::Array;
use hybrid_array::typenum::U256;
use lib_q_sha3::digest::XofReader;
use zeroize::Zeroize;

use crate::core_types::ArraySize;
pub use crate::core_types::{
    FieldElement,
    Integer,
    NttPolynomial,
    NttVector,
};
use crate::crypto::{
    PRF,
    PrfOutput,
    XOF,
};
#[cfg(not(feature = "hardened"))]
use crate::encode::Encode;
use crate::param::CbdSamplingSize;
use crate::util::{
    B32,
    Truncate,
};

impl Zeroize for FieldElement {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl FieldElement {
    pub const Q: Integer = 3329;
    pub const Q32: u32 = Self::Q as u32;
    pub const Q64: u64 = Self::Q as u64;
    const BARRETT_SHIFT: usize = 24;
    #[allow(clippy::integer_division_remainder_used)]
    const BARRETT_MULTIPLIER: u64 = (1 << Self::BARRETT_SHIFT) / Self::Q64;

    // A fast modular reduction for small numbers `x < 2*q`
    fn small_reduce(x: u16) -> u16 {
        if x < Self::Q { x } else { x - Self::Q }
    }

    fn barrett_reduce(x: u32) -> u16 {
        let product = u64::from(x) * Self::BARRETT_MULTIPLIER;
        let quotient = Truncate::truncate(product >> Self::BARRETT_SHIFT);
        let remainder = x - quotient * Self::Q32;
        Self::small_reduce(Truncate::truncate(remainder))
    }

    // Algorithm 11. BaseCaseMultiply
    //
    // This is a hot loop.  We promote to u64 so that we can do the absolute minimum number of
    // modular reductions, since these are the expensive operation.
    fn base_case_multiply(a0: Self, a1: Self, b0: Self, b1: Self, i: usize) -> (Self, Self) {
        let a0 = u32::from(a0.0);
        let a1 = u32::from(a1.0);
        let b0 = u32::from(b0.0);
        let b1 = u32::from(b1.0);
        let g = u32::from(GAMMA[i].0);

        let b1g = u32::from(Self::barrett_reduce(b1 * g));

        let c0 = Self::barrett_reduce(a0 * b0 + a1 * b1g);
        let c1 = Self::barrett_reduce(a0 * b1 + a1 * b0);
        (Self(c0), Self(c1))
    }

    /// Reduce `v` into the prime field (used by hardened-path RNG plumbing).
    #[cfg(feature = "hardened")]
    #[allow(clippy::integer_division_remainder_used)]
    pub(crate) fn from_u16_reduced(v: u16) -> Self {
        Self(v % Self::Q)
    }

    /// Modular inverse mod `Q` (3329). Returns `None` if `self == 0`.
    #[cfg(feature = "hardened")]
    pub(crate) fn inv(self) -> Option<Self> {
        if self.0 == 0 {
            return None;
        }
        Some(self.pow_mod_u32(u32::from(Self::Q) - 2))
    }

    #[cfg(feature = "hardened")]
    fn pow_mod_u32(self, mut e: u32) -> Self {
        let mut acc = Self(1);
        let mut base = self;
        while e > 0 {
            if e & 1 != 0 {
                acc = acc * base;
            }
            base = base * base;
            e >>= 1;
        }
        acc
    }

    /// Sample a uniform non-zero element from `Z_q` using `rng` (rejection sampling).
    ///
    /// Used by hardened NTT blinding and masked dot-product paths. Placing this on `FieldElement`
    /// avoids both a circular import (masking → algebra) and a duplicate free function in each
    /// call site.
    #[cfg(feature = "hardened")]
    #[allow(clippy::integer_division_remainder_used)]
    pub(crate) fn random_nonzero<R: rand_core::Rng>(rng: &mut R) -> Self {
        let mut buf = [0u8; 2];
        loop {
            rng.fill_bytes(&mut buf);
            let fe = Self::from_u16_reduced(u16::from_le_bytes(buf));
            if fe.0 != 0 {
                return fe;
            }
        }
    }
}

impl Add<FieldElement> for FieldElement {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(Self::small_reduce(self.0 + rhs.0))
    }
}

impl Sub<FieldElement> for FieldElement {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        // Guard against underflow if `rhs` is too large
        Self(Self::small_reduce(self.0 + Self::Q - rhs.0))
    }
}

impl Mul<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: FieldElement) -> FieldElement {
        let x = u32::from(self.0);
        let y = u32::from(rhs.0);
        Self(Self::barrett_reduce(x * y))
    }
}

/// An element of the ring `R_q`, i.e., a polynomial over `Z_q` of degree 255
#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct Polynomial(pub Array<FieldElement, U256>);

impl Add<&Polynomial> for &Polynomial {
    type Output = Polynomial;

    fn add(self, rhs: &Polynomial) -> Polynomial {
        Polynomial(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x + y)
                .collect(),
        )
    }
}

impl Sub<&Polynomial> for &Polynomial {
    type Output = Polynomial;

    fn sub(self, rhs: &Polynomial) -> Polynomial {
        Polynomial(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x - y)
                .collect(),
        )
    }
}

impl Mul<&Polynomial> for FieldElement {
    type Output = Polynomial;

    fn mul(self, rhs: &Polynomial) -> Polynomial {
        Polynomial(rhs.0.iter().map(|&x| self * x).collect())
    }
}

impl Polynomial {
    // Algorithm 7. SamplePolyCBD_eta(B)
    //
    // To avoid all the bitwise manipulation in the algorithm as written, we reuse the logic in
    // ByteDecode.  We decode the PRF output into integers with eta bits, then use
    // `count_ones` to perform the summation described in the algorithm.
    #[cfg(not(feature = "hardened"))]
    pub fn sample_cbd<Eta>(B: &PrfOutput<Eta>) -> Self
    where
        Eta: CbdSamplingSize,
    {
        let vals: Polynomial = Encode::<Eta::SampleSize>::decode(B);
        Self(vals.0.iter().map(|val| Eta::ONES[val.0 as usize]).collect())
    }

    /// Hardened build uses constant-time table lookup for `Eta::ONES` (feature `hardened`).
    #[cfg(feature = "hardened")]
    pub fn sample_cbd<Eta>(B: &PrfOutput<Eta>) -> Self
    where
        Eta: CbdSamplingSize,
    {
        crate::masking::sample_poly_cbd_ct::<Eta>(B)
    }
}

/// A vector of polynomials of length `k`
#[derive(Clone, Default, Debug, PartialEq)]
pub struct PolynomialVector<K: ArraySize>(pub Array<Polynomial, K>);

impl<K: ArraySize> Add<PolynomialVector<K>> for PolynomialVector<K> {
    type Output = PolynomialVector<K>;

    fn add(self, rhs: PolynomialVector<K>) -> PolynomialVector<K> {
        PolynomialVector(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(x, y)| x + y)
                .collect(),
        )
    }
}

impl<K: ArraySize> PolynomialVector<K> {
    pub fn sample_cbd<Eta>(sigma: &B32, start_n: u8) -> Self
    where
        Eta: CbdSamplingSize,
    {
        Self(Array::from_fn(|i| {
            let N = start_n + Truncate::truncate(i);
            let prf_output = PRF::<Eta>(sigma, N);
            Polynomial::sample_cbd::<Eta>(&prf_output)
        }))
    }
}

impl Zeroize for NttPolynomial {
    fn zeroize(&mut self) {
        for fe in &mut self.0 {
            fe.zeroize();
        }
    }
}

impl Add<&NttPolynomial> for &NttPolynomial {
    type Output = NttPolynomial;

    fn add(self, rhs: &NttPolynomial) -> NttPolynomial {
        NttPolynomial(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x + y)
                .collect(),
        )
    }
}

// Algorithm 6. SampleNTT (lines 4-13)
struct FieldElementReader<'a> {
    xof: &'a mut dyn XofReader,
    data: [u8; 96],
    start: usize,
    next: Option<Integer>,
}

impl<'a> FieldElementReader<'a> {
    fn new(xof: &'a mut impl XofReader) -> Self {
        let mut out = Self {
            xof,
            data: [0u8; 96],
            start: 0,
            next: None,
        };

        // Fill the buffer
        out.xof.read(&mut out.data);

        out
    }

    fn next(&mut self) -> FieldElement {
        if let Some(val) = self.next {
            self.next = None;
            return FieldElement(val);
        }

        loop {
            if self.start == self.data.len() {
                self.xof.read(&mut self.data);
                self.start = 0;
            }

            let end = self.start + 3;
            let b = &self.data[self.start..end];
            self.start = end;

            let d1 = Integer::from(b[0]) + ((Integer::from(b[1]) & 0xF) << 8);
            let d2 = (Integer::from(b[1]) >> 4) + ((Integer::from(b[2]) as Integer) << 4);

            if d1 < FieldElement::Q {
                if d2 < FieldElement::Q {
                    self.next = Some(d2);
                }
                return FieldElement(d1);
            }

            if d2 < FieldElement::Q {
                return FieldElement(d2);
            }
        }
    }
}

impl NttPolynomial {
    // Algorithm 6 SampleNTT(B)
    pub fn sample_uniform(B: &mut impl XofReader) -> Self {
        let mut reader = FieldElementReader::new(B);
        Self(Array::from_fn(|_| reader.next()))
    }
}

// Since the powers of zeta used in the NTT and MultiplyNTTs are fixed, we use pre-computed tables
// to avoid the need to compute the exponetiations at runtime.
//
// * ZETA_POW_BITREV[i] = zeta^{BitRev_7(i)}
// * GAMMA[i] = zeta^{2 BitRev_7(i) + 1}
//
// Note that the const environment here imposes some annoying conditions.  Because operator
// overloading can't be const, we have to do all the reductions here manually.  Because `for` loops
// are forbidden in `const` functions, we do them manually with `while` loops.
//
// The values computed here match those provided in Appendix A of FIPS 203.  ZETA_POW_BITREV
// corresponds to the first table, and GAMMA to the second table.
#[allow(clippy::cast_possible_truncation)]
const ZETA_POW_BITREV: [FieldElement; 128] = {
    const ZETA: u64 = 17;
    #[allow(clippy::integer_division_remainder_used)]
    const fn bitrev7(x: usize) -> usize {
        ((x >> 6) % 2) |
            (((x >> 5) % 2) << 1) |
            (((x >> 4) % 2) << 2) |
            (((x >> 3) % 2) << 3) |
            (((x >> 2) % 2) << 4) |
            (((x >> 1) % 2) << 5) |
            ((x % 2) << 6)
    }

    // Compute the powers of zeta
    let mut pow = [FieldElement(0); 128];
    let mut i = 0;
    let mut curr = 1u64;
    #[allow(clippy::integer_division_remainder_used)]
    while i < 128 {
        pow[i] = FieldElement(curr as u16);
        i += 1;
        curr = (curr * ZETA) % FieldElement::Q64;
    }

    // Reorder the powers according to bitrev7
    let mut pow_bitrev = [FieldElement(0); 128];
    let mut i = 0;
    while i < 128 {
        pow_bitrev[i] = pow[bitrev7(i)];
        i += 1;
    }
    pow_bitrev
};

#[allow(clippy::cast_possible_truncation)]
const GAMMA: [FieldElement; 128] = {
    const ZETA: u64 = 17;
    let mut gamma = [FieldElement(0); 128];
    let mut i = 0;
    while i < 128 {
        let zpr = ZETA_POW_BITREV[i].0 as u64;
        #[allow(clippy::integer_division_remainder_used)]
        let g = (zpr * zpr * ZETA) % FieldElement::Q64;
        gamma[i] = FieldElement(g as u16);
        i += 1;
    }
    gamma
};

// --- Signed Montgomery arithmetic for the default (non-hardened) NTT/INTT ------------------------
//
// The default NTT/INTT keep coefficients in *normal* domain (NOT Montgomery), exactly as the rest of
// the crate expects: the transform output is byte-encoded directly into keys and ciphertexts. The
// Montgomery trick here only replaces the per-butterfly modular multiply.
//
// `FieldElement::barrett_reduce` does a 64-bit multiply whose latency the butterflies serialize on.
// Signed Montgomery multiplication (`fqmul`) reduces a 32-bit product with 16-bit operations and no
// data-dependent branch, shortening the dependency chain so the butterflies pipeline. To keep the
// data in normal domain, each twiddle is pre-multiplied by R = 2^16 (`ZETA_MONT`): then
// `fqmul(zeta * R, x) == zeta * x (mod q)`, so no Montgomery factor accumulates on the coefficients.
//
// This mirrors the reference (PQClean/RustCrypto) signed `int16_t` NTT; correctness is gated on the
// full ACVP KAT suite (`tests/key-gen.rs`, `tests/encap-decap.rs`), not just the unit round-trip.

/// `q^{-1} mod 2^16`, as the `i16` bit pattern (`62209 ≡ -3327`); satisfies `q * QINV ≡ 1 (mod 2^16)`.
#[cfg(not(feature = "hardened"))]
const MONT_QINV: i16 = -3327;

/// Signed Montgomery reduction: for `|a| <= q * 2^15`, returns `a * 2^{-16} mod q` in `(-q, q)`.
#[cfg(not(feature = "hardened"))]
#[inline(always)]
const fn montgomery_reduce(a: i32) -> i16 {
    // Low 16 bits of `a * q^{-1}` (the i16 truncation takes the product mod 2^16).
    let m = (a as i16).wrapping_mul(MONT_QINV);
    // `a - m*q` is divisible by 2^16; the arithmetic shift yields the representative in (-q, q).
    ((a - (m as i32) * FieldElement::Q as i32) >> 16) as i16
}

/// Montgomery multiply: `a * b * 2^{-16} mod q`, result in `(-q, q)`.
#[cfg(not(feature = "hardened"))]
#[inline(always)]
const fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce(a as i32 * b as i32)
}

/// Centered Barrett reduction: maps any `i16` to a same-class representative in `[-q/2, q/2]`.
#[cfg(not(feature = "hardened"))]
#[inline(always)]
const fn barrett_reduce_i16(a: i16) -> i16 {
    const V: i32 = ((1 << 26) + (FieldElement::Q as i32) / 2) / FieldElement::Q as i32; // 20159
    let t = ((V * a as i32 + (1 << 25)) >> 26) as i16;
    a - t * FieldElement::Q as i16
}

/// Normalize a representative in `(-q, q)` to the canonical `[0, q)` range (branchless: add `q` iff
/// negative — `a >> 15` is all-ones for negative `i16`, else zero).
#[cfg(not(feature = "hardened"))]
#[inline(always)]
const fn to_canonical(a: i16) -> u16 {
    (a + ((a >> 15) & FieldElement::Q as i16)) as u16
}

/// Twiddles in Montgomery form: `ZETA_MONT[i] = center(zeta^{BitRev7(i)} * 2^16 mod q)`. Derived from
/// `ZETA_POW_BITREV` so there is no hand-transcribed table to drift from the FIPS-203 values.
#[cfg(not(feature = "hardened"))]
const ZETA_MONT: [i16; 128] = {
    let mut t = [0i16; 128];
    let mut i = 0;
    #[allow(
        clippy::integer_division_remainder_used,
        clippy::cast_possible_truncation
    )]
    while i < 128 {
        let m = (ZETA_POW_BITREV[i].0 as u64 * (1u64 << 16)) % FieldElement::Q64; // in [0, q)
        t[i] = if m > FieldElement::Q64 / 2 {
            (m as i32 - FieldElement::Q as i32) as i16
        } else {
            m as i16
        };
        i += 1;
    }
    t
};

/// Post-INTT scale by `128^{-1} (= 3303)`, expressed as a Montgomery multiplier so the result lands
/// back in normal domain: `fqmul(x, 512) == x * 3303 (mod q)` since `512 == 3303 * 2^16 mod q`.
#[cfg(not(feature = "hardened"))]
const INV_NTT_SCALE_MONT: i16 = 512;

// Algorithm 10. MuliplyNTTs
impl Mul<&NttPolynomial> for &NttPolynomial {
    type Output = NttPolynomial;

    fn mul(self, rhs: &NttPolynomial) -> NttPolynomial {
        let mut out = NttPolynomial(Array::default());

        for i in 0..128 {
            let (c0, c1) = FieldElement::base_case_multiply(
                self.0[2 * i],
                self.0[2 * i + 1],
                rhs.0[2 * i],
                rhs.0[2 * i + 1],
                i,
            );

            out.0[2 * i] = c0;
            out.0[2 * i + 1] = c1;
        }

        out
    }
}

impl From<Array<FieldElement, U256>> for NttPolynomial {
    fn from(f: Array<FieldElement, U256>) -> NttPolynomial {
        NttPolynomial(f)
    }
}

impl From<NttPolynomial> for Array<FieldElement, U256> {
    fn from(f_hat: NttPolynomial) -> Array<FieldElement, U256> {
        f_hat.0
    }
}

/// Wraps `crate::hardened_rng::shuffle_indices` for a fixed-size `[usize; 128]` scratch buffer.
///
/// Each NTT layer shuffles up to 128 independent butterfly pairs. We pass a `&mut [usize]`
/// slice of the active length so the Fisher-Yates implementation stays in one place.
#[cfg(feature = "hardened")]
fn ntt_shuffle_layer<R: rand_core::Rng>(rng: &mut R, scratch: &mut [usize; 128], len: usize) {
    crate::hardened_rng::shuffle_indices(rng, len, &mut scratch[..len]);
}

// Algorithm 8. NTT
impl Polynomial {
    #[allow(clippy::many_single_char_names)]
    pub fn ntt(&self) -> NttPolynomial {
        let mut k = 1;

        let mut f = self.0;
        #[cfg(not(feature = "hardened"))]
        {
            // Signed Montgomery butterflies in normal domain (twiddles carry the R factor). The
            // coefficients enter in `[0, q)` so they fit `i16` directly; over the 7 layers `|r|`
            // grows to `< 8q < 2^15`, so no intermediate reduction is needed.
            let mut r = [0i16; 256];
            for (dst, src) in r.iter_mut().zip(f.iter()) {
                *dst = src.0 as i16;
            }
            for len in [128, 64, 32, 16, 8, 4, 2] {
                for start in (0..256).step_by(2 * len) {
                    let zeta = ZETA_MONT[k];
                    k += 1;

                    for j in start..(start + len) {
                        let t = fqmul(zeta, r[j + len]);
                        r[j + len] = r[j] - t;
                        r[j] = r[j] + t;
                    }
                }
            }
            for (dst, &v) in f.iter_mut().zip(r.iter()) {
                dst.0 = to_canonical(barrett_reduce_i16(v));
            }
        }
        #[cfg(feature = "hardened")]
        {
            #[allow(clippy::needless_range_loop)]
            {
                let mut rng = crate::hardened_rng::OsRngFill;
                let r = FieldElement::random_nonzero(&mut rng);
                let r_inv = r.inv().expect("random_nonzero returns nonzero element");
                for x in &mut f {
                    *x = *x * r;
                }
                let mut scratch = [0usize; 128];
                for len in [128, 64, 32, 16, 8, 4, 2] {
                    for start in (0..256).step_by(2 * len) {
                        let zeta = ZETA_POW_BITREV[k];
                        k += 1;
                        ntt_shuffle_layer(&mut rng, &mut scratch, len);
                        for ii in 0..len {
                            let o = scratch[ii];
                            let j = start + o;
                            let t = zeta * f[j + len];
                            f[j + len] = f[j] - t;
                            f[j] = f[j] + t;
                        }
                    }
                }
                for x in &mut f {
                    *x = *x * r_inv;
                }
            }
        }

        f.into()
    }
}

// Algorithm 9. NTT^{-1}
impl NttPolynomial {
    #[allow(clippy::many_single_char_names)]
    pub fn ntt_inverse(&self) -> Polynomial {
        // The non-hardened path reads `f` into a signed scratch buffer; only the hardened path
        // mutates it in place (blinding/shuffle), hence the cfg-gated `mut`.
        #[cfg(not(feature = "hardened"))]
        let f: Array<FieldElement, U256> = self.0.clone();
        #[cfg(feature = "hardened")]
        let mut f: Array<FieldElement, U256> = self.0.clone();

        let mut k = 127;
        #[cfg(not(feature = "hardened"))]
        {
            // Gentleman-Sande butterflies in normal domain via signed Montgomery multiply. `r[j]` is
            // Barrett-reduced each layer to keep it bounded; `r[j + len]` stays in `(-q, q)` (fqmul
            // output). The final `fqmul(·, 512)` applies the `128^{-1}` scale, then we canonicalize.
            let mut r = [0i16; 256];
            for (dst, src) in r.iter_mut().zip(f.iter()) {
                *dst = src.0 as i16;
            }
            for len in [2, 4, 8, 16, 32, 64, 128] {
                for start in (0..256).step_by(2 * len) {
                    let zeta = ZETA_MONT[k];
                    k -= 1;

                    for j in start..(start + len) {
                        let t = r[j];
                        r[j] = barrett_reduce_i16(t + r[j + len]);
                        r[j + len] = fqmul(zeta, r[j + len] - t);
                    }
                }
            }
            let mut out = Array::<FieldElement, U256>::default();
            for (o, &v) in out.iter_mut().zip(r.iter()) {
                o.0 = to_canonical(fqmul(v, INV_NTT_SCALE_MONT));
            }
            Polynomial(out)
        }
        #[cfg(feature = "hardened")]
        {
            #[allow(clippy::needless_range_loop)]
            {
                let mut rng = crate::hardened_rng::OsRngFill;
                let r = FieldElement::random_nonzero(&mut rng);
                let r_inv = r.inv().expect("random_nonzero returns nonzero element");
                for x in &mut f {
                    *x = *x * r;
                }
                let mut scratch = [0usize; 128];
                for len in [2, 4, 8, 16, 32, 64, 128] {
                    for start in (0..256).step_by(2 * len) {
                        let zeta = ZETA_POW_BITREV[k];
                        k -= 1;
                        ntt_shuffle_layer(&mut rng, &mut scratch, len);
                        for ii in 0..len {
                            let o = scratch[ii];
                            let j = start + o;
                            let t = f[j];
                            f[j] = t + f[j + len];
                            f[j + len] = zeta * (f[j + len] - t);
                        }
                    }
                }
                let poly = FieldElement(3303) * &Polynomial(f);
                r_inv * &poly
            }
        }
    }
}

impl<K: ArraySize> NttVector<K> {
    pub fn sample_uniform(rho: &B32, i: usize, transpose: bool) -> Self {
        Self(Array::from_fn(|j| {
            let (i, j) = if transpose { (j, i) } else { (i, j) };
            let mut xof = XOF(rho, Truncate::truncate(j), Truncate::truncate(i));
            NttPolynomial::sample_uniform(&mut xof)
        }))
    }
}

impl<K> Zeroize for NttVector<K>
where
    K: ArraySize,
{
    fn zeroize(&mut self) {
        for poly in &mut self.0 {
            poly.zeroize();
        }
    }
}

impl<K: ArraySize> Add<&NttVector<K>> for &NttVector<K> {
    type Output = NttVector<K>;

    fn add(self, rhs: &NttVector<K>) -> NttVector<K> {
        NttVector(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(x, y)| x + y)
                .collect(),
        )
    }
}

impl<K: ArraySize> Mul<&NttVector<K>> for &NttVector<K> {
    type Output = NttPolynomial;

    fn mul(self, rhs: &NttVector<K>) -> NttPolynomial {
        self.0
            .iter()
            .zip(rhs.0.iter())
            .map(|(x, y)| x * y)
            .fold(NttPolynomial::default(), |x, y| &x + &y)
    }
}

impl<K: ArraySize> PolynomialVector<K> {
    pub fn ntt(&self) -> NttVector<K> {
        NttVector(self.0.iter().map(Polynomial::ntt).collect())
    }
}

impl<K: ArraySize> NttVector<K> {
    pub fn ntt_inverse(&self) -> PolynomialVector<K> {
        PolynomialVector(self.0.iter().map(NttPolynomial::ntt_inverse).collect())
    }
}

/// A K x K matrix of NTT-domain polynomials.  Each vector represents a row of the matrix, so that
/// multiplying on the right just requires iteration.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct NttMatrix<K: ArraySize>(Array<NttVector<K>, K>);

impl<K: ArraySize> Mul<&NttVector<K>> for &NttMatrix<K> {
    type Output = NttVector<K>;

    fn mul(self, rhs: &NttVector<K>) -> NttVector<K> {
        NttVector(self.0.iter().map(|x| x * rhs).collect())
    }
}

impl<K: ArraySize> NttMatrix<K> {
    pub fn sample_uniform(rho: &B32, transpose: bool) -> Self {
        Self(Array::from_fn(|i| {
            NttVector::sample_uniform(rho, i, transpose)
        }))
    }

    #[cfg(feature = "hardened")]
    #[allow(clippy::inline_always)]
    #[inline(always)]
    pub(crate) fn row(&self, i: usize) -> &NttVector<K> {
        &self.0[i]
    }

    pub fn transpose(&self) -> Self {
        Self(Array::from_fn(|i| {
            NttVector(Array::from_fn(|j| self.0[j].0[i].clone()))
        }))
    }
}

#[cfg(test)]
mod test {
    use hybrid_array::typenum::{
        U2,
        U3,
        U8,
    };

    use super::*;
    use crate::util::Flatten;

    // Multiplication in R_q, modulo X^256 + 1
    impl Mul<&Polynomial> for &Polynomial {
        type Output = Polynomial;

        fn mul(self, rhs: &Polynomial) -> Self::Output {
            let mut out = Self::Output::default();
            for (i, x) in self.0.iter().enumerate() {
                for (j, y) in rhs.0.iter().enumerate() {
                    let (sign, index) = if i + j < 256 {
                        (FieldElement(1), i + j)
                    } else {
                        (FieldElement(FieldElement::Q - 1), i + j - 256)
                    };

                    out.0[index] = out.0[index] + (sign * *x * *y);
                }
            }
            out
        }
    }

    // A polynomial with only a scalar component, to make simple test cases
    fn const_ntt(x: Integer) -> NttPolynomial {
        let mut p = Polynomial::default();
        p.0[0] = FieldElement(x);
        p.ntt()
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn polynomial_ops() {
        let f = Polynomial(Array::from_fn(|i| FieldElement(i as Integer)));
        let g = Polynomial(Array::from_fn(|i| FieldElement(2 * i as Integer)));
        let sum = Polynomial(Array::from_fn(|i| FieldElement(3 * i as Integer)));
        assert_eq!((&f + &g), sum);
        assert_eq!((&sum - &g), f);
        assert_eq!(FieldElement(3) * &f, sum);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation, clippy::similar_names)]
    fn ntt() {
        let f = Polynomial(Array::from_fn(|i| FieldElement(i as Integer)));
        let g = Polynomial(Array::from_fn(|i| FieldElement(2 * i as Integer)));
        let f_hat = f.ntt();
        let g_hat = g.ntt();

        // Verify that NTT and NTT^-1 are actually inverses
        let f_unhat = f_hat.ntt_inverse();
        assert_eq!(f, f_unhat);

        // Verify that NTT is a homomorphism with regard to addition
        let fg = &f + &g;
        let f_hat_g_hat = &f_hat + &g_hat;
        let fg_unhat = f_hat_g_hat.ntt_inverse();
        assert_eq!(fg, fg_unhat);

        // Verify that NTT is a homomorphism with regard to multiplication
        let fg = &f * &g;
        let f_hat_g_hat = &f_hat * &g_hat;
        let fg_unhat = f_hat_g_hat.ntt_inverse();
        assert_eq!(fg, fg_unhat);
    }

    /// Kyber NTT is \\(\\mathbb{Z}_q\\)-linear; a global coefficient scaling commutes with the
    /// transform. This property underpins multiplicative twiddle pre/post scaling strategies.
    #[test]
    #[cfg(feature = "hardened")]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::integer_division_remainder_used
    )]
    fn ntt_scalar_linearity() {
        let f = Polynomial(Array::from_fn(|i| {
            FieldElement(((i as u32 * 7) % u32::from(FieldElement::Q)) as u16)
        }));
        let s = FieldElement(13);
        let scaled = s * &f;
        let left = scaled.ntt();
        let f_hat = f.ntt();
        let right = NttPolynomial(f_hat.0.iter().map(|&c| c * s).collect());
        assert_eq!(left, right);
    }

    #[test]
    fn ntt_vector() {
        // Verify vector addition
        let v1: NttVector<U3> = NttVector(Array([const_ntt(1), const_ntt(1), const_ntt(1)]));
        let v2: NttVector<U3> = NttVector(Array([const_ntt(2), const_ntt(2), const_ntt(2)]));
        let v3: NttVector<U3> = NttVector(Array([const_ntt(3), const_ntt(3), const_ntt(3)]));
        assert_eq!((&v1 + &v2), v3);

        // Verify dot product
        assert_eq!((&v1 * &v2), const_ntt(6));
        assert_eq!((&v1 * &v3), const_ntt(9));
        assert_eq!((&v2 * &v3), const_ntt(18));
    }

    #[test]
    fn ntt_matrix() {
        // Verify matrix multiplication by a vector
        let a: NttMatrix<U3> = NttMatrix(Array([
            NttVector(Array([const_ntt(1), const_ntt(2), const_ntt(3)])),
            NttVector(Array([const_ntt(4), const_ntt(5), const_ntt(6)])),
            NttVector(Array([const_ntt(7), const_ntt(8), const_ntt(9)])),
        ]));
        let v_in: NttVector<U3> = NttVector(Array([const_ntt(1), const_ntt(2), const_ntt(3)]));
        let v_out: NttVector<U3> = NttVector(Array([const_ntt(14), const_ntt(32), const_ntt(50)]));
        assert_eq!(&a * &v_in, v_out);

        // Verify transpose
        let aT = NttMatrix(Array([
            NttVector(Array([const_ntt(1), const_ntt(4), const_ntt(7)])),
            NttVector(Array([const_ntt(2), const_ntt(5), const_ntt(8)])),
            NttVector(Array([const_ntt(3), const_ntt(6), const_ntt(9)])),
        ]));
        assert_eq!(a.transpose(), aT);
    }

    // To verify the accuracy of sampling, we use a theorem related to the law of large numbers,
    // which bounds the convergence of the Kullback-Liebler distance between the empirical
    // distribution and the hypothesized distribution.
    //
    // Theorem (Cover & Thomas, 1991, Theorem 12.2.1): Let $X_1, \ldots, X_n$ be i.i.d. $~P(x)$.
    // Then:
    //
    //   Pr{ D(P_{x^n} || P) > \epsilon } \leq 2^{ -n ( \epsilon - |X|^{ log(n+1) / n } ) }
    //
    // So if we test by computing D(P_{x^n} || P) and requiring the value to be below a threshold
    // \epsilon, then an unbiased sampling should pass with overwhelming probability 1 - 2^{-k},
    // for some k based on \epsilon, |X|, and n.
    //
    // If we take k = 256 and n = 256, then we can solve for the required threshold \epsilon:
    //
    //   \epsilon = 1 + |X|^{ 0.03125 }
    //
    // For the cases we're interested in here:
    //
    //   CBD(eta = 2) => |X| = 5   => epsilon ~= 2.0516
    //   CBD(eta = 2) => |X| = 7   => epsilon ~= 2.0627
    //   Uniform byte => |X| = 256 => epsilon ~= 2.1892
    //
    // Taking epsilon = 2.05 makes us conservative enough in all cases, without significantly
    // increasing the probability of false negatives.
    const KL_THRESHOLD: f64 = 2.05;

    // The centered binomial distributions are calculated as:
    //
    //   bin_\eta(k) = (2\eta \choose k + \eta) 2^{-2\eta}
    //
    // for k in $-\eta, \ldots, \eta$.  The cases of interest here are \eta = 2, 3.
    type Distribution = [f64; Q_SIZE];
    const Q_SIZE: usize = FieldElement::Q as usize;
    static CBD2: Distribution = {
        let mut dist = [0.0; Q_SIZE];
        dist[Q_SIZE - 2] = 1.0 / 16.0;
        dist[Q_SIZE - 1] = 4.0 / 16.0;
        dist[0] = 6.0 / 16.0;
        dist[1] = 4.0 / 16.0;
        dist[2] = 1.0 / 16.0;
        dist
    };
    static CBD3: Distribution = {
        let mut dist = [0.0; Q_SIZE];
        dist[Q_SIZE - 3] = 1.0 / 64.0;
        dist[Q_SIZE - 2] = 6.0 / 64.0;
        dist[Q_SIZE - 1] = 15.0 / 64.0;
        dist[0] = 20.0 / 64.0;
        dist[1] = 15.0 / 64.0;
        dist[2] = 6.0 / 64.0;
        dist[3] = 1.0 / 64.0;
        dist
    };
    static UNIFORM: Distribution = [1.0 / (FieldElement::Q as f64); Q_SIZE];

    fn kl_divergence(p: &Distribution, q: &Distribution) -> f64 {
        p.iter()
            .zip(q.iter())
            .map(|(p, q)| if *p == 0.0 { 0.0 } else { p * (p / q).log2() })
            .sum()
    }

    #[allow(clippy::cast_precision_loss, clippy::large_stack_arrays)]
    fn test_sample(sample: &[FieldElement], ref_dist: &Distribution) {
        // Verify data and compute the empirical distribution
        let mut sample_dist: Distribution = [0.0; Q_SIZE];
        let bump: f64 = 1.0 / (sample.len() as f64);
        for x in sample {
            assert!(x.0 < FieldElement::Q);
            assert!(ref_dist[x.0 as usize] > 0.0);

            sample_dist[x.0 as usize] += bump;
        }

        let d = kl_divergence(&sample_dist, ref_dist);
        assert!(d < KL_THRESHOLD);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn sample_uniform() {
        // We require roughly Q/2 samples to verify the uniform distribution.  This is because for
        // M < N, the uniform distribution over a subset of M elements has KL distance:
        //
        //   M sum(p * log(q / p)) = log(q / p) = log(N / M)
        //
        // Since Q ~= 2^11 and 256 == 2^8, we need 2^3 == 8 runs of 256 to get out of the bad
        // regime and get a meaningful measurement.
        let rho = B32::default();
        let sample: Array<Array<FieldElement, U256>, U8> = Array::from_fn(|i| {
            let mut xof = XOF(&rho, 0, i as u8);
            NttPolynomial::sample_uniform(&mut xof).into()
        });

        test_sample(&sample.flatten(), &UNIFORM);
    }

    #[test]
    fn sample_cbd() {
        // Eta = 2
        let sigma = B32::default();
        let prf_output = PRF::<U2>(&sigma, 0);
        let sample = Polynomial::sample_cbd::<U2>(&prf_output).0;
        test_sample(&sample, &CBD2);

        // Eta = 3
        let sigma = B32::default();
        let prf_output = PRF::<U3>(&sigma, 0);
        let sample = Polynomial::sample_cbd::<U3>(&prf_output).0;
        test_sample(&sample, &CBD3);
    }
}
