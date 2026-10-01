//! Constant-time Shamir secret sharing over `GF(2^8)`.
//!
//! Splits a bare 32-byte symmetric secret into `n` shares such that any `k` of them reconstruct
//! it and any `k - 1` reveal nothing — information-theoretically, classically or quantumly. The
//! secret is treated as 32 independent bytes; each byte is shared by its own uniformly random
//! degree-`(k - 1)` polynomial over `GF(2^8)`.
//!
//! # Scope: symmetric key material only
//!
//! [`split`] takes a bare `[u8; 32]`. It must only ever be handed **symmetric** key material —
//! a key that participates in no asymmetric operation itself. Never destructure a KEM or
//! signature secret key into bytes to feed it here: Shamir-sharing a key whose use is non-linear
//! (e.g. an ML-KEM decapsulation key, whose partial decapsulation admits no correct linear
//! reconstruction) is structurally unsound, not merely a parameter choice. There is deliberately
//! no `From<_>` conversion into [`split`]'s `secret` parameter, so a caller cannot pass such a
//! key without first destructuring it — which callers must never do for anything but a symmetric
//! secret.
//!
//! # Construction
//!
//! [`split`] samples, for each of the 32 secret bytes independently, a uniformly random
//! degree-`(k - 1)` polynomial over `GF(2^8)` (constant term = that byte of the secret) and
//! evaluates it at `x = 1..=n`. [`reconstruct`] recovers the unique degree-`(len - 1)`
//! interpolating polynomial through exactly the given points via Lagrange interpolation at
//! `x = 0`, per byte.
//!
//! [`reconstruct`] takes no threshold parameter: it always interpolates the unique
//! degree-`(shares.len() - 1)` polynomial through exactly the shares handed to it. Handing it
//! fewer than the `k` used at split time is not rejected — Shamir's scheme cannot detect that
//! from the shares alone, because there is no way to distinguish "not enough shares for THIS `k`"
//! from "a valid, different, smaller-`k` scheme" without external knowledge of the real `k`.
//! Feeding it `m < k` shares is well-defined math (a specific, generally-wrong value) rather than
//! an error, which is exactly the security property: for a byte a guesser does not know, every
//! one of the 256 candidate values is equally consistent with the `m < k` shares actually held,
//! so the reconstructed output on a wrong guess is indistinguishable from noise. Enforcing the
//! threshold is therefore the **caller's** job: collect `>= k` shares against whatever
//! out-of-band `k` the scheme committed to, and validate each share's provenance, before calling
//! [`reconstruct`].
//!
//! # Field arithmetic
//!
//! `GF(2^8)` with the AES reduction polynomial `x^8 + x^4 + x^3 + x + 1` (`0x11B`). Multiply
//! (`gf_mul`) is a branchless carry-less multiply-and-reduce (peasant's algorithm using
//! all-ones/all-zeros bitmasks derived from a bit of the operands, never an `if` on data) — no
//! log/antilog table, so there is no secret-dependent table index either. Inverse (`gf_inv`)
//! is exponentiation by the fixed *public* exponent 254 (`a^254 == a^-1` for `a != 0`, Fermat:
//! the multiplicative group has order 255) via a fixed square-and-multiply addition chain — the
//! sequence of squarings and multiplies is identical for every input value, so there is no
//! secret-dependent branch there either. The `sca-test`-gated `shamir_gf256_ct` module below
//! carries a dudect-style timing check for `gf_mul`.
//!
//! # `no_std`
//!
//! `#![no_std]` unless the `std` feature is on. The primitive ([`split`], [`reconstruct`], and
//! their `GF(2^8)` arithmetic) needs a heap and is gated behind the `alloc` feature (on by
//! default); [`Share`] and [`ShamirError`] compile with neither `std` nor `alloc`. Builds for
//! `wasm32-unknown-unknown` and bare-metal `thumbv7em-none-eabi(hf)` targets.

// Conventional shape (matches the rest of the ecosystem): no_std unless the `std` feature is
// explicitly on, so `--no-default-features` alone gives a genuine no_std build. `std` exists only
// to let the in-crate test suite use `std::time`, formatting and a thread RNG; it wires in no
// std-only code in the library itself.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::{
    vec,
    vec::Vec,
};

use zeroize::{
    Zeroize,
    ZeroizeOnDrop,
};

/// Minimum reconstruction threshold. `k = 1` is not sharing (the lone "share" IS the secret in
/// the clear), so it is rejected rather than silently accepted as a degenerate case.
pub const MIN_THRESHOLD: u8 = 2;

/// One recipient's share of a split 32-byte secret. `index` is this share's `x`-coordinate
/// (`1..=n`); `0` is reserved for the secret's own point (`f(0)`) and is never a valid share
/// index. `Zeroize`/`ZeroizeOnDrop`: `bytes` is symmetric-key share material and is scrubbed on
/// drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Share {
    /// The share's `x`-coordinate (`1..=n`).
    pub index: u8,
    /// The 32 evaluated field elements `(f_0(index), …, f_31(index))`.
    pub bytes: [u8; 32],
}

impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Share")
            .field("index", &self.index)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Errors from [`split`] / [`reconstruct`].
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ShamirError {
    /// `k < MIN_THRESHOLD`.
    #[error("threshold k must be >= {MIN_THRESHOLD}, got {0}")]
    ThresholdTooSmall(u8),
    /// `k > n`.
    #[error("threshold k ({k}) exceeds share count n ({n})")]
    ThresholdExceedsShares {
        /// The requested threshold.
        k: u8,
        /// The requested share count.
        n: u8,
    },
    /// [`reconstruct`] was called with an empty slice.
    #[error("reconstruct called with no shares")]
    NoShares,
    /// A share with index `0` was passed to [`reconstruct`] (`0` is the secret's own point, not
    /// a valid share).
    #[error("share index 0 is reserved for the secret and is never a valid share")]
    ZeroIndex,
    /// Two shares in the same [`reconstruct`] call carried the same index.
    #[error("duplicate share index {0}")]
    DuplicateIndex(u8),
}

// ── GF(2^8) arithmetic, AES reduction polynomial 0x11B ──────────────────────────────────────

/// Branchless `GF(2^8)` multiply (AES reduction polynomial `x^8 + x^4 + x^3 + x + 1`, `0x11B`).
/// No secret-dependent branch or table index: every step is a fixed sequence of shifts, ANDs and
/// XORs, selecting with an all-ones/all-zeros mask derived from one bit of an operand instead of
/// an `if` on that bit.
#[cfg(feature = "alloc")]
#[must_use]
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    for _ in 0..8 {
        let lo_mask = 0u8.wrapping_sub(b & 1);
        p ^= a & lo_mask;
        let hi_mask = 0u8.wrapping_sub((a >> 7) & 1);
        a = (a << 1) ^ (0x1B & hi_mask);
        b >>= 1;
    }
    p
}

/// `GF(2^8)` multiplicative inverse via `a^254` (Fermat: the multiplicative group has order 255,
/// so `a^255 == 1` and `a^254 == a^-1` for every `a != 0`). Fixed square-and-multiply addition
/// chain over the constant, public exponent `254 == 0b1111_1110` — the sequence of squarings and
/// multiplies is identical for every input `a`, so there is no secret-dependent branch. Returns
/// `0` for `a == 0` (matches `0^254 == 0`; `0` has no true inverse, and every caller here rejects
/// a zero share index before this is ever invoked on one).
#[cfg(feature = "alloc")]
#[must_use]
fn gf_inv(a: u8) -> u8 {
    let a2 = gf_mul(a, a);
    let a4 = gf_mul(a2, a2);
    let a8 = gf_mul(a4, a4);
    let a16 = gf_mul(a8, a8);
    let a32 = gf_mul(a16, a16);
    let a64 = gf_mul(a32, a32);
    let a128 = gf_mul(a64, a64);
    // 254 = 128 + 64 + 32 + 16 + 8 + 4 + 2
    let hi = gf_mul(gf_mul(a128, a64), gf_mul(a32, a16));
    let lo = gf_mul(gf_mul(a8, a4), a2);
    gf_mul(hi, lo)
}

/// Evaluate the degree-`(coeffs.len() - 1)` polynomial with `coeffs[i]` = coefficient of `x^i`
/// (`coeffs[0]` = the secret byte) at `x`, via Horner's method. `x` is a public share index —
/// this whole module treats indices as public, never secret.
#[cfg(feature = "alloc")]
#[must_use]
fn eval_poly_byte(coeffs: &[[u8; 32]], byte_idx: usize, x: u8) -> u8 {
    let mut acc = 0u8;
    for c in coeffs.iter().rev() {
        acc = gf_mul(acc, x) ^ c[byte_idx];
    }
    acc
}

// ── split / reconstruct ──────────────────────────────────────────────────────────────────────

/// Split `secret` into `n` shares such that any `k` reconstruct it and any `k - 1` reveal nothing
/// (information-theoretic, classically or quantumly). 32 independent degree-`(k - 1)` polynomials
/// over `GF(2^8)`, one per secret byte; share `i` (`1..=n`) is `(f_0(i), f_1(i), …, f_31(i))`.
///
/// The `k - 1` random higher-degree coefficients are scrubbed before returning.
///
/// # Errors
///
/// [`ShamirError::ThresholdTooSmall`] if `k < 2`; [`ShamirError::ThresholdExceedsShares`] if
/// `k > n`. `n <= 255` and share indices `1..=n` always hold by construction (`n: u8`).
#[cfg(feature = "alloc")]
pub fn split<R: rand_core::CryptoRng>(
    secret: &[u8; 32],
    k: u8,
    n: u8,
    rng: &mut R,
) -> Result<Vec<Share>, ShamirError> {
    if k < MIN_THRESHOLD {
        return Err(ShamirError::ThresholdTooSmall(k));
    }
    if k > n {
        return Err(ShamirError::ThresholdExceedsShares { k, n });
    }

    let mut coeffs: Vec<[u8; 32]> = Vec::with_capacity(k as usize);
    coeffs.push(*secret);
    for _ in 1..k {
        let mut c = [0u8; 32];
        rng.fill_bytes(&mut c);
        coeffs.push(c);
    }

    let mut shares = Vec::with_capacity(n as usize);
    for x in 1..=n {
        let mut bytes = [0u8; 32];
        for (byte_idx, out) in bytes.iter_mut().enumerate() {
            *out = eval_poly_byte(&coeffs, byte_idx, x);
        }
        shares.push(Share { index: x, bytes });
    }

    for c in &mut coeffs {
        c.zeroize();
    }
    Ok(shares)
}

/// Reconstruct the secret: the Lagrange interpolation, at `x = 0`, of the unique
/// degree-`(shares.len() - 1)` polynomial through the given shares. See the module docs for why
/// this has no `k` parameter and cannot, on its own, detect "too few shares for the real `k`".
///
/// # Errors
///
/// [`ShamirError::NoShares`] on an empty slice; [`ShamirError::ZeroIndex`] if any share carries
/// index `0`; [`ShamirError::DuplicateIndex`] if two shares carry the same index.
#[cfg(feature = "alloc")]
pub fn reconstruct(shares: &[Share]) -> Result<[u8; 32], ShamirError> {
    if shares.is_empty() {
        return Err(ShamirError::NoShares);
    }
    for s in shares {
        if s.index == 0 {
            return Err(ShamirError::ZeroIndex);
        }
    }
    for i in 0..shares.len() {
        for other in &shares[i + 1..] {
            if shares[i].index == other.index {
                return Err(ShamirError::DuplicateIndex(shares[i].index));
            }
        }
    }

    // Lagrange coefficient at 0 for each share: lambda_i = prod_{j != i} x_j / (x_i XOR x_j)
    // (subtraction is XOR in GF(2^8); "0 - x_j" is just x_j).
    let mut lambda = vec![0u8; shares.len()];
    for (i, li) in lambda.iter_mut().enumerate() {
        let xi = shares[i].index;
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, sj) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            num = gf_mul(num, sj.index);
            den = gf_mul(den, xi ^ sj.index);
        }
        *li = gf_mul(num, gf_inv(den));
    }

    let mut secret = [0u8; 32];
    for (byte_idx, out) in secret.iter_mut().enumerate() {
        let mut acc = 0u8;
        for (i, s) in shares.iter().enumerate() {
            acc ^= gf_mul(lambda[i], s.bytes[byte_idx]);
        }
        *out = acc;
    }
    Ok(secret)
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use rand::rng;
    use rand_core::Rng;

    use super::*;

    /// Deterministic RNG that plays back a fixed byte buffer via `fill_bytes`, in order — panics
    /// (out-of-bounds slice index) rather than wrapping if a test asks for more bytes than it was
    /// given, since a KAT test silently wrapping into re-used randomness would quietly generate
    /// the WRONG deterministic coefficients rather than failing loudly.
    struct FixedBytesRng<'a> {
        data: &'a [u8],
        pos: usize,
    }

    impl<'a> FixedBytesRng<'a> {
        fn new(data: &'a [u8]) -> Self {
            Self { data, pos: 0 }
        }
    }

    impl rand_core::TryRng for FixedBytesRng<'_> {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut b = [0u8; 4];
            self.try_fill_bytes(&mut b)?;
            Ok(u32::from_le_bytes(b))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut b = [0u8; 8];
            self.try_fill_bytes(&mut b)?;
            Ok(u64::from_le_bytes(b))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            let end = self.pos + dst.len();
            dst.copy_from_slice(&self.data[self.pos..end]);
            self.pos = end;
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for FixedBytesRng<'_> {}

    fn hex32(b: &[u8; 32]) -> alloc::string::String {
        use core::fmt::Write;
        let mut s = alloc::string::String::with_capacity(64);
        for x in b {
            let _ = write!(s, "{x:02x}");
        }
        s
    }

    // ── An independent GF(2^8) reference: classic log/antilog-table arithmetic (generator 0x03),
    //    deliberately a DIFFERENT algorithm from the branchless multiply-and-reduce under test, so
    //    agreement between the two is not "the same bug written twice". Need not be constant-time —
    //    it is only a test oracle. ────────────────────────────────────────────────────────────────
    mod gf_ref {
        /// `a * 2` in GF(2^8) with reduction polynomial 0x11B (branchy — reference only).
        fn xtime(a: u8) -> u8 {
            let shifted = a << 1;
            if a & 0x80 != 0 {
                shifted ^ 0x1B
            } else {
                shifted
            }
        }

        /// Exp/log tables for the multiplicative group generated by 0x03. `EXP[i] = 3^i`
        /// (`i = 0..255`, period 255); `LOG[v] = i` such that `3^i == v` (`v != 0`).
        fn tables() -> ([u8; 255], [u8; 256]) {
            let mut exp = [0u8; 255];
            let mut log = [0u8; 256];
            let mut x = 1u8;
            for (i, e) in exp.iter_mut().enumerate() {
                *e = x;
                log[x as usize] = i as u8;
                // x = x * 3 = (x * 2) XOR x
                x = xtime(x) ^ x;
            }
            (exp, log)
        }

        pub struct Gf {
            exp: [u8; 255],
            log: [u8; 256],
        }

        impl Gf {
            pub fn new() -> Self {
                let (exp, log) = tables();
                Self { exp, log }
            }

            pub fn mul(&self, a: u8, b: u8) -> u8 {
                if a == 0 || b == 0 {
                    return 0;
                }
                let idx = (u16::from(self.log[a as usize]) + u16::from(self.log[b as usize])) % 255;
                self.exp[idx as usize]
            }

            pub fn inv(&self, a: u8) -> u8 {
                if a == 0 {
                    return 0;
                }
                let idx = (255 - u16::from(self.log[a as usize])) % 255;
                self.exp[idx as usize]
            }

            /// Horner evaluation of a per-byte polynomial at `x` using table arithmetic.
            pub fn eval(&self, coeffs: &[[u8; 32]], byte_idx: usize, x: u8) -> u8 {
                let mut acc = 0u8;
                for c in coeffs.iter().rev() {
                    acc = self.mul(acc, x) ^ c[byte_idx];
                }
                acc
            }

            /// Independent Shamir reconstruct (Lagrange at 0) via table arithmetic.
            pub fn reconstruct(&self, shares: &[super::Share]) -> [u8; 32] {
                let mut out = [0u8; 32];
                for (byte_idx, o) in out.iter_mut().enumerate() {
                    let mut acc = 0u8;
                    for (i, si) in shares.iter().enumerate() {
                        let mut num = 1u8;
                        let mut den = 1u8;
                        for (j, sj) in shares.iter().enumerate() {
                            if i == j {
                                continue;
                            }
                            num = self.mul(num, sj.index);
                            den = self.mul(den, si.index ^ sj.index);
                        }
                        let lambda = self.mul(num, self.inv(den));
                        acc ^= self.mul(lambda, si.bytes[byte_idx]);
                    }
                    *o = acc;
                }
                out
            }
        }
    }

    // ── Acceptance: k_of_n_reconstructs_for_every_k_subset (n=5, k=3, all 10 subsets) ───────

    #[test]
    fn k_of_n_reconstructs_for_every_k_subset() {
        let mut r = rng();
        let secret = {
            let mut s = [0u8; 32];
            r.fill_bytes(&mut s);
            s
        };
        let (k, n) = (3u8, 5u8);
        let shares = split(&secret, k, n, &mut r).expect("split");
        assert_eq!(shares.len(), n as usize);

        // All C(5,3) = 10 subsets of size k reconstruct the exact secret.
        let mut subset_count = 0;
        for a in 0..shares.len() {
            for b in (a + 1)..shares.len() {
                for c in (b + 1)..shares.len() {
                    let subset = [shares[a].clone(), shares[b].clone(), shares[c].clone()];
                    let rec = reconstruct(&subset).expect("reconstruct");
                    assert_eq!(rec, secret, "subset ({a},{b},{c}) failed to reconstruct");
                    subset_count += 1;
                }
            }
        }
        assert_eq!(subset_count, 10, "C(5,3) must be exactly 10 subsets");
    }

    // ── Acceptance: k_minus_one_shares_reveal_nothing (statistical, byte-0 hit rate ~1/256) ─

    #[test]
    fn k_minus_one_shares_reveal_nothing() {
        let mut r = rng();
        let secret = {
            let mut s = [0u8; 32];
            r.fill_bytes(&mut s);
            s
        };
        let (k, n) = (4u8, 7u8);
        let shares = split(&secret, k, n, &mut r).expect("split");

        // k-1 genuine shares plus one fabricated share at a still-missing index, random bytes.
        let genuine: Vec<Share> = shares[..(k as usize - 1)].to_vec();
        let missing_index = shares[k as usize - 1].index; // still-unused index, in range

        const TRIALS: u32 = 10_000;
        let mut hits = 0u32;
        for _ in 0..TRIALS {
            let mut guess_bytes = [0u8; 32];
            r.fill_bytes(&mut guess_bytes);
            let mut attempt = genuine.clone();
            attempt.push(Share {
                index: missing_index,
                bytes: guess_bytes,
            });
            let rec =
                reconstruct(&attempt).expect("reconstruct with k shares (k-1 genuine + 1 guess)");
            if rec[0] == secret[0] {
                hits += 1;
            }
        }

        // Expected hit probability per byte is exactly 1/256 (uniform bijection between the
        // guessed byte and the reconstructed byte-0 value — see module docs). Binomial(TRIALS,
        // 1/256): mean = TRIALS/256 ~= 39.06, sigma = sqrt(TRIALS * p * (1-p)) ~= 6.22.
        let p = 1.0 / 256.0;
        let mean = f64::from(TRIALS) * p;
        let sigma = (f64::from(TRIALS) * p * (1.0 - p)).sqrt();
        let observed = f64::from(hits);
        let z = (observed - mean).abs() / sigma;
        // Gate at 6 sigma (the house "loose" statistical bound, matching `shamir_gf256_ct`'s
        // dudect gate). A correct split makes byte-0 exactly uniform (1/256), so this z is pure
        // sampling noise: a 3-sigma bound false-fails an unseeded run ~0.3% of the time, whereas a
        // GENUINE leak (k-1 shares determining the secret) drives the hit rate to ~1, hundreds of
        // sigma out -- so 6 sigma loses no real detection power while it stops phantom reds.
        assert!(
            z < 6.0,
            "byte-0 hit rate {hits}/{TRIALS} ({:.5}) is {z:.2} sigma from the expected 1/256 \
             (mean {mean:.2}, sigma {sigma:.2}) -- k-1 shares are leaking information",
            observed / f64::from(TRIALS)
        );
    }

    // ── Acceptance: agrees with an independent log/antilog-table reference (cross-algorithm) ─

    #[test]
    fn agrees_with_independent_log_antilog_reference() {
        let gf = gf_ref::Gf::new();
        let mut r = rng();

        // Sweep a spread of (k, n) with random secrets and random coefficients, driving BOTH the
        // branchless implementation and the table reference from the SAME coefficient bytes.
        for &(k, n) in &[
            (2u8, 2u8),
            (2, 5),
            (3, 5),
            (4, 7),
            (5, 5),
            (8, 12),
            (10, 255),
        ] {
            for _ in 0..25 {
                let mut secret = [0u8; 32];
                r.fill_bytes(&mut secret);

                // (k-1) rows of 32 random coefficient bytes, played back to split() in order.
                let mut coeff_bytes = vec![0u8; (k as usize - 1) * 32];
                r.fill_bytes(&mut coeff_bytes);

                let mut coeffs: Vec<[u8; 32]> = Vec::with_capacity(k as usize);
                coeffs.push(secret);
                let (rows, _rest) = coeff_bytes.as_chunks::<32>();
                for row in rows {
                    coeffs.push(*row);
                }

                let mut fixed = FixedBytesRng::new(&coeff_bytes);
                let shares = split(&secret, k, n, &mut fixed).expect("split");
                assert_eq!(shares.len(), n as usize);

                // 1. Every branchless share equals the table-reference evaluation of the same poly.
                for s in &shares {
                    let mut want = [0u8; 32];
                    for (byte_idx, w) in want.iter_mut().enumerate() {
                        *w = gf.eval(&coeffs, byte_idx, s.index);
                    }
                    assert_eq!(
                        hex32(&s.bytes),
                        hex32(&want),
                        "k={k} n={n} share {} diverges from the log/antilog reference",
                        s.index
                    );
                }

                // 2. Branchless reconstruct and the table-reference reconstruct both recover the
                //    secret from the first k shares.
                let subset = &shares[..k as usize];
                assert_eq!(reconstruct(subset).expect("reconstruct"), secret);
                assert_eq!(gf.reconstruct(subset), secret);
            }
        }
    }

    // ── Pinned known-answer vector: fixed secret + fixed coefficients, exact share bytes.
    //    Cross-validated in-test by the independent table reference, and pins cross-target
    //    determinism (the arithmetic is pure integer math with no platform-dependent behaviour). ─

    #[test]
    fn pinned_known_answer_vector() {
        // secret = 00,01,02,...,1f ; one extra coefficient row (k=2) = ff,fe,...,e0.
        let mut secret = [0u8; 32];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut coeff_row = [0u8; 32];
        for (i, b) in coeff_row.iter_mut().enumerate() {
            *b = 0xFF - i as u8;
        }
        let (k, n) = (2u8, 3u8);

        let mut fixed = FixedBytesRng::new(&coeff_row);
        let shares = split(&secret, k, n, &mut fixed).expect("split");

        // f(x) per byte j is secret[j] XOR gf_mul(coeff_row[j], x). Frozen expected share bytes
        // (hex) for x = 1, 2, 3 — cross-target determinism pin.
        let expected: [&str; 3] = [
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "e5e6e3e0e9eaefecfdfefbf8f1f2f7f4d5d6d3d0d9dadfdccdcecbc8c1c2c7c4",
            "1a181e1c121016140a080e0c020006043a383e3c323036342a282e2c22202624",
        ];

        // Cross-check against the independent log/antilog table reference (a genuinely different
        // algorithm), so the frozen constants above are pinned by BOTH implementations.
        let gf = gf_ref::Gf::new();
        let coeffs = [secret, coeff_row];
        for (s, want_hex) in shares.iter().zip(expected.iter()) {
            let mut want = [0u8; 32];
            for (byte_idx, w) in want.iter_mut().enumerate() {
                *w = gf.eval(&coeffs, byte_idx, s.index);
            }
            assert_eq!(
                hex32(&s.bytes),
                hex32(&want),
                "pinned share {} vs reference",
                s.index
            );
            assert_eq!(
                hex32(&s.bytes),
                *want_hex,
                "pinned share {} vs frozen constant",
                s.index
            );
        }
        assert_eq!(
            reconstruct(&shares[..k as usize]).expect("reconstruct"),
            secret
        );
    }

    // ── Input validation ─────────────────────────────────────────────────────────────────────

    #[test]
    fn rejects_duplicate_index() {
        let a = Share {
            index: 1,
            bytes: [0xAA; 32],
        };
        let b = Share {
            index: 1,
            bytes: [0xBB; 32],
        };
        assert_eq!(reconstruct(&[a, b]), Err(ShamirError::DuplicateIndex(1)));
    }

    #[test]
    fn rejects_k_gt_n() {
        let mut r = rng();
        let secret = [0u8; 32];
        assert_eq!(
            split(&secret, 6, 5, &mut r),
            Err(ShamirError::ThresholdExceedsShares { k: 6, n: 5 })
        );
    }

    #[test]
    fn rejects_threshold_below_two() {
        let mut r = rng();
        let secret = [0u8; 32];
        assert_eq!(
            split(&secret, 1, 5, &mut r),
            Err(ShamirError::ThresholdTooSmall(1))
        );
        assert_eq!(
            split(&secret, 0, 5, &mut r),
            Err(ShamirError::ThresholdTooSmall(0))
        );
    }

    #[test]
    fn reconstruct_rejects_empty() {
        assert_eq!(reconstruct(&[]), Err(ShamirError::NoShares));
    }

    #[test]
    fn reconstruct_rejects_zero_index() {
        let a = Share {
            index: 0,
            bytes: [0x11; 32],
        };
        assert_eq!(reconstruct(&[a]), Err(ShamirError::ZeroIndex));
    }

    /// `k = n` (every share is required) still round-trips.
    #[test]
    fn k_equals_n_round_trips() {
        let mut r = rng();
        let mut secret = [0u8; 32];
        r.fill_bytes(&mut secret);
        let shares = split(&secret, 4, 4, &mut r).expect("split");
        assert_eq!(reconstruct(&shares).expect("reconstruct"), secret);
    }

    /// More than `k` shares (an over-supplied honest set) still reconstructs correctly — extra
    /// genuine points on the same curve do not perturb the interpolated value at 0.
    #[test]
    fn more_than_k_shares_still_reconstructs() {
        let mut r = rng();
        let mut secret = [0u8; 32];
        r.fill_bytes(&mut secret);
        let shares = split(&secret, 3, 6, &mut r).expect("split");
        assert_eq!(reconstruct(&shares).expect("reconstruct all 6"), secret);
        assert_eq!(
            reconstruct(&shares[..5]).expect("reconstruct 5 of 6"),
            secret
        );
    }

    /// `Zeroize` scrubs a share's bytes (the derived `ZeroizeOnDrop` runs the same impl on drop).
    #[test]
    fn share_zeroizes() {
        let mut s = Share {
            index: 7,
            bytes: [0x5A; 32],
        };
        s.zeroize();
        assert_eq!(s.bytes, [0u8; 32]);
    }
}

/// Constant-time smoke test for `gf_mul` (dudect-style Welch's-`t` timing check, house
/// `lib-q-sca-test` harness). `cargo test -p lib-q-sss --features sca-test shamir_gf256_ct`.
///
/// This is a wall-clock timing probe, not a substitute for instrumented power traces — see
/// `lib_q_sca_test::dudect` for the same caveat. It exists to catch a secret-dependent branch or
/// table index regressing into `gf_mul`/`gf_inv` (both deliberately branchless today).
#[cfg(all(test, feature = "sca-test"))]
mod shamir_gf256_ct {
    use lib_q_sca_test::dudect::{
        timing_passes_loose,
        timing_t_statistic,
    };
    use rand::rng;
    use rand_core::Rng;

    use super::gf_mul;

    /// Compares timing of `gf_mul` over a fixed all-zero operand pair (class A: the "cheapest"
    /// possible input for a naive branchy implementation — every conditional would take its
    /// not-taken path every iteration) against uniformly random operand pairs (class B). A
    /// branchless implementation's timing must not distinguish the two classes.
    #[test]
    fn gf_mul_timing_is_operand_independent() {
        let mut r = rng();
        const SAMPLES: usize = 3000;

        let mut fixed_times = alloc::vec::Vec::with_capacity(SAMPLES);
        let mut random_times = alloc::vec::Vec::with_capacity(SAMPLES);

        for _ in 0..SAMPLES {
            let (fa, fb) = (0x00u8, 0x00u8);
            let start = std::time::Instant::now();
            let out =
                std::hint::black_box(gf_mul(std::hint::black_box(fa), std::hint::black_box(fb)));
            std::hint::black_box(out);
            fixed_times.push(start.elapsed().as_secs_f64());

            let mut ab = [0u8; 2];
            r.fill_bytes(&mut ab);
            let start = std::time::Instant::now();
            let out = std::hint::black_box(gf_mul(
                std::hint::black_box(ab[0]),
                std::hint::black_box(ab[1]),
            ));
            std::hint::black_box(out);
            random_times.push(start.elapsed().as_secs_f64());
        }

        let t = timing_t_statistic(&fixed_times, &random_times);
        eprintln!(
            "gf_mul dudect-style Welch t-statistic (fixed 0x00,0x00 vs random operands, \
             {SAMPLES} samples/class): {t:?}"
        );
        assert!(
            timing_passes_loose(6.0, &fixed_times, &random_times),
            "gf_mul timing distinguishes fixed-vs-random operands beyond the loose gate: t={t:?}"
        );
    }
}
