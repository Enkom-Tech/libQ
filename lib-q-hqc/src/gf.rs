//! Table-free, branch-free GF(2^8) arithmetic for HQC.
//!
//! This is a faithful port of `reference/hqc/src/ref/gf.c`: `gf_reduce`, `gf_carryless_mul`,
//! `gf_mul`, `gf_square`, `gf_inverse`. Unlike the table-based Galois-field helpers private to
//! [`crate::reed_solomon::ReedSolomon`] (`gf_multiply`, `gf_inverse`, `gf_inverse_u16`), none of
//! these functions branch on a secret value or index a table with a secret-derived index:
//!
//! - `gf_carryless_mul` selects among a 4-entry table using an arithmetic equality mask
//!   (`eq_select`) rather than `table[secret_index]`, and has no `if`/`match` on `a`/`b` at all.
//! - `gf_reduce` always runs the same fixed number of shift/XOR steps regardless of its input.
//! - `gf_square` and `gf_mul` are built purely from the two primitives above.
//! - `gf_inverse` runs a fixed addition-chain (`1 2 3 4 7 11 15 30 60 120 127 254`) of `gf_mul`
//!   and `gf_square` calls with no early return — in particular `a == 0` is not special-cased,
//!   yet `gf_inverse(0) == 0` still holds (every term in the chain is `0`); see
//!   `gf_inverse_zero_is_zero` below, checked against the table implementation.
//!
//! All three HQC parameter sets (`Hqc1Params`, `Hqc3Params`, `Hqc5Params`) use the same field:
//! `M = 8`, `GF_POLY = 0x11D`. The functions here are hard-coded to exactly that field — they
//! are not generic over [`crate::params_correct::HqcParams`] — and the `const _: () = assert!(..)`
//! block below pins that assumption at compile time: if a future parameter set ever used a
//! different `M`/`GF_POLY`, the crate would fail to build rather than silently computing wrong
//! field arithmetic.

use crate::params_correct::{
    Hqc1Params,
    Hqc3Params,
    Hqc5Params,
    HqcParams,
};

/// Field degree `m` for GF(2^m). Fixed for all HQC parameter sets.
pub const GF_M: u32 = 8;

/// Irreducible polynomial defining GF(2^8): `x^8 + x^4 + x^3 + x + 1`.
pub const GF_POLY: u16 = 0x11D;

// Pin the assumption that every HQC parameter set shares this exact field. A future parameter
// set with a different `M`/`GF_POLY` would silently get wrong answers from the functions in this
// module if this weren't checked, since none of them take `P: HqcParams` as a type parameter.
const _: () = assert!(<Hqc1Params as HqcParams>::M == GF_M as usize);
const _: () = assert!(<Hqc1Params as HqcParams>::GF_POLY == GF_POLY);
const _: () = assert!(<Hqc3Params as HqcParams>::M == GF_M as usize);
const _: () = assert!(<Hqc3Params as HqcParams>::GF_POLY == GF_POLY);
const _: () = assert!(<Hqc5Params as HqcParams>::M == GF_M as usize);
const _: () = assert!(<Hqc5Params as HqcParams>::GF_POLY == GF_POLY);

/// Feedback tap positions for reduction modulo `GF_POLY = 0x11D` (bits set at 4, 3, 2; bit 0 is
/// handled by the initial no-shift XOR, bit 8 by the `x >> 8` split). Mirrors
/// `gf_reduction_taps` in `reference/hqc/src/ref/gf.c:60`.
const GF_REDUCTION_TAPS: [u32; 3] = [4, 3, 2];

/// Branch-free equality select: returns `value` if `x == i`, else `0` — without a conditional
/// branch or a secret-indexed lookup.
///
/// This mirrors the mask idiom used twice in `reference/hqc/src/ref/gf.c`'s
/// `gf_carryless_mul` (lines 119-121 and 130-132):
/// `g ^= (u[i] & -(1 - ((tmp2 | -tmp2) >> 31)))` where `tmp2 = tmp1 - i`. In C, `tmp1 - i` is
/// computed in `int` (integer promotion of the `uint16_t` operands) and then stored into a
/// `uint32_t`, so a negative difference wraps to its 32-bit two's-complement representation —
/// that is exactly [`u32::wrapping_sub`]. `tmp2 | -tmp2` has bit 31 set iff `tmp2 != 0` (the
/// standard "is this word nonzero" trick), and the final unary `-` (again 32-bit two's
/// complement, i.e. [`u32::wrapping_neg`]) turns "is zero" into an all-ones mask.
#[inline]
fn eq_select(value: u16, x: u16, i: u16) -> u16 {
    let diff = (x as u32).wrapping_sub(i as u32);
    let neg_diff = diff.wrapping_neg();
    let is_nonzero = (diff | neg_diff) >> 31; // 1 if x != i, else 0
    let is_eq = 1u32.wrapping_sub(is_nonzero); // 1 if x == i, else 0
    let mask = 0u32.wrapping_sub(is_eq); // all-ones if x == i, else 0
    ((value as u32) & mask) as u16
}

/// Reduce a polynomial modulo `GF_POLY` in GF(2^8).
///
/// Assumes `deg(x) <= 14` (the largest degree that arises from multiplying two GF(2^8)
/// elements) and always performs exactly two fixed reduction passes with fixed tap positions,
/// regardless of the value of `x`. Port of `gf_reduce` in `reference/hqc/src/ref/gf.c:76-97`.
fn gf_reduce(mut x: u16) -> u16 {
    for _ in 0..2 {
        let mut md: u32 = (x as u32) >> GF_M;
        x &= (1u16 << GF_M) - 1;
        x ^= md as u16;

        let mut z1: u32 = 0;
        for j in (0..GF_REDUCTION_TAPS.len()).rev() {
            let z2 = GF_REDUCTION_TAPS[j];
            let dist = z2 - z1;
            md <<= dist;
            x ^= md as u16;
            z1 = z2;
        }
    }
    x
}

/// Carryless (XOR, no-carry) multiplication of two GF(2^8) representatives, producing the full
/// 16-bit unreduced product as `(low_byte, high_byte)`.
///
/// Implementation of algorithm `mul1` from <https://hal.inria.fr/inria-00188261v4/document> with
/// `s = 2`, `w = 8`, ported from `gf_carryless_mul` in `reference/hqc/src/ref/gf.c:109-145`. Every
/// selection among the 4-entry table `u` is done via [`eq_select`] on the *public* loop counter
/// `i`/`j`, never by indexing `u` with a value derived from the secret inputs `a`/`b`.
fn gf_carryless_mul(a: u8, b: u8) -> (u8, u8) {
    let u1: u16 = (b as u16) & ((1u16 << 7) - 1);
    let u2: u16 = u1 << 1;
    let u3: u16 = u2 ^ u1;
    let u: [u16; 4] = [0, u1, u2, u3];

    let tmp1: u16 = (a as u16) & 3;
    let mut l: u16 = 0;
    for i in 0..4u16 {
        l ^= eq_select(u[i as usize], tmp1, i);
    }
    let mut h: u16 = 0;

    let mut i: u16 = 2;
    while i < 8 {
        let tmp3: u16 = ((a as u16) >> i) & 3;
        let mut g: u16 = 0;
        for j in 0..4u16 {
            g ^= eq_select(u[j as usize], tmp3, j);
        }
        l ^= g << i;
        h ^= g >> (8 - i);
        i += 2;
    }

    let mask: u16 = 0u16.wrapping_sub(((b >> 7) & 1) as u16);
    l ^= ((a as u16) << 7) & mask;
    h ^= ((a as u16) >> 1) & mask;

    (l as u8, h as u8)
}

/// Multiply two elements of GF(2^8).
///
/// Table-free and branch-free: no `if`, no array indexed by a secret value. Port of `gf_mul` in
/// `reference/hqc/src/ref/gf.c:153-158`.
pub fn gf_mul(a: u8, b: u8) -> u8 {
    let (lo, hi) = gf_carryless_mul(a, b);
    let tmp = (lo as u16) ^ ((hi as u16) << 8);
    gf_reduce(tmp) as u8
}

/// Square an element of GF(2^8).
///
/// Table-free and branch-free. Port of `gf_square` in `reference/hqc/src/ref/gf.c:165-174`.
pub fn gf_square(a: u8) -> u8 {
    let mut b: u32 = a as u32;
    let mut s: u32 = b & 1;
    for i in 1..GF_M {
        b <<= 1;
        s ^= b & (1u32 << (2 * i));
    }
    gf_reduce(s as u16) as u8
}

/// Compute the multiplicative inverse of an element of GF(2^8) using the fixed addition chain
/// `1 2 3 4 7 11 15 30 60 120 127 254`, i.e. `a^254` (which equals `a^-1` for `a != 0` by
/// Fermat's little theorem over the 255-element multiplicative group).
///
/// Table-free and branch-free: there is no `if a == 0` special case anywhere in this function or
/// in [`gf_mul`]/[`gf_square`] beneath it, yet `gf_inverse(0) == 0` still holds — every multiply
/// and square in the chain starting from `0` stays `0`, so the "inverse of 0 is 0" convention
/// callers rely on falls out naturally rather than being special-cased. This is verified against
/// the table-based reference in `gf_inverse_zero_is_zero` and the exhaustive
/// `gf_inverse_matches_table_over_full_domain` below. Port of `gf_inverse` in
/// `reference/hqc/src/ref/gf.c:182-198`.
pub fn gf_inverse(a: u8) -> u8 {
    let mut inv = gf_square(a); // a^2
    let mut tmp1 = gf_mul(inv, a); // a^3
    inv = gf_square(inv); // a^4
    let tmp2 = gf_mul(inv, tmp1); // a^7
    tmp1 = gf_mul(inv, tmp2); // a^11
    inv = gf_mul(tmp1, inv); // a^15
    inv = gf_square(inv); // a^30
    inv = gf_square(inv); // a^60
    inv = gf_square(inv); // a^120
    inv = gf_mul(inv, tmp2); // a^127
    inv = gf_square(inv); // a^254
    inv
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rebuild GF(2^8) exp/log tables independently of `reed_solomon.rs`'s private `gf_exp`/
    /// `gf_log` fields, using the same generation recurrence described in
    /// `reference/hqc/src/ref/gf.c`'s `gf_generate` (and mirrored by
    /// `ReedSolomon::init_gf_tables`): `exp[i] = alpha^i`, `log[alpha^i] = i`, `alpha = 2`. This
    /// gives an independent oracle to check the new table-free functions against, without
    /// widening any visibility in `reed_solomon.rs` (whose table-based helpers are private).
    fn build_tables() -> ([u8; 256], [u8; 256]) {
        let mut exp = [0u8; 256];
        let mut log = [0u8; 256];
        let mut elt: u16 = 1;
        let alpha: u16 = 2;
        for i in 0..255usize {
            exp[i] = elt as u8;
            log[elt as usize] = i as u8;
            elt *= alpha;
            if elt >= 1 << GF_M {
                elt ^= GF_POLY;
            }
        }
        log[0] = 0; // log(0) undefined; 0 by convention (matches gf_generate / init_gf_tables)
        (exp, log)
    }

    fn table_mul(exp: &[u8; 256], log: &[u8; 256], a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let sum = log[a as usize] as usize + log[b as usize] as usize;
        exp[sum % 255]
    }

    fn table_inverse(exp: &[u8; 256], log: &[u8; 256], a: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        exp[(255 - log[a as usize] as usize) % 255]
    }

    #[test]
    fn gf_params_are_fixed_m8_poly_0x11d_for_all_param_sets() {
        assert_eq!(<Hqc1Params as HqcParams>::M, GF_M as usize);
        assert_eq!(<Hqc1Params as HqcParams>::GF_POLY, GF_POLY);
        assert_eq!(<Hqc3Params as HqcParams>::M, GF_M as usize);
        assert_eq!(<Hqc3Params as HqcParams>::GF_POLY, GF_POLY);
        assert_eq!(<Hqc5Params as HqcParams>::M, GF_M as usize);
        assert_eq!(<Hqc5Params as HqcParams>::GF_POLY, GF_POLY);
    }

    /// Exhaustive: all 256*256 pairs, not a sample.
    #[test]
    fn gf_mul_matches_table_over_full_domain() {
        let (exp, log) = build_tables();
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                assert_eq!(
                    gf_mul(a, b),
                    table_mul(&exp, &log, a, b),
                    "gf_mul({a}, {b}) mismatch"
                );
            }
        }
    }

    /// Exhaustive: all 256 values, not a sample.
    #[test]
    fn gf_square_matches_table_over_full_domain() {
        let (exp, log) = build_tables();
        for a in 0u8..=255 {
            assert_eq!(
                gf_square(a),
                table_mul(&exp, &log, a, a),
                "gf_square({a}) mismatch"
            );
        }
    }

    /// Exhaustive: all 256 values, not a sample.
    #[test]
    fn gf_inverse_matches_table_over_full_domain() {
        let (exp, log) = build_tables();
        for a in 0u8..=255 {
            assert_eq!(
                gf_inverse(a),
                table_inverse(&exp, &log, a),
                "gf_inverse({a}) mismatch"
            );
        }
    }

    #[test]
    fn gf_inverse_zero_is_zero() {
        let (exp, log) = build_tables();
        assert_eq!(gf_inverse(0), 0);
        assert_eq!(table_inverse(&exp, &log, 0), 0);
    }

    #[test]
    fn gf_inverse_is_multiplicative_inverse_for_nonzero_elements() {
        for a in 1u8..=255 {
            assert_eq!(gf_mul(a, gf_inverse(a)), 1, "a * a^-1 != 1 for a={a}");
        }
    }
}
