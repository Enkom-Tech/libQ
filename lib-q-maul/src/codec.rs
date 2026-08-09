//! Compression, decompression, bit-packing and message encoding.
//!
//! `Comp_(q,d)(x) = round(2^d x / q) mod 2^d` and `Decomp_(q,d)(y) = round(q y / 2^d)`, exactly as
//! defined in ePrint 2025/1755 §5.2 (p18), with ties rounded up per §5.1 ("we denote by `round(x)`
//! the nearest integer to `x`, with ties rounded up").
//!
//! Every routine here runs on secret data and is branch-free: no `%`, no data-dependent index.

use alloc::vec::Vec;

use crate::arith::Modulus;
use crate::params::{
    N,
    ParamSet,
    Poly,
};

/// `Comp_(q,d)(x)` for `x in [0, q)`.
///
/// `round(2^d x / q)` with ties up is exactly `floor((2^(d+1) x + q) / (2q))`; the trailing mask is
/// the `mod 2^d`, which is what makes the `x` near `q` case wrap to 0 rather than overflow.
#[inline]
#[must_use]
pub fn compress(x: i32, d: u32, m: &Modulus) -> u32 {
    let n = (i64::from(x) << (d + 1)) + m.q();
    (m.div_2q(n) as u32) & ((1u32 << d) - 1)
}

/// `Decomp_(q,d)(y)` — exact, only shifts.
#[inline]
#[must_use]
pub fn decompress(y: u32, d: u32, m: &Modulus) -> i32 {
    let num = 2 * m.q() * i64::from(y) + (1i64 << d);
    (num >> (d + 1)) as i32
}

/// Compress a whole polynomial.
#[must_use]
pub fn compress_poly(p: &Poly, d: u32, m: &Modulus) -> [u32; N] {
    let mut out = [0u32; N];
    for i in 0..N {
        out[i] = compress(p[i], d, m);
    }
    out
}

/// Decompress a whole polynomial.
#[must_use]
pub fn decompress_poly(c: &[u32; N], d: u32, m: &Modulus) -> Poly {
    let mut out = [0i32; N];
    for i in 0..N {
        out[i] = decompress(c[i], d, m);
    }
    out
}

/// Pack `vals` (each `< 2^bits`) little-endian into `out`.
///
/// Only ever called with `vals.len() * bits` a multiple of 8 (256 coefficients times any bit
/// width is), so no partial trailing byte is possible.
pub fn pack_bits(vals: &[u32], bits: u32, out: &mut Vec<u8>) {
    debug_assert!(bits > 0 && bits <= 16);
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    for &v in vals {
        acc |= u64::from(v & ((1u32 << bits) - 1)) << nbits;
        nbits += bits;
        while nbits >= 8 {
            out.push((acc & 0xFF) as u8);
            acc >>= 8;
            nbits -= 8;
        }
    }
    debug_assert_eq!(nbits, 0, "pack_bits: not byte-aligned");
}

/// Inverse of [`pack_bits`]. Returns `None` if `src` is too short.
#[must_use]
pub fn unpack_bits(src: &[u8], bits: u32, count: usize) -> Option<Vec<u32>> {
    let need = count * (bits as usize);
    if !need.is_multiple_of(8) || src.len() < need / 8 {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    let mut idx = 0usize;
    for _ in 0..count {
        while nbits < bits {
            acc |= u64::from(src[idx]) << nbits;
            idx += 1;
            nbits += 8;
        }
        out.push((acc & ((1u64 << bits) - 1)) as u32);
        acc >>= bits;
        nbits -= bits;
    }
    Some(out)
}

/// Encode a 32-byte message as `ceil(q/2) * m` with `m in R_2` (one bit per coefficient).
#[must_use]
pub fn message_to_poly(msg: &[u8; 32], p: &ParamSet) -> Poly {
    let half = (p.q + 1) / 2; // ceil(q/2) for odd q
    let mut out = [0i32; N];
    for i in 0..N {
        let bit = i32::from((msg[i / 8] >> (i % 8)) & 1);
        out[i] = half * bit;
    }
    out
}

/// Recover the message bits: `round(2 x / q) mod 2` for each coefficient, branch-free.
///
/// `round(2x/q)` with ties up is `1` exactly when `4x >= q` and `4x < 3q`; outside that band it is
/// `0` or `2`, both even. Written as two sign tests so there is no division and no branch on the
/// secret coefficient.
#[must_use]
pub fn poly_to_message(x: &Poly, p: &ParamSet) -> [u8; 32] {
    let q = i64::from(p.q);
    let mut out = [0u8; 32];
    for i in 0..N {
        let v = 4 * i64::from(x[i]);
        // ge = 1 when v >= q
        let ge = 1u8 & !(((v - q) >> 63) as u8);
        // lt = 1 when v < 3q
        let lt = 1u8 & (((v - 3 * q) >> 63) as u8);
        out[i / 8] |= (ge & lt) << (i % 8);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::ALL;

    #[test]
    fn compress_matches_the_rational_definition_on_every_input() {
        for p in ALL {
            let m = Modulus::new(p);
            for d in [p.du, p.dv] {
                for x in 0..p.q {
                    // Reference: round(2^d x / q) mod 2^d computed in exact rational arithmetic.
                    let num = (i64::from(x) << (d + 1)) + i64::from(p.q);
                    let want = ((num / (2 * i64::from(p.q))) as u32) & ((1u32 << d) - 1);
                    assert_eq!(compress(x, d, &m), want, "{} d={d} x={x}", p.name);
                }
            }
        }
    }

    #[test]
    fn compress_then_decompress_stays_within_the_rounding_error() {
        for p in ALL {
            let m = Modulus::new(p);
            for d in [p.du, p.dv] {
                let bound = i64::from(p.q) / (1i64 << (d + 1)) + 1;
                for x in 0..p.q {
                    let y = decompress(compress(x, d, &m), d, &m);
                    let diff = m.center(m.reduce(i64::from(y) - i64::from(x)));
                    assert!(
                        diff.abs() <= bound,
                        "{} d={d}: |Decomp(Comp({x})) - {x}| = {} > {bound}",
                        p.name,
                        diff.abs()
                    );
                }
            }
        }
    }

    #[test]
    fn message_round_trips_through_the_encoder_with_no_noise() {
        for p in ALL {
            let mut msg = [0u8; 32];
            for (i, b) in msg.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(37).wrapping_add(11);
            }
            let poly = message_to_poly(&msg, p);
            assert_eq!(poly_to_message(&poly, p), msg, "{}", p.name);
        }
    }

    #[test]
    fn message_decoder_tolerates_noise_up_to_a_quarter_of_q_and_flips_past_it() {
        // The decoder's job is a q/4 decision boundary. Show it holds inside the band AND that it
        // genuinely changes outside it -- a decoder that always returned the same bit would pass
        // the first half alone.
        for p in ALL {
            let m = Modulus::new(p);
            let msg = [0xA5u8; 32];
            let base = message_to_poly(&msg, p);
            let inside = i64::from(p.q) / 4 - 1;
            let mut noisy = base;
            for (i, c) in noisy.iter_mut().enumerate() {
                let delta = if i % 2 == 0 { inside } else { -inside };
                *c = m.reduce(i64::from(*c) + delta);
            }
            assert_eq!(poly_to_message(&noisy, p), msg, "{} inside band", p.name);

            let outside = i64::from(p.q) / 2;
            let mut flipped = base;
            for c in &mut flipped {
                *c = m.reduce(i64::from(*c) + outside);
            }
            let got = poly_to_message(&flipped, p);
            assert_ne!(got, msg, "{} outside band should flip", p.name);
        }
    }

    #[test]
    fn bit_packing_round_trips_at_every_width_the_crate_uses() {
        for p in ALL {
            for bits in [p.du, p.dv, p.pk_bits] {
                let vals: Vec<u32> = (0..N as u32)
                    .map(|i| i.wrapping_mul(2_654_435_761) & ((1u32 << bits) - 1))
                    .collect();
                let mut buf = Vec::new();
                pack_bits(&vals, bits, &mut buf);
                assert_eq!(buf.len(), N * (bits as usize) / 8, "{} bits={bits}", p.name);
                let back = unpack_bits(&buf, bits, N).expect("unpack");
                assert_eq!(back, vals, "{} bits={bits}", p.name);
            }
        }
    }

    #[test]
    fn unpack_rejects_a_short_buffer() {
        let buf = [0u8; 10];
        assert!(unpack_bits(&buf, 11, N).is_none());
    }
}
