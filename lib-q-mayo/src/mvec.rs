//! Arithmetic on "m-vectors": vectors of `M = 64` GF(16) elements packed 16
//! nibbles per `u64` limb (`M_VEC_LIMBS = 4` limbs), little-endian nibble
//! order. Port of `generic/arithmetic_fixed.h` from the MAYO reference
//! implementation. All operations are branch-free.

use crate::gf16::mul_table;
use crate::params::M_VEC_LIMBS;

const LSB: u64 = 0x1111_1111_1111_1111;
const MSB: u64 = 0x8888_8888_8888_8888;

#[inline(always)]
pub fn m_vec_copy(input: &[u64], out: &mut [u64]) {
    out[..M_VEC_LIMBS].copy_from_slice(&input[..M_VEC_LIMBS]);
}

#[inline(always)]
pub fn m_vec_add(input: &[u64], acc: &mut [u64]) {
    let input: &[u64; M_VEC_LIMBS] = input[..M_VEC_LIMBS].try_into().unwrap();
    let acc: &mut [u64; M_VEC_LIMBS] = (&mut acc[..M_VEC_LIMBS]).try_into().unwrap();
    for i in 0..M_VEC_LIMBS {
        acc[i] ^= input[i];
    }
}

/// `acc += a * input` for a GF(16) scalar `a`, nibble-sliced, no lookups.
#[inline(always)]
pub fn m_vec_mul_add(input: &[u64], a: u8, acc: &mut [u64]) {
    // one bounds check per call instead of eight inside the limb loop —
    // this is the innermost kernel of every matrix product
    let input: &[u64; M_VEC_LIMBS] = input[..M_VEC_LIMBS].try_into().unwrap();
    let acc: &mut [u64; M_VEC_LIMBS] = (&mut acc[..M_VEC_LIMBS]).try_into().unwrap();
    let tab = mul_table(a);
    for i in 0..M_VEC_LIMBS {
        acc[i] ^= ((input[i] & LSB) * ((tab & 0xFF) as u64)) ^
            (((input[i] >> 1) & LSB) * (((tab >> 8) & 0xF) as u64)) ^
            (((input[i] >> 2) & LSB) * (((tab >> 16) & 0xF) as u64)) ^
            (((input[i] >> 3) & LSB) * (((tab >> 24) & 0xF) as u64));
    }
}

/// `acc += x * input` (multiplication by the field generator x).
#[inline(always)]
fn m_vec_mul_add_x(input: &[u64], acc: &mut [u64]) {
    for i in 0..M_VEC_LIMBS {
        let t = input[i] & MSB;
        acc[i] ^= ((input[i] ^ t) << 1) ^ ((t >> 3).wrapping_mul(3));
    }
}

/// `acc += x^-1 * input`.
#[inline(always)]
fn m_vec_mul_add_x_inv(input: &[u64], acc: &mut [u64]) {
    for i in 0..M_VEC_LIMBS {
        let t = input[i] & LSB;
        acc[i] ^= ((input[i] ^ t) >> 1) ^ t.wrapping_mul(9);
    }
}

/// Reduce 16 accumulator "bins" (bin `b` holds the sum of m-vectors that must
/// be multiplied by the field element `b`) into `out`. Overwrites `out`.
///
/// Port of `m_vec_multiply_bins`; the chain of x / x^-1 multiplications
/// evaluates all 16 scalar multiples with 15 shifts instead of 16 full
/// multiplications. `bins` is scratch and is clobbered.
pub fn m_vec_multiply_bins(bins: &mut [u64], out: &mut [u64]) {
    #[inline(always)]
    fn at(bins: &mut [u64], src: usize, dst: usize, f: fn(&[u64], &mut [u64])) {
        let (a, b) = if src < dst {
            let (lo, hi) = bins.split_at_mut(dst * M_VEC_LIMBS);
            (
                &lo[src * M_VEC_LIMBS..src * M_VEC_LIMBS + M_VEC_LIMBS],
                &mut hi[..M_VEC_LIMBS],
            )
        } else {
            let (lo, hi) = bins.split_at_mut(src * M_VEC_LIMBS);
            let a: &[u64] = &hi[..M_VEC_LIMBS];
            (
                a,
                &mut lo[dst * M_VEC_LIMBS..dst * M_VEC_LIMBS + M_VEC_LIMBS],
            )
        };
        f(a, b);
    }

    at(bins, 5, 10, m_vec_mul_add_x_inv);
    at(bins, 11, 12, m_vec_mul_add_x);
    at(bins, 10, 7, m_vec_mul_add_x_inv);
    at(bins, 12, 6, m_vec_mul_add_x);
    at(bins, 7, 14, m_vec_mul_add_x_inv);
    at(bins, 6, 3, m_vec_mul_add_x);
    at(bins, 14, 15, m_vec_mul_add_x_inv);
    at(bins, 3, 8, m_vec_mul_add_x);
    at(bins, 15, 13, m_vec_mul_add_x_inv);
    at(bins, 8, 4, m_vec_mul_add_x);
    at(bins, 13, 9, m_vec_mul_add_x_inv);
    at(bins, 4, 2, m_vec_mul_add_x);
    at(bins, 9, 1, m_vec_mul_add_x_inv);
    at(bins, 2, 1, m_vec_mul_add_x);
    m_vec_copy(&bins[M_VEC_LIMBS..2 * M_VEC_LIMBS], out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gf16::mul_f;

    fn nibble(v: &[u64], i: usize) -> u8 {
        ((v[i / 16] >> ((i % 16) * 4)) & 0xF) as u8
    }

    #[test]
    fn mul_add_matches_scalar() {
        let input: [u64; M_VEC_LIMBS] = [
            0x0123_4567_89AB_CDEF,
            0xFEDC_BA98_7654_3210,
            0xA5A5_5A5A_FFFF_0000,
            0x1111_9999_EEEE_7777,
        ];
        for a in 0..16u8 {
            let mut acc = [0u64; M_VEC_LIMBS];
            m_vec_mul_add(&input, a, &mut acc);
            for i in 0..64 {
                assert_eq!(nibble(&acc, i), mul_f(a, nibble(&input, i)), "a={a} i={i}");
            }
        }
    }

    #[test]
    fn multiply_bins_matches_scalar() {
        // bin b holds a distinctive vector; result must be sum_b b * bins[b]
        let mut bins = [0u64; 16 * M_VEC_LIMBS];
        let mut expected = [0u8; 64];
        for b in 0..16usize {
            for limb in 0..M_VEC_LIMBS {
                bins[b * M_VEC_LIMBS + limb] =
                    (0x0123_4567_89AB_CDEFu64).rotate_left((b * 4 + limb) as u32);
            }
            for (i, e) in expected.iter_mut().enumerate() {
                *e ^= mul_f(b as u8, nibble(&bins[b * M_VEC_LIMBS..], i));
            }
        }
        let mut out = [0u64; M_VEC_LIMBS];
        m_vec_multiply_bins(&mut bins, &mut out);
        for (i, &e) in expected.iter().enumerate() {
            assert_eq!(nibble(&out, i), e, "i={i}");
        }
    }
}
