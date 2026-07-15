//! GF(16) = GF(2)[x]/(x^4 + x + 1) scalar arithmetic and constant-time masks.
//!
//! Everything here is integer-only: no lookup tables, no secret-dependent
//! branches. Ports of `simple_arithmetic.h` and the `ct_*` helpers in
//! `arithmetic.h` from the MAYO reference implementation.

/// GF(16) multiplication via carryless multiply + reduction mod x^4 + x + 1.
#[inline(always)]
pub fn mul_f(a: u8, b: u8) -> u8 {
    let a = a as u32;
    let b = b as u32;
    let mut p = (a & 1) * b;
    p ^= (a & 2) * b;
    p ^= (a & 4) * b;
    p ^= (a & 8) * b;

    let top = p & 0xF0;
    ((p ^ (top >> 4) ^ (top >> 3)) & 0x0F) as u8
}

/// Multiply each of the 8 nibble pairs packed in `b` (one GF(16) element per
/// byte, low nibble) by the GF(16) scalar `a`.
#[inline(always)]
pub fn mul_fx8(a: u8, b: u64) -> u64 {
    let a = a as u64;
    let mut p = (a & 1) * b;
    p ^= (a & 2) * b;
    p ^= (a & 4) * b;
    p ^= (a & 8) * b;

    let top = p & 0xF0F0_F0F0_F0F0_F0F0;
    (p ^ (top >> 4) ^ (top >> 3)) & 0x0F0F_0F0F_0F0F_0F0F
}

/// GF(16) inversion by exponentiation (a^14), constant time.
#[inline(always)]
pub fn inverse_f(a: u8) -> u8 {
    let a2 = mul_f(a, a);
    let a4 = mul_f(a2, a2);
    let a8 = mul_f(a4, a4);
    let a6 = mul_f(a2, a4);
    mul_f(a8, a6)
}

/// Multiplication table for nibble-sliced vectors: the four bytes hold
/// `a*1, a*2, a*4, a*8` reduced mod f, used by [`crate::mvec::m_vec_mul_add`].
#[inline(always)]
pub fn mul_table(b: u8) -> u32 {
    let x = (b as u32).wrapping_mul(0x0804_0201);
    let high = x & 0xF0F0_F0F0;
    x ^ (high >> 4) ^ (high >> 3)
}

// The reference implementation XORs a volatile "blocker" into every CT mask
// so the compiler cannot recognize `mask = -(a != b)` and re-materialize it
// as a branch. `black_box` is the Rust equivalent of that barrier.

/// Constant-time byte compare: 0x00 if `a == b`, 0xFF otherwise.
#[inline(always)]
pub fn ct_compare_8(a: u8, b: u8) -> u8 {
    core::hint::black_box(((-((a ^ b) as i32)) >> 31) as u8)
}

/// Constant-time compare: all-zeros if `a == b`, all-ones otherwise.
#[inline(always)]
pub fn ct_compare_64(a: i32, b: i32) -> u64 {
    core::hint::black_box((-((a ^ b) as i64) >> 63) as u64)
}

/// Constant-time greater-than: all-ones if `a > b`, all-zeros otherwise.
#[inline(always)]
pub fn ct_64_is_greater_than(a: i32, b: i32) -> u64 {
    let diff = (b as i64) - (a as i64);
    core::hint::black_box((diff >> 63) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slow_mul(a: u8, b: u8) -> u8 {
        // schoolbook polynomial multiply over GF(2), reduce mod x^4 + x + 1
        let mut p: u16 = 0;
        for i in 0..4 {
            if (a >> i) & 1 == 1 {
                p ^= (b as u16) << i;
            }
        }
        for i in (4..8).rev() {
            if (p >> i) & 1 == 1 {
                p ^= (0b10011) << (i - 4);
            }
        }
        (p & 0xF) as u8
    }

    #[test]
    fn mul_matches_schoolbook() {
        for a in 0..16u8 {
            for b in 0..16u8 {
                assert_eq!(mul_f(a, b), slow_mul(a, b), "a={a} b={b}");
            }
        }
    }

    #[test]
    fn inverse_is_inverse() {
        for a in 1..16u8 {
            assert_eq!(mul_f(a, inverse_f(a)), 1, "a={a}");
        }
        assert_eq!(inverse_f(0), 0);
    }

    #[test]
    fn mul_fx8_matches_scalar() {
        for a in 0..16u8 {
            let b: u64 = 0x0F0E_0D0C_0B0A_0908;
            let out = mul_fx8(a, b);
            for byte in 0..8 {
                let x = ((b >> (8 * byte)) & 0xF) as u8;
                assert_eq!(((out >> (8 * byte)) & 0xFF) as u8, mul_f(a, x));
            }
        }
    }

    #[test]
    fn ct_helpers() {
        assert_eq!(ct_compare_8(3, 3), 0x00);
        assert_eq!(ct_compare_8(3, 4), 0xFF);
        assert_eq!(ct_compare_64(7, 7), 0);
        assert_eq!(ct_compare_64(7, 8), u64::MAX);
        assert_eq!(ct_64_is_greater_than(2, 1), u64::MAX);
        assert_eq!(ct_64_is_greater_than(1, 2), 0);
        assert_eq!(ct_64_is_greater_than(1, 1), 0);
    }
}
