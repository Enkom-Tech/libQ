//! AVX2 intrinsics for x86_64
//!
//! This module provides AVX2 SIMD intrinsics for lib-Q cryptographic operations.
//! It serves as a replacement for libcrux-intrinsics AVX2 module.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use core::arch::x86_64::*;

/// 256-bit vector of 8-bit integers
pub type Vec256 = __m256i;
/// 128-bit vector of 8-bit integers
pub type Vec128 = __m128i;
/// 256-bit vector of 32-bit floats
pub type Vec256Float = __m256;

// Memory operations
/// Store 256-bit vector to unaligned memory as 8-bit integers
#[inline(always)]
pub fn mm256_storeu_si256_u8(output: &mut [u8], vector: Vec256) {
    debug_assert_eq!(output.len(), 32);
    unsafe {
        _mm256_storeu_si256(output.as_mut_ptr() as *mut Vec256, vector);
    }
}

/// Store 256-bit vector to unaligned memory as 16-bit integers
#[inline(always)]
pub fn mm256_storeu_si256_i16(output: &mut [i16], vector: Vec256) {
    debug_assert_eq!(output.len(), 16);
    unsafe {
        _mm256_storeu_si256(output.as_mut_ptr() as *mut Vec256, vector);
    }
}

/// Store 256-bit vector to unaligned memory as 32-bit integers
#[inline(always)]
pub fn mm256_storeu_si256_i32(output: &mut [i32], vector: Vec256) {
    debug_assert_eq!(output.len(), 8);
    unsafe {
        _mm256_storeu_si256(output.as_mut_ptr() as *mut Vec256, vector);
    }
}

/// Store 128-bit vector to unaligned memory as 16-bit integers
#[inline(always)]
pub fn mm_storeu_si128(output: &mut [i16], vector: Vec128) {
    debug_assert!(output.len() >= 8);
    unsafe {
        _mm_storeu_si128(output.as_mut_ptr() as *mut Vec128, vector);
    }
}

/// Store 128-bit vector to unaligned memory as 32-bit integers
#[inline(always)]
pub fn mm_storeu_si128_i32(output: &mut [i32], vector: Vec128) {
    debug_assert_eq!(output.len(), 4);
    unsafe {
        _mm_storeu_si128(output.as_mut_ptr() as *mut Vec128, vector);
    }
}

/// Store 128-bit vector to unaligned memory as bytes
#[inline(always)]
pub fn mm_storeu_bytes_si128(output: &mut [u8], vector: Vec128) {
    debug_assert_eq!(output.len(), 16);
    unsafe {
        _mm_storeu_si128(output.as_mut_ptr() as *mut Vec128, vector);
    }
}

/// Load 128-bit vector from unaligned memory
#[inline(always)]
pub fn mm_loadu_si128(input: &[u8]) -> Vec128 {
    debug_assert_eq!(input.len(), 16);
    unsafe { _mm_loadu_si128(input.as_ptr() as *const Vec128) }
}

/// Load 256-bit vector from unaligned memory as 8-bit integers
#[inline(always)]
pub fn mm256_loadu_si256_u8(input: &[u8]) -> Vec256 {
    debug_assert_eq!(input.len(), 32);
    unsafe { _mm256_loadu_si256(input.as_ptr() as *const Vec256) }
}

/// Load 256-bit vector from unaligned memory as 16-bit integers
#[inline(always)]
pub fn mm256_loadu_si256_i16(input: &[i16]) -> Vec256 {
    debug_assert_eq!(input.len(), 16);
    unsafe { _mm256_loadu_si256(input.as_ptr() as *const Vec256) }
}

/// Load 256-bit vector from unaligned memory as 32-bit integers
#[inline(always)]
pub fn mm256_loadu_si256_i32(input: &[i32]) -> Vec256 {
    debug_assert_eq!(input.len(), 8);
    unsafe { _mm256_loadu_si256(input.as_ptr() as *const Vec256) }
}

// Vector creation operations
/// Create 256-bit vector with all elements set to zero
#[inline(always)]
pub fn mm256_setzero_si256() -> Vec256 {
    unsafe { _mm256_setzero_si256() }
}

/// Create 256-bit vector with all 32-bit elements set to the same value
#[inline(always)]
pub fn mm256_set1_epi32(a: i32) -> Vec256 {
    unsafe { _mm256_set1_epi32(a) }
}

/// Create 256-bit vector with all 16-bit elements set to the same value
#[inline(always)]
pub fn mm256_set1_epi16(constant: i16) -> Vec256 {
    unsafe { _mm256_set1_epi16(constant) }
}

/// Create 256-bit vector with all 64-bit elements set to the same value
#[inline(always)]
pub fn mm256_set1_epi64x(a: i64) -> Vec256 {
    unsafe { _mm256_set1_epi64x(a) }
}

/// Create 256-bit vector with 8 32-bit elements
#[allow(clippy::too_many_arguments)]
#[inline(always)]
pub fn mm256_set_epi32(
    e7: i32,
    e6: i32,
    e5: i32,
    e4: i32,
    e3: i32,
    e2: i32,
    e1: i32,
    e0: i32,
) -> Vec256 {
    unsafe { _mm256_set_epi32(e7, e6, e5, e4, e3, e2, e1, e0) }
}

/// Create 256-bit vector with 16 16-bit elements
#[allow(clippy::too_many_arguments)]
#[inline(always)]
pub fn mm256_set_epi16(
    input15: i16,
    input14: i16,
    input13: i16,
    input12: i16,
    input11: i16,
    input10: i16,
    input9: i16,
    input8: i16,
    input7: i16,
    input6: i16,
    input5: i16,
    input4: i16,
    input3: i16,
    input2: i16,
    input1: i16,
    input0: i16,
) -> Vec256 {
    unsafe {
        _mm256_set_epi16(
            input15, input14, input13, input12, input11, input10, input9, input8, input7, input6,
            input5, input4, input3, input2, input1, input0,
        )
    }
}

/// Create 256-bit vector with 32 8-bit elements
#[allow(clippy::too_many_arguments)]
#[inline(always)]
pub fn mm256_set_epi8(
    byte31: i8,
    byte30: i8,
    byte29: i8,
    byte28: i8,
    byte27: i8,
    byte26: i8,
    byte25: i8,
    byte24: i8,
    byte23: i8,
    byte22: i8,
    byte21: i8,
    byte20: i8,
    byte19: i8,
    byte18: i8,
    byte17: i8,
    byte16: i8,
    byte15: i8,
    byte14: i8,
    byte13: i8,
    byte12: i8,
    byte11: i8,
    byte10: i8,
    byte9: i8,
    byte8: i8,
    byte7: i8,
    byte6: i8,
    byte5: i8,
    byte4: i8,
    byte3: i8,
    byte2: i8,
    byte1: i8,
    byte0: i8,
) -> Vec256 {
    unsafe {
        _mm256_set_epi8(
            byte31, byte30, byte29, byte28, byte27, byte26, byte25, byte24, byte23, byte22, byte21,
            byte20, byte19, byte18, byte17, byte16, byte15, byte14, byte13, byte12, byte11, byte10,
            byte9, byte8, byte7, byte6, byte5, byte4, byte3, byte2, byte1, byte0,
        )
    }
}

/// Create 256-bit vector with 4 64-bit elements
#[inline(always)]
pub fn mm256_set_epi64x(input3: i64, input2: i64, input1: i64, input0: i64) -> Vec256 {
    unsafe { _mm256_set_epi64x(input3, input2, input1, input0) }
}

/// Create 128-bit vector with 4 32-bit elements
#[inline(always)]
pub fn mm_set_epi32(input3: i32, input2: i32, input1: i32, input0: i32) -> Vec128 {
    unsafe { _mm_set_epi32(input3, input2, input1, input0) }
}

/// Create 128-bit vector with 16 8-bit elements
#[allow(clippy::too_many_arguments)]
#[inline(always)]
pub fn mm_set_epi8(
    byte15: i8,
    byte14: i8,
    byte13: i8,
    byte12: i8,
    byte11: i8,
    byte10: i8,
    byte9: i8,
    byte8: i8,
    byte7: i8,
    byte6: i8,
    byte5: i8,
    byte4: i8,
    byte3: i8,
    byte2: i8,
    byte1: i8,
    byte0: i8,
) -> Vec128 {
    unsafe {
        _mm_set_epi8(
            byte15, byte14, byte13, byte12, byte11, byte10, byte9, byte8, byte7, byte6, byte5,
            byte4, byte3, byte2, byte1, byte0,
        )
    }
}

/// Create 128-bit vector with all 16-bit elements set to the same value
#[inline(always)]
pub fn mm_set1_epi16(constant: i16) -> Vec128 {
    unsafe { _mm_set1_epi16(constant) }
}

/// Create 256-bit vector from two 128-bit vectors
#[inline(always)]
pub fn mm256_set_m128i(hi: Vec128, lo: Vec128) -> Vec256 {
    unsafe { _mm256_set_m128i(hi, lo) }
}

// Arithmetic operations
/// Add 32-bit integers
#[inline(always)]
pub fn mm256_add_epi32(a: Vec256, b: Vec256) -> Vec256 {
    unsafe { _mm256_add_epi32(a, b) }
}

/// Add 16-bit integers
#[inline(always)]
pub fn mm256_add_epi16(lhs: Vec256, rhs: Vec256) -> Vec256 {
    unsafe { _mm256_add_epi16(lhs, rhs) }
}

/// Add 64-bit integers
#[inline(always)]
pub fn mm256_add_epi64(lhs: Vec256, rhs: Vec256) -> Vec256 {
    unsafe { _mm256_add_epi64(lhs, rhs) }
}

/// Add 16-bit integers (128-bit)
#[inline(always)]
pub fn mm_add_epi16(lhs: Vec128, rhs: Vec128) -> Vec128 {
    unsafe { _mm_add_epi16(lhs, rhs) }
}

/// Subtract 32-bit integers
#[inline(always)]
pub fn mm256_sub_epi32(a: Vec256, b: Vec256) -> Vec256 {
    unsafe { _mm256_sub_epi32(a, b) }
}

/// Subtract 16-bit integers
#[inline(always)]
pub fn mm256_sub_epi16(lhs: Vec256, rhs: Vec256) -> Vec256 {
    unsafe { _mm256_sub_epi16(lhs, rhs) }
}

/// Subtract 16-bit integers (128-bit)
#[inline(always)]
pub fn mm_sub_epi16(lhs: Vec128, rhs: Vec128) -> Vec128 {
    unsafe { _mm_sub_epi16(lhs, rhs) }
}

/// Multiply 32-bit integers (low 32 bits of result)
#[inline(always)]
pub fn mm256_mullo_epi32(a: Vec256, b: Vec256) -> Vec256 {
    unsafe { _mm256_mullo_epi32(a, b) }
}

/// Multiply 16-bit integers (low 16 bits of result)
#[inline(always)]
pub fn mm256_mullo_epi16(lhs: Vec256, rhs: Vec256) -> Vec256 {
    unsafe { _mm256_mullo_epi16(lhs, rhs) }
}

/// Multiply 16-bit integers (low 16 bits of result, 128-bit)
#[inline(always)]
pub fn mm_mullo_epi16(lhs: Vec128, rhs: Vec128) -> Vec128 {
    unsafe { _mm_mullo_epi16(lhs, rhs) }
}

/// Multiply 32-bit integers (full 64-bit result)
#[inline(always)]
pub fn mm256_mul_epi32(a: Vec256, b: Vec256) -> Vec256 {
    unsafe { _mm256_mul_epi32(a, b) }
}

/// Multiply unsigned 32-bit integers (full 64-bit result)
#[inline(always)]
pub fn mm256_mul_epu32(lhs: Vec256, rhs: Vec256) -> Vec256 {
    unsafe { _mm256_mul_epu32(lhs, rhs) }
}

/// Multiply and add 16-bit integers
#[inline(always)]
pub fn mm256_madd_epi16(lhs: Vec256, rhs: Vec256) -> Vec256 {
    unsafe { _mm256_madd_epi16(lhs, rhs) }
}

/// Multiply high 16-bit integers
#[inline(always)]
pub fn mm256_mulhi_epi16(lhs: Vec256, rhs: Vec256) -> Vec256 {
    unsafe { _mm256_mulhi_epi16(lhs, rhs) }
}

/// Multiply high 16-bit integers (128-bit)
#[inline(always)]
pub fn mm_mulhi_epi16(lhs: Vec128, rhs: Vec128) -> Vec128 {
    unsafe { _mm_mulhi_epi16(lhs, rhs) }
}

// Shift operations
/// Shift left 32-bit integers
#[inline(always)]
pub fn mm256_slli_epi32<const IMM8: i32>(a: Vec256) -> Vec256 {
    unsafe { _mm256_slli_epi32::<IMM8>(a) }
}

/// Shift left 16-bit integers
#[inline(always)]
pub fn mm256_slli_epi16<const SHIFT_BY: i32>(vector: Vec256) -> Vec256 {
    unsafe { _mm256_slli_epi16::<SHIFT_BY>(vector) }
}

/// Shift left 64-bit integers
#[inline(always)]
pub fn mm256_slli_epi64<const LEFT: i32>(x: Vec256) -> Vec256 {
    unsafe { _mm256_slli_epi64::<LEFT>(x) }
}

/// Shift right arithmetic 32-bit integers
#[inline(always)]
pub fn mm256_srai_epi32<const IMM8: i32>(a: Vec256) -> Vec256 {
    unsafe { _mm256_srai_epi32::<IMM8>(a) }
}

/// Shift right arithmetic 16-bit integers
#[inline(always)]
pub fn mm256_srai_epi16<const SHIFT_BY: i32>(vector: Vec256) -> Vec256 {
    unsafe { _mm256_srai_epi16::<SHIFT_BY>(vector) }
}

/// Shift right logical 32-bit integers
#[inline(always)]
pub fn mm256_srli_epi32<const SHIFT_BY: i32>(vector: Vec256) -> Vec256 {
    unsafe { _mm256_srli_epi32::<SHIFT_BY>(vector) }
}

/// Shift right logical 16-bit integers
#[inline(always)]
pub fn mm256_srli_epi16<const SHIFT_BY: i32>(vector: Vec256) -> Vec256 {
    unsafe { _mm256_srli_epi16::<SHIFT_BY>(vector) }
}

/// Shift right logical 64-bit integers
#[inline(always)]
pub fn mm256_srli_epi64<const SHIFT_BY: i32>(vector: Vec256) -> Vec256 {
    unsafe { _mm256_srli_epi64::<SHIFT_BY>(vector) }
}

/// Shift right logical 64-bit integers (128-bit)
#[inline(always)]
pub fn mm_srli_epi64<const SHIFT_BY: i32>(vector: Vec128) -> Vec128 {
    unsafe { _mm_srli_epi64::<SHIFT_BY>(vector) }
}

/// Variable shift right logical 32-bit integers
#[inline(always)]
pub fn mm256_srlv_epi32(vector: Vec256, counts: Vec256) -> Vec256 {
    unsafe { _mm256_srlv_epi32(vector, counts) }
}

/// Variable shift right logical 64-bit integers
#[inline(always)]
pub fn mm256_srlv_epi64(vector: Vec256, counts: Vec256) -> Vec256 {
    unsafe { _mm256_srlv_epi64(vector, counts) }
}

/// Variable shift left 32-bit integers
#[inline(always)]
pub fn mm256_sllv_epi32(vector: Vec256, counts: Vec256) -> Vec256 {
    unsafe { _mm256_sllv_epi32(vector, counts) }
}

/// Variable shift left 32-bit integers (128-bit)
#[inline(always)]
pub fn mm_sllv_epi32(vector: Vec128, counts: Vec128) -> Vec128 {
    unsafe { _mm_sllv_epi32(vector, counts) }
}

/// Byte-shift each 128-bit lane of a 256-bit vector right by `SHIFT_BY` bytes, shifting in zeros.
///
/// This is the `_mm256_srli_si256`/`_mm256_bsrli_epi128` semantics: each 128-bit lane is treated
/// as one 16-byte integer and shifted as a whole (carrying across its two 64-bit halves), NOT the
/// two halves shifted independently. A previous hand-rolled version did per-`epi64` shifts, which
/// silently dropped the carry between halves (and returned 0 for `SHIFT_BY == 8`, since
/// `psrlq` by 64 yields 0) — corrupting e.g. `gamma1` z-encoding in ML-DSA. Use the real intrinsic.
#[inline(always)]
pub fn mm256_bsrli_epi128<const SHIFT_BY: i32>(x: Vec256) -> Vec256 {
    unsafe { _mm256_bsrli_epi128::<SHIFT_BY>(x) }
}

// Bitwise operations
/// Bitwise AND
#[inline(always)]
pub fn mm256_and_si256(a: Vec256, b: Vec256) -> Vec256 {
    unsafe { _mm256_and_si256(a, b) }
}

/// Bitwise AND NOT
#[inline(always)]
pub fn mm256_andnot_si256(a: Vec256, b: Vec256) -> Vec256 {
    unsafe { _mm256_andnot_si256(a, b) }
}

/// Bitwise OR
#[inline(always)]
pub fn mm256_or_si256(a: Vec256, b: Vec256) -> Vec256 {
    unsafe { _mm256_or_si256(a, b) }
}

/// Bitwise XOR
#[inline(always)]
pub fn mm256_xor_si256(a: Vec256, b: Vec256) -> Vec256 {
    unsafe { _mm256_xor_si256(a, b) }
}

// Comparison operations
/// Compare 32-bit integers for equality
#[inline(always)]
pub fn mm256_cmpeq_epi32(a: Vec256, b: Vec256) -> Vec256 {
    unsafe { _mm256_cmpeq_epi32(a, b) }
}

/// Compare 32-bit integers for greater than
#[inline(always)]
pub fn mm256_cmpgt_epi32(a: Vec256, b: Vec256) -> Vec256 {
    unsafe { _mm256_cmpgt_epi32(a, b) }
}

/// Compare 32-bit integers for less than
#[inline(always)]
pub fn mm256_cmplt_epi32(a: Vec256, b: Vec256) -> Vec256 {
    unsafe { _mm256_cmpgt_epi32(b, a) }
}

/// Compare 32-bit integers for greater than or equal
#[inline(always)]
pub fn mm256_cmpge_epi32(a: Vec256, b: Vec256) -> Vec256 {
    unsafe {
        // a >= b is equivalent to (a > b) || (a == b)
        let gt = _mm256_cmpgt_epi32(a, b);
        let eq = _mm256_cmpeq_epi32(a, b);
        _mm256_or_si256(gt, eq)
    }
}

/// Test if all bits are zero
#[inline(always)]
pub fn mm256_testz_si256(a: Vec256, b: Vec256) -> i32 {
    unsafe { _mm256_testz_si256(a, b) }
}

/// Sign of 32-bit integers
#[inline(always)]
pub fn mm256_sign_epi32(a: Vec256, b: Vec256) -> Vec256 {
    unsafe {
        // _mm256_sign_epi32 is not a standard intrinsic, so we implement it manually
        // sign(a, b) = (b < 0) ? -a : ((b == 0) ? 0 : a)
        let b_lt_zero = _mm256_cmpgt_epi32(_mm256_setzero_si256(), b); // b < 0
        let b_eq_zero = _mm256_cmpeq_epi32(b, _mm256_setzero_si256()); // b == 0
        let neg_a = _mm256_sub_epi32(_mm256_setzero_si256(), a); // -a

        let result = _mm256_or_si256(
            _mm256_and_si256(b_lt_zero, neg_a),
            _mm256_andnot_si256(b_lt_zero, a),
        );

        _mm256_andnot_si256(b_eq_zero, result) // Zero out where b == 0
    }
}

/// Move mask from 8-bit integers
#[inline(always)]
pub fn mm_movemask_epi8(vector: Vec128) -> i32 {
    unsafe { _mm_movemask_epi8(vector) }
}

// Type conversion operations
/// Cast 256-bit integer to 256-bit float
#[inline(always)]
pub fn mm256_castsi256_ps(a: Vec256) -> Vec256Float {
    unsafe { _mm256_castsi256_ps(a) }
}

/// Cast 256-bit float to 256-bit integer
#[inline(always)]
pub fn mm256_castps_si256(a: Vec256Float) -> Vec256 {
    unsafe { _mm256_castps_si256(a) }
}

/// Cast 256-bit integer to 128-bit integer
#[inline(always)]
pub fn mm256_castsi256_si128(vector: Vec256) -> Vec128 {
    unsafe { _mm256_castsi256_si128(vector) }
}

/// Cast 128-bit integer to 256-bit integer
#[inline(always)]
pub fn mm256_castsi128_si256(vector: Vec128) -> Vec256 {
    unsafe { _mm256_castsi128_si256(vector) }
}

/// Convert 16-bit integers to 32-bit integers
#[inline(always)]
pub fn mm256_cvtepi16_epi32(vector: Vec128) -> Vec256 {
    unsafe { _mm256_cvtepi16_epi32(vector) }
}

// Move mask operations
/// Move mask from 256-bit float
#[inline(always)]
pub fn mm256_movemask_ps(a: Vec256Float) -> i32 {
    unsafe { _mm256_movemask_ps(a) }
}

// Shuffle and blend operations
/// Shuffle 32-bit integers
#[inline(always)]
pub fn mm256_shuffle_epi32<const IMM8: i32>(a: Vec256) -> Vec256 {
    unsafe { _mm256_shuffle_epi32::<IMM8>(a) }
}

/// Shuffle 8-bit integers
#[inline(always)]
pub fn mm256_shuffle_epi8(vector: Vec256, control: Vec256) -> Vec256 {
    unsafe { _mm256_shuffle_epi8(vector, control) }
}

/// Shuffle 8-bit integers (128-bit)
#[inline(always)]
pub fn mm_shuffle_epi8(vector: Vec128, control: Vec128) -> Vec128 {
    unsafe { _mm_shuffle_epi8(vector, control) }
}

/// Blend 32-bit integers
#[inline(always)]
pub fn mm256_blend_epi32<const IMM8: i32>(a: Vec256, b: Vec256) -> Vec256 {
    unsafe { _mm256_blend_epi32::<IMM8>(a, b) }
}

/// Blend 16-bit integers
#[inline(always)]
pub fn mm256_blend_epi16<const CONTROL: i32>(lhs: Vec256, rhs: Vec256) -> Vec256 {
    unsafe { _mm256_blend_epi16::<CONTROL>(lhs, rhs) }
}

/// Blend variable 32-bit integers
#[inline(always)]
pub fn vec256_blendv_epi32(a: Vec256, b: Vec256, mask: Vec256) -> Vec256 {
    unsafe {
        _mm256_castps_si256(_mm256_blendv_ps(
            _mm256_castsi256_ps(a),
            _mm256_castsi256_ps(b),
            _mm256_castsi256_ps(mask),
        ))
    }
}

/// Unpack low 64-bit integers
#[inline(always)]
pub fn mm256_unpacklo_epi64(a: Vec256, b: Vec256) -> Vec256 {
    unsafe { _mm256_unpacklo_epi64(a, b) }
}

/// Unpack high 64-bit integers
#[inline(always)]
pub fn mm256_unpackhi_epi64(a: Vec256, b: Vec256) -> Vec256 {
    unsafe { _mm256_unpackhi_epi64(a, b) }
}

/// Unpack low 32-bit integers
#[inline(always)]
pub fn mm256_unpacklo_epi32(lhs: Vec256, rhs: Vec256) -> Vec256 {
    unsafe { _mm256_unpacklo_epi32(lhs, rhs) }
}

/// Unpack high 32-bit integers
#[inline(always)]
pub fn mm256_unpackhi_epi32(lhs: Vec256, rhs: Vec256) -> Vec256 {
    unsafe { _mm256_unpackhi_epi32(lhs, rhs) }
}

/// Permute 128-bit lanes
#[inline(always)]
pub fn mm256_permute2x128_si256<const IMM8: i32>(a: Vec256, b: Vec256) -> Vec256 {
    unsafe { _mm256_permute2x128_si256::<IMM8>(a, b) }
}

/// Permute 4x64-bit integers
#[inline(always)]
pub fn mm256_permute4x64_epi64<const CONTROL: i32>(vector: Vec256) -> Vec256 {
    unsafe { _mm256_permute4x64_epi64::<CONTROL>(vector) }
}

/// Permute variable 8x32-bit integers
#[inline(always)]
pub fn mm256_permutevar8x32_epi32(vector: Vec256, control: Vec256) -> Vec256 {
    unsafe { _mm256_permutevar8x32_epi32(vector, control) }
}

/// Extract 128-bit lane
#[inline(always)]
pub fn mm256_extracti128_si256<const IMM8: i32>(a: Vec256) -> Vec128 {
    unsafe { _mm256_extracti128_si256::<IMM8>(a) }
}

/// Insert 128-bit lane
#[inline(always)]
pub fn mm256_inserti128_si256<const IMM8: i32>(a: Vec256, b: Vec128) -> Vec256 {
    unsafe { _mm256_inserti128_si256::<IMM8>(a, b) }
}

// Absolute value
/// Absolute value of 32-bit integers
#[inline(always)]
pub fn mm256_abs_epi32(a: Vec256) -> Vec256 {
    unsafe {
        // _mm256_abs_epi32 is not a standard intrinsic, so we implement it manually
        // abs(x) = (x < 0) ? -x : x
        let mask = _mm256_srai_epi32::<31>(a); // All 1s if negative, all 0s if positive
        let neg_a = _mm256_sub_epi32(_mm256_setzero_si256(), a); // -a
        _mm256_or_si256(_mm256_and_si256(mask, neg_a), _mm256_andnot_si256(mask, a))
    }
}

// Pack operations
/// Pack 16-bit integers to 8-bit integers
#[inline(always)]
pub fn mm_packs_epi16(lhs: Vec128, rhs: Vec128) -> Vec128 {
    unsafe { _mm_packs_epi16(lhs, rhs) }
}

/// Pack 32-bit integers to 16-bit integers
#[inline(always)]
pub fn mm256_packs_epi32(lhs: Vec256, rhs: Vec256) -> Vec256 {
    unsafe { _mm256_packs_epi32(lhs, rhs) }
}

// Unit tests live in this module (not in `tests/`) so LLVM coverage attributes
// `#[inline(always)]` bodies to this file on Linux; integration tests link the
// library without `cfg(test)` and can under-report the same wrappers.
#[cfg(all(test, feature = "simd256"))]
mod tests {
    use super::*;

    #[test]
    fn avx2_wrappers_smoke() {
        let mut u8buf = [0u8; 32];
        let mut u8_16 = [0u8; 16];
        let mut i16buf = [0i16; 16];
        let mut i32buf = [0i32; 8];
        let mut i32_4 = [0i32; 4];

        let z = mm256_setzero_si256();
        mm256_storeu_si256_u8(&mut u8buf, z);
        mm256_storeu_si256_i16(&mut i16buf, z);
        mm256_storeu_si256_i32(&mut i32buf, z);

        let v128 = mm_set_epi32(4, 3, 2, 1);
        mm_storeu_si128(&mut i16buf, v128);
        mm_storeu_si128_i32(&mut i32_4, v128);
        mm_storeu_bytes_si128(&mut u8_16, v128);

        let loaded = mm_loadu_si128(&u8_16);
        let _ = mm_movemask_epi8(loaded);

        let from_u8 = mm256_loadu_si256_u8(&u8buf);
        let from_i16 = mm256_loadu_si256_i16(&i16buf);
        let from_i32 = mm256_loadu_si256_i32(&i32buf);

        let a = mm256_set1_epi32(2);
        let b = mm256_set1_epi16(3);
        let c = mm256_set1_epi64x(-1);
        let d = mm256_set_epi32(7, 6, 5, 4, 3, 2, 1, 0);
        let e = mm256_set_epi16(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
        let f = mm256_set_epi8(
            31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
            9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        );
        let g = mm256_set_epi64x(3, 2, 1, 0);
        let h = mm_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
        let i = mm_set1_epi16(9);
        let j = mm256_set_m128i(v128, v128);

        let mut acc = mm256_add_epi32(from_u8, a);
        acc = mm256_add_epi16(acc, b);
        acc = mm256_add_epi64(acc, c);
        acc = mm256_sub_epi32(acc, d);
        acc = mm256_sub_epi16(acc, e);
        let v128b = mm_add_epi16(v128, h);
        let _ = mm_sub_epi16(v128b, i);

        acc = mm256_mullo_epi32(acc, from_i32);
        acc = mm256_mullo_epi16(acc, f);
        let _ = mm_mullo_epi16(v128, h);
        acc = mm256_mul_epi32(acc, g);
        acc = mm256_mul_epu32(acc, from_i16);
        acc = mm256_madd_epi16(acc, j);
        acc = mm256_mulhi_epi16(acc, a);
        let _ = mm_mulhi_epi16(v128, v128);

        acc = mm256_slli_epi32::<1>(acc);
        acc = mm256_slli_epi16::<2>(acc);
        acc = mm256_slli_epi64::<1>(acc);
        acc = mm256_srai_epi32::<1>(acc);
        acc = mm256_srai_epi16::<1>(acc);
        acc = mm256_srli_epi32::<1>(acc);
        acc = mm256_srli_epi16::<1>(acc);
        acc = mm256_srli_epi64::<1>(acc);
        let v1 = mm_srli_epi64::<8>(v128);
        let counts = mm256_set1_epi32(1);
        acc = mm256_srlv_epi32(acc, counts);
        acc = mm256_srlv_epi64(acc, counts);
        acc = mm256_sllv_epi32(acc, counts);
        let _ = mm_sllv_epi32(v1, v1);

        acc = mm256_bsrli_epi128::<1>(acc);
        acc = mm256_bsrli_epi128::<2>(acc);
        acc = mm256_bsrli_epi128::<3>(acc);
        acc = mm256_bsrli_epi128::<4>(acc);
        acc = mm256_bsrli_epi128::<5>(acc);
        acc = mm256_bsrli_epi128::<6>(acc);
        acc = mm256_bsrli_epi128::<7>(acc);
        acc = mm256_bsrli_epi128::<8>(acc);
        acc = mm256_bsrli_epi128::<99>(acc);

        acc = mm256_and_si256(acc, a);
        acc = mm256_andnot_si256(acc, b);
        acc = mm256_or_si256(acc, c);
        acc = mm256_xor_si256(acc, d);

        let eq = mm256_cmpeq_epi32(acc, acc);
        let gt = mm256_cmpgt_epi32(acc, z);
        let lt = mm256_cmplt_epi32(acc, acc);
        let ge = mm256_cmpge_epi32(acc, z);
        let _ = mm256_testz_si256(eq, gt);
        acc = mm256_sign_epi32(lt, ge);

        let ps = mm256_castsi256_ps(acc);
        let back = mm256_castps_si256(ps);
        let _ = mm256_movemask_ps(ps);
        let lo = mm256_castsi256_si128(back);
        let wide = mm256_castsi128_si256(lo);
        let ext = mm256_cvtepi16_epi32(lo);
        acc = mm256_add_epi32(wide, ext);

        acc = mm256_shuffle_epi32::<0x1B>(acc);
        acc = mm256_shuffle_epi8(acc, mm256_setzero_si256());
        let sh = mm_shuffle_epi8(lo, mm_set_epi32(0, 0, 0, 0));
        let _ = mm_movemask_epi8(sh);

        acc = mm256_blend_epi32::<0xF0>(acc, z);
        acc = mm256_blend_epi16::<0xAA>(acc, a);
        acc = vec256_blendv_epi32(acc, b, mm256_cmpeq_epi32(acc, acc));

        acc = mm256_unpacklo_epi64(acc, b);
        acc = mm256_unpackhi_epi64(acc, c);
        acc = mm256_unpacklo_epi32(acc, d);
        acc = mm256_unpackhi_epi32(acc, e);

        acc = mm256_permute2x128_si256::<0x31>(acc, z);
        acc = mm256_permute4x64_epi64::<0x4E>(acc);
        acc = mm256_permutevar8x32_epi32(acc, mm256_set_epi32(7, 6, 5, 4, 3, 2, 1, 0));

        let lane = mm256_extracti128_si256::<0>(acc);
        acc = mm256_inserti128_si256::<1>(acc, lane);

        acc = mm256_abs_epi32(acc);
        let _ = mm_packs_epi16(lo, lo);
        acc = mm256_packs_epi32(acc, z);

        mm256_storeu_si256_u8(&mut u8buf, acc);

        let _: Vec256 = acc;
        let _: Vec128 = lane;
        let _: Vec256Float = ps;
    }
}
