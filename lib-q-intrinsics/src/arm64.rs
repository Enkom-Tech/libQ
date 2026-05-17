//! ARM64 intrinsics for AArch64
//!
//! This module provides ARM64 SIMD intrinsics for lib-Q cryptographic operations.
//! It serves as a replacement for libcrux-intrinsics ARM64 module.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use core::arch::aarch64::*;

/// 128-bit vector of 8-bit integers
pub type Vec128 = uint8x16_t;
/// 128-bit vector of 16-bit integers
pub type Vec128_16 = uint16x8_t;
/// 128-bit vector of 32-bit integers
pub type Vec128_32 = uint32x4_t;
/// 128-bit vector of 64-bit integers
pub type Vec128_64 = uint64x2_t;

// Memory operations
/// Store 128-bit vector to unaligned memory
#[inline(always)]
pub fn vst1q_u8(output: &mut [u8], vector: Vec128) {
    debug_assert_eq!(output.len(), 16);
    unsafe {
        vst1q_u8(output.as_mut_ptr(), vector);
    }
}

/// Load 128-bit vector from unaligned memory
#[inline(always)]
pub fn vld1q_u8(input: &[u8]) -> Vec128 {
    debug_assert_eq!(input.len(), 16);
    unsafe { vld1q_u8(input.as_ptr()) }
}

/// Store 128-bit vector of 32-bit integers to unaligned memory
#[inline(always)]
pub fn vst1q_u32(output: &mut [u32], vector: Vec128_32) {
    debug_assert_eq!(output.len(), 4);
    unsafe {
        vst1q_u32(output.as_mut_ptr(), vector);
    }
}

/// Load 128-bit vector of 32-bit integers from unaligned memory
#[inline(always)]
pub fn vld1q_u32(input: &[u32]) -> Vec128_32 {
    debug_assert_eq!(input.len(), 4);
    unsafe { vld1q_u32(input.as_ptr()) }
}

// Vector creation operations
/// Create 128-bit vector with all elements set to zero
#[inline(always)]
pub fn vdupq_n_u8(a: u8) -> Vec128 {
    unsafe { vdupq_n_u8(a) }
}

/// Create 128-bit vector with all 32-bit elements set to the same value
#[inline(always)]
pub fn vdupq_n_u32(a: u32) -> Vec128_32 {
    unsafe { vdupq_n_u32(a) }
}

// Arithmetic operations
/// Add 8-bit integers
#[inline(always)]
pub fn vaddq_u8(a: Vec128, b: Vec128) -> Vec128 {
    unsafe { vaddq_u8(a, b) }
}

/// Add 32-bit integers
#[inline(always)]
pub fn vaddq_u32(a: Vec128_32, b: Vec128_32) -> Vec128_32 {
    unsafe { vaddq_u32(a, b) }
}

/// Subtract 8-bit integers
#[inline(always)]
pub fn vsubq_u8(a: Vec128, b: Vec128) -> Vec128 {
    unsafe { vsubq_u8(a, b) }
}

/// Subtract 32-bit integers
#[inline(always)]
pub fn vsubq_u32(a: Vec128_32, b: Vec128_32) -> Vec128_32 {
    unsafe { vsubq_u32(a, b) }
}

/// Multiply 32-bit integers (low 32 bits of result)
#[inline(always)]
pub fn vmulq_u32(a: Vec128_32, b: Vec128_32) -> Vec128_32 {
    unsafe { vmulq_u32(a, b) }
}

// Shift operations
/// Shift left 32-bit integers
#[inline(always)]
pub fn vshlq_n_u32(a: Vec128_32, n: i32) -> Vec128_32 {
    unsafe { vshlq_n_u32(a, n) }
}

/// Shift right 32-bit integers
#[inline(always)]
pub fn vshrq_n_u32(a: Vec128_32, n: i32) -> Vec128_32 {
    unsafe { vshrq_n_u32(a, n) }
}

// Bitwise operations
/// Bitwise AND
#[inline(always)]
pub fn vandq_u8(a: Vec128, b: Vec128) -> Vec128 {
    unsafe { vandq_u8(a, b) }
}

/// Bitwise AND for 32-bit integers
#[inline(always)]
pub fn vandq_u32(a: Vec128_32, b: Vec128_32) -> Vec128_32 {
    unsafe { vandq_u32(a, b) }
}

/// Bitwise OR
#[inline(always)]
pub fn vorrq_u8(a: Vec128, b: Vec128) -> Vec128 {
    unsafe { vorrq_u8(a, b) }
}

/// Bitwise OR for 32-bit integers
#[inline(always)]
pub fn vorrq_u32(a: Vec128_32, b: Vec128_32) -> Vec128_32 {
    unsafe { vorrq_u32(a, b) }
}

/// Bitwise XOR
#[inline(always)]
pub fn veorq_u8(a: Vec128, b: Vec128) -> Vec128 {
    unsafe { veorq_u8(a, b) }
}

/// Bitwise XOR for 32-bit integers
#[inline(always)]
pub fn veorq_u32(a: Vec128_32, b: Vec128_32) -> Vec128_32 {
    unsafe { veorq_u32(a, b) }
}

// Comparison operations
/// Compare 32-bit integers for greater than
#[inline(always)]
pub fn vcgtq_u32(a: Vec128_32, b: Vec128_32) -> Vec128_32 {
    unsafe { vcgtq_u32(a, b) }
}

/// Compare 32-bit integers for greater than or equal
#[inline(always)]
pub fn vcgeq_u32(a: Vec128_32, b: Vec128_32) -> Vec128_32 {
    unsafe { vcgeq_u32(a, b) }
}

// Shuffle and blend operations
/// Table lookup
#[inline(always)]
pub fn vtbl1_u8(table: Vec128, indices: Vec128) -> Vec128 {
    unsafe { vtbl1_u8(table, indices) }
}

/// Extended table lookup
#[inline(always)]
pub fn vtbx1_u8(a: Vec128, table: Vec128, indices: Vec128) -> Vec128 {
    unsafe { vtbx1_u8(a, table, indices) }
}

// Additional helper functions
/// Absolute difference
#[inline(always)]
pub fn vabdq_u8(a: Vec128, b: Vec128) -> Vec128 {
    unsafe { vabdq_u8(a, b) }
}

/// Absolute difference for 32-bit integers
#[inline(always)]
pub fn vabdq_u32(a: Vec128_32, b: Vec128_32) -> Vec128_32 {
    unsafe { vabdq_u32(a, b) }
}

/// Maximum
#[inline(always)]
pub fn vmaxq_u8(a: Vec128, b: Vec128) -> Vec128 {
    unsafe { vmaxq_u8(a, b) }
}

/// Maximum for 32-bit integers
#[inline(always)]
pub fn vmaxq_u32(a: Vec128_32, b: Vec128_32) -> Vec128_32 {
    unsafe { vmaxq_u32(a, b) }
}

/// Minimum
#[inline(always)]
pub fn vminq_u8(a: Vec128, b: Vec128) -> Vec128 {
    unsafe { vminq_u8(a, b) }
}

/// Minimum for 32-bit integers
#[inline(always)]
pub fn vminq_u32(a: Vec128_32, b: Vec128_32) -> Vec128_32 {
    unsafe { vminq_u32(a, b) }
}
