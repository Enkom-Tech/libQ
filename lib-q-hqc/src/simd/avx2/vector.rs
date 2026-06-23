//! AVX2-optimized vector operations for HQC
//!
//! This module implements vector operations using AVX2 SIMD instructions.

#![allow(unsafe_code)]

#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
use core::arch::x86_64::{
    __m256i,
    _mm256_loadu_si256,
    _mm256_storeu_si256,
    _mm256_xor_si256,
};

/// AVX2-optimized vector addition (XOR)
///
/// Computes `output = a ^ b` using AVX2 instructions.
///
/// # Safety
///
/// This function uses unsafe AVX2 intrinsics and requires:
/// - x86_64 CPU with AVX2 support (Intel Haswell+ or AMD Excavator+)
/// - OS support for AVX2 state management (XSAVE/XSAVEOPT)
/// - All input slices must be valid and properly sized
/// - Memory alignment handled internally with unaligned loads/stores
///
/// The function is safe to call when the above conditions are met and
/// the `simd-avx2` feature is enabled. Runtime CPU feature detection
/// should be performed before calling this function.
///
/// # Arguments
/// * `output` - Output buffer
/// * `a` - First input vector
/// * `b` - Second input vector
#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
pub fn vect_add_avx2(output: &mut [u8], a: &[u8], b: &[u8]) {
    unsafe {
        let chunks = output.len() / 32;

        for i in 0..chunks {
            let offset = i * 32;
            let vec_a = _mm256_loadu_si256(a.as_ptr().add(offset) as *const __m256i);
            let vec_b = _mm256_loadu_si256(b.as_ptr().add(offset) as *const __m256i);
            let result = _mm256_xor_si256(vec_a, vec_b);
            _mm256_storeu_si256(output.as_mut_ptr().add(offset) as *mut __m256i, result);
        }

        // Handle remaining bytes
        let remaining = output.len() % 32;
        if remaining > 0 {
            let offset = chunks * 32;
            for j in 0..remaining {
                output[offset + j] = a[offset + j] ^ b[offset + j];
            }
        }
    }
}

/// AVX2-optimized vector shift and XOR
///
/// Computes `dest ^= source >> distance` using AVX2 instructions.
///
/// # Arguments
/// * `dest` - Destination buffer (modified in place)
/// * `source` - Source buffer
/// * `distance` - Number of bits to shift right
#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
pub fn shift_xor_avx2(dest: &mut [u64], source: &[u64], distance: usize) {
    // The optimized AVX2 shift-XOR lives in `polynomial::shift_xor_avx2` — that is the one the
    // `Avx2` dispatcher (`simd::avx2::mod`) actually calls. Delegate to it so this (otherwise
    // unused) entry point shares the single real implementation instead of the portable fallback.
    super::polynomial::shift_xor_avx2(dest, source, distance);
}

// Fallback implementations for when AVX2 is not available
#[cfg(not(all(target_arch = "x86_64", feature = "simd-avx2")))]
pub fn vect_add_avx2(output: &mut [u8], a: &[u8], b: &[u8]) {
    super::super::portable::vect_add_portable(output, a, b);
}

#[cfg(not(all(target_arch = "x86_64", feature = "simd-avx2")))]
pub fn shift_xor_avx2(dest: &mut [u64], source: &[u64], distance: usize) {
    super::super::portable::shift_xor_portable(dest, source, distance);
}
