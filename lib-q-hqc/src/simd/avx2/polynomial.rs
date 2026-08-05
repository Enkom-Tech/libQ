//! Shift-XOR polynomial helper for HQC's SIMD dispatch layer
//!
//! This module contains `shift_xor_avx2`, which is only partially
//! AVX2-accelerated — see its doc comment for the exact acceleration
//! boundary. HQC's actual polynomial multiply is
//! `super::gf2x::avx2_vect_mul_mod_xnm1` (Toom-3 + Karatsuba + PCLMUL),
//! not anything in this module.

#![allow(unsafe_code)]

#[allow(unused_macros)]
#[cfg(all(test, feature = "simd-avx2"))]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        // Debug logging disabled for no_std compatibility
        // Use eprintln! directly in test functions if needed
    };
}

#[allow(unused_macros)]
#[cfg(not(all(test, feature = "simd-avx2")))]
macro_rules! debug_log {
    ($($arg:tt)*) => {};
}

#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
use core::arch::x86_64::{
    __m256i,
    _mm256_loadu_si256,
    _mm256_storeu_si256,
    _mm256_xor_si256,
};

/// Vector shift and XOR (public interface) — partially AVX2-accelerated.
///
/// Computes `dest ^= source >> distance` using AVX2 instructions.
/// This matches the portable implementation's behavior for u64 arrays.
///
/// **Acceleration boundary:** the AVX2 path only executes when `distance` is a
/// multiple of 64 bits (i.e. a whole-word shift) *and* a full 4×u64 chunk is in
/// range. Any other `distance` — including all sub-word bit shifts — runs the
/// scalar loop below, by design: cross-word carry propagation for a non-aligned
/// AVX2 shift was judged complex and error-prone, so this deliberately falls
/// back to scalar to match `shift_xor_portable` bit-for-bit rather than risk a
/// silent correctness bug in a crypto crate.
///
/// # Safety
///
/// This function uses unsafe operations internally but provides a safe interface:
/// - Works directly on u64 arrays (matching portable implementation)
/// - Uses unaligned memory access (safe for all valid memory)
/// - Requires AVX2 support (checked at runtime by caller)
/// - All bounds checking is handled internally
///
/// # Arguments
/// * `dest` - Destination buffer (modified in place)
/// * `source` - Source buffer
/// * `distance` - Number of bits to shift right
#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
pub fn shift_xor_avx2(dest: &mut [u64], source: &[u64], distance: usize) {
    let word_shift = distance / 64;
    let bit_shift = distance % 64;

    debug_log!(
        "shift_xor_avx2: word_shift={}, bit_shift={}, dest.len={}, source.len={}",
        word_shift,
        bit_shift,
        dest.len(),
        source.len()
    );

    if bit_shift == 0 {
        // Word-aligned shift: simple AVX2 XOR (only when shifting by multiples of 64 bits)
        if word_shift >= dest.len() {
            return;
        }
        let chunks = (dest.len() - word_shift) / 4; // 4 u64s per 256-bit AVX2 vector

        debug_log!("  word-aligned: chunks={}", chunks);

        // Process 4 u64s at a time with AVX2
        for i in 0..chunks {
            let offset = i * 4;
            if offset + word_shift + 4 <= dest.len() {
                if offset + 4 <= source.len() {
                    // Full chunk available from source
                    let src_chunk = unsafe {
                        _mm256_loadu_si256(source.as_ptr().add(offset) as *const __m256i)
                    };
                    let dest_chunk = unsafe {
                        _mm256_loadu_si256(dest.as_ptr().add(word_shift + offset) as *const __m256i)
                    };
                    let result = unsafe { _mm256_xor_si256(dest_chunk, src_chunk) };
                    unsafe {
                        _mm256_storeu_si256(
                            dest.as_mut_ptr().add(word_shift + offset) as *mut __m256i,
                            result,
                        );
                    }
                } else {
                    // Partial chunk - use scalar operations
                    for j in 0..4 {
                        let idx = offset + j;
                        if idx < source.len() && idx + word_shift < dest.len() {
                            dest[idx + word_shift] ^= source[idx];
                        }
                    }
                }
            }
        }

        // Handle remaining u64s with scalar operations
        for i in (chunks * 4)..source.len() {
            if i + word_shift < dest.len() {
                dest[i + word_shift] ^= source[i];
            }
        }
    } else {
        // Bit-level shift - use scalar operations to match portable behavior exactly
        let inv_shift = 64 - bit_shift;

        debug_log!("  bit-level: inv_shift={}", inv_shift);

        // Use scalar operations to match portable implementation exactly
        for (i, &src_val) in source.iter().enumerate() {
            if i + word_shift < dest.len() {
                let shifted = src_val >> bit_shift;
                dest[i + word_shift] ^= shifted;

                // Handle carry to next word
                if i + word_shift + 1 < dest.len() && i + 1 < source.len() {
                    let carry = source[i + 1] << inv_shift;
                    dest[i + word_shift + 1] ^= carry;
                }
            }
        }
    }
}

// Note: the AVX2 vector-add (XOR) lives in `vector::vect_add_avx2` (the one the `Avx2` dispatcher
// uses); there is intentionally no `polynomial::vect_add_avx2` (a duplicate would create a
// polynomial<->vector module cycle).

// Fallback implementation for when AVX2 is not available
#[cfg(not(all(target_arch = "x86_64", feature = "simd-avx2")))]
pub fn shift_xor_avx2(dest: &mut [u64], source: &[u64], distance: usize) {
    super::super::portable::shift_xor_portable(dest, source, distance);
}
