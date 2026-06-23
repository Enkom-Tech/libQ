//! AVX2-optimized polynomial operations for HQC
//!
//! This module implements the core polynomial multiplication operations
//! using AVX2 SIMD instructions for significant performance improvement.

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

/// AVX2-optimized sparse-dense polynomial multiplication
///
/// This is the main performance-critical operation in HQC.
/// Ported from the reference C implementation in gf2x_avx2.c
///
/// # Safety
///
/// This function uses unsafe AVX2 intrinsics and requires:
/// - x86_64 CPU with AVX2 support (Intel Haswell+ or AMD Excavator+)
/// - OS support for AVX2 state management (XSAVE/XSAVEOPT)
/// - Proper memory alignment (handled internally with unaligned loads/stores)
/// - All input slices must be valid and properly sized
///
/// The function is safe to call when the above conditions are met and
/// the `simd-avx2` feature is enabled. Runtime CPU feature detection
/// should be performed before calling this function.
///
/// # Arguments
/// * `output` - Output buffer for the result (must be same size as dense)
/// * `sparse` - Sparse polynomial (fixed weight, represented as bit positions)
/// * `dense` - Dense polynomial (full representation)
/// * `weight` - Weight of the sparse polynomial
/// Sparse–dense product in GF(2)[x]/(x^n - 1) with correct cyclic reduction modulo `n_bits`.
///
/// Uses the same bit-accurate reference as [`super::super::portable::sparse_dense_mul_portable`].
/// AVX2-accelerated cyclic shifts can be layered in later without changing this API.
#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
pub fn sparse_dense_mul_avx2(
    output: &mut [u8],
    sparse: &[u8],
    dense: &[u8],
    weight: u32,
    n_bits: usize,
) {
    super::super::portable::sparse_dense_mul_portable(output, sparse, dense, weight, n_bits);
}

/// AVX2-optimized byte-level shift and XOR operation
///
/// This function matches the behavior of `shift_xor_portable_bytes` but uses AVX2.
/// It works on byte arrays and performs bit-level shifts with carry.
///
/// # Safety
///
/// This function uses unsafe AVX2 intrinsics and requires:
/// - x86_64 CPU with AVX2 support
/// - Valid, non-overlapping slices (except when dest == source)
/// - Sufficient memory for unaligned loads/stores
/// - Proper bounds checking (handled by caller)
///
/// The function performs bit-level shifts with AVX2 instructions and
/// is optimized for 32-byte aligned operations with fallback for
/// remaining bytes.
#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
pub fn shift_xor_avx2_bytes(dest: &mut [u8], source: &[u8], distance: usize) {
    let byte_shift = distance / 8;
    let bit_shift = distance % 8;

    debug_log!(
        "shift_xor_avx2_bytes: byte_shift={}, bit_shift={}, dest.len={}, source.len={}",
        byte_shift,
        bit_shift,
        dest.len(),
        source.len()
    );

    if bit_shift == 0 {
        // Byte-aligned shift: simple AVX2 XOR
        if byte_shift >= dest.len() {
            return;
        }
        let chunks = (dest.len() - byte_shift) / 32;

        debug_log!("  byte-aligned: chunks={}", chunks);

        // Process 32-byte chunks with AVX2
        for i in 0..chunks {
            let offset = i * 32;
            if offset + byte_shift + 32 <= dest.len() {
                // Load source chunk (use zeros if beyond source length)
                let src_chunk = if offset + 32 <= source.len() {
                    unsafe { _mm256_loadu_si256(source.as_ptr().add(offset) as *const __m256i) }
                } else {
                    // Create a chunk with zeros for the part beyond source length
                    let mut src_bytes = [0u8; 32];
                    let copy_len = source.len().saturating_sub(offset);
                    if copy_len > 0 {
                        src_bytes[..copy_len].copy_from_slice(&source[offset..offset + copy_len]);
                    }
                    unsafe { core::ptr::read(src_bytes.as_ptr() as *const __m256i) }
                };

                let dest_chunk = unsafe {
                    _mm256_loadu_si256(dest.as_ptr().add(byte_shift + offset) as *const __m256i)
                };
                let result = unsafe { _mm256_xor_si256(dest_chunk, src_chunk) };
                unsafe {
                    _mm256_storeu_si256(
                        dest.as_mut_ptr().add(byte_shift + offset) as *mut __m256i,
                        result,
                    );
                }
            }
        }

        // Handle remaining bytes with scalar operations
        for i in (chunks * 32)..(dest.len() - byte_shift) {
            dest[i + byte_shift] ^= if i < source.len() { source[i] } else { 0 };
        }
    } else {
        // Bit-level shift - use scalar operations to match portable behavior exactly
        // AVX2 optimization for bit-level shifts with carry is complex and error-prone
        // due to cross-chunk carry propagation issues
        let inv_shift = 8 - bit_shift;

        debug_log!("  bit-level: inv_shift={}", inv_shift);

        // Use scalar operations to match portable implementation exactly
        for i in 0..(dest.len() - byte_shift - 1) {
            let shifted = (if i < source.len() { source[i] } else { 0 } << bit_shift) |
                (if i + 1 < source.len() {
                    source[i + 1] >> inv_shift
                } else {
                    0
                });
            dest[i + byte_shift] ^= shifted;
        }
    }
}

// Debug-instrumented version will be added later when we have proper test infrastructure

/// AVX2-optimized vector shift and XOR (public interface)
///
/// Computes `dest ^= source >> distance` using AVX2 instructions.
/// This matches the portable implementation's behavior for u64 arrays.
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

// Fallback implementations for when AVX2 is not available
#[cfg(not(all(target_arch = "x86_64", feature = "simd-avx2")))]
pub fn sparse_dense_mul_avx2(
    output: &mut [u8],
    sparse: &[u8],
    dense: &[u8],
    weight: u32,
    n_bits: usize,
) {
    super::super::portable::sparse_dense_mul_portable(output, sparse, dense, weight, n_bits);
}

#[cfg(not(all(target_arch = "x86_64", feature = "simd-avx2")))]
pub fn shift_xor_avx2(dest: &mut [u64], source: &[u64], distance: usize) {
    super::super::portable::shift_xor_portable(dest, source, distance);
}
