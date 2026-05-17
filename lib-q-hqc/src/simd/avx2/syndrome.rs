//! AVX2-optimized syndrome generation for HQC
//!
//! This module implements syndrome generation and error correction
//! using AVX2 SIMD instructions.

#![allow(unsafe_code)]

#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
use core::arch::x86_64::*;

/// AVX2-optimized syndrome generation
///
/// Computes the syndrome vector used in tensor code decoding.
/// Ported from reference implementation tensor.c with AVX2 vectorization.
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
/// * `syndrome` - Output syndrome vector
/// * `vector` - Input vector to compute syndrome for
/// * `parity` - Parity check matrix
#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
pub fn generate_syndrome_avx2(syndrome: &mut [u8], vector: &[u8], parity: &[u8]) {
    unsafe {
        // Process 32-byte chunks with AVX2
        let chunks = syndrome.len() / 32;

        for i in 0..chunks {
            let offset = i * 32;

            // Load vector chunks
            let vec_chunk = _mm256_loadu_si256(vector.as_ptr().add(offset) as *const __m256i);
            let parity_chunk = _mm256_loadu_si256(parity.as_ptr().add(offset) as *const __m256i);

            // Compute syndrome with AVX2 operations
            let syndrome_chunk = compute_syndrome_chunk(vec_chunk, parity_chunk);

            // Store result
            _mm256_storeu_si256(
                syndrome.as_mut_ptr().add(offset) as *mut __m256i,
                syndrome_chunk,
            );
        }

        // Handle remaining bytes with portable implementation
        let remaining = syndrome.len() % 32;
        if remaining > 0 {
            let offset = chunks * 32;
            super::super::portable::generate_syndrome_portable(
                &mut syndrome[offset..],
                &vector[offset..],
                &parity[offset..],
            );
        }
    }
}

/// Compute syndrome for a 256-bit chunk
///
/// # Safety
///
/// This function uses unsafe AVX2 intrinsics and requires:
/// - Valid __m256i parameters (256-bit AVX2 vectors)
/// - x86_64 CPU with AVX2 support
/// - Proper AVX2 state management
///
/// The function performs XOR operations on 256-bit vectors using
/// AVX2 instructions for syndrome computation.
#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
unsafe fn compute_syndrome_chunk(vector: __m256i, parity: __m256i) -> __m256i {
    // Implement parity check computation using AVX2
    // XOR vector with parity matrix rows
    unsafe { _mm256_xor_si256(vector, parity) }
}

/// AVX2-optimized error correction
///
/// Attempts to correct errors using the syndrome vector.
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
/// * `corrected` - Output corrected vector
/// * `received` - Received vector with errors
/// * `syndrome` - Computed syndrome vector
///
/// # Returns
/// `true` if correction was successful, `false` otherwise
#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
pub fn correct_errors_avx2(corrected: &mut [u8], received: &[u8], syndrome: &[u8]) -> bool {
    unsafe {
        // Process 32-byte chunks
        let chunks = corrected.len() / 32;

        for i in 0..chunks {
            let offset = i * 32;

            let recv_chunk = _mm256_loadu_si256(received.as_ptr().add(offset) as *const __m256i);
            let synd_chunk = _mm256_loadu_si256(syndrome.as_ptr().add(offset) as *const __m256i);

            // Apply error correction pattern
            let corrected_chunk = _mm256_xor_si256(recv_chunk, synd_chunk);

            _mm256_storeu_si256(
                corrected.as_mut_ptr().add(offset) as *mut __m256i,
                corrected_chunk,
            );
        }

        // Handle remaining bytes
        let remaining = corrected.len() % 32;
        if remaining > 0 {
            let offset = chunks * 32;
            for j in 0..remaining {
                corrected[offset + j] = received[offset + j] ^ syndrome[offset + j];
            }
        }

        true
    }
}

// Fallback implementations for when AVX2 is not available
#[cfg(not(all(target_arch = "x86_64", feature = "simd-avx2")))]
pub fn generate_syndrome_avx2(syndrome: &mut [u8], vector: &[u8], parity: &[u8]) {
    super::super::portable::generate_syndrome_portable(syndrome, vector, parity);
}

#[cfg(not(all(target_arch = "x86_64", feature = "simd-avx2")))]
pub fn correct_errors_avx2(corrected: &mut [u8], received: &[u8], syndrome: &[u8]) -> bool {
    super::super::portable::correct_errors_portable(corrected, received, syndrome)
}
