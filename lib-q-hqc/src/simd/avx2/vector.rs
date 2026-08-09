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
/// Computes `output[i] = a[i] ^ b[i]` for `i` in `0..min(output.len(), a.len(), b.len())`,
/// using AVX2 instructions. This matches the portable implementation's behavior
/// (`vect_add_portable`, which zips `a` and `b`): if `a`/`b` are shorter than `output`,
/// only the overlapping prefix is written and any `output` tail beyond that is left
/// untouched.
///
/// This function performs its own runtime AVX2 feature check and falls back to the
/// portable implementation when AVX2 is not available, so it is sound to call directly
/// regardless of whether the caller has already checked `has_avx2()` — see audit finding
/// F4(b) (this function was previously safe but required CPU-feature detection "in prose"
/// only, i.e. it could execute VEX-encoded AVX2 instructions and SIGILL on a CPU without
/// AVX2).
///
/// # Arguments
/// * `output` - Output buffer
/// * `a` - First input vector
/// * `b` - Second input vector
#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
pub fn vect_add_avx2(output: &mut [u8], a: &[u8], b: &[u8]) {
    if !crate::simd::runtime::has_avx2() {
        // No AVX2 on this CPU: do not attempt to run VEX-encoded intrinsics (F4(b)).
        super::super::portable::vect_add_portable(output, a, b);
        return;
    }

    // SAFETY: `has_avx2()` was just confirmed true above, so the CPU supports the
    // AVX2 intrinsics used in `vect_add_avx2_unchecked`.
    unsafe { vect_add_avx2_unchecked(output, a, b) }
}

/// # Safety
///
/// The caller must ensure the CPU supports AVX2 (e.g. `crate::simd::runtime::has_avx2()`
/// returned `true`). Length preconditions are enforced internally (F4(a)): the SIMD loop
/// and its scalar remainder are both bounded by `min(output.len(), a.len(), b.len())`, so
/// this never reads or writes past the end of any of the three slices, even when they
/// have different lengths.
#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
unsafe fn vect_add_avx2_unchecked(output: &mut [u8], a: &[u8], b: &[u8]) {
    let len = output.len().min(a.len()).min(b.len());
    let chunks = len / 32;

    unsafe {
        for i in 0..chunks {
            let offset = i * 32;
            let vec_a = _mm256_loadu_si256(a.as_ptr().add(offset) as *const __m256i);
            let vec_b = _mm256_loadu_si256(b.as_ptr().add(offset) as *const __m256i);
            let result = _mm256_xor_si256(vec_a, vec_b);
            _mm256_storeu_si256(output.as_mut_ptr().add(offset) as *mut __m256i, result);
        }
    }

    // Handle remaining bytes (still bounded by `len`, not `output.len()`)
    let remaining = len % 32;
    if remaining > 0 {
        let offset = chunks * 32;
        for j in 0..remaining {
            output[offset + j] = a[offset + j] ^ b[offset + j];
        }
    }
}

// Note: the shift-XOR AVX2 op lives in `polynomial::shift_xor_avx2` (the one the `Avx2` dispatcher
// uses); there is intentionally no `vector::shift_xor_avx2` (a duplicate would create a
// vector<->polynomial module cycle).

// Fallback implementation for when AVX2 is not available (the real `vect_add_avx2` is above).
#[cfg(not(all(target_arch = "x86_64", feature = "simd-avx2")))]
pub fn vect_add_avx2(output: &mut [u8], a: &[u8], b: &[u8]) {
    super::super::portable::vect_add_portable(output, a, b);
}
