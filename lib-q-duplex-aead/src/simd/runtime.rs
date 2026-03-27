//! Runtime CPU capability check for optional AVX2 path.

/// `true` if AVX2 is available (x86_64 + feature + CPU).
#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
pub fn has_avx2() -> bool {
    cpufeatures::new!(avx2_check, "avx2");
    avx2_check::get()
}

#[cfg(not(all(target_arch = "x86_64", feature = "simd-avx2")))]
pub fn has_avx2() -> bool {
    false
}
