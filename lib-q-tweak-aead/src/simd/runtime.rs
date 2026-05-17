//! CPU feature detection for AVX2.

#[cfg(all(target_arch = "x86_64", feature = "simd-avx2", feature = "std"))]
pub fn has_avx2() -> bool {
    std::arch::is_x86_feature_detected!("avx2")
}

#[cfg(all(target_arch = "x86_64", feature = "simd-avx2", not(feature = "std")))]
pub fn has_avx2() -> bool {
    cfg!(target_feature = "avx2")
}

#[cfg(not(all(target_arch = "x86_64", feature = "simd-avx2")))]
pub fn has_avx2() -> bool {
    false
}
