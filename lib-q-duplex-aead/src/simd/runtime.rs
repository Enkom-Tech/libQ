//! Runtime CPU capability check for optional AVX2 path.

/// `true` if AVX2 is available (x86_64 + feature + CPU).
#[cfg(all(target_arch = "x86_64", feature = "simd-avx2", feature = "std"))]
pub fn has_avx2() -> bool {
    std::arch::is_x86_feature_detected!("avx2")
}

/// no_std fallback for AVX2 detection (compile-time target features only).
#[cfg(all(target_arch = "x86_64", feature = "simd-avx2", not(feature = "std")))]
pub fn has_avx2() -> bool {
    cfg!(target_feature = "avx2")
}

#[cfg(not(all(target_arch = "x86_64", feature = "simd-avx2")))]
pub fn has_avx2() -> bool {
    false
}
