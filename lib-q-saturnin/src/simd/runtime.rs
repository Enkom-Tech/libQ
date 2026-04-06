//! Runtime CPU feature detection for Saturnin SIMD backends.

/// Returns true when AVX2 can be used.
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64", feature = "std"))]
pub fn has_avx2() -> bool {
    cpufeatures::new!(saturnin_avx2_check, "avx2");
    saturnin_avx2_check::get()
}

/// no_std fallback for AVX2 detection.
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64", not(feature = "std")))]
pub fn has_avx2() -> bool {
    cfg!(target_feature = "avx2")
}

/// Non-x86_64 or disabled-feature fallback.
#[cfg(not(all(feature = "simd-avx2", target_arch = "x86_64")))]
pub fn has_avx2() -> bool {
    false
}

/// Returns true when NEON can be used.
#[cfg(all(feature = "simd-neon", target_arch = "aarch64", feature = "std"))]
pub fn has_neon() -> bool {
    std::arch::is_aarch64_feature_detected!("neon")
}

/// no_std fallback for NEON detection.
#[cfg(all(feature = "simd-neon", target_arch = "aarch64", not(feature = "std")))]
pub fn has_neon() -> bool {
    cfg!(target_feature = "neon")
}

/// Non-aarch64 or disabled-feature fallback.
#[cfg(not(all(feature = "simd-neon", target_arch = "aarch64")))]
pub fn has_neon() -> bool {
    false
}
