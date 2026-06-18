//! Runtime CPU feature detection for the hardware AES backends.

/// x86/x86_64: AES-NI requires the `aes` and `sse2` CPU features.
#[cfg(all(
    feature = "simd-aesni",
    any(target_arch = "x86", target_arch = "x86_64")
))]
#[inline]
pub(crate) fn has_aes() -> bool {
    // `is_x86_feature_detected!` caches its result; needs `std`, which the
    // `simd-aesni` feature enables.
    std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("sse2")
}

/// aarch64: ARMv8 AES instructions are gated behind the `aes` feature.
#[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]
#[inline]
pub(crate) fn has_aes() -> bool {
    std::arch::is_aarch64_feature_detected!("aes")
}
