//! Platform-specific intrinsics for lib-Q

use lib_q_platform::{
    CpuFeatures,
    Platform,
    SimdSupport,
};

/// Platform-specific intrinsic operations
/// This module provides platform-specific SIMD implementations
/// Get the best available SIMD support for the current platform
pub fn best_simd_support() -> SimdSupport {
    SimdSupport::new()
}

/// Get CPU features for the current platform
pub fn cpu_features() -> CpuFeatures {
    CpuFeatures::new()
}

/// Get the current platform
pub fn current_platform() -> Platform {
    Platform::detect()
}

/// Check if AVX2 is available
pub fn has_avx2() -> bool {
    cpu_features().has_avx2()
}

/// Check if NEON is available
pub fn has_neon() -> bool {
    cpu_features().has_neon()
}

/// Check if SIMD256 is available
pub fn has_simd256() -> bool {
    best_simd_support().has_simd256()
}

/// Check if SIMD128 is available
pub fn has_simd128() -> bool {
    best_simd_support().has_simd128()
}

#[cfg(feature = "simd128")]
pub mod simd128_intrinsics {
    //! SIMD128 intrinsic operations

    use super::*;

    /// Get SIMD128 support status
    pub fn is_available() -> bool {
        has_simd128()
    }

    /// Get the platform-specific SIMD128 implementation
    pub fn get_implementation() -> &'static str {
        match current_platform() {
            Platform::X86_64 => "SSE2",
            Platform::AArch64 => "NEON",
            Platform::Unknown => "Generic",
        }
    }
}

#[cfg(feature = "simd256")]
pub mod simd256_intrinsics {
    //! SIMD256 intrinsic operations

    use super::*;

    /// Get SIMD256 support status
    pub fn is_available() -> bool {
        has_simd256()
    }

    /// Get the platform-specific SIMD256 implementation
    pub fn get_implementation() -> &'static str {
        match current_platform() {
            Platform::X86_64 => "AVX2",
            Platform::AArch64 => "SVE",
            Platform::Unknown => "Generic",
        }
    }
}

#[cfg(feature = "simd512")]
pub mod simd512_intrinsics {
    //! SIMD512 intrinsic operations

    use super::*;

    /// Get SIMD512 support status
    pub fn is_available() -> bool {
        best_simd_support().has_simd512()
    }

    /// Get the platform-specific SIMD512 implementation
    pub fn get_implementation() -> &'static str {
        match current_platform() {
            Platform::X86_64 => "AVX-512",
            Platform::AArch64 => "SVE2",
            Platform::Unknown => "Generic",
        }
    }
}
