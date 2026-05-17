//! lib-Q SIMD Intrinsics
//!
//! This crate provides SIMD intrinsics for lib-Q cryptographic operations,
//! serving as a replacement for external intrinsics libraries.

#![no_std]
#![allow(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

/// Platform-specific intrinsics
pub mod platform;

/// Generic fallback implementations
pub mod generic;

/// AVX2 intrinsics for x86_64
#[cfg(all(feature = "simd256", target_arch = "x86_64"))]
pub mod avx2;

/// ARM64 intrinsics for AArch64
#[cfg(all(feature = "simd128", target_arch = "aarch64"))]
pub mod arm64;

// Always declare the modules for better IDE support, but make them empty if not enabled
#[cfg(not(all(feature = "simd256", target_arch = "x86_64")))]
pub mod avx2 {
    //! AVX2 intrinsics module (disabled when feature not available)
    // Empty module when AVX2 is not available
    // This helps IDEs understand the module structure
}

#[cfg(not(all(feature = "simd128", target_arch = "aarch64")))]
pub mod arm64 {
    //! ARM64 intrinsics module (disabled when feature not available)
    // Empty module when ARM64 is not available
    // This helps IDEs understand the module structure
}

/// SIMD128 operations (placeholder for future implementation)
#[cfg(feature = "simd128")]
pub mod simd128;

/// SIMD256 operations (placeholder for future implementation)
#[cfg(feature = "simd256")]
pub mod simd256;

/// SIMD512 operations (placeholder for future implementation)
#[cfg(feature = "simd512")]
pub mod simd512;

/// Type aliases and common types for better IDE support
pub mod types {
    #[cfg(all(feature = "simd128", target_arch = "aarch64"))]
    pub use super::arm64::{
        Vec128 as ArmVec128,
        Vec128_16,
        Vec128_32,
        Vec128_64,
    };
    #[cfg(all(feature = "simd256", target_arch = "x86_64"))]
    pub use super::avx2::{
        Vec128,
        Vec256,
        Vec256Float,
    };
}

// Re-export commonly used types and functions
#[cfg(all(feature = "simd128", target_arch = "aarch64"))]
pub use arm64::*;
#[cfg(all(feature = "simd128", target_arch = "aarch64"))]
pub use arm64::{
    Vec128 as ArmVec128,
    Vec128_16,
    Vec128_32,
    Vec128_64,
};
#[cfg(all(feature = "simd256", target_arch = "x86_64"))]
pub use avx2::*;
// Re-export vector types for compatibility
#[cfg(all(feature = "simd256", target_arch = "x86_64"))]
pub use avx2::{
    Vec128,
    Vec256,
    Vec256Float,
};
