//! SIMD optimizations for HQC operations
//!
//! Provides AVX2-optimized implementations with runtime detection
//! and automatic fallback to portable code.
//!
//! ## Architecture
//!
//! This module follows the libQ SIMD architecture pattern:
//! - Runtime CPU feature detection with portable fallback
//! - Optional feature flag: `simd-avx2`
//! - Separate implementations for different SIMD instruction sets
//! - Trait-based interface for polymorphic dispatch
//!
//! ## Usage
//!
//! ```rust,ignore
//! use lib_q_hqc::simd::runtime::has_avx2;
//! use lib_q_hqc::simd::PolynomialOps;
//!
//! if has_avx2() {
//!     // Use AVX2 optimized implementation
//!     crate::simd::avx2::polynomial::sparse_dense_mul_optimized(output, a, b, weight);
//! } else {
//!     // Use portable implementation
//!     crate::simd::portable::polynomial::sparse_dense_mul_portable(output, a, b, weight);
//! }
//! ```

pub mod portable;
pub mod traits;

/// Runtime CPU feature detection and dispatch
pub mod runtime;

#[cfg(target_arch = "x86_64")]
pub mod avx2;

// Re-export traits and ZST markers
#[cfg(target_arch = "x86_64")]
pub use avx2::Avx2;
pub use portable::Portable;
pub use traits::{
    PolynomialOps,
    SyndromeOps,
};
