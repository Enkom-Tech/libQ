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
//!     // Use the AVX2-backed implementation. Note: not every operation is
//!     // vectorized — `sparse_dense_mul` in particular has no AVX2
//!     // implementation and delegates to the portable code in every
//!     // configuration; see `simd::avx2`'s module doc for what is and is
//!     // not accelerated.
//!     crate::simd::Avx2::vect_add(output, a, b);
//! } else {
//!     // Use portable implementation
//!     crate::simd::Portable::vect_add(output, a, b);
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
