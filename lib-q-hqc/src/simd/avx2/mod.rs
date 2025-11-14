//! AVX2 SIMD optimizations for HQC operations
//!
//! This module provides AVX2-optimized implementations of HQC operations
//! for x86_64 CPUs with AVX2 support.
//!
//! ## Requirements
//!
//! - x86_64 CPU with AVX2 support (Intel Haswell+ or AMD Excavator+)
//! - `simd-avx2` feature enabled
//! - Runtime CPU feature detection
//!
//! ## Performance
//!
//! These implementations provide 34-46% performance improvement over
//! portable implementations for the targeted operations.

pub mod polynomial;
pub mod syndrome;
pub mod vector;

use super::traits::{
    PolynomialOps,
    SyndromeOps,
};

/// AVX2 implementation marker
/// This is a zero-sized type used for static dispatch
pub struct Avx2;

impl PolynomialOps for Avx2 {
    fn sparse_dense_mul(output: &mut [u8], sparse: &[u8], dense: &[u8], weight: u32) {
        polynomial::sparse_dense_mul_avx2(output, sparse, dense, weight);
    }

    fn shift_xor(dest: &mut [u64], source: &[u64], distance: usize) {
        polynomial::shift_xor_avx2(dest, source, distance);
    }

    fn vect_add(output: &mut [u8], a: &[u8], b: &[u8]) {
        vector::vect_add_avx2(output, a, b);
    }
}

impl SyndromeOps for Avx2 {
    fn generate_syndrome(syndrome: &mut [u8], vector: &[u8], parity: &[u8]) {
        syndrome::generate_syndrome_avx2(syndrome, vector, parity);
    }

    fn correct_errors(corrected: &mut [u8], received: &[u8], syndrome: &[u8]) -> bool {
        syndrome::correct_errors_avx2(corrected, received, syndrome)
    }
}
