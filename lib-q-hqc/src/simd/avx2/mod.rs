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
//! Not every `*_avx2` name here runs vectorized code. Per operation:
//!
//! - **`vect_add`** — genuinely AVX2-accelerated (32-byte chunks) and is on the
//!   KEM's decoding path.
//! - **`sparse_dense_mul`** — has no AVX2 implementation. It delegates to the
//!   portable implementation in every configuration (see the doc on
//!   `impl PolynomialOps for Avx2::sparse_dense_mul` below). HQC's polynomial
//!   multiply does not use this function at all — it goes through
//!   [`gf2x::avx2_vect_mul_mod_xnm1`], which *is* a real Toom-3 + Karatsuba +
//!   PCLMUL AVX2 routine.
//! - **`shift_xor`** — accelerated only when the shift distance is a multiple
//!   of 64 bits; every other distance runs scalar, by design (see
//!   `polynomial::shift_xor_avx2`'s doc comment).
//! - **`generate_syndrome` / `correct_errors`** — genuinely use AVX2
//!   intrinsics above a 32-byte threshold, but neither is wired into HQC's
//!   decoding path (see the notes on `impl SyndromeOps for Avx2` below).
//!
//! No percentage speedup figure is published for this module; see
//! `lib-q-hqc/benches/performance_benchmarks.rs` for a reproducible
//! `simd-avx2`-vs-default comparison.

pub mod polynomial;
pub mod syndrome;
pub mod vector;

/// Dense polynomial multiply mod \(x^N-1\) (PCLMUL + Karatsuba); requires `alloc`.
#[cfg(all(target_arch = "x86_64", feature = "simd-avx2", feature = "alloc"))]
pub mod gf2x;

use super::traits::{
    PolynomialOps,
    SyndromeOps,
};

/// AVX2 implementation marker
/// This is a zero-sized type used for static dispatch
pub struct Avx2;

impl PolynomialOps for Avx2 {
    /// No AVX2 implementation exists for `sparse_dense_mul`. HQC's polynomial
    /// multiply goes through [`gf2x::avx2_vect_mul_mod_xnm1`] (Toom-3 +
    /// Karatsuba + PCLMUL); `sparse_dense_mul` is not on the KEM path and is
    /// retained only for the `PolynomialOps` trait shape and its equivalence
    /// tests. This delegates to the portable implementation in every
    /// configuration.
    fn sparse_dense_mul(
        output: &mut [u8],
        sparse: &[u8],
        dense: &[u8],
        weight: u32,
        n_bits: usize,
    ) {
        super::portable::sparse_dense_mul_portable(output, sparse, dense, weight, n_bits);
    }

    fn shift_xor(dest: &mut [u64], source: &[u64], distance: usize) {
        polynomial::shift_xor_avx2(dest, source, distance);
    }

    fn vect_add(output: &mut [u8], a: &[u8], b: &[u8]) {
        vector::vect_add_avx2(output, a, b);
    }
}

/// `generate_syndrome` and `correct_errors` genuinely use AVX2 intrinsics
/// (above a 32-byte threshold), but `SyndromeOps` is not wired into HQC's
/// decoding path — real decoding lives in `concatenated_code` / `reed_muller`
/// / `reed_solomon`. See also the portable implementations' own doc comments,
/// which describe them as simplified placeholders for SIMD-equivalence
/// testing rather than production tensor-code syndrome computation.
impl SyndromeOps for Avx2 {
    fn generate_syndrome(syndrome: &mut [u8], vector: &[u8], parity: &[u8]) {
        syndrome::generate_syndrome_avx2(syndrome, vector, parity);
    }

    fn correct_errors(corrected: &mut [u8], received: &[u8], syndrome: &[u8]) {
        syndrome::correct_errors_avx2(corrected, received, syndrome)
    }
}
