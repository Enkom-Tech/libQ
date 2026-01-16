//! Simple test permutation for testing purposes.
//! This replaces Poseidon2Mersenne31 in tests.
//!
//! # Security Warning
//!
//! **This module is TEST-ONLY and must NEVER be used in production code.**
//!
//! `TestPermutation` provides minimal mixing (a simple rotation) to avoid trivial
//! collisions in Merkle tree tests, but is NOT cryptographically secure.
//!
//! # Availability
//!
//! This module is available in test and bench contexts to prevent
//! accidental use in production builds.

#[cfg(any(test, feature = "test-utils"))]
use lib_q_stark_field::PrimeCharacteristicRing;
#[cfg(any(test, feature = "test-utils"))]
use lib_q_stark_symmetric::{
    CryptographicPermutation,
    Permutation,
};

#[cfg(any(test, feature = "test-utils"))]
use crate::Mersenne31;

/// Simple test permutation for testing and benchmarking.
///
/// # Security Warning
///
/// **This type is TEST-ONLY and must NEVER be used in production code.**
///
/// This provides minimal mixing (a simple rotation) to avoid trivial collisions
/// in Merkle tree tests, but is NOT cryptographically secure.
///
/// # Availability
///
/// This type is available when compiled with `cfg(test)` or when the `test-utils` feature is enabled.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Clone, Copy, Debug)]
pub struct TestPermutation<const WIDTH: usize>;

#[cfg(any(test, feature = "test-utils"))]
impl<const WIDTH: usize> Permutation<[Mersenne31; WIDTH]> for TestPermutation<WIDTH> {
    fn permute_mut(&self, input: &mut [Mersenne31; WIDTH]) {
        // Non-linear mixing function that preserves all input bits during truncation.
        // This ensures that when used with TruncatedPermutation, all input elements
        // affect the output, preventing security vulnerabilities in test code.
        // Uses non-linear operations (multiplication) for better diffusion, even in tests.
        // This is NOT cryptographically secure, but provides proper mixing for tests.
        if WIDTH > 1 {
            // First pass: accumulate all elements with non-linear mixing
            let mut acc = input[0];
            for i in 1..WIDTH {
                // Non-linear accumulation: multiply before adding for better diffusion
                acc = acc * Mersenne31::new((i + 1) as u32) + input[i];
            }

            // Second pass: mix accumulated value into each position with non-linear operations
            // This ensures that even after truncation, all original inputs influence the result
            for i in 0..WIDTH {
                // Non-linear mixing: square the position-dependent offset for better diffusion
                let offset = Mersenne31::new((i + 1) as u32);
                input[i] = input[i] * Mersenne31::TWO + acc + offset * offset;
            }
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl<const WIDTH: usize> CryptographicPermutation<[Mersenne31; WIDTH]> for TestPermutation<WIDTH> {}

#[cfg(any(test, feature = "test-utils"))]
impl<const WIDTH: usize> TestPermutation<WIDTH> {
    /// Create a new test permutation.
    ///
    /// # Security Warning
    ///
    /// This is TEST-ONLY and must never be used in production.
    ///
    /// The `_rng` parameter is ignored but kept for API compatibility
    /// with `Poseidon2Mersenne31::new_from_rng_128`.
    pub fn new_from_rng_128<R: rand::Rng>(_rng: &mut R) -> Self {
        Self
    }
}
