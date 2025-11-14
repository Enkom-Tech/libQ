//! SIMD operation traits for HQC
//!
//! Defines the interface for SIMD-optimized operations used in HQC.
//! This allows for polymorphic dispatch between different SIMD implementations
//! (AVX2, portable, etc.) while maintaining a consistent API.

/// Operations required for HQC polynomial arithmetic
pub trait PolynomialOps {
    /// Sparse-dense polynomial multiplication in GF(2)[x]/(x^n - 1)
    ///
    /// This is the primary performance bottleneck in HQC operations.
    /// The sparse polynomial has a fixed weight (number of non-zero coefficients).
    ///
    /// # Arguments
    /// * `output` - Output buffer for the result
    /// * `sparse` - Sparse polynomial (fixed weight)
    /// * `dense` - Dense polynomial (full representation)
    /// * `weight` - Weight of the sparse polynomial
    fn sparse_dense_mul(output: &mut [u8], sparse: &[u8], dense: &[u8], weight: u32);

    /// Vector XOR operation with shift
    ///
    /// Computes `dest ^= source >> distance` efficiently using SIMD.
    /// This is used in polynomial multiplication for handling bit shifts.
    ///
    /// # Arguments
    /// * `dest` - Destination buffer (modified in place)
    /// * `source` - Source buffer
    /// * `distance` - Number of bits to shift right
    fn shift_xor(dest: &mut [u64], source: &[u64], distance: usize);

    /// Vector addition in GF(2) (XOR)
    ///
    /// Computes `output = a ^ b` for vectors of equal length.
    ///
    /// # Arguments
    /// * `output` - Output buffer
    /// * `a` - First input vector
    /// * `b` - Second input vector
    fn vect_add(output: &mut [u8], a: &[u8], b: &[u8]);
}

/// Operations for syndrome generation in error correction
pub trait SyndromeOps {
    /// Generate syndrome for error correction
    ///
    /// Computes the syndrome vector used in tensor code decoding.
    /// This is another performance-critical operation in HQC.
    ///
    /// # Arguments
    /// * `syndrome` - Output syndrome vector
    /// * `vector` - Input vector to compute syndrome for
    /// * `parity` - Parity check matrix
    fn generate_syndrome(syndrome: &mut [u8], vector: &[u8], parity: &[u8]);

    /// Syndrome-based error correction
    ///
    /// Attempts to correct errors using the syndrome vector.
    ///
    /// # Arguments
    /// * `corrected` - Output corrected vector
    /// * `received` - Received vector with errors
    /// * `syndrome` - Computed syndrome vector
    ///
    /// # Returns
    /// `true` if correction was successful, `false` otherwise
    fn correct_errors(corrected: &mut [u8], received: &[u8], syndrome: &[u8]) -> bool;
}
