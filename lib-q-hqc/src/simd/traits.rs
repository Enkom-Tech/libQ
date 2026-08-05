//! SIMD operation traits for HQC
//!
//! Defines the interface for SIMD-optimized operations used in HQC.
//! This allows for polymorphic dispatch between different SIMD implementations
//! (AVX2, portable, etc.) while maintaining a consistent API.

/// Operations required for HQC polynomial arithmetic
pub trait PolynomialOps {
    /// Sparse-dense polynomial multiplication in GF(2)\[x\]/(x^n - 1)
    ///
    /// HQC's actual polynomial multiply is `gf2x::avx2_vect_mul_mod_xnm1`
    /// (Toom-3 + Karatsuba + PCLMUL); this method is not on that path and has
    /// no AVX2 specialization — the `Avx2` implementation delegates to the
    /// portable code in every configuration. It is kept for the trait's
    /// shape and its cross-implementation equivalence tests.
    /// The sparse polynomial has a fixed weight (number of non-zero coefficients).
    ///
    /// # Arguments
    /// * `output` - Output buffer for the result (same length as `dense`)
    /// * `sparse` - First operand (bit-packed, same byte length as `dense` typical)
    /// * `dense` - Second operand (full representation)
    /// * `weight` - Hint for preallocating position lists (actual bits used are all set bits in `sparse`)
    /// * `n_bits` - Ring dimension `N` for GF(2)\[x\]/(x^n - 1); operations wrap modulo `n_bits`
    fn sparse_dense_mul(output: &mut [u8], sparse: &[u8], dense: &[u8], weight: u32, n_bits: usize);

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
    /// This trait is not wired into HQC's actual decoding path — real
    /// decoding lives in `concatenated_code` / `reed_muller` /
    /// `reed_solomon`. The portable implementation backing this trait is a
    /// simplified stand-in kept for SIMD-equivalence testing.
    ///
    /// # Arguments
    /// * `syndrome` - Output syndrome vector
    /// * `vector` - Input vector to compute syndrome for
    /// * `parity` - Parity check matrix
    fn generate_syndrome(syndrome: &mut [u8], vector: &[u8], parity: &[u8]);

    /// Combine a received vector with a syndrome (bench-only stand-in; see the trait doc above)
    ///
    /// This does not perform real error correction: it XORs `received` with `syndrome` into
    /// `corrected` and has no way to detect or report a failed correction, because the
    /// "syndrome" this trait works with is a synthetic XOR value, not a value derived from an
    /// actual parity-check matrix that a real decoder could validate against. Earlier revisions
    /// returned a `bool` that was documented as "`false` otherwise" but could never be anything
    /// but `true` — that was a false contract, not a real success/failure signal, so the return
    /// value was removed rather than kept as a promise the implementation cannot keep.
    ///
    /// # Arguments
    /// * `corrected` - Output vector (set to `received ^ syndrome`, byte-wise)
    /// * `received` - Received vector with errors
    /// * `syndrome` - Computed syndrome vector
    fn correct_errors(corrected: &mut [u8], received: &[u8], syndrome: &[u8]);
}
