//! NIST Hash Preimage AIR - Proves knowledge of a cSHAKE256 preimage
//!
//! This AIR proves that the prover knows a preimage `x` such that
//! `cSHAKE256(x, b"HashPreimageNistAir")` equals a public 32-byte output.
//!
//! # Design
//!
//! Single-row trace: columns 0..32 hold the 32-byte hash output as one field element per byte
//! (byte value as field element). The trace is padded to a power-of-two height.
//!
//! # Status: NOT IMPLEMENTED (returns errors)
//!
//! Full Keccak-f / cSHAKE256 constraints are **not yet implemented**. Without them the AIR
//! cannot soundly bind the secret preimage to the public hash output, so the public entry
//! points ([`crate::ZkpProver::prove_secret_value_nist`] and
//! [`crate::ZkpVerifier::verify_secret_value_nist`]) return
//! [`lib_q_core::Error::NotImplemented`] rather than producing/accepting a proof that proves
//! nothing. The [`Air::eval`] implementation also emits an unsatisfiable constraint as a
//! defense-in-depth measure. Trace generation and public-value encoding remain so the real
//! constraints can be layered in later without changing the public API surface.
//!
//! # Security
//!
//! cSHAKE256 is NIST-approved (FIPS 202 / SP 800-185). Public values = 32-byte hash encoded
//! as 4 field elements (8 bytes per `Complex<Mersenne31>`: real = bytes 0..4 LE, imag = bytes 4..8 LE).

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use digest::{
    ExtendableOutput,
    Update,
};
use lib_q_sha3::CShake256;
use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_field::{
    BasedVectorSpace,
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;

use super::{
    AirError,
    TraceGenerator,
    next_power_of_two,
    validate_trace_dimensions,
};

/// Domain separation for NIST preimage AIR (cSHAKE256 customization string).
pub const CSHAKE_DOMAIN: &[u8] = b"HashPreimageNistAir";

/// Fixed cSHAKE256 output size in bytes.
pub const HASH_OUTPUT_BYTES: usize = 32;

/// Maximum preimage size in bytes (for API validation).
pub const MAX_PREIMAGE_SIZE: usize = 1024;

/// Trace width: 32 columns for hash output (one field element per byte).
const TRACE_WIDTH: usize = HASH_OUTPUT_BYTES;

/// AIR for proving knowledge of a cSHAKE256 preimage (NIST-only).
///
/// Public values are the 32-byte hash encoded as 4 field elements (`Complex<Mersenne31>`):
/// each element packs 8 bytes (real = first 4 bytes LE as u32, imag = next 4 bytes LE as u32).
#[derive(Debug, Clone, Default)]
pub struct HashPreimageNistAir;

impl HashPreimageNistAir {
    /// Create a new HashPreimageNistAir.
    pub fn new() -> Self {
        Self
    }
}

impl<F: Field + BasedVectorSpace<Mersenne31>> BaseAir<F> for HashPreimageNistAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for HashPreimageNistAir
where
    AB::F: Field + BasedVectorSpace<Mersenne31>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let _local = main.current_slice();
        // SOUNDNESS: real Keccak-f / cSHAKE256 constraints are NOT yet implemented. A
        // placeholder `assert_zero(0)` would make every statement verify (the proof would
        // bind nothing to the public hash output), so we instead emit an unsatisfiable
        // constraint (`assert_zero(1)`). This guarantees no proof produced by this AIR can
        // ever verify until proper Keccak-f constraints exist.
        //
        // The public prove/verify entry points
        // (`ZkpProver::prove_secret_value_nist` / `ZkpVerifier::verify_secret_value_nist`)
        // additionally return `Error::NotImplemented` before this AIR is ever invoked.
        let one = <AB::F as PrimeCharacteristicRing>::ONE;
        builder.assert_zero(AB::Expr::from(one));
    }
}

/// Input type for HashPreimageNistAir trace generation.
pub type HashPreimageNistInput = Vec<u8>;

/// Encode 32 bytes as 4 field elements (`Complex<Mersenne31>`: 8 bytes per element, LE u32 for real/imag).
fn hash_bytes_to_public_values(
    bytes: &[u8; HASH_OUTPUT_BYTES],
) -> Vec<lib_q_stark_field::extension::Complex<Mersenne31>> {
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_field::integers::QuotientMap;

    let mut out = Vec::with_capacity(4);
    for chunk in bytes.chunks(8) {
        let real = u32::from_le_bytes([
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
            chunk.get(3).copied().unwrap_or(0),
        ]);
        let imag = u32::from_le_bytes([
            chunk.get(4).copied().unwrap_or(0),
            chunk.get(5).copied().unwrap_or(0),
            chunk.get(6).copied().unwrap_or(0),
            chunk.get(7).copied().unwrap_or(0),
        ]);
        let c = Complex::new_complex(Mersenne31::from_int(real), Mersenne31::from_int(imag));
        out.push(c);
    }
    out
}

/// Decode expected hash bytes (verifier input) to public values using the same encoding.
pub fn expected_hash_to_public_values<F: Field + BasedVectorSpace<Mersenne31>>(
    expected_hash: &[u8],
) -> Vec<F> {
    use lib_q_stark_field::PrimeCharacteristicRing;

    let mut padded = [0u8; HASH_OUTPUT_BYTES];
    let n = core::cmp::min(expected_hash.len(), HASH_OUTPUT_BYTES);
    padded[..n].copy_from_slice(&expected_hash[..n]);
    let complex_vals = hash_bytes_to_public_values(&padded);
    complex_vals
        .iter()
        .map(|c| {
            let coeffs = c.as_basis_coefficients_slice();
            F::from_basis_coefficients_fn(|i| {
                if i < coeffs.len() {
                    coeffs[i]
                } else {
                    PrimeCharacteristicRing::ZERO
                }
            })
        })
        .collect()
}

impl TraceGenerator<lib_q_stark_field::extension::Complex<Mersenne31>, HashPreimageNistInput>
    for HashPreimageNistAir
{
    fn generate_trace(
        &self,
        inputs: &HashPreimageNistInput,
    ) -> Result<RowMajorMatrix<lib_q_stark_field::extension::Complex<Mersenne31>>, AirError> {
        use lib_q_stark_field::extension::Complex;

        type Val = Complex<Mersenne31>;

        if inputs.is_empty() {
            return Err(AirError::InvalidInput {
                reason: "Preimage cannot be empty".into(),
            });
        }
        if inputs.len() > MAX_PREIMAGE_SIZE {
            return Err(AirError::InvalidInput {
                reason: alloc::format!(
                    "Preimage size {} exceeds maximum {}",
                    inputs.len(),
                    MAX_PREIMAGE_SIZE
                ),
            });
        }

        let mut hasher = CShake256::new_with_function_name(&[], CSHAKE_DOMAIN);
        hasher.update(inputs);
        let mut hash_output = [0u8; HASH_OUTPUT_BYTES];
        hasher.finalize_xof_into(&mut hash_output);

        const MIN_ROWS: usize = 4;
        let num_rows = next_power_of_two(MIN_ROWS);
        validate_trace_dimensions(TRACE_WIDTH, num_rows)?;

        let mut trace_values = vec![Val::ZERO; num_rows * TRACE_WIDTH];
        for (i, &b) in hash_output.iter().enumerate() {
            trace_values[i] = Val::from(Mersenne31::new(b as u32));
        }
        for row in 1..num_rows {
            for col in 0..TRACE_WIDTH {
                trace_values[row * TRACE_WIDTH + col] = Val::ZERO;
            }
        }

        Ok(RowMajorMatrix::new(trace_values, TRACE_WIDTH))
    }

    fn public_values(
        &self,
        inputs: &HashPreimageNistInput,
    ) -> Vec<lib_q_stark_field::extension::Complex<Mersenne31>> {
        let mut hasher = CShake256::new_with_function_name(&[], CSHAKE_DOMAIN);
        hasher.update(inputs);
        let mut hash_output = [0u8; HASH_OUTPUT_BYTES];
        hasher.finalize_xof_into(&mut hash_output);
        hash_bytes_to_public_values(&hash_output)
    }
}

#[cfg(test)]
mod tests {
    use lib_q_stark_air::BaseAir;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    use super::*;

    type TestField = Complex<Mersenne31>;

    #[test]
    fn test_hash_preimage_nist_air_new() {
        let air = HashPreimageNistAir::new();
        assert_eq!(BaseAir::<TestField>::width(&air), TRACE_WIDTH);
    }

    #[test]
    fn test_hash_preimage_nist_public_values_deterministic() {
        let air = HashPreimageNistAir::new();
        let preimage = b"hello".to_vec();
        let pv1 = air.public_values(&preimage);
        let pv2 = air.public_values(&preimage);
        assert_eq!(pv1.len(), 4);
        assert_eq!(pv1, pv2);
    }

    #[test]
    fn test_hash_preimage_nist_generate_trace() {
        use lib_q_stark_matrix::Matrix;
        let air = HashPreimageNistAir::new();
        let preimage = b"test".to_vec();
        let trace = air.generate_trace(&preimage).unwrap();
        assert_eq!(trace.width(), TRACE_WIDTH);
        assert!(trace.height() >= 4);
    }
}
