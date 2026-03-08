//! AIR (Algebraic Intermediate Representation) module
//!
//! This module provides standalone AIR implementations for common proof types
//! used in zero-knowledge proofs. Each AIR defines constraints that can be
//! verified using STARK proving systems.
//!
//! # Available AIRs
//!
//! - [`ArithmeticAir`] - Basic arithmetic operations (multiplication constraints)
//! - [`RangeProofAir`] - Proves a value is within a specified range
//! - [`HashPreimageAir`] - Proves knowledge of a SHAKE256 preimage
//! - [`MerkleInclusionAir`] - Proves membership in a Merkle tree
//!
//! # Security
//!
//! All AIR implementations follow these security principles:
//! - Input validation to prevent DoS attacks
//! - Automatic zeroization of secret data via `SecretWitness`
//! - Constant-time operations where applicable
//!
//! # Example
//!
//! ```rust,ignore
//! use lib_q_zkp::air::{ArithmeticAir, TraceGenerator};
//! use lib_q_stark_field::extension::Complex;
//! use lib_q_stark_mersenne31::Mersenne31;
//!
//! type Val = Complex<Mersenne31>;
//!
//! // Create an AIR for 3 multiplication operations
//! let air = ArithmeticAir::new(3).unwrap();
//!
//! // Generate a trace
//! let inputs = vec![(Val::from(2u32), Val::from(3u32))];
//! let trace = air.generate_trace(&inputs)?;
//! ```

extern crate alloc;

use alloc::string::{
    String,
    ToString,
};
use alloc::vec::Vec;
use core::fmt;

use lib_q_poseidon::{
    PoseidonField,
    PoseidonParams,
    sbox,
};
use lib_q_stark_field::{
    BasedVectorSpace,
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;

pub mod anonymous_auth;
pub mod arithmetic;
pub mod batch_stark_verifier;
pub mod commitment_verifier;
pub mod constraint_verifier;
pub mod credential;
pub mod fri_verifier;
pub mod hash_preimage;
pub mod identity_proof;
pub mod merkle_inclusion;
pub mod opening_verifier;
pub mod poseidon_gadget;
pub mod poseidon_hash;
pub mod range_proof;
pub mod recursive_types;
pub mod session_key;
pub mod stark_verifier;
pub mod state_transition;
pub mod transaction;
pub mod verifier_utils;

pub use anonymous_auth::{
    AnonymousAuthAir,
    AnonymousAuthInput,
};
pub use arithmetic::ArithmeticAir;
pub use batch_stark_verifier::{
    BatchRecursiveStarkVerificationInput,
    BatchStarkVerifierAir,
};
pub use commitment_verifier::{
    CommitmentVerificationInput,
    CommitmentVerifierAir,
};
pub use constraint_verifier::{
    ConstraintVerificationInput,
    ConstraintVerifierAir,
};
pub use credential::{
    CredentialAir,
    CredentialInput,
    CredentialSchema,
};
pub use fri_verifier::{
    FriVerificationInput,
    FriVerifierAir,
};
pub use hash_preimage::HashPreimageAir;
pub use identity_proof::{
    IdentityProofAir,
    IdentityProofInput,
    MlDsaLevel,
};
pub use merkle_inclusion::{
    MerkleHash,
    MerkleInclusionAir,
    MerkleProofInput,
};
pub use opening_verifier::{
    OpeningVerificationInput,
    OpeningVerifierAir,
};
pub use poseidon_gadget::PoseidonGadget;
pub use poseidon_hash::PoseidonHashAir;
pub use range_proof::RangeProofAir;
pub use recursive_types::{
    RecursiveStarkInput,
    SerializedFriRound,
    SerializedStarkProof,
};
pub use session_key::{
    KdfAlgorithm,
    KdfParams,
    SessionKeyDerivationAir,
    SessionKeyInput,
};
#[cfg(feature = "recursive-proofs-experimental")]
pub use stark_verifier::{
    MerklePathExtractable,
    build_recursive_verification_input_from_proof,
    build_recursive_verification_input_from_proof_with_poseidon,
};
pub use stark_verifier::{
    RecursiveStarkVerificationInput,
    StarkVerifierAir,
    build_recursive_verification_input,
};

/// Maximum number of operations allowed in a single AIR instance
/// to prevent memory exhaustion attacks.
pub const MAX_OPERATIONS: usize = 1 << 20; // ~1 million operations

/// Maximum trace width to prevent excessive memory allocation.
/// Recursive StarkVerifierAir can exceed 65536; raised to 131072 for aggregation.
pub const MAX_TRACE_WIDTH: usize = 1 << 17; // 131072 columns

/// Maximum trace height (number of rows) to prevent memory exhaustion.
pub const MAX_TRACE_HEIGHT: usize = 1 << 24; // ~16 million rows

/// Error type for AIR operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AirError {
    /// AIR configuration has invalid dimensions
    InvalidDimensions {
        /// Description of the dimension error
        reason: String,
    },

    /// AIR exceeds maximum allowed size
    ExceedsMaxSize {
        /// Name of the parameter that exceeded limits
        parameter: String,
        /// Maximum allowed value
        max: usize,
        /// Actual value provided
        actual: usize,
    },

    /// Invalid input data for trace generation
    InvalidInput {
        /// Description of what was invalid
        reason: String,
    },

    /// Trace dimensions don't match AIR requirements
    TraceMismatch {
        /// Expected width
        expected_width: usize,
        /// Actual width
        actual_width: usize,
    },

    /// Witness values don't satisfy constraints
    InvalidWitness {
        /// Description of which constraint failed
        constraint: String,
    },

    /// Internal error during AIR evaluation
    InternalError {
        /// Description of the error
        reason: String,
    },

    /// Feature required but not enabled
    NotSupported {
        /// Description of what is not supported
        reason: String,
    },
}

impl fmt::Display for AirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AirError::InvalidDimensions { reason } => {
                write!(f, "Invalid AIR dimensions: {}", reason)
            }
            AirError::ExceedsMaxSize {
                parameter,
                max,
                actual,
            } => {
                write!(
                    f,
                    "AIR parameter '{}' exceeds maximum: max={}, actual={}",
                    parameter, max, actual
                )
            }
            AirError::InvalidInput { reason } => {
                write!(f, "Invalid input for trace generation: {}", reason)
            }
            AirError::TraceMismatch {
                expected_width,
                actual_width,
            } => {
                write!(
                    f,
                    "Trace width mismatch: expected {}, got {}",
                    expected_width, actual_width
                )
            }
            AirError::InvalidWitness { constraint } => {
                write!(
                    f,
                    "Invalid witness: constraint '{}' not satisfied",
                    constraint
                )
            }
            AirError::InternalError { reason } => {
                write!(f, "Internal AIR error: {}", reason)
            }
            AirError::NotSupported { reason } => {
                write!(f, "Not supported: {}", reason)
            }
        }
    }
}

impl From<AirError> for lib_q_core::Error {
    fn from(err: AirError) -> Self {
        lib_q_core::Error::InternalError {
            operation: "AIR operation".into(),
            details: err.to_string(),
        }
    }
}

/// Trait for AIRs that can generate execution traces from inputs
///
/// This trait extends the basic AIR functionality with the ability to
/// generate valid execution traces from given inputs. The trace can then
/// be used with STARK proving to generate proofs.
///
/// # Type Parameters
///
/// - `F`: The field type for trace values
/// - `I`: The input type for trace generation
pub trait TraceGenerator<F: Field, I> {
    /// Generate an execution trace from the given inputs
    ///
    /// # Arguments
    ///
    /// * `inputs` - The inputs to generate the trace from
    ///
    /// # Returns
    ///
    /// A `RowMajorMatrix<F>` containing the trace, or an error if trace
    /// generation fails.
    ///
    /// # Errors
    ///
    /// Returns `AirError` if:
    /// - Input dimensions are invalid
    /// - Input values don't produce a valid trace
    /// - Memory allocation fails
    fn generate_trace(&self, inputs: &I) -> Result<RowMajorMatrix<F>, AirError>;

    /// Get the public values from the given inputs
    ///
    /// Public values are the values that are shared between prover and verifier.
    /// These are typically outputs or commitments that are part of the statement
    /// being proven.
    ///
    /// # Arguments
    ///
    /// * `inputs` - The inputs to extract public values from
    ///
    /// # Returns
    ///
    /// A vector of public field elements
    fn public_values(&self, inputs: &I) -> Vec<F> {
        let _ = inputs;
        Vec::new()
    }
}

/// Helper function to validate trace dimensions
///
/// # Arguments
///
/// * `width` - Trace width (number of columns)
/// * `height` - Trace height (number of rows)
///
/// # Returns
///
/// `Ok(())` if dimensions are valid, `Err(AirError)` otherwise
pub fn validate_trace_dimensions(width: usize, height: usize) -> Result<(), AirError> {
    if width == 0 {
        return Err(AirError::InvalidDimensions {
            reason: "Trace width must be greater than 0".into(),
        });
    }

    if width > MAX_TRACE_WIDTH {
        return Err(AirError::ExceedsMaxSize {
            parameter: "width".into(),
            max: MAX_TRACE_WIDTH,
            actual: width,
        });
    }

    if height == 0 {
        return Err(AirError::InvalidDimensions {
            reason: "Trace height must be greater than 0".into(),
        });
    }

    if height > MAX_TRACE_HEIGHT {
        return Err(AirError::ExceedsMaxSize {
            parameter: "height".into(),
            max: MAX_TRACE_HEIGHT,
            actual: height,
        });
    }

    if !height.is_power_of_two() {
        return Err(AirError::InvalidDimensions {
            reason: "Trace height must be a power of 2".into(),
        });
    }

    Ok(())
}

/// Round up to the next power of 2
///
/// # Arguments
///
/// * `n` - The number to round up
///
/// # Returns
///
/// The smallest power of 2 that is >= n
pub fn next_power_of_two(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    n.next_power_of_two()
}

/// Convert PoseidonField to any Field F that supports u32 conversion
///
/// Converts PoseidonField (Complex<Mersenne31>) to the target field type,
/// preserving both real and imaginary parts via basis decomposition.
///
/// # Arguments
///
/// * `pf` - The PoseidonField (Complex<Mersenne31>) to convert
///
/// # Returns
///
/// The field element in type F
pub fn poseidon_to_field<F: Field + BasedVectorSpace<Mersenne31>>(pf: &PoseidonField) -> F {
    let coeffs: &[Mersenne31] = pf.as_basis_coefficients_slice();
    F::from_basis_coefficients_fn(|i| {
        if i < coeffs.len() {
            coeffs[i]
        } else {
            <Mersenne31 as PrimeCharacteristicRing>::ZERO
        }
    })
}

/// Convert slice of PoseidonField to Vec<F>
///
/// # Arguments
///
/// * `slice` - Slice of PoseidonField elements
///
/// # Returns
///
/// Vector of field elements in type F
pub fn poseidon_slice_to_field<F: Field + BasedVectorSpace<Mersenne31>>(
    slice: &[PoseidonField],
) -> Vec<F> {
    slice.iter().map(poseidon_to_field).collect()
}

/// Convert PoseidonField hash output to bytes
///
/// Uses RawDataSerializable to convert Complex<Mersenne31> elements to bytes.
/// Each Complex element produces 8 bytes (4 for real, 4 for imag).
///
/// # Arguments
///
/// * `hash` - Slice of PoseidonField elements (hash output)
///
/// # Returns
///
/// Vector of bytes representing the hash
pub fn poseidon_field_to_bytes(hash: &[PoseidonField]) -> Vec<u8> {
    use lib_q_stark_field::RawDataSerializable;
    // Complex<Mersenne31> has NUM_BYTES = 8 (4 real + 4 imag)
    hash.iter().flat_map(|f| (*f).into_bytes()).collect()
}

/// Compute one Poseidon permutation row: state in, intermediates, state out.
///
/// Uses `params.state_width` (e.g. 5 for Poseidon-128). Caller must pass at least
/// `params.state_width` elements in `state`. Returns (final_state, intermediates).
pub fn compute_poseidon_row(
    state: &[PoseidonField],
    params: &PoseidonParams,
) -> (Vec<PoseidonField>, Vec<PoseidonField>) {
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    let n = params.state_width;
    assert!(state.len() >= n, "state must have at least {} elements", n);
    let zero = Complex::<Mersenne31>::new_complex(Mersenne31::ZERO, Mersenne31::ZERO);
    let mut intermediates = Vec::new();
    let mut round_idx = 0usize;
    let mut s: Vec<PoseidonField> = state[0..n].to_vec();
    let full_half = params.full_rounds / 2;

    for _ in 0..full_half {
        let after_arc: Vec<PoseidonField> = (0..n)
            .map(|i| s[i] + params.round_constants[round_idx + i])
            .collect();
        round_idx += n;
        intermediates.extend(after_arc.iter().cloned());
        let after_sbox: Vec<PoseidonField> = (0..n).map(|i| sbox(after_arc[i])).collect();
        intermediates.extend(after_sbox.iter().cloned());
        let mut next_s = alloc::vec![zero; n];
        for (i, next_s_i) in next_s.iter_mut().enumerate().take(n) {
            for (j, &after_sbox_j) in after_sbox.iter().enumerate().take(n) {
                *next_s_i += params.mds_matrix[i][j] * after_sbox_j;
            }
        }
        intermediates.extend(next_s.iter().cloned());
        s = next_s;
    }
    for _ in 0..params.partial_rounds {
        let after_arc: Vec<PoseidonField> = (0..n)
            .map(|i| s[i] + params.round_constants[round_idx + i])
            .collect();
        round_idx += n;
        intermediates.extend(after_arc.iter().cloned());
        let mut after_sbox = alloc::vec![zero; n];
        after_sbox[0] = sbox(after_arc[0]);
        after_sbox[1..n].copy_from_slice(&after_arc[1..n]);
        intermediates.extend(after_sbox.iter().cloned());
        let mut next_s = alloc::vec![zero; n];
        for (i, next_s_i) in next_s.iter_mut().enumerate().take(n) {
            for (j, &after_sbox_j) in after_sbox.iter().enumerate().take(n) {
                *next_s_i += params.mds_matrix[i][j] * after_sbox_j;
            }
        }
        intermediates.extend(next_s.iter().cloned());
        s = next_s;
    }
    for _ in 0..full_half {
        let after_arc: Vec<PoseidonField> = (0..n)
            .map(|i| s[i] + params.round_constants[round_idx + i])
            .collect();
        round_idx += n;
        intermediates.extend(after_arc.iter().cloned());
        let after_sbox: Vec<PoseidonField> = (0..n).map(|i| sbox(after_arc[i])).collect();
        intermediates.extend(after_sbox.iter().cloned());
        let mut next_s = alloc::vec![zero; n];
        for (i, next_s_i) in next_s.iter_mut().enumerate().take(n) {
            for (j, &after_sbox_j) in after_sbox.iter().enumerate().take(n) {
                *next_s_i += params.mds_matrix[i][j] * after_sbox_j;
            }
        }
        intermediates.extend(next_s.iter().cloned());
        s = next_s;
    }
    (s, intermediates)
}

/// Convert bytes to PoseidonField elements
///
/// This is a helper function to consistently convert byte slices to PoseidonField
/// (Complex<Mersenne31>) elements. Each byte is converted to a field element.
///
/// # Arguments
///
/// * `bytes` - Slice of bytes to convert
///
/// # Returns
///
/// Vector of PoseidonField elements
pub fn bytes_to_poseidon_field(bytes: &[u8]) -> Vec<PoseidonField> {
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;
    bytes
        .iter()
        .map(|b| Complex::<Mersenne31>::from(Mersenne31::new(*b as u32)))
        .collect()
}

/// Decode the first 8 bytes of an Identity Token (IT) to the expected public value.
/// The IT is the first 16 bytes of the encoding of the Poseidon hash output; the first 8 bytes
/// encode one Complex<Mersenne31> (4 bytes real + 4 bytes imag, little-endian).
pub fn it_bytes_to_public_value<F: Field + BasedVectorSpace<Mersenne31>>(it: &[u8; 16]) -> F {
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;
    let mut real_bytes = [0u8; 4];
    let mut imag_bytes = [0u8; 4];
    real_bytes.copy_from_slice(&it[0..4]);
    imag_bytes.copy_from_slice(&it[4..8]);
    let real = Mersenne31::new(u32::from_le_bytes(real_bytes));
    let imag = Mersenne31::new(u32::from_le_bytes(imag_bytes));
    let c = Complex::new_complex(real, imag);
    poseidon_to_field::<F>(&c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_trace_dimensions_valid() {
        assert!(validate_trace_dimensions(8, 16).is_ok());
        assert!(validate_trace_dimensions(1, 1).is_ok());
        assert!(validate_trace_dimensions(100, 1024).is_ok());
    }

    #[test]
    fn test_validate_trace_dimensions_zero_width() {
        let result = validate_trace_dimensions(0, 16);
        assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));
    }

    #[test]
    fn test_validate_trace_dimensions_zero_height() {
        let result = validate_trace_dimensions(8, 0);
        assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));
    }

    #[test]
    fn test_validate_trace_dimensions_not_power_of_two() {
        let result = validate_trace_dimensions(8, 15);
        assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));
    }

    #[test]
    fn test_next_power_of_two() {
        assert_eq!(next_power_of_two(0), 1);
        assert_eq!(next_power_of_two(1), 1);
        assert_eq!(next_power_of_two(2), 2);
        assert_eq!(next_power_of_two(3), 4);
        assert_eq!(next_power_of_two(5), 8);
        assert_eq!(next_power_of_two(16), 16);
    }

    #[test]
    fn test_air_error_display() {
        let err = AirError::InvalidDimensions {
            reason: "test".into(),
        };
        assert!(err.to_string().contains("Invalid AIR dimensions"));

        let err = AirError::ExceedsMaxSize {
            parameter: "width".into(),
            max: 100,
            actual: 200,
        };
        assert!(err.to_string().contains("exceeds maximum"));
    }
}
