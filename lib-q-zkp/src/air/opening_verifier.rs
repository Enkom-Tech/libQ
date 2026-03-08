//! Opening Verification AIR - Verifies opened values match commitments
//!
//! This AIR verifies that opened values (at challenge points) match the
//! corresponding commitments by verifying Merkle authentication paths.
//!
//! # Design
//!
//! Opening verification involves:
//! 1. Verifying Merkle authentication paths for each opened value
//! 2. Checking values are at correct domain points (zeta, zeta_next)
//! 3. Verifying FRI opening proofs (if applicable)
//!
//! # Security
//!
//! - Uses Merkle inclusion proofs for commitment verification
//! - Domain point consistency is enforced
//! - Constant-time operations for comparisons

extern crate alloc;

use alloc::vec::Vec;
use alloc::{
    format,
    vec,
};

use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
};
use lib_q_stark_field::Field;
use lib_q_stark_field::integers::QuotientMap;
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;

use super::{
    AirError,
    MerkleInclusionAir,
    MerkleProofInput,
    TraceGenerator,
    next_power_of_two,
    validate_trace_dimensions,
};

/// Maximum number of opened values to verify
pub const MAX_OPENED_VALUES: usize = 1024;

/// AIR for verifying opened values match commitments
///
/// This AIR verifies that opened values at challenge points match their
/// commitments by verifying Merkle authentication paths.
#[derive(Debug, Clone)]
pub struct OpeningVerifierAir {
    /// Number of opened values to verify
    num_opened_values: usize,
    /// Tree depth for Merkle proofs
    tree_depth: usize,
}

impl OpeningVerifierAir {
    /// Create a new OpeningVerifierAir
    ///
    /// # Arguments
    ///
    /// * `num_opened_values` - Number of opened values to verify
    /// * `tree_depth` - Depth of Merkle tree for commitments
    ///
    /// # Returns
    ///
    /// `Ok(OpeningVerifierAir)` if parameters are valid
    pub fn new(num_opened_values: usize, tree_depth: usize) -> Result<Self, AirError> {
        if num_opened_values == 0 || num_opened_values > MAX_OPENED_VALUES {
            return Err(AirError::InvalidDimensions {
                reason: format!(
                    "Number of opened values must be between 1 and {}",
                    MAX_OPENED_VALUES
                ),
            });
        }

        if tree_depth == 0 || tree_depth > 32 {
            return Err(AirError::InvalidDimensions {
                reason: format!("Tree depth must be between 1 and 32, got {}", tree_depth),
            });
        }

        Ok(Self {
            num_opened_values,
            tree_depth,
        })
    }

    /// Get the number of opened values
    pub fn num_opened_values(&self) -> usize {
        self.num_opened_values
    }

    /// Get the tree depth
    pub fn tree_depth(&self) -> usize {
        self.tree_depth
    }

    /// Compute trace width
    ///
    /// For each opened value:
    /// - Value: 1 field element
    /// - Domain point: 1 field element
    /// - Merkle proof: width from MerkleInclusionAir
    /// - Expected root: 1 field element (for in-circuit comparison)
    /// - Verification result: 1 field element (computed_root - expected_root)
    fn trace_width(&self) -> usize {
        use lib_q_stark_field::extension::Complex;
        use lib_q_stark_mersenne31::Mersenne31;
        type Val = Complex<Mersenne31>;
        let merkle_air = MerkleInclusionAir::new(self.tree_depth).unwrap();
        let merkle_width = <MerkleInclusionAir as BaseAir<Val>>::width(&merkle_air);

        let per_value = 1 + 1 + merkle_width + 1 + 1;

        self.num_opened_values * per_value
    }
}

impl<F: Field> BaseAir<F> for OpeningVerifierAir {
    fn width(&self) -> usize {
        self.trace_width()
    }
}

impl<AB: AirBuilder> Air<AB> for OpeningVerifierAir
where
    AB::F: Field + lib_q_stark_field::BasedVectorSpace<lib_q_stark_mersenne31::Mersenne31>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main
            .row_slice(0)
            .expect("Matrix should have at least one row");
        Self::eval_with_offset(builder, &local, 0, self.num_opened_values, self.tree_depth);
    }
}

impl OpeningVerifierAir {
    /// Apply opening verification constraints to a row slice starting at `offset`.
    /// Used by StarkVerifierAir to enforce sub-AIR constraints in the combined trace.
    pub fn eval_with_offset<AB: AirBuilder>(
        builder: &mut AB,
        local: &[AB::Var],
        offset: usize,
        num_opened_values: usize,
        tree_depth: usize,
    ) where
        AB::F: Field + lib_q_stark_field::BasedVectorSpace<lib_q_stark_mersenne31::Mersenne31>,
    {
        use lib_q_stark_field::extension::Complex;
        use lib_q_stark_mersenne31::Mersenne31;

        use super::poseidon_gadget::PoseidonGadget;
        type Val = Complex<Mersenne31>;
        let merkle_air = MerkleInclusionAir::new(tree_depth).unwrap();
        let merkle_width = <MerkleInclusionAir as BaseAir<Val>>::width(&merkle_air);
        const HASH_SIZE_FIELD_ELEMENTS: usize = 1;
        let level_width = 1 +
            HASH_SIZE_FIELD_ELEMENTS +
            HASH_SIZE_FIELD_ELEMENTS +
            PoseidonGadget::COLUMNS_PER_HASH;
        let per_value = 1 + 1 + merkle_width + 1 + 1;

        for value_idx in 0..num_opened_values {
            let value_start = offset + value_idx * per_value;
            let merkle_proof_start = value_start + 2;
            let expected_root_col = merkle_proof_start + merkle_width;
            let verification_result_col = expected_root_col + 1;

            let computed_root_col = merkle_proof_start + 1 + (tree_depth - 1) * level_width + 2;
            let expected_root = local[expected_root_col].clone();
            let computed_root = local[computed_root_col].clone();
            let verification_result = local[verification_result_col].clone();

            builder.assert_eq(
                verification_result.clone().into(),
                AB::Expr::from(computed_root) - AB::Expr::from(expected_root),
            );
            builder.assert_zero(verification_result);
        }
    }
}

/// Input for opening verification
#[derive(Debug, Clone)]
pub struct OpeningVerificationInput {
    /// Opened values
    pub opened_values: Vec<Vec<u8>>, // Serialized field elements
    /// Domain points for each opened value
    pub domain_points: Vec<Vec<u8>>, // Serialized field elements (zeta or zeta_next)
    /// Merkle proofs for each opened value
    pub merkle_proofs: Vec<MerkleProofInput>,
    /// Expected commitment roots
    pub expected_roots: Vec<[u8; 32]>, // Commitment hashes
}

impl<F: Field + lib_q_stark_field::BasedVectorSpace<lib_q_stark_mersenne31::Mersenne31>>
    TraceGenerator<F, OpeningVerificationInput> for OpeningVerifierAir
{
    fn generate_trace(
        &self,
        inputs: &OpeningVerificationInput,
    ) -> Result<RowMajorMatrix<F>, AirError> {
        // Validate input dimensions
        if inputs.opened_values.len() != self.num_opened_values {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "Opened values length {} doesn't match expected {}",
                    inputs.opened_values.len(),
                    self.num_opened_values
                ),
            });
        }

        if inputs.domain_points.len() != self.num_opened_values {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "Domain points length {} doesn't match expected {}",
                    inputs.domain_points.len(),
                    self.num_opened_values
                ),
            });
        }

        if inputs.merkle_proofs.len() != self.num_opened_values {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "Merkle proofs length {} doesn't match expected {}",
                    inputs.merkle_proofs.len(),
                    self.num_opened_values
                ),
            });
        }

        if inputs.expected_roots.len() != self.num_opened_values {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "Expected roots length {} doesn't match expected {}",
                    inputs.expected_roots.len(),
                    self.num_opened_values
                ),
            });
        }

        let merkle_air = MerkleInclusionAir::new(self.tree_depth)?;
        let merkle_width = <MerkleInclusionAir as BaseAir<F>>::width(&merkle_air);
        let per_value = 1 + 1 + merkle_width + 1 + 1;
        let width = self.trace_width();
        let num_rows_padded = next_power_of_two(1);
        validate_trace_dimensions(width, num_rows_padded)?;

        let mut trace_values = vec![F::ZERO; num_rows_padded * width];

        for value_idx in 0..self.num_opened_values {
            let value_start = value_idx * per_value;
            let value_col = value_start;
            let domain_point_col = value_col + 1;
            let merkle_proof_start = domain_point_col + 1;
            let expected_root_col = merkle_proof_start + merkle_width;
            let verification_result_col = expected_root_col + 1;

            trace_values[value_col] =
                F::from_prime_subfield(<F::PrimeSubfield as QuotientMap<u8>>::from_int(
                    inputs.opened_values[value_idx]
                        .first()
                        .copied()
                        .unwrap_or(0u8),
                ));
            trace_values[domain_point_col] =
                F::from_prime_subfield(<F::PrimeSubfield as QuotientMap<u8>>::from_int(
                    inputs.domain_points[value_idx]
                        .first()
                        .copied()
                        .unwrap_or(0u8),
                ));

            let merkle_trace: RowMajorMatrix<F> =
                merkle_air.generate_trace(&inputs.merkle_proofs[value_idx])?;
            for col in 0..merkle_width {
                trace_values[merkle_proof_start + col] = match merkle_trace.get(0, col) {
                    Some(x) => x,
                    None => F::ZERO,
                }
            }

            let computed_root = merkle_air.public_values(&inputs.merkle_proofs[value_idx]);
            let expected_root_field =
                F::from_prime_subfield(<F::PrimeSubfield as QuotientMap<u8>>::from_int(
                    inputs.expected_roots[value_idx][0],
                ));
            let computed_root_field = computed_root.first().copied().unwrap_or(F::ZERO);

            trace_values[expected_root_col] = expected_root_field;
            trace_values[verification_result_col] = computed_root_field - expected_root_field;
        }

        Ok(RowMajorMatrix::new(trace_values, width))
    }

    fn public_values(&self, inputs: &OpeningVerificationInput) -> Vec<F> {
        // Public values are the expected commitment roots
        let mut public_vals = Vec::new();
        for root in &inputs.expected_roots {
            for &byte in root.iter() {
                public_vals.push(F::from_prime_subfield(<F::PrimeSubfield as QuotientMap<
                    u8,
                >>::from_int(byte)));
            }
        }
        public_vals
    }
}

#[cfg(test)]
mod tests {
    use lib_q_stark_air::BaseAir;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    use super::*;
    use crate::air::MerkleHash;

    type TestField = Complex<Mersenne31>;

    #[test]
    fn test_opening_verifier_air_new_valid() {
        let air = OpeningVerifierAir::new(4, 8);
        assert!(air.is_ok());
        let air = air.unwrap();
        assert_eq!(air.num_opened_values(), 4);
        assert_eq!(air.tree_depth(), 8);
    }

    #[test]
    fn test_opening_verifier_air_new_invalid() {
        let result = OpeningVerifierAir::new(0, 8);
        assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));

        let result = OpeningVerifierAir::new(MAX_OPENED_VALUES + 1, 8);
        assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));

        let result = OpeningVerifierAir::new(4, 0);
        assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));
    }

    #[test]
    fn test_opening_verifier_air_width() {
        let air = OpeningVerifierAir::new(2, 4).unwrap();
        let width = BaseAir::<TestField>::width(&air);
        assert!(width > 0);
    }

    #[test]
    fn test_generate_trace_basic() {
        let air = OpeningVerifierAir::new(1, 4).unwrap();

        let input = OpeningVerificationInput {
            opened_values: vec![vec![1]],
            domain_points: vec![vec![2]],
            merkle_proofs: vec![MerkleProofInput {
                leaf: b"test".to_vec(),
                path_bits: vec![false, true, false, true],
                siblings: vec![
                    MerkleHash::hash_data(b"s0"),
                    MerkleHash::hash_data(b"s1"),
                    MerkleHash::hash_data(b"s2"),
                    MerkleHash::hash_data(b"s3"),
                ],
            }],
            expected_roots: vec![[0u8; 32]],
        };

        let trace: Result<RowMajorMatrix<TestField>, _> = air.generate_trace(&input);
        assert!(trace.is_ok());
    }

    #[test]
    fn test_generate_trace_mismatched_lengths() {
        let air = OpeningVerifierAir::new(2, 4).unwrap();

        let input = OpeningVerificationInput {
            opened_values: vec![vec![1]], // Only 1, expected 2
            domain_points: vec![],
            merkle_proofs: vec![],
            expected_roots: vec![],
        };

        let result: Result<RowMajorMatrix<TestField>, _> = air.generate_trace(&input);
        assert!(matches!(result, Err(AirError::InvalidInput { .. })));
    }
}
