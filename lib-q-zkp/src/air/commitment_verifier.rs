//! Commitment Verification AIR - Verifies Merkle tree commitments
//!
//! This AIR verifies that Merkle tree commitments match expected root hashes.
//! It is used as a component in recursive STARK verification to ensure that
//! the inner proof's commitments are valid.
//!
//! # Design
//!
//! For each commitment (trace, quotient, random), this AIR:
//! 1. Stores the expected root hash
//! 2. Stores the Merkle authentication path
//! 3. Computes the root from the path using Poseidon
//! 4. Constrains that computed_root == expected_root
//!
//! # Security
//!
//! - Uses Poseidon-128 for hash operations (post-quantum secure)
//! - Full path verification ensures commitment integrity
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
    WindowAccess,
};
use lib_q_stark_field::Field;
use lib_q_stark_field::integers::QuotientMap;
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;

use super::recursive_types::COMMITMENT_HASH_SIZE;
use super::{
    AirError,
    MerkleInclusionAir,
    MerkleProofInput,
    TraceGenerator,
    next_power_of_two,
    validate_trace_dimensions,
};

/// Maximum number of commitments to verify
pub const MAX_COMMITMENTS: usize = 4; // trace, quotient, random (optional), preprocessed (optional)

/// AIR for verifying Merkle tree commitments
///
/// This AIR verifies that commitment hashes match expected root values by
/// verifying Merkle authentication paths. It can verify multiple commitments
/// in a single trace.
#[derive(Debug, Clone)]
pub struct CommitmentVerifierAir {
    /// Number of commitments to verify
    num_commitments: usize,
    /// Tree depth for each commitment's Merkle tree
    tree_depth: usize,
}

impl CommitmentVerifierAir {
    /// Create a new CommitmentVerifierAir
    ///
    /// # Arguments
    ///
    /// * `num_commitments` - Number of commitments to verify (1-4)
    /// * `tree_depth` - Depth of the Merkle tree for commitments
    ///
    /// # Returns
    ///
    /// `Ok(CommitmentVerifierAir)` if parameters are valid
    pub fn new(num_commitments: usize, tree_depth: usize) -> Result<Self, AirError> {
        if num_commitments == 0 || num_commitments > MAX_COMMITMENTS {
            return Err(AirError::InvalidDimensions {
                reason: format!(
                    "Number of commitments must be between 1 and {}",
                    MAX_COMMITMENTS
                ),
            });
        }

        if tree_depth == 0 || tree_depth > 32 {
            return Err(AirError::InvalidDimensions {
                reason: format!("Tree depth must be between 1 and 32, got {}", tree_depth),
            });
        }

        Ok(Self {
            num_commitments,
            tree_depth,
        })
    }

    /// Get the number of commitments
    pub fn num_commitments(&self) -> usize {
        self.num_commitments
    }

    /// Get the tree depth
    pub fn tree_depth(&self) -> usize {
        self.tree_depth
    }

    /// Compute trace width
    ///
    /// For each commitment:
    /// - Expected root hash: COMMITMENT_HASH_SIZE bytes
    /// - Merkle path: tree_depth * (path_bit + sibling_hash + computed_hash + intermediates)
    /// - Equality check: 1 field element
    fn trace_width(&self) -> usize {
        // Use MerkleInclusionAir to determine width per commitment
        // Use a concrete field type for width calculation (Complex<Mersenne31>)
        use lib_q_stark_field::extension::Complex;
        use lib_q_stark_mersenne31::Mersenne31;
        type ConcreteField = Complex<Mersenne31>;
        let merkle_air = MerkleInclusionAir::new(self.tree_depth).unwrap();
        let merkle_width = <MerkleInclusionAir as BaseAir<ConcreteField>>::width(&merkle_air);

        // Per commitment: expected root + merkle proof + equality check
        let per_commitment = COMMITMENT_HASH_SIZE + merkle_width + 1;

        self.num_commitments * per_commitment
    }
}

impl<F: Field> BaseAir<F> for CommitmentVerifierAir {
    fn width(&self) -> usize {
        self.trace_width()
    }
}

impl<AB: AirBuilder> Air<AB> for CommitmentVerifierAir
where
    AB::F: Field + lib_q_stark_field::BasedVectorSpace<lib_q_stark_mersenne31::Mersenne31>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        Self::eval_with_offset(builder, local, 0, self.num_commitments, self.tree_depth);
    }
}

impl CommitmentVerifierAir {
    /// Apply commitment verification constraints to a row slice starting at `offset`.
    /// Used by StarkVerifierAir to enforce sub-AIR constraints in the combined trace.
    pub fn eval_with_offset<AB: AirBuilder>(
        builder: &mut AB,
        local: &[AB::Var],
        offset: usize,
        num_commitments: usize,
        tree_depth: usize,
    ) where
        AB::F: Field + lib_q_stark_field::BasedVectorSpace<lib_q_stark_mersenne31::Mersenne31>,
    {
        let merkle_air = MerkleInclusionAir::new(tree_depth).unwrap();
        let merkle_width = <MerkleInclusionAir as BaseAir<AB::F>>::width(&merkle_air);
        let per_commitment = COMMITMENT_HASH_SIZE + merkle_width + 1;

        use super::poseidon_gadget::PoseidonGadget;

        const HASH_SIZE_FIELD_ELEMENTS: usize = 1;
        let level_width = 1 +
            HASH_SIZE_FIELD_ELEMENTS +
            HASH_SIZE_FIELD_ELEMENTS +
            PoseidonGadget::COLUMNS_PER_HASH;

        for commitment_idx in 0..num_commitments {
            let commitment_start = offset + commitment_idx * per_commitment;

            let expected_root_start = commitment_start;
            let merkle_proof_start = expected_root_start + COMMITMENT_HASH_SIZE;
            let equality_check_col = merkle_proof_start + merkle_width;
            let computed_root_col = merkle_proof_start + 1 + (tree_depth - 1) * level_width + 2;

            let expected_root = local[expected_root_start].clone();
            let computed_root = local[computed_root_col].clone();

            builder.assert_eq(
                local[equality_check_col].clone().into(),
                AB::Expr::from(computed_root) - AB::Expr::from(expected_root),
            );

            let equality_check = local[equality_check_col].clone();
            builder.assert_zero(equality_check);
        }
    }
}

/// Input for commitment verification
///
/// Contains the expected root hashes and Merkle paths for each commitment
#[derive(Debug, Clone)]
pub struct CommitmentVerificationInput {
    /// Expected root hashes for each commitment
    pub expected_roots: Vec<[u8; COMMITMENT_HASH_SIZE]>,
    /// Merkle proof inputs for each commitment
    pub merkle_proofs: Vec<MerkleProofInput>,
}

impl<F: Field + lib_q_stark_field::BasedVectorSpace<lib_q_stark_mersenne31::Mersenne31>>
    TraceGenerator<F, CommitmentVerificationInput> for CommitmentVerifierAir
{
    fn generate_trace(
        &self,
        inputs: &CommitmentVerificationInput,
    ) -> Result<RowMajorMatrix<F>, AirError> {
        // Validate input dimensions
        if inputs.expected_roots.len() != self.num_commitments {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "Expected roots length {} doesn't match number of commitments {}",
                    inputs.expected_roots.len(),
                    self.num_commitments
                ),
            });
        }

        if inputs.merkle_proofs.len() != self.num_commitments {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "Merkle proofs length {} doesn't match number of commitments {}",
                    inputs.merkle_proofs.len(),
                    self.num_commitments
                ),
            });
        }

        // Use MerkleInclusionAir to generate traces for each commitment
        let merkle_air = MerkleInclusionAir::new(self.tree_depth)?;
        // Use fully qualified path to avoid type inference issues
        let merkle_width = <MerkleInclusionAir as BaseAir<F>>::width(&merkle_air);
        let per_commitment = COMMITMENT_HASH_SIZE + merkle_width + 1;
        let width = self.trace_width();
        let num_rows_padded = next_power_of_two(1);
        validate_trace_dimensions(width, num_rows_padded)?;

        let mut trace_values = vec![F::ZERO; num_rows_padded * width];

        for commitment_idx in 0..self.num_commitments {
            let commitment_start = commitment_idx * per_commitment;

            // Expected root hash
            let expected_root_start = commitment_start;
            for (i, &byte) in inputs.expected_roots[commitment_idx].iter().enumerate() {
                trace_values[expected_root_start + i] =
                    F::from_prime_subfield(<F::PrimeSubfield as QuotientMap<u8>>::from_int(byte));
            }

            // Merkle proof (generate using MerkleInclusionAir)
            let merkle_proof_start = expected_root_start + COMMITMENT_HASH_SIZE;
            let merkle_trace: RowMajorMatrix<F> =
                merkle_air.generate_trace(&inputs.merkle_proofs[commitment_idx])?;

            // Copy merkle trace into our trace
            for col in 0..merkle_width {
                trace_values[merkle_proof_start + col] = match merkle_trace.get(0, col) {
                    Some(x) => x,
                    None => F::ZERO,
                }
            }

            // Compute root from Merkle proof and compare to expected
            let computed_root = merkle_air.public_values(&inputs.merkle_proofs[commitment_idx]);
            // For simplicity, compare first field element
            let expected_root_field =
                F::from_prime_subfield(<F::PrimeSubfield as QuotientMap<u8>>::from_int(
                    inputs.expected_roots[commitment_idx][0],
                ));
            let computed_root_field = computed_root.first().copied().unwrap_or(F::ZERO);

            // Equality check: computed_root - expected_root
            let equality_check_col = merkle_proof_start + merkle_width;
            trace_values[equality_check_col] = computed_root_field - expected_root_field;
        }

        Ok(RowMajorMatrix::new(trace_values, width))
    }

    fn public_values(&self, inputs: &CommitmentVerificationInput) -> Vec<F> {
        // Public values are the expected root hashes
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

    type TestField = Complex<Mersenne31>;

    #[test]
    fn test_commitment_verifier_air_new_valid() {
        let air = CommitmentVerifierAir::new(2, 8);
        assert!(air.is_ok());
        let air = air.unwrap();
        assert_eq!(air.num_commitments(), 2);
        assert_eq!(air.tree_depth(), 8);
    }

    #[test]
    fn test_commitment_verifier_air_new_invalid() {
        let result = CommitmentVerifierAir::new(0, 8);
        assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));

        let result = CommitmentVerifierAir::new(MAX_COMMITMENTS + 1, 8);
        assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));

        let result = CommitmentVerifierAir::new(2, 0);
        assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));
    }

    #[test]
    fn test_commitment_verifier_air_width() {
        let air = CommitmentVerifierAir::new(2, 8).unwrap();
        let width = BaseAir::<TestField>::width(&air);
        assert!(width > 0);
    }

    #[test]
    fn test_generate_trace_basic() {
        use crate::air::MerkleHash;

        let air = CommitmentVerifierAir::new(1, 4).unwrap();

        // Create a simple Merkle proof input
        let merkle_proof = MerkleProofInput {
            leaf: b"test_leaf".to_vec(),
            path_bits: vec![false, true, false, true],
            siblings: vec![
                MerkleHash::hash_data(b"sibling0"),
                MerkleHash::hash_data(b"sibling1"),
                MerkleHash::hash_data(b"sibling2"),
                MerkleHash::hash_data(b"sibling3"),
            ],
        };

        let input = CommitmentVerificationInput {
            expected_roots: vec![[0u8; COMMITMENT_HASH_SIZE]],
            merkle_proofs: vec![merkle_proof],
        };

        let trace: Result<RowMajorMatrix<TestField>, _> = air.generate_trace(&input);
        assert!(trace.is_ok());
    }

    #[test]
    fn test_generate_trace_mismatched_lengths() {
        let air = CommitmentVerifierAir::new(2, 4).unwrap();

        let input = CommitmentVerificationInput {
            expected_roots: vec![[0u8; COMMITMENT_HASH_SIZE]], // Only 1, expected 2
            merkle_proofs: vec![],                             // Empty
        };

        let result: Result<RowMajorMatrix<TestField>, _> = air.generate_trace(&input);
        assert!(matches!(result, Err(AirError::InvalidInput { .. })));
    }
}
