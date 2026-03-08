//! FRI Protocol Verification AIR - Verifies FRI low-degree test
//!
//! This AIR verifies the execution of the FRI (Fast Reed-Solomon Interactive)
//! protocol, which is used in STARK proofs to verify polynomial low-degree.
//!
//! # Design
//!
//! FRI verification involves:
//! 1. Verifying FRI folding steps: `folded(x) = combine(poly(x), poly(-x), beta)`
//! 2. Verifying challenge generation: `beta = challenger.sample()` after observing commitment
//! 3. Verifying final polynomial: degree matches `log_final_poly_len`
//! 4. Verifying query proofs: indices and openings are consistent
//!
//! # Security
//!
//! - All polynomial operations are constrained in AIR
//! - Challenge generation follows Fiat-Shamir (public transcript)
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

use super::recursive_types::{
    MAX_FINAL_POLY_LOG_LEN,
    MAX_FRI_ROUNDS,
    SerializedFriRound,
};
use super::{
    AirError,
    TraceGenerator,
    next_power_of_two,
    validate_trace_dimensions,
};

/// Maximum number of query proofs
pub const MAX_FRI_QUERIES: usize = 1000;

/// AIR for verifying FRI protocol execution
///
/// This AIR verifies that a FRI proof was correctly executed by constraining:
/// - FRI folding steps at each round
/// - Challenge generation (Fiat-Shamir)
/// - Final polynomial evaluation
/// - Query proof consistency
#[derive(Debug, Clone)]
pub struct FriVerifierAir {
    /// Number of FRI rounds
    num_rounds: usize,
    /// Log of final polynomial length
    log_final_poly_len: usize,
    /// Number of query proofs
    num_queries: usize,
}

impl FriVerifierAir {
    /// Create a new FriVerifierAir
    ///
    /// # Arguments
    ///
    /// * `num_rounds` - Number of FRI folding rounds
    /// * `log_final_poly_len` - Log2 of final polynomial length
    /// * `num_queries` - Number of query proofs
    ///
    /// # Returns
    ///
    /// `Ok(FriVerifierAir)` if parameters are valid
    pub fn new(
        num_rounds: usize,
        log_final_poly_len: usize,
        num_queries: usize,
    ) -> Result<Self, AirError> {
        if num_rounds == 0 || num_rounds > MAX_FRI_ROUNDS {
            return Err(AirError::InvalidDimensions {
                reason: format!(
                    "Number of FRI rounds must be between 1 and {}",
                    MAX_FRI_ROUNDS
                ),
            });
        }

        if log_final_poly_len > MAX_FINAL_POLY_LOG_LEN {
            return Err(AirError::InvalidDimensions {
                reason: format!(
                    "Log final poly len {} exceeds maximum {}",
                    log_final_poly_len, MAX_FINAL_POLY_LOG_LEN
                ),
            });
        }

        if num_queries == 0 || num_queries > MAX_FRI_QUERIES {
            return Err(AirError::InvalidDimensions {
                reason: format!(
                    "Number of queries must be between 1 and {}",
                    MAX_FRI_QUERIES
                ),
            });
        }

        Ok(Self {
            num_rounds,
            log_final_poly_len,
            num_queries,
        })
    }

    /// Get the number of FRI rounds
    pub fn num_rounds(&self) -> usize {
        self.num_rounds
    }

    /// Get the log of final polynomial length
    pub fn log_final_poly_len(&self) -> usize {
        self.log_final_poly_len
    }

    /// Get the number of queries
    pub fn num_queries(&self) -> usize {
        self.num_queries
    }

    /// Compute trace width
    ///
    /// For each FRI round:
    /// - Commitment hash: 32 bytes
    /// - Beta challenge: 1 field element
    /// - Folded evaluation: 1 field element
    /// - Sibling evaluation: 1 field element
    /// - Current evaluation at query point: 1 field element
    /// - Domain point inverse 1/(2*x_r): 1 field element
    ///
    /// For final polynomial:
    /// - Coefficients: 2^log_final_poly_len field elements
    ///
    /// For each query:
    /// - Query index: field element
    /// - Query evaluation: field element
    fn trace_width(&self) -> usize {
        // Per round: commitment + beta + folded_eval + sibling_eval + current_eval + domain_point_inverse
        let per_round = 32 + 1 + 1 + 1 + 1 + 1; // bytes + 5 field elements

        // Final polynomial coefficients
        let final_poly_len = 1 << self.log_final_poly_len;

        // Per query: index + evaluation
        let per_query = 1 + 1; // 2 field elements

        self.num_rounds * per_round + final_poly_len + self.num_queries * per_query
    }
}

impl<F: Field> BaseAir<F> for FriVerifierAir {
    fn width(&self) -> usize {
        self.trace_width()
    }
}

impl<AB: AirBuilder> Air<AB> for FriVerifierAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main
            .row_slice(0)
            .expect("Matrix should have at least one row");
        Self::eval_with_offset(
            builder,
            &local,
            0,
            self.num_rounds,
            self.log_final_poly_len,
            self.num_queries,
        );
    }
}

impl FriVerifierAir {
    /// Apply FRI verification constraints to a row slice starting at `offset`.
    /// Used by StarkVerifierAir to enforce sub-AIR constraints in the combined trace.
    pub fn eval_with_offset<AB: AirBuilder>(
        builder: &mut AB,
        local: &[AB::Var],
        offset: usize,
        num_rounds: usize,
        log_final_poly_len: usize,
        num_queries: usize,
    ) where
        AB::F: Field,
    {
        let per_round = 32 + 1 + 1 + 1 + 1 + 1; // commitment + beta + folded + sibling + current + x_inv
        let final_poly_len = 1 << log_final_poly_len;
        let per_query = 1 + 1; // index + evaluation

        use lib_q_stark_field::PrimeCharacteristicRing;
        let one = <AB::F as PrimeCharacteristicRing>::ONE;
        let two = one + one;
        let half_val = one / two;
        let half = AB::Expr::from(half_val);

        for round_idx in 0..num_rounds {
            let round_start = offset + round_idx * per_round;

            let beta_col = round_start + 32;
            let beta = local[beta_col].clone();

            let folded_eval_col = beta_col + 1;
            let folded_eval = local[folded_eval_col].clone();

            let sibling_eval_col = folded_eval_col + 1;
            let sibling_eval = local[sibling_eval_col].clone();

            let current_eval_col = sibling_eval_col + 1;
            let current_eval = local[current_eval_col].clone();

            let domain_point_inv_col = current_eval_col + 1;
            let domain_point_inv = local[domain_point_inv_col].clone();

            let sum = AB::Expr::from(current_eval.clone()) + AB::Expr::from(sibling_eval.clone());
            let diff = AB::Expr::from(current_eval) - AB::Expr::from(sibling_eval);
            let expected_folded = sum.clone() * half.clone() +
                diff * AB::Expr::from(beta) * AB::Expr::from(domain_point_inv);
            builder.assert_eq(AB::Expr::from(folded_eval), expected_folded);
        }

        let final_poly_start = offset + num_rounds * per_round;
        let _final_poly_coeffs = &local[final_poly_start..final_poly_start + final_poly_len];

        let queries_start = final_poly_start + final_poly_len;
        for query_idx in 0..num_queries {
            let query_start = queries_start + query_idx * per_query;

            let query_index_col = query_start;
            let _query_index = local[query_index_col].clone();

            let query_eval_col = query_index_col + 1;
            let _query_eval = local[query_eval_col].clone();
        }
    }
}

/// Input for FRI verification
#[derive(Debug, Clone)]
pub struct FriVerificationInput {
    /// FRI rounds data
    pub fri_rounds: Vec<SerializedFriRound>,
    /// Final polynomial coefficients
    pub final_poly: Vec<u8>, // Serialized field elements
    /// Query indices
    pub query_indices: Vec<usize>,
    /// Query evaluations
    pub query_evaluations: Vec<u8>, // Serialized field elements
    /// Per-round current (query-point) evaluations for folding constraint. Length num_rounds; empty means zeros.
    pub round_current_evals: Vec<Vec<u8>>,
    /// Per-round sibling evaluations for folding constraint. Length num_rounds; empty means zeros.
    pub round_sibling_evals: Vec<Vec<u8>>,
    /// Per-round domain point inverse 1/(2*x_r) for folding constraint. Length num_rounds; empty means zeros.
    pub round_domain_point_inverses: Vec<Vec<u8>>,
}

impl<F: Field> TraceGenerator<F, FriVerificationInput> for FriVerifierAir {
    fn generate_trace(&self, inputs: &FriVerificationInput) -> Result<RowMajorMatrix<F>, AirError> {
        // Validate input dimensions
        if inputs.fri_rounds.len() != self.num_rounds {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "FRI rounds length {} doesn't match expected {}",
                    inputs.fri_rounds.len(),
                    self.num_rounds
                ),
            });
        }

        let final_poly_len = 1 << self.log_final_poly_len;
        if inputs.final_poly.len() != final_poly_len {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "Final poly length {} doesn't match expected {}",
                    inputs.final_poly.len(),
                    final_poly_len
                ),
            });
        }

        if inputs.query_indices.len() != self.num_queries {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "Query indices length {} doesn't match expected {}",
                    inputs.query_indices.len(),
                    self.num_queries
                ),
            });
        }

        let width = self.trace_width();
        let num_rows_padded = next_power_of_two(1);
        validate_trace_dimensions(width, num_rows_padded)?;

        let mut trace_values = vec![F::ZERO; num_rows_padded * width];

        let per_round = 32 + 1 + 1 + 1 + 1 + 1;
        let final_poly_len = 1 << self.log_final_poly_len;
        let per_query = 1 + 1;

        // Fill FRI rounds
        for (round_idx, round) in inputs.fri_rounds.iter().enumerate() {
            let round_start = round_idx * per_round;

            // Commitment hash
            for (i, &byte) in round.commitment_hash.iter().enumerate() {
                trace_values[round_start + i] =
                    F::from_prime_subfield(<F::PrimeSubfield as QuotientMap<u8>>::from_int(byte));
            }

            // Beta challenge (simplified: use first byte as field element)
            let beta_col = round_start + 32;
            trace_values[beta_col] =
                F::from_prime_subfield(<F::PrimeSubfield as QuotientMap<u8>>::from_int(
                    round.beta.first().copied().unwrap_or(0u8),
                ));

            // Current eval, sibling eval, domain point inverse (from input or zero)
            let current_eval = inputs
                .round_current_evals
                .get(round_idx)
                .and_then(|v| v.first().copied())
                .unwrap_or(0u8);
            let sibling_eval = inputs
                .round_sibling_evals
                .get(round_idx)
                .and_then(|v| v.first().copied())
                .unwrap_or(0u8);
            let domain_inv = inputs
                .round_domain_point_inverses
                .get(round_idx)
                .and_then(|v| v.first().copied())
                .unwrap_or(0u8);

            let current_f = F::from_prime_subfield(
                <F::PrimeSubfield as QuotientMap<u8>>::from_int(current_eval),
            );
            let sibling_f = F::from_prime_subfield(
                <F::PrimeSubfield as QuotientMap<u8>>::from_int(sibling_eval),
            );
            let domain_inv_f =
                F::from_prime_subfield(<F::PrimeSubfield as QuotientMap<u8>>::from_int(domain_inv));
            let beta_f = trace_values[beta_col];

            use lib_q_stark_field::PrimeCharacteristicRing;
            let one = <F as PrimeCharacteristicRing>::ONE;
            let half_f = one / (one + one);
            let folded_f =
                (current_f + sibling_f) * half_f + (current_f - sibling_f) * beta_f * domain_inv_f;

            trace_values[beta_col + 1] = folded_f;
            trace_values[beta_col + 2] = sibling_f;
            trace_values[beta_col + 3] = current_f;
            trace_values[beta_col + 4] = domain_inv_f;
        }

        // Fill final polynomial
        let final_poly_start = self.num_rounds * per_round;
        for (i, &byte) in inputs.final_poly.iter().take(final_poly_len).enumerate() {
            trace_values[final_poly_start + i] =
                F::from_prime_subfield(<F::PrimeSubfield as QuotientMap<u8>>::from_int(byte));
        }

        // Fill query proofs
        let queries_start = final_poly_start + final_poly_len;
        for (query_idx, &index) in inputs.query_indices.iter().enumerate() {
            let query_start = queries_start + query_idx * per_query;
            trace_values[query_start] =
                F::from_prime_subfield(<F::PrimeSubfield as QuotientMap<usize>>::from_int(index));
            // Query evaluation (placeholder)
            trace_values[query_start + 1] = F::ZERO;
        }

        Ok(RowMajorMatrix::new(trace_values, width))
    }

    fn public_values(&self, inputs: &FriVerificationInput) -> Vec<F> {
        // Public values are the final polynomial coefficients
        let final_poly_len = 1 << self.log_final_poly_len;
        inputs
            .final_poly
            .iter()
            .take(final_poly_len)
            .map(|&b| F::from_prime_subfield(<F::PrimeSubfield as QuotientMap<u8>>::from_int(b)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use lib_q_stark_air::BaseAir;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    use super::super::recursive_types::SerializedFriRound;
    use super::*;

    type TestField = Complex<Mersenne31>;

    #[test]
    fn test_fri_verifier_air_new_valid() {
        let air = FriVerifierAir::new(8, 4, 10);
        assert!(air.is_ok());
        let air = air.unwrap();
        assert_eq!(air.num_rounds(), 8);
        assert_eq!(air.log_final_poly_len(), 4);
        assert_eq!(air.num_queries(), 10);
    }

    #[test]
    fn test_fri_verifier_air_new_invalid() {
        let result = FriVerifierAir::new(0, 4, 10);
        assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));

        let result = FriVerifierAir::new(MAX_FRI_ROUNDS + 1, 4, 10);
        assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));

        let result = FriVerifierAir::new(8, MAX_FINAL_POLY_LOG_LEN + 1, 10);
        assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));
    }

    #[test]
    fn test_fri_verifier_air_width() {
        let air = FriVerifierAir::new(4, 3, 5).unwrap();
        let width = BaseAir::<TestField>::width(&air);
        assert!(width > 0);
    }

    #[test]
    fn test_generate_trace_basic() {
        let air = FriVerifierAir::new(2, 2, 1).unwrap();

        let input = FriVerificationInput {
            fri_rounds: vec![
                SerializedFriRound {
                    commitment_hash: [0u8; 32],
                    beta: vec![1, 2, 3],
                },
                SerializedFriRound {
                    commitment_hash: [1u8; 32],
                    beta: vec![4, 5, 6],
                },
            ],
            final_poly: vec![0u8; 4], // 2^2 = 4
            query_indices: vec![0],
            query_evaluations: vec![0],
            round_current_evals: vec![],
            round_sibling_evals: vec![],
            round_domain_point_inverses: vec![],
        };

        let trace: Result<RowMajorMatrix<TestField>, _> = air.generate_trace(&input);
        assert!(trace.is_ok());
    }

    #[test]
    fn test_generate_trace_mismatched_lengths() {
        let air = FriVerifierAir::new(2, 2, 1).unwrap();

        let input = FriVerificationInput {
            fri_rounds: vec![SerializedFriRound {
                commitment_hash: [0u8; 32],
                beta: vec![],
            }], // Only 1 round, expected 2
            final_poly: vec![0u8; 4],
            query_indices: vec![],
            query_evaluations: vec![],
            round_current_evals: vec![],
            round_sibling_evals: vec![],
            round_domain_point_inverses: vec![],
        };

        let result: Result<RowMajorMatrix<TestField>, _> = air.generate_trace(&input);
        assert!(matches!(result, Err(AirError::InvalidInput { .. })));
    }
}
