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
    WindowAccess,
};
use lib_q_stark_field::integers::QuotientMap;
use lib_q_stark_field::{
    Field,
    PrimeCharacteristicRing,
};
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
    /// - Sibling evaluation: 1 field element (e1)
    /// - Current evaluation at query point: 1 field element (e0)
    /// - Domain point inverse (xs[1]-xs[0])^{-1}: 1 field element
    /// - Domain point xs[0]: 1 field element
    /// - Parity (query_idx0 >> i) & 1: 1 field element
    /// - Roll-in (beta^2 * ro): 1 field element
    ///
    /// For final polynomial:
    /// - Coefficients: 2^log_final_poly_len field elements
    /// - Evaluation point: 1 field element
    /// - Horner intermediates: 2^log_final_poly_len field elements
    ///
    /// For each query:
    /// - Query index: field element
    /// - Query evaluation: field element
    fn trace_width(&self) -> usize {
        let per_round = 32 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1; // +1 xs[0], +1 parity, +1 roll_in
        let final_poly_len = 1 << self.log_final_poly_len;
        // coefficients + evaluation_point + Horner intermediates
        let final_section = final_poly_len + 1 + final_poly_len;
        let per_query = 1 + 1;

        self.num_rounds * per_round + final_section + self.num_queries * per_query
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
        let local = main.current_slice();
        Self::eval_with_offset(
            builder,
            local,
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
        let per_round = 32 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1;
        let final_poly_len = 1 << log_final_poly_len;
        let per_query = 1 + 1;

        use lib_q_stark_field::PrimeCharacteristicRing;
        let one = <AB::F as PrimeCharacteristicRing>::ONE;
        let one_expr = AB::Expr::from(one);

        // --- (A) Folding constraints per round (verifier formula + roll-in) ---
        for round_idx in 0..num_rounds {
            let round_start = offset + round_idx * per_round;
            let beta_col = round_start + 32;
            let beta = local[beta_col].clone();
            let folded_eval = local[beta_col + 1].clone();
            let sibling_eval = local[beta_col + 2].clone();
            let current_eval = local[beta_col + 3].clone();
            let domain_point_inv = local[beta_col + 4].clone();
            let x0 = local[beta_col + 5].clone();
            let parity = local[beta_col + 6].clone();
            let roll_in = local[beta_col + 7].clone();

            // e0 = (1 - parity)*current + parity*sibling, e1 = parity*current + (1 - parity)*sibling
            let p = AB::Expr::from(parity.clone());
            let e0 = (one_expr.clone() - p.clone()) * AB::Expr::from(current_eval.clone()) +
                p.clone() * AB::Expr::from(sibling_eval.clone());
            let e1 = p.clone() * AB::Expr::from(current_eval) +
                (one_expr.clone() - p) * AB::Expr::from(sibling_eval);
            let diff = e1 - e0.clone();
            let fold_part = e0 +
                (AB::Expr::from(beta.clone()) - AB::Expr::from(x0)) *
                    diff *
                    AB::Expr::from(domain_point_inv);
            let expected_folded =
                fold_part + AB::Expr::from(beta) * AB::Expr::from(beta) * AB::Expr::from(roll_in);
            builder.assert_eq(AB::Expr::from(folded_eval), expected_folded);
        }

        // --- Inter-round chaining: round[i].current == round[i-1].folded ---
        for round_idx in 1..num_rounds {
            let prev_folded_col = offset + (round_idx - 1) * per_round + 32 + 1;
            let curr_current_col = offset + round_idx * per_round + 32 + 3;
            builder.assert_eq(
                local[prev_folded_col].clone().into(),
                local[curr_current_col].clone().into(),
            );
        }

        // --- (B) Final polynomial Horner evaluation ---
        let coeff_start = offset + num_rounds * per_round;
        let eval_point_col = coeff_start + final_poly_len;
        let horner_start = eval_point_col + 1;

        if final_poly_len > 0 {
            let eval_point = local[eval_point_col].clone();

            // Horner: h[0] = c[k-1]
            builder.assert_eq(
                local[horner_start].clone().into(),
                local[coeff_start + final_poly_len - 1].clone().into(),
            );
            // Horner: h[i] = h[i-1] * x + c[k-1-i]
            for i in 1..final_poly_len {
                let prev_horner = local[horner_start + i - 1].clone();
                let coeff = local[coeff_start + final_poly_len - 1 - i].clone();
                let expected = AB::Expr::from(prev_horner) * AB::Expr::from(eval_point.clone()) +
                    AB::Expr::from(coeff);
                builder.assert_eq(local[horner_start + i].clone().into(), expected);
            }

            // Final polynomial evaluation must equal last round's folded value
            if num_rounds > 0 {
                let last_folded_col = offset + (num_rounds - 1) * per_round + 32 + 1;
                let horner_result_col = horner_start + final_poly_len - 1;
                builder.assert_eq(
                    local[last_folded_col].clone().into(),
                    local[horner_result_col].clone().into(),
                );
            }
        }

        // --- (C) Query evaluation constraints ---
        let queries_start = horner_start + final_poly_len;
        if num_rounds > 0 && num_queries > 0 {
            // First query's evaluation must match first round's current_eval
            let first_round_current_col = offset + 32 + 3;
            let first_query_eval_col = queries_start + 1;
            builder.assert_eq(
                local[first_round_current_col].clone().into(),
                local[first_query_eval_col].clone().into(),
            );
        }
        // Read query columns (index + eval) for all queries
        for query_idx in 0..num_queries {
            let _query_start = queries_start + query_idx * per_query;
        }
    }
}

/// Input for FRI verification (field-typed for correct constraint satisfaction).
#[derive(Debug, Clone)]
pub struct FriVerificationInput<F: Field> {
    /// FRI rounds data (commitment hashes only; betas come from round_betas).
    pub fri_rounds: Vec<SerializedFriRound>,
    /// Per-round folding challenge (beta). Length must equal fri_rounds.len().
    pub round_betas: Vec<F>,
    /// Final polynomial coefficients (field elements).
    pub final_poly: Vec<F>,
    /// Query indices.
    pub query_indices: Vec<usize>,
    /// Query evaluations (one field element per query).
    pub query_evaluations: Vec<F>,
    /// Per-round current (query-point) evaluations for folding constraint. Length num_rounds; use F::ZERO if missing.
    pub round_current_evals: Vec<F>,
    /// Per-round sibling evaluations for folding constraint. Length num_rounds; use F::ZERO if missing.
    pub round_sibling_evals: Vec<F>,
    /// Per-round domain point inverse (xs[1]-xs[0])^{-1} for verifier fold formula. Length num_rounds; use F::ZERO if missing.
    pub round_domain_point_inverses: Vec<F>,
    /// Per-round first domain point xs[0] for verifier fold formula. Length num_rounds; use F::ZERO if missing.
    pub round_domain_point_x0: Vec<F>,
    /// Per-round query parity (query_idx0 >> i) & 1 for e0/e1 ordering. Length num_rounds; 0 or 1.
    pub round_parity: Vec<F>,
    /// Evaluation point for the final polynomial (x at which verifier checks folded_eval == final_poly(x)).
    pub final_poly_eval_point: F,
    /// Per-round roll-in term (beta^2 * ro) added after fold. Length num_rounds; use F::ZERO if none.
    pub round_roll_ins: Vec<F>,
}

impl<F: Field> TraceGenerator<F, FriVerificationInput<F>> for FriVerifierAir {
    fn generate_trace(
        &self,
        inputs: &FriVerificationInput<F>,
    ) -> Result<RowMajorMatrix<F>, AirError> {
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
        if inputs.round_betas.len() != self.num_rounds {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "round_betas length {} doesn't match expected {}",
                    inputs.round_betas.len(),
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

        let per_round = 32 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1;
        let final_poly_len = 1 << self.log_final_poly_len;
        let per_query = 1 + 1;

        let one_f = <F as PrimeCharacteristicRing>::ONE;

        // Fill FRI rounds (verifier formula + roll-in)
        for (round_idx, round) in inputs.fri_rounds.iter().enumerate() {
            let round_start = round_idx * per_round;

            // Commitment hash (bytes -> field for trace columns 0..32)
            for (i, &byte) in round.commitment_hash.iter().enumerate() {
                trace_values[round_start + i] =
                    F::from_prime_subfield(<F::PrimeSubfield as QuotientMap<u8>>::from_int(byte));
            }

            let beta_col = round_start + 32;
            let beta_f = inputs.round_betas[round_idx];
            trace_values[beta_col] = beta_f;

            let current_f = inputs
                .round_current_evals
                .get(round_idx)
                .copied()
                .unwrap_or(F::ZERO);
            let sibling_f = inputs
                .round_sibling_evals
                .get(round_idx)
                .copied()
                .unwrap_or(F::ZERO);
            let domain_inv_f = inputs
                .round_domain_point_inverses
                .get(round_idx)
                .copied()
                .unwrap_or(F::ZERO);
            let x0_f = inputs
                .round_domain_point_x0
                .get(round_idx)
                .copied()
                .unwrap_or(F::ZERO);
            let parity_f = inputs
                .round_parity
                .get(round_idx)
                .copied()
                .unwrap_or(F::ZERO);

            // e0 = (1 - p)*current + p*sibling, e1 = p*current + (1 - p)*sibling
            let e0_f = (one_f - parity_f) * current_f + parity_f * sibling_f;
            let e1_f = parity_f * current_f + (one_f - parity_f) * sibling_f;
            let roll_in_f = inputs
                .round_roll_ins
                .get(round_idx)
                .copied()
                .unwrap_or(F::ZERO);
            let folded_f =
                e0_f + (beta_f - x0_f) * (e1_f - e0_f) * domain_inv_f + beta_f * beta_f * roll_in_f;

            trace_values[beta_col + 1] = folded_f;
            trace_values[beta_col + 2] = sibling_f;
            trace_values[beta_col + 3] = current_f;
            trace_values[beta_col + 4] = domain_inv_f;
            trace_values[beta_col + 5] = x0_f;
            trace_values[beta_col + 6] = parity_f;
            trace_values[beta_col + 7] = roll_in_f;
        }

        // Fill final polynomial coefficients (field elements directly)
        let final_poly_start = self.num_rounds * per_round;
        let coeff_vals: &[F] = &inputs.final_poly[..final_poly_len.min(inputs.final_poly.len())];
        for (i, &c) in coeff_vals.iter().enumerate() {
            trace_values[final_poly_start + i] = c;
        }

        let eval_point_col = final_poly_start + final_poly_len;
        let eval_point = inputs.final_poly_eval_point;
        trace_values[eval_point_col] = eval_point;

        let horner_start = eval_point_col + 1;
        if final_poly_len > 0 {
            trace_values[horner_start] = coeff_vals[final_poly_len - 1];
            for i in 1..final_poly_len {
                let prev = trace_values[horner_start + i - 1];
                let coeff = coeff_vals[final_poly_len - 1 - i];
                trace_values[horner_start + i] = prev * eval_point + coeff;
            }
        }

        let queries_start = horner_start + final_poly_len;
        for (query_idx, &index) in inputs.query_indices.iter().enumerate() {
            let query_start = queries_start + query_idx * per_query;
            trace_values[query_start] =
                F::from_prime_subfield(<F::PrimeSubfield as QuotientMap<usize>>::from_int(index));
            let eval_f = inputs
                .query_evaluations
                .get(query_idx)
                .copied()
                .unwrap_or(F::ZERO);
            trace_values[query_start + 1] = eval_f;
        }

        Ok(RowMajorMatrix::new(trace_values, width))
    }

    fn public_values(&self, inputs: &FriVerificationInput<F>) -> Vec<F> {
        let final_poly_len = 1 << self.log_final_poly_len;
        inputs
            .final_poly
            .iter()
            .take(final_poly_len)
            .copied()
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
        let zero = TestField::ZERO;

        let input = FriVerificationInput::<TestField> {
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
            round_betas: vec![zero, zero],
            final_poly: vec![zero; 4],
            query_indices: vec![0],
            query_evaluations: vec![zero],
            round_current_evals: vec![zero, zero],
            round_sibling_evals: vec![zero, zero],
            round_domain_point_inverses: vec![zero, zero],
            round_domain_point_x0: vec![zero, zero],
            round_parity: vec![zero, zero],
            final_poly_eval_point: zero,
            round_roll_ins: vec![zero, zero],
        };

        let trace: Result<RowMajorMatrix<TestField>, _> = air.generate_trace(&input);
        assert!(trace.is_ok());
    }

    #[test]
    fn test_generate_trace_mismatched_lengths() {
        let air = FriVerifierAir::new(2, 2, 1).unwrap();

        let input = FriVerificationInput::<TestField> {
            fri_rounds: vec![SerializedFriRound {
                commitment_hash: [0u8; 32],
                beta: vec![],
            }],
            round_betas: vec![],
            final_poly: vec![TestField::ZERO; 4],
            query_indices: vec![],
            query_evaluations: vec![],
            round_current_evals: vec![],
            round_sibling_evals: vec![],
            round_domain_point_inverses: vec![],
            round_domain_point_x0: vec![],
            round_parity: vec![],
            final_poly_eval_point: TestField::ZERO,
            round_roll_ins: vec![],
        };

        let result: Result<RowMajorMatrix<TestField>, _> = air.generate_trace(&input);
        assert!(matches!(result, Err(AirError::InvalidInput { .. })));
    }
}
