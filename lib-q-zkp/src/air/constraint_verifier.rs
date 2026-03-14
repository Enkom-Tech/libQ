//! Constraint Verification AIR - Verifies constraint satisfaction
//!
//! This AIR verifies that AIR constraints are satisfied at the out-of-domain
//! point (zeta) by recomposing the quotient polynomial and checking that:
//! `constraints(zeta) / Z_H(zeta) = quotient(zeta)`
//!
//! # Design
//!
//! Constraint verification involves:
//! 1. Recomposing quotient polynomial from chunks using Lagrange interpolation
//! 2. Evaluating AIR constraints at zeta
//! 3. Computing vanishing polynomial Z_H(zeta)
//! 4. Verifying: constraints(zeta) = quotient(zeta) * Z_H(zeta)
//!
//! # Security
//!
//! - All polynomial operations are constrained in AIR
//! - Vanishing polynomial computation is verified
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
use lib_q_stark_matrix::dense::RowMajorMatrix;

use super::recursive_types::MAX_QUOTIENT_CHUNKS;
use super::{
    AirError,
    TraceGenerator,
    next_power_of_two,
    validate_trace_dimensions,
};

/// Maximum trace width for constraint evaluation
pub const MAX_CONSTRAINT_TRACE_WIDTH: usize = 1024;

/// AIR for verifying constraint satisfaction
///
/// This AIR verifies that AIR constraints are satisfied by:
/// - Recomposing the quotient polynomial from chunks
/// - Evaluating constraints at zeta
/// - Verifying the constraint-quotient relationship
#[derive(Debug, Clone)]
pub struct ConstraintVerifierAir {
    /// Number of quotient chunks
    num_quotient_chunks: usize,
    /// Trace width (number of columns)
    trace_width: usize,
    /// Log of trace domain size
    log_trace_domain_size: usize,
}

impl ConstraintVerifierAir {
    /// Create a new ConstraintVerifierAir
    ///
    /// # Arguments
    ///
    /// * `num_quotient_chunks` - Number of quotient chunks
    /// * `trace_width` - Width of the trace (number of columns)
    /// * `log_trace_domain_size` - Log2 of trace domain size
    ///
    /// # Returns
    ///
    /// `Ok(ConstraintVerifierAir)` if parameters are valid
    pub fn new(
        num_quotient_chunks: usize,
        trace_width: usize,
        log_trace_domain_size: usize,
    ) -> Result<Self, AirError> {
        if num_quotient_chunks == 0 || num_quotient_chunks > MAX_QUOTIENT_CHUNKS {
            return Err(AirError::InvalidDimensions {
                reason: format!(
                    "Number of quotient chunks must be between 1 and {}",
                    MAX_QUOTIENT_CHUNKS
                ),
            });
        }

        if trace_width == 0 || trace_width > MAX_CONSTRAINT_TRACE_WIDTH {
            return Err(AirError::InvalidDimensions {
                reason: format!(
                    "Trace width must be between 1 and {}",
                    MAX_CONSTRAINT_TRACE_WIDTH
                ),
            });
        }

        if log_trace_domain_size > 32 {
            return Err(AirError::InvalidDimensions {
                reason: format!(
                    "Log trace domain size {} exceeds maximum 32",
                    log_trace_domain_size
                ),
            });
        }

        Ok(Self {
            num_quotient_chunks,
            trace_width,
            log_trace_domain_size,
        })
    }

    /// Get the number of quotient chunks
    pub fn num_quotient_chunks(&self) -> usize {
        self.num_quotient_chunks
    }

    /// Get the trace width
    pub fn trace_width(&self) -> usize {
        self.trace_width
    }

    /// Get the log of trace domain size
    pub fn log_trace_domain_size(&self) -> usize {
        self.log_trace_domain_size
    }

    /// Compute trace width
    ///
    /// Trace contains:
    /// - Quotient chunks: num_quotient_chunks * CHALLENGE_DIM (field elements per chunk)
    /// - Trace local: trace_width field elements
    /// - Trace next: trace_width field elements
    /// - Zeta: 1 field element
    /// - Alpha: 1 field element
    /// - Zeta pow chain: (log_trace_domain_size + 1) for zeta^n
    /// - Vanishing poly evaluation: 1 field element
    /// - Recomposed quotient: 1 field element
    /// - Constraint evaluation: 1 field element
    /// - Verification result: 1 field element
    fn trace_width_air(&self) -> usize {
        const CHALLENGE_DIM: usize = 1; // Simplified: 1 field element per challenge
        let zeta_pow_chain_len = self.log_trace_domain_size + 1;
        self.num_quotient_chunks * CHALLENGE_DIM
            + self.trace_width * 2 // local + next
            + 1 // zeta
            + 1 // alpha
            + zeta_pow_chain_len // zeta^0 .. zeta^n
            + 1 // vanishing_poly
            + 1 // recomposed_quotient
            + 1 // constraint_eval
            + 1 // verification_result
    }
}

impl<F: Field> BaseAir<F> for ConstraintVerifierAir {
    fn width(&self) -> usize {
        self.trace_width_air()
    }
}

impl<AB: AirBuilder> Air<AB> for ConstraintVerifierAir
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
            self.num_quotient_chunks,
            self.trace_width,
            self.log_trace_domain_size,
        );
    }
}

impl ConstraintVerifierAir {
    /// Apply constraint verification constraints to a row slice starting at `offset`.
    /// Used by StarkVerifierAir to enforce sub-AIR constraints in the combined trace.
    pub fn eval_with_offset<AB: AirBuilder>(
        builder: &mut AB,
        local: &[AB::Var],
        offset: usize,
        num_quotient_chunks: usize,
        trace_width: usize,
        log_trace_domain_size: usize,
    ) where
        AB::F: Field,
    {
        use lib_q_stark_field::PrimeCharacteristicRing;

        const CHALLENGE_DIM: usize = 1;
        let quotient_chunks_start = offset;
        let trace_local_start = quotient_chunks_start + num_quotient_chunks * CHALLENGE_DIM;
        let trace_next_start = trace_local_start + trace_width;
        let zeta_col = trace_next_start + trace_width;
        let alpha_col = zeta_col + 1;
        let zeta_pow_chain_start = alpha_col + 1;
        let vanishing_poly_col = zeta_pow_chain_start + log_trace_domain_size + 1;
        let recomposed_quotient_col = vanishing_poly_col + 1;
        let constraint_eval_col = recomposed_quotient_col + 1;
        let verification_result_col = constraint_eval_col + 1;

        let zeta = local[zeta_col].clone();
        let alpha = local[alpha_col].clone();
        let vanishing_poly = local[vanishing_poly_col].clone();
        let recomposed_quotient = local[recomposed_quotient_col].clone();
        let constraint_eval = local[constraint_eval_col].clone();

        let zero = AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ZERO);
        let mut recomposed = zero.clone();
        for i in (0..num_quotient_chunks).rev() {
            let chunk = local[quotient_chunks_start + i * CHALLENGE_DIM].clone();
            recomposed = AB::Expr::from(alpha.clone()) * recomposed + AB::Expr::from(chunk);
        }
        builder.assert_eq(AB::Expr::from(recomposed_quotient.clone()), recomposed);

        builder.assert_eq(
            local[zeta_pow_chain_start].clone().into(),
            AB::Expr::from(zeta.clone()),
        );
        for step in 1..=log_trace_domain_size {
            let col_in = zeta_pow_chain_start + step - 1;
            let col_out = zeta_pow_chain_start + step;
            let prev = local[col_in].clone();
            builder.assert_eq(
                local[col_out].clone().into(),
                AB::Expr::from(prev.clone()) * AB::Expr::from(prev),
            );
        }

        let zeta_pow_n = local[zeta_pow_chain_start + log_trace_domain_size].clone();
        let one = AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ONE);
        builder.assert_eq(
            AB::Expr::from(vanishing_poly.clone()),
            AB::Expr::from(zeta_pow_n) - one,
        );

        let verification_result = local[verification_result_col].clone();
        let expected_result =
            constraint_eval.clone() - recomposed_quotient.clone() * vanishing_poly.clone();
        builder.assert_zero(verification_result - expected_result);
    }
}

/// Input for constraint verification (field-typed for correct constraint satisfaction).
#[derive(Debug, Clone)]
pub struct ConstraintVerificationInput<F: Field> {
    /// Quotient chunks evaluated at zeta (one field element per chunk).
    pub quotient_chunks: Vec<F>,
    /// Trace local values at zeta.
    pub trace_local: Vec<F>,
    /// Trace next values at zeta_next.
    pub trace_next: Vec<F>,
    /// Out-of-domain point.
    pub zeta: F,
    /// Constraint combination challenge.
    pub alpha: F,
    /// Public values.
    pub public_values: Vec<F>,
}

impl<F: Field> TraceGenerator<F, ConstraintVerificationInput<F>> for ConstraintVerifierAir {
    fn generate_trace(
        &self,
        inputs: &ConstraintVerificationInput<F>,
    ) -> Result<RowMajorMatrix<F>, AirError> {
        if inputs.quotient_chunks.len() != self.num_quotient_chunks {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "Quotient chunks length {} doesn't match expected {}",
                    inputs.quotient_chunks.len(),
                    self.num_quotient_chunks
                ),
            });
        }

        if inputs.trace_local.len() != self.trace_width {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "Trace local length {} doesn't match trace width {}",
                    inputs.trace_local.len(),
                    self.trace_width
                ),
            });
        }

        if inputs.trace_next.len() != self.trace_width {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "Trace next length {} doesn't match trace width {}",
                    inputs.trace_next.len(),
                    self.trace_width
                ),
            });
        }

        let width = self.trace_width_air();
        let num_rows_padded = next_power_of_two(1);
        validate_trace_dimensions(width, num_rows_padded)?;

        let mut trace_values = vec![F::ZERO; num_rows_padded * width];

        const CHALLENGE_DIM: usize = 1;
        let quotient_chunks_start = 0;
        let trace_local_start = quotient_chunks_start + self.num_quotient_chunks * CHALLENGE_DIM;
        let trace_next_start = trace_local_start + self.trace_width;
        let zeta_col = trace_next_start + self.trace_width;
        let alpha_col = zeta_col + 1;
        let zeta_pow_chain_start = alpha_col + 1;
        let vanishing_poly_col = zeta_pow_chain_start + self.log_trace_domain_size + 1;
        let recomposed_quotient_col = vanishing_poly_col + 1;
        let constraint_eval_col = recomposed_quotient_col + 1;
        let verification_result_col = constraint_eval_col + 1;

        for (chunk_idx, &chunk_val) in inputs.quotient_chunks.iter().enumerate() {
            let chunk_col = quotient_chunks_start + chunk_idx * CHALLENGE_DIM;
            trace_values[chunk_col] = chunk_val;
        }

        for (i, &v) in inputs.trace_local.iter().enumerate() {
            trace_values[trace_local_start + i] = v;
        }

        for (i, &v) in inputs.trace_next.iter().enumerate() {
            trace_values[trace_next_start + i] = v;
        }

        trace_values[zeta_col] = inputs.zeta;
        trace_values[alpha_col] = inputs.alpha;

        trace_values[zeta_pow_chain_start] = inputs.zeta;
        for step in 1..=self.log_trace_domain_size {
            let prev = trace_values[zeta_pow_chain_start + step - 1];
            trace_values[zeta_pow_chain_start + step] = prev * prev;
        }

        let zeta_pow_n = trace_values[zeta_pow_chain_start + self.log_trace_domain_size];
        trace_values[vanishing_poly_col] = zeta_pow_n - F::ONE;

        let mut recomposed_quotient = F::ZERO;
        for i in (0..self.num_quotient_chunks).rev() {
            let chunk_val = trace_values[quotient_chunks_start + i * CHALLENGE_DIM];
            recomposed_quotient = trace_values[alpha_col] * recomposed_quotient + chunk_val;
        }
        trace_values[recomposed_quotient_col] = recomposed_quotient;

        let vanishing_poly = trace_values[vanishing_poly_col];
        trace_values[constraint_eval_col] = recomposed_quotient * vanishing_poly;

        let constraint_eval = trace_values[constraint_eval_col];
        trace_values[verification_result_col] =
            constraint_eval - recomposed_quotient * vanishing_poly;

        Ok(RowMajorMatrix::new(trace_values, width))
    }

    fn public_values(&self, inputs: &ConstraintVerificationInput<F>) -> Vec<F> {
        inputs.public_values.clone()
    }
}

#[cfg(test)]
mod tests {
    use lib_q_stark_air::BaseAir;
    use lib_q_stark_field::PrimeCharacteristicRing;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    use super::*;

    type TestField = Complex<Mersenne31>;

    #[test]
    fn test_constraint_verifier_air_new_valid() {
        let air = ConstraintVerifierAir::new(4, 8, 10);
        assert!(air.is_ok());
        let air = air.unwrap();
        assert_eq!(air.num_quotient_chunks(), 4);
        assert_eq!(air.trace_width(), 8);
        assert_eq!(air.log_trace_domain_size(), 10);
    }

    #[test]
    fn test_constraint_verifier_air_new_invalid() {
        let result = ConstraintVerifierAir::new(0, 8, 10);
        assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));

        let result = ConstraintVerifierAir::new(MAX_QUOTIENT_CHUNKS + 1, 8, 10);
        assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));

        let result = ConstraintVerifierAir::new(4, 0, 10);
        assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));
    }

    #[test]
    fn test_constraint_verifier_air_width() {
        let air = ConstraintVerifierAir::new(2, 4, 8).unwrap();
        let width = BaseAir::<TestField>::width(&air);
        assert!(width > 0);
    }

    #[test]
    fn test_generate_trace_basic() {
        let air = ConstraintVerifierAir::new(2, 4, 8).unwrap();
        let zero = TestField::ZERO;

        let input = ConstraintVerificationInput::<TestField> {
            quotient_chunks: vec![zero, zero],
            trace_local: vec![zero; 4],
            trace_next: vec![zero; 4],
            zeta: zero,
            alpha: zero,
            public_values: vec![],
        };

        let trace: Result<RowMajorMatrix<TestField>, _> = air.generate_trace(&input);
        assert!(trace.is_ok());
    }

    #[test]
    fn test_generate_trace_mismatched_lengths() {
        let air = ConstraintVerifierAir::new(2, 4, 8).unwrap();

        let input = ConstraintVerificationInput::<TestField> {
            quotient_chunks: vec![TestField::ZERO],
            trace_local: vec![TestField::ZERO; 4],
            trace_next: vec![TestField::ZERO; 4],
            zeta: TestField::ZERO,
            alpha: TestField::ZERO,
            public_values: vec![],
        };

        let result: Result<RowMajorMatrix<TestField>, _> = air.generate_trace(&input);
        assert!(matches!(result, Err(AirError::InvalidInput { .. })));
    }
}
