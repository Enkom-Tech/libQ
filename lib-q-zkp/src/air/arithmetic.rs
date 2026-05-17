//! Arithmetic AIR - Proves multiplication constraints
//!
//! This AIR proves that a set of multiplication operations were performed correctly:
//! for each triplet (a, b, c), the constraint a * b = c must hold.
//!
//! # Trace Layout
//!
//! For `n` operations, the trace has width `n * 3`:
//! ```text
//! | a_0 | b_0 | c_0 | a_1 | b_1 | c_1 | ... | a_{n-1} | b_{n-1} | c_{n-1} |
//! ```
//!
//! # Constraints
//!
//! For each triplet (a, b, c): `a * b - c = 0`
//!
//! # Security
//!
//! - Input validation prevents DoS through excessive trace size
//! - Trace generation validates all inputs are valid field elements

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_field::Field;
use lib_q_stark_matrix::dense::RowMajorMatrix;

use super::{
    AirError,
    MAX_OPERATIONS,
    TraceGenerator,
    next_power_of_two,
    validate_trace_dimensions,
};

/// Number of columns per operation (a, b, c)
const COLS_PER_OP: usize = 3;

/// AIR for basic arithmetic operations (a * b = c)
///
/// This AIR proves that a sequence of multiplications was computed correctly.
/// Each operation takes two inputs (a, b) and produces one output (c = a * b).
///
/// # Example
///
/// ```rust,ignore
/// use lib_q_zkp::air::{ArithmeticAir, TraceGenerator};
/// use lib_q_stark_field::extension::Complex;
/// use lib_q_stark_mersenne31::Mersenne31;
///
/// type Val = Complex<Mersenne31>;
///
/// let air = ArithmeticAir::new(2).unwrap();
/// let inputs = vec![
///     (Val::from(3u32), Val::from(4u32)),  // 3 * 4 = 12
///     (Val::from(5u32), Val::from(6u32)),  // 5 * 6 = 30
/// ];
/// let trace = air.generate_trace(&inputs).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct ArithmeticAir {
    /// Number of multiplication operations per row
    num_operations: usize,
}

impl ArithmeticAir {
    /// Create a new ArithmeticAir for the given number of operations per row
    ///
    /// # Arguments
    ///
    /// * `num_operations` - Number of (a, b, c) triplets per row
    ///
    /// # Returns
    ///
    /// A new `ArithmeticAir` instance or an error if parameters are invalid
    ///
    /// # Errors
    ///
    /// Returns `AirError` if:
    /// - `num_operations` is 0
    /// - `num_operations` exceeds `MAX_OPERATIONS`
    pub fn new(num_operations: usize) -> Result<Self, AirError> {
        if num_operations == 0 {
            return Err(AirError::InvalidDimensions {
                reason: "Number of operations must be greater than 0".to_string(),
            });
        }

        if num_operations > MAX_OPERATIONS {
            return Err(AirError::ExceedsMaxSize {
                parameter: "num_operations".to_string(),
                max: MAX_OPERATIONS,
                actual: num_operations,
            });
        }

        let width = num_operations * COLS_PER_OP;
        if width > super::MAX_TRACE_WIDTH {
            return Err(AirError::ExceedsMaxSize {
                parameter: "trace_width".to_string(),
                max: super::MAX_TRACE_WIDTH,
                actual: width,
            });
        }

        Ok(Self { num_operations })
    }

    /// Get the number of operations per row
    pub fn num_operations(&self) -> usize {
        self.num_operations
    }
}

impl<F: Field> BaseAir<F> for ArithmeticAir {
    fn width(&self) -> usize {
        self.num_operations * COLS_PER_OP
    }
}

impl<AB: AirBuilder> Air<AB> for ArithmeticAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();

        // Enforce a * b = c for each triplet
        for i in 0..self.num_operations {
            let a = local[i * COLS_PER_OP];
            let b = local[i * COLS_PER_OP + 1];
            let c = local[i * COLS_PER_OP + 2];

            // Constraint: a * b - c = 0
            builder.assert_zero(a * b - c);
        }
    }
}

/// Input type for ArithmeticAir trace generation
///
/// A list of (a, b) pairs, where each pair represents a multiplication operation.
pub type ArithmeticInput<F> = Vec<(F, F)>;

impl<F: Field> TraceGenerator<F, ArithmeticInput<F>> for ArithmeticAir {
    fn generate_trace(&self, inputs: &ArithmeticInput<F>) -> Result<RowMajorMatrix<F>, AirError> {
        if inputs.is_empty() {
            return Err(AirError::InvalidInput {
                reason: "Input list cannot be empty".to_string(),
            });
        }

        // Calculate required rows (round up to power of 2)
        let total_ops = inputs.len();
        let ops_per_row = self.num_operations;
        let num_rows = total_ops.div_ceil(ops_per_row);
        let num_rows_padded = next_power_of_two(num_rows);

        let width = self.num_operations * COLS_PER_OP;
        validate_trace_dimensions(width, num_rows_padded)?;

        // Allocate trace
        let mut trace_values = vec![F::ZERO; num_rows_padded * width];

        // Fill trace with input values
        for (idx, (a, b)) in inputs.iter().enumerate() {
            let row = idx / ops_per_row;
            let col_offset = (idx % ops_per_row) * COLS_PER_OP;
            let base = row * width + col_offset;

            trace_values[base] = *a;
            trace_values[base + 1] = *b;
            trace_values[base + 2] = *a * *b;
        }

        // Pad remaining cells with valid triplets (0 * 0 = 0)
        // Already zero-initialized, which satisfies 0 * 0 = 0

        Ok(RowMajorMatrix::new(trace_values, width))
    }

    fn public_values(&self, inputs: &ArithmeticInput<F>) -> Vec<F> {
        // For arithmetic AIR, we can optionally expose the products as public values
        inputs.iter().map(|(a, b)| *a * *b).collect()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use lib_q_stark_air::BaseAir;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_matrix::Matrix;
    use lib_q_stark_mersenne31::Mersenne31;

    use super::*;

    type TestField = Complex<Mersenne31>;

    #[test]
    fn test_arithmetic_air_new_valid() {
        let air = ArithmeticAir::new(5);
        assert!(air.is_ok());
        assert_eq!(air.unwrap().num_operations(), 5);
    }

    #[test]
    fn test_arithmetic_air_new_zero_ops() {
        let result = ArithmeticAir::new(0);
        assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));
    }

    #[test]
    fn test_arithmetic_air_width() {
        let air = ArithmeticAir::new(4).unwrap();
        assert_eq!(BaseAir::<TestField>::width(&air), 12); // 4 ops * 3 cols
    }

    #[test]
    fn test_generate_trace_basic() {
        let air = ArithmeticAir::new(2).unwrap();
        let inputs: ArithmeticInput<TestField> = vec![
            (
                TestField::from(Mersenne31::new(3)),
                TestField::from(Mersenne31::new(4)),
            ),
            (
                TestField::from(Mersenne31::new(5)),
                TestField::from(Mersenne31::new(6)),
            ),
        ];

        let trace = air.generate_trace(&inputs);
        assert!(trace.is_ok());

        let trace = trace.unwrap();
        assert_eq!(trace.width(), 6); // 2 ops * 3 cols
        assert!(trace.height().is_power_of_two());
    }

    #[test]
    fn test_generate_trace_empty_input() {
        let air = ArithmeticAir::new(2).unwrap();
        let inputs: ArithmeticInput<TestField> = vec![];

        let result = air.generate_trace(&inputs);
        assert!(matches!(result, Err(AirError::InvalidInput { .. })));
    }

    #[test]
    fn test_generate_trace_values_correct() {
        use lib_q_stark_matrix::Matrix;

        let air = ArithmeticAir::new(1).unwrap();
        let a = TestField::from(Mersenne31::new(7));
        let b = TestField::from(Mersenne31::new(8));
        let inputs: ArithmeticInput<TestField> = vec![(a, b)];

        let trace = air.generate_trace(&inputs).unwrap();
        let row = trace.row_slice(0).expect("row should exist");

        // Check a, b, c = a*b
        assert_eq!(row[0], a);
        assert_eq!(row[1], b);
        assert_eq!(row[2], a * b);
        assert_eq!(row[2], TestField::from(Mersenne31::new(56))); // 7 * 8 = 56
    }

    #[test]
    fn test_public_values() {
        let air = ArithmeticAir::new(2).unwrap();
        let inputs: ArithmeticInput<TestField> = vec![
            (
                TestField::from(Mersenne31::new(2)),
                TestField::from(Mersenne31::new(3)),
            ),
            (
                TestField::from(Mersenne31::new(4)),
                TestField::from(Mersenne31::new(5)),
            ),
        ];

        let public = air.public_values(&inputs);
        assert_eq!(public.len(), 2);
        assert_eq!(public[0], TestField::from(Mersenne31::new(6))); // 2 * 3
        assert_eq!(public[1], TestField::from(Mersenne31::new(20))); // 4 * 5
    }
}
