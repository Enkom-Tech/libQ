use lib_q_stark_air::{
    Air,
    AirBuilder,
    RowWindow,
};
use lib_q_stark_field::Field;
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use tracing::instrument;

/// Runs constraint checks using a given [`Air`] implementation and trace matrix.
///
/// Iterates over every row in `main`, providing both the current and next row
/// (with wraparound) to the [`Air`] logic. Also injects public values into the
/// [`DebugConstraintBuilder`] for first/last row assertions.
///
/// # Arguments
/// - `air`: The [`Air`] logic to run.
/// - `main`: The [`RowMajorMatrix`] containing witness rows.
/// - `public_values`: Public values provided to the builder.
///
/// This function is used in debug mode (via `#[cfg(debug_assertions)]`), in tests, and by
/// recursive verifier regression tests that need to assert constraint satisfaction before prove.
#[allow(dead_code)] // Used conditionally in debug mode and in tests
#[allow(unsafe_code)] // Safe: bounds are guaranteed by loop invariants (row_index in [0, height))
#[instrument(skip_all)]
pub fn check_constraints<F, A>(air: &A, main: &RowMajorMatrix<F>, public_values: &[F])
where
    F: Field,
    A: for<'a> Air<DebugConstraintBuilder<'a, F>>,
{
    let height = main.height();
    let preprocessed = air.preprocessed_trace();

    (0..height).for_each(|row_index| {
        let row_index_next = (row_index + 1) % height;

        // SAFETY: row_index is in range [0, height) because we iterate over 0..height.
        // The loop invariant guarantees row_index < height, satisfying row_slice_unchecked's requirement.
        let local = unsafe { main.row_slice_unchecked(row_index) };
        // SAFETY: row_index_next = (row_index + 1) % height, which is always in range [0, height).
        // Since row_index < height, row_index + 1 <= height, and modulo ensures 0 <= row_index_next < height.
        let next = unsafe { main.row_slice_unchecked(row_index_next) };
        let main_window = RowWindow::from_two_rows(&local, &next);

        let (prep_local, prep_next);
        let preprocessed_window = match preprocessed.as_ref() {
            Some(prep) => {
                // SAFETY: Same invariants as above - row_index and row_index_next are both in [0, height).
                // The preprocessed trace has the same height as the main trace, so these indices are valid.
                prep_local = unsafe { prep.row_slice_unchecked(row_index) };
                prep_next = unsafe { prep.row_slice_unchecked(row_index_next) };
                RowWindow::from_two_rows(&prep_local, &prep_next)
            }
            None => RowWindow::from_two_rows(&[], &[]),
        };

        let mut builder = DebugConstraintBuilder {
            row_index,
            main: main_window,
            preprocessed: preprocessed_window,
            public_values,
            is_first_row: F::from_bool(row_index == 0),
            is_last_row: F::from_bool(row_index == height - 1),
            is_transition: F::from_bool(row_index != height - 1),
        };

        air.eval(&mut builder);
    });
}

/// A builder that runs constraint assertions during testing.
///
/// Used in conjunction with [`check_constraints`] to simulate
/// an execution trace and verify that the [`Air`] logic enforces all constraints.
#[derive(Debug)]
pub struct DebugConstraintBuilder<'a, F: Field> {
    /// The index of the row currently being evaluated.
    row_index: usize,
    /// Two-row window over the main trace.
    main: RowWindow<'a, F>,
    /// Two-row window over the preprocessed trace (zero-width if not present).
    preprocessed: RowWindow<'a, F>,
    /// The public values provided for constraint validation (e.g. inputs or outputs).
    public_values: &'a [F],
    /// A flag indicating whether this is the first row.
    is_first_row: F,
    /// A flag indicating whether this is the last row.
    is_last_row: F,
    /// A flag indicating whether this is a transition row (not the last row).
    is_transition: F,
}

impl<'a, F> AirBuilder for DebugConstraintBuilder<'a, F>
where
    F: Field,
{
    type F = F;
    type Expr = F;
    type Var = F;
    type PreprocessedWindow = RowWindow<'a, F>;
    type MainWindow = RowWindow<'a, F>;
    type PublicVar = F;

    fn main(&self) -> Self::MainWindow {
        self.main
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row
    }

    /// # Panics
    /// This function panics if `size` is not `2`.
    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            self.is_transition
        } else {
            panic!("only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x = x.into();
        if x != F::ZERO {
            #[cfg(feature = "std")]
            std::eprintln!(
                "Constraint assert_zero failed: row={}, value={:?}",
                self.row_index,
                x
            );
        }
        assert_eq!(
            x,
            F::ZERO,
            "constraints had nonzero value on row {}",
            self.row_index
        );
    }

    fn assert_eq<I1: Into<Self::Expr>, I2: Into<Self::Expr>>(&mut self, x: I1, y: I2) {
        let x = x.into();
        let y = y.into();
        if x != y {
            #[cfg(feature = "std")]
            std::eprintln!(
                "Constraint assert_eq failed: row={}, left={:?}, right={:?}",
                self.row_index,
                x,
                y
            );
        }
        assert_eq!(
            x, y,
            "values didn't match on row {}: {} != {}",
            self.row_index, x, y
        );
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use lib_q_stark_air::{
        BaseAir,
        WindowAccess,
    };
    use lib_q_stark_field::{
        Field,
        PrimeCharacteristicRing,
    };
    use lib_q_stark_mersenne31::Mersenne31;

    use super::*;

    /// A test AIR that enforces a simple linear transition logic:
    /// - Each cell in the next row must equal the current cell plus 1 (i.e., `next = current + 1`)
    /// - On the last row, the current row must match the provided public values.
    ///
    /// This is useful for validating constraint evaluation, transition logic,
    /// and row condition flags (first/last/transition).
    #[derive(Debug)]
    struct RowLogicAir<const W: usize>;

    impl<F: Field, const W: usize> BaseAir<F> for RowLogicAir<W> {
        fn width(&self) -> usize {
            W
        }
    }

    impl<F: Field, const W: usize> Air<DebugConstraintBuilder<'_, F>> for RowLogicAir<W> {
        fn eval(&self, builder: &mut DebugConstraintBuilder<'_, F>) {
            let main = builder.main();
            let current = main.current_slice();
            let next = main.next_slice();

            for col in 0..W {
                let a = current[col];
                let b = next[col];

                builder.when_transition().assert_eq(b, a + F::ONE);
            }

            let public_values = builder.public_values;
            let main = builder.main();
            let current = main.current_slice();
            let mut when_last = builder.when(builder.is_last_row);
            for (i, &pv) in public_values.iter().enumerate().take(W) {
                when_last.assert_eq(current[i], pv);
            }
        }
    }

    #[test]
    fn test_incremental_rows_with_last_row_check() {
        let air = RowLogicAir::<2>;
        let values = vec![
            Mersenne31::ONE,
            Mersenne31::ONE, // Row 0
            Mersenne31::new(2),
            Mersenne31::new(2), // Row 1
            Mersenne31::new(3),
            Mersenne31::new(3), // Row 2
            Mersenne31::new(4),
            Mersenne31::new(4), // Row 3 (last)
        ];
        let main = RowMajorMatrix::new(values, 2);
        check_constraints(&air, &main, &[Mersenne31::new(4); 2]);
    }

    #[test]
    #[should_panic]
    fn test_incorrect_increment_logic() {
        let air = RowLogicAir::<2>;
        let values = vec![
            Mersenne31::ONE,
            Mersenne31::ONE, // Row 0
            Mersenne31::new(2),
            Mersenne31::new(2), // Row 1
            Mersenne31::new(5),
            Mersenne31::new(5), // Row 2 (wrong)
            Mersenne31::new(6),
            Mersenne31::new(6), // Row 3
        ];
        let main = RowMajorMatrix::new(values, 2);
        check_constraints(&air, &main, &[Mersenne31::new(6); 2]);
    }

    #[test]
    #[should_panic]
    fn test_wrong_last_row_public_value() {
        let air = RowLogicAir::<2>;
        let values = vec![
            Mersenne31::ONE,
            Mersenne31::ONE, // Row 0
            Mersenne31::new(2),
            Mersenne31::new(2), // Row 1
            Mersenne31::new(3),
            Mersenne31::new(3), // Row 2
            Mersenne31::new(4),
            Mersenne31::new(4), // Row 3
        ];
        let main = RowMajorMatrix::new(values, 2);
        check_constraints(&air, &main, &[Mersenne31::new(4), Mersenne31::new(5)]);
    }

    #[test]
    fn test_single_row_wraparound_logic() {
        let air = RowLogicAir::<2>;
        let values = vec![
            Mersenne31::new(99),
            Mersenne31::new(77), // Row 0
        ];
        let main = RowMajorMatrix::new(values, 2);
        check_constraints(&air, &main, &[Mersenne31::new(99), Mersenne31::new(77)]);
    }
}
