use lib_q_stark_air::{
    Air,
    AirBuilder,
    RowWindow,
};
use lib_q_stark_field::Field;
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use tracing::instrument;

#[instrument(skip_all)]
#[allow(unused)]
pub fn check_constraints<F, A>(air: &A, main: &RowMajorMatrix<F>, public_values: &[F])
where
    F: Field,
    A: for<'a> Air<DebugConstraintBuilder<'a, F>>,
{
    let height = main.height();
    let preprocessed = air.preprocessed_trace();

    (0..height).for_each(|row_index| {
        let row_index_next = (row_index + 1) % height;

        let local = main.row_slice(row_index).expect("row_index in bounds");
        let next = main.row_slice(row_index_next).expect("next row in bounds");
        let main_window = RowWindow::from_two_rows(&local, &next);

        let (prep_local, prep_next);
        let preprocessed_window = match preprocessed.as_ref() {
            Some(prep) => {
                prep_local = prep.row_slice(row_index).expect("row_index in bounds");
                prep_next = prep.row_slice(row_index_next).expect("next row in bounds");
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

#[derive(Debug)]
pub struct DebugConstraintBuilder<'a, F: Field> {
    row_index: usize,
    main: RowWindow<'a, F>,
    preprocessed: RowWindow<'a, F>,
    public_values: &'a [F],
    is_first_row: F,
    is_last_row: F,
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

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            self.is_transition
        } else {
            panic!("only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        assert_eq!(
            x.into(),
            F::ZERO,
            "constraints had nonzero value on row {}",
            self.row_index
        );
    }

    fn assert_eq<I1: Into<Self::Expr>, I2: Into<Self::Expr>>(&mut self, x: I1, y: I2) {
        let x = x.into();
        let y = y.into();
        assert_eq!(
            x, y,
            "values didn't match on row {}: {} != {}",
            self.row_index, x, y
        );
    }
}
