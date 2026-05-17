use alloc::vec::Vec;

pub use lib_q_stark_air::symbolic::BaseLeaf;
use lib_q_stark_air::symbolic::{
    BaseEntry,
    SymbolicExpression,
    SymbolicVariable,
};
use lib_q_stark_air::{
    Air,
    AirBuilder,
    WindowAccess,
};
use lib_q_stark_field::{
    ExtensionField,
    Field,
};
use lib_q_stark_util::log2_ceil_usize;
use tracing::instrument;

/// Describes the shape of an AIR for symbolic constraint evaluation.
#[derive(Debug, Clone, Copy, Default)]
pub struct AirLayout {
    pub preprocessed_width: usize,
    pub main_width: usize,
    pub num_public_values: usize,
}

/// Maps between global constraint indices and the separated base/ext streams.
///
/// When alpha powers are pre-computed in global order `[alpha^{N-1}, ..., alpha^0]`,
/// the layout tells us which powers correspond to base-field constraints (for
/// `packed_linear_combination`) and which to extension-field constraints.
#[derive(Debug, Default)]
pub struct ConstraintLayout {
    pub base_indices: Vec<usize>,
    pub ext_indices: Vec<usize>,
}

impl ConstraintLayout {
    pub const fn total_constraints(&self) -> usize {
        self.base_indices.len() + self.ext_indices.len()
    }

    /// Decompose `alpha` into reordered powers for base and extension constraints.
    ///
    /// Returns `(base_alpha_powers, ext_alpha_powers)` where:
    /// - `base_alpha_powers[d][j]` = d-th basis coefficient of the alpha power for
    ///   the j-th base constraint (transposed + reordered for `packed_linear_combination`)
    /// - `ext_alpha_powers[j]` = full EF alpha power for the j-th extension constraint
    pub fn decompose_alpha<F: Field, EF: ExtensionField<F>>(
        &self,
        alpha: EF,
    ) -> (Vec<Vec<F>>, Vec<EF>) {
        let total = self.total_constraints();

        let mut alpha_powers = alpha.powers().collect_n(total);
        alpha_powers.reverse();

        let base_alpha_powers = (0..EF::DIMENSION)
            .map(|d| {
                self.base_indices
                    .iter()
                    .map(|&idx| alpha_powers[idx].as_basis_coefficients_slice()[d])
                    .collect()
            })
            .collect();

        let ext_alpha_powers = self
            .ext_indices
            .iter()
            .map(|&idx| alpha_powers[idx])
            .collect();

        (base_alpha_powers, ext_alpha_powers)
    }
}

/// Tracks whether a constraint was emitted via `assert_zero` (base) or `assert_zero_ext` (ext).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
enum ConstraintType {
    Base,
    Ext,
}

/// Evaluate the AIR symbolically and return the constraint layout.
#[instrument(name = "compute constraint layout", skip_all, level = "debug")]
pub fn get_constraint_layout<F, A>(air: &A, layout: AirLayout) -> ConstraintLayout
where
    F: Field,
    A: Air<SymbolicAirBuilder<F>>,
{
    let mut builder = SymbolicAirBuilder::new(layout);
    air.eval(&mut builder);
    builder.constraint_layout()
}

/// Evaluate the AIR symbolically and return the base-field constraints.
#[instrument(
    name = "evaluate base constraints symbolically",
    skip_all,
    level = "debug"
)]
pub fn get_symbolic_constraints<F, A>(air: &A, layout: AirLayout) -> Vec<SymbolicExpression<F>>
where
    F: Field,
    A: Air<SymbolicAirBuilder<F>>,
{
    let mut builder = SymbolicAirBuilder::new(layout);
    air.eval(&mut builder);
    builder.base_constraints()
}

/// Compute the max constraint degree and determine the log number of quotient chunks.
#[instrument(skip_all, level = "debug")]
pub fn get_log_num_quotient_chunks<F, A>(air: &A, layout: AirLayout, is_zk: usize) -> usize
where
    F: Field,
    A: Air<SymbolicAirBuilder<F>>,
{
    assert!(is_zk <= 1, "is_zk must be either 0 or 1");

    if let Some(degree_hint) = air.max_constraint_degree() {
        let constraint_degree = (degree_hint + is_zk).max(2);
        return log2_ceil_usize(constraint_degree - 1);
    }

    let constraints = get_symbolic_constraints(air, layout);
    let max_degree = constraints
        .iter()
        .map(|c| c.degree_multiple())
        .max()
        .unwrap_or(0);
    let constraint_degree = (max_degree + is_zk).max(2);
    log2_ceil_usize(constraint_degree - 1)
}

/// An [`AirBuilder`] for evaluating constraints symbolically, and recording them for later use.
#[derive(Debug)]
pub struct SymbolicAirBuilder<F: Field> {
    #[allow(dead_code)]
    preprocessed: lib_q_stark_matrix::dense::RowMajorMatrix<SymbolicVariable<F>>,
    preprocessed_window: SymbolicWindow<SymbolicVariable<F>>,
    main: lib_q_stark_matrix::dense::RowMajorMatrix<SymbolicVariable<F>>,
    public_values: Vec<SymbolicVariable<F>>,
    base_constraints: Vec<SymbolicExpression<F>>,
    constraint_types: Vec<ConstraintType>,
}

impl<F: Field> SymbolicAirBuilder<F> {
    pub fn new(layout: AirLayout) -> Self {
        use lib_q_stark_matrix::dense::RowMajorMatrix;

        let AirLayout {
            preprocessed_width,
            main_width,
            num_public_values,
        } = layout;

        let prep_values: Vec<_> = [0, 1]
            .into_iter()
            .flat_map(|offset| {
                (0..preprocessed_width).map(move |index| {
                    SymbolicVariable::new(BaseEntry::Preprocessed { offset }, index)
                })
            })
            .collect();

        let main_values: Vec<_> = [0, 1]
            .into_iter()
            .flat_map(|offset| {
                (0..main_width)
                    .map(move |index| SymbolicVariable::new(BaseEntry::Main { offset }, index))
            })
            .collect();

        let public_values = (0..num_public_values)
            .map(move |index| SymbolicVariable::new(BaseEntry::Public, index))
            .collect();

        let preprocessed = RowMajorMatrix::new(prep_values, preprocessed_width);
        let preprocessed_window = SymbolicWindow::from_matrix(&preprocessed);
        Self {
            preprocessed,
            preprocessed_window,
            main: RowMajorMatrix::new(main_values, main_width),
            public_values,
            base_constraints: alloc::vec![],
            constraint_types: alloc::vec![],
        }
    }

    pub fn constraint_layout(&self) -> ConstraintLayout {
        let mut base_indices = Vec::new();
        let mut ext_indices = Vec::new();
        for (idx, kind) in self.constraint_types.iter().enumerate() {
            match kind {
                ConstraintType::Base => base_indices.push(idx),
                ConstraintType::Ext => ext_indices.push(idx),
            }
        }
        ConstraintLayout {
            base_indices,
            ext_indices,
        }
    }

    pub fn base_constraints(&self) -> Vec<SymbolicExpression<F>> {
        self.base_constraints.clone()
    }
}

/// A two-row window wrapper over a `RowMajorMatrix` for symbolic evaluation.
///
/// This local type lets us implement `WindowAccess` without orphan rule issues.
#[derive(Clone, Debug)]
pub struct SymbolicWindow<T> {
    values: Vec<T>,
    width: usize,
}

impl<T: Clone + Send + Sync> SymbolicWindow<T> {
    fn from_matrix(m: &lib_q_stark_matrix::dense::RowMajorMatrix<T>) -> Self {
        Self {
            values: core::borrow::Borrow::<[T]>::borrow(&m.values).to_vec(),
            width: m.width,
        }
    }
}

impl<T> WindowAccess<T> for SymbolicWindow<T> {
    fn current_slice(&self) -> &[T] {
        &self.values[..self.width]
    }

    fn next_slice(&self) -> &[T] {
        &self.values[self.width..]
    }
}

impl<F: Field> AirBuilder for SymbolicAirBuilder<F> {
    type F = F;
    type Expr = SymbolicExpression<F>;
    type Var = SymbolicVariable<F>;
    type PreprocessedWindow = SymbolicWindow<Self::Var>;
    type MainWindow = SymbolicWindow<Self::Var>;
    type PublicVar = SymbolicVariable<F>;

    fn main(&self) -> Self::MainWindow {
        SymbolicWindow::from_matrix(&self.main)
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed_window
    }

    fn is_first_row(&self) -> Self::Expr {
        lib_q_stark_air::symbolic::SymbolicExpr::Leaf(BaseLeaf::IsFirstRow)
    }

    fn is_last_row(&self) -> Self::Expr {
        lib_q_stark_air::symbolic::SymbolicExpr::Leaf(BaseLeaf::IsLastRow)
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            lib_q_stark_air::symbolic::SymbolicExpr::Leaf(BaseLeaf::IsTransition)
        } else {
            panic!("uni-stark only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.base_constraints.push(x.into());
        self.constraint_types.push(ConstraintType::Base);
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        &self.public_values
    }
}
