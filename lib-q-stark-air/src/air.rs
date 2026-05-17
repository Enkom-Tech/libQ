use alloc::vec::Vec;
use core::ops::{
    Add,
    Mul,
    Sub,
};

use lib_q_stark_field::{
    Algebra,
    ExtensionField,
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::dense::{
    RowMajorMatrix,
    RowMajorMatrixView,
};

/// Read access to a pair of trace rows (typically current and next).
///
/// Implementors expose two flat slices that constraint evaluators use
/// to express algebraic relations between rows.
pub trait WindowAccess<T> {
    fn current_slice(&self) -> &[T];
    fn next_slice(&self) -> &[T];

    #[inline]
    fn current(&self, i: usize) -> Option<T>
    where
        T: Clone,
    {
        self.current_slice().get(i).cloned()
    }

    #[inline]
    fn next(&self, i: usize) -> Option<T>
    where
        T: Clone,
    {
        self.next_slice().get(i).cloned()
    }
}

/// A lightweight two-row window into a trace matrix.
///
/// Stores two `&[T]` slices -- one for the current row and one for
/// the next -- without carrying any matrix metadata.
#[derive(Debug, Clone, Copy)]
pub struct RowWindow<'a, T> {
    current: &'a [T],
    next: &'a [T],
}

impl<'a, T> RowWindow<'a, T> {
    /// Create a window from a [`RowMajorMatrixView`] that has exactly
    /// two rows.
    ///
    /// # Panics
    ///
    /// Panics if the view does not contain exactly `2 * width` elements.
    #[inline]
    pub fn from_view(view: &RowMajorMatrixView<'a, T>) -> Self {
        let width = view.width;
        assert_eq!(
            view.values.len(),
            2 * width,
            "RowWindow::from_view: expected 2 rows (2*{width} elements), got {}",
            view.values.len()
        );
        let (current, next) = view.values.split_at(width);
        Self { current, next }
    }

    /// Create a window from two separate row slices.
    ///
    /// # Panics
    ///
    /// Panics (in debug builds) if the slices have different lengths.
    #[inline]
    pub fn from_two_rows(current: &'a [T], next: &'a [T]) -> Self {
        debug_assert_eq!(
            current.len(),
            next.len(),
            "RowWindow::from_two_rows: row lengths differ ({} vs {})",
            current.len(),
            next.len()
        );
        Self { current, next }
    }
}

impl<T> WindowAccess<T> for RowWindow<'_, T> {
    #[inline]
    fn current_slice(&self) -> &[T] {
        self.current
    }

    #[inline]
    fn next_slice(&self) -> &[T] {
        self.next
    }
}

/// The underlying structure of an AIR.
pub trait BaseAir<F>: Sync {
    /// The number of columns (a.k.a. registers) in this AIR.
    fn width(&self) -> usize;

    /// Return an optional preprocessed trace matrix to be included in the prover's trace.
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        None
    }

    /// Which main trace columns have their next row accessed by this AIR's
    /// constraints.
    ///
    /// By default returns every column index, requiring opening all main
    /// columns at both `zeta` and `zeta_next`. Override to return an empty
    /// vector for single-row AIRs or a subset for partial next-row access.
    ///
    /// Must be consistent with [`Air::eval`]. Omitting a column the AIR
    /// reads will cause verification failures or soundness gaps.
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..self.width()).collect()
    }

    /// Which preprocessed trace columns have their next row accessed.
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        self.preprocessed_trace()
            .map(|t| (0..t.width).collect())
            .unwrap_or_default()
    }

    /// Optional hint for the number of constraints, letting the prover skip
    /// symbolic evaluation. Must exactly match the actual count.
    fn num_constraints(&self) -> Option<usize> {
        None
    }

    /// Optional upper bound on constraint degree multiple, letting both
    /// prover and verifier skip symbolic degree inference.
    fn max_constraint_degree(&self) -> Option<usize> {
        None
    }

    /// Return the number of expected public values.
    fn num_public_values(&self) -> usize {
        0
    }
}

/// An algebraic intermediate representation (AIR) definition.
///
/// Contains an evaluation function for computing the constraints of the AIR.
/// This function can be applied to a concrete evaluation trace or symbolically.
pub trait Air<AB: AirBuilder>: BaseAir<AB::F> {
    fn eval(&self, builder: &mut AB);
}

/// A builder providing both a trace on which AIR constraints can be evaluated
/// and a method of accumulating constraint evaluations.
///
/// Supports symbolic evaluation (constraints as polynomials) and concrete
/// evaluation (constraints combined using randomness).
pub trait AirBuilder: Sized {
    /// Underlying field type.
    type F: PrimeCharacteristicRing + Sync;

    /// Output type for an AIR constraint evaluation.
    type Expr: Algebra<Self::F> + Algebra<Self::Var>;

    /// Variable type appearing in the trace matrix.
    type Var: Into<Self::Expr>
        + Copy
        + Send
        + Sync
        + Add<Self::F, Output = Self::Expr>
        + Add<Self::Var, Output = Self::Expr>
        + Add<Self::Expr, Output = Self::Expr>
        + Sub<Self::F, Output = Self::Expr>
        + Sub<Self::Var, Output = Self::Expr>
        + Sub<Self::Expr, Output = Self::Expr>
        + Mul<Self::F, Output = Self::Expr>
        + Mul<Self::Var, Output = Self::Expr>
        + Mul<Self::Expr, Output = Self::Expr>;

    /// Two-row window over the preprocessed trace columns.
    type PreprocessedWindow: WindowAccess<Self::Var> + Clone;

    /// Two-row window over the main trace columns.
    type MainWindow: WindowAccess<Self::Var> + Clone;

    /// Variable type for public values.
    type PublicVar: Into<Self::Expr> + Copy;

    /// Return the current and next row slices of the main trace.
    fn main(&self) -> Self::MainWindow;

    /// Return the preprocessed registers as a two-row window.
    fn preprocessed(&self) -> &Self::PreprocessedWindow;

    /// Expression evaluating to a non-zero value only on the first row.
    fn is_first_row(&self) -> Self::Expr;

    /// Expression evaluating to a non-zero value only on the last row.
    fn is_last_row(&self) -> Self::Expr;

    /// Expression evaluating to zero only on the last row.
    fn is_transition(&self) -> Self::Expr {
        self.is_transition_window(2)
    }

    /// Expression evaluating to zero only on the last `size - 1` rows.
    fn is_transition_window(&self, size: usize) -> Self::Expr;

    /// Returns a sub-builder whose constraints are enforced only when `condition` is nonzero.
    fn when<I: Into<Self::Expr>>(&mut self, condition: I) -> FilteredAirBuilder<'_, Self> {
        FilteredAirBuilder {
            inner: self,
            condition: condition.into(),
        }
    }

    /// Returns a sub-builder whose constraints are enforced only when `x != y`.
    fn when_ne<I1: Into<Self::Expr>, I2: Into<Self::Expr>>(
        &mut self,
        x: I1,
        y: I2,
    ) -> FilteredAirBuilder<'_, Self> {
        self.when(x.into() - y.into())
    }

    /// Returns a sub-builder whose constraints are enforced only on the first row.
    fn when_first_row(&mut self) -> FilteredAirBuilder<'_, Self> {
        self.when(self.is_first_row())
    }

    /// Returns a sub-builder whose constraints are enforced only on the last row.
    fn when_last_row(&mut self) -> FilteredAirBuilder<'_, Self> {
        self.when(self.is_last_row())
    }

    /// Returns a sub-builder whose constraints are enforced on all transition rows.
    fn when_transition(&mut self) -> FilteredAirBuilder<'_, Self> {
        self.when(self.is_transition())
    }

    /// Like [`when_transition`](Self::when_transition), but requires a window of `size` rows.
    fn when_transition_window(&mut self, size: usize) -> FilteredAirBuilder<'_, Self> {
        self.when(self.is_transition_window(size))
    }

    /// Assert that the given element is zero.
    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I);

    /// Assert that every element of a given array is 0.
    fn assert_zeros<const N: usize, I: Into<Self::Expr>>(&mut self, array: [I; N]) {
        for elem in array {
            self.assert_zero(elem);
        }
    }

    /// Assert that a given array consists of only boolean values.
    fn assert_bools<const N: usize, I: Into<Self::Expr>>(&mut self, array: [I; N]) {
        let zero_array = array.map(|x| x.into().bool_check());
        self.assert_zeros(zero_array);
    }

    /// Assert that `x` is equal to `1`.
    fn assert_one<I: Into<Self::Expr>>(&mut self, x: I) {
        self.assert_zero(x.into() - Self::Expr::ONE);
    }

    /// Assert that two expressions are equal.
    fn assert_eq<I1: Into<Self::Expr>, I2: Into<Self::Expr>>(&mut self, x: I1, y: I2) {
        self.assert_zero(x.into() - y.into());
    }

    /// Public input values available during constraint evaluation.
    fn public_values(&self) -> &[Self::PublicVar] {
        &[]
    }

    /// Assert that `x` is a boolean, i.e. either `0` or `1`.
    fn assert_bool<I: Into<Self::Expr>>(&mut self, x: I) {
        self.assert_zero(x.into().bool_check());
    }
}

/// Extension of [`AirBuilder`] for builders that supply periodic column values.
pub trait PeriodicAirBuilder: AirBuilder {
    type PeriodicVar: Into<Self::Expr> + Copy;
    fn periodic_values(&self) -> &[Self::PeriodicVar];
}

/// Extension trait for builders that carry additional runtime context.
pub trait AirBuilderWithContext: AirBuilder {
    type EvalContext;
    fn eval_context(&self) -> &Self::EvalContext;
}

/// Extension of `AirBuilder` for working over extension fields.
pub trait ExtensionBuilder: AirBuilder<F: Field> {
    /// Extension field type.
    type EF: ExtensionField<Self::F>;

    /// Expression type over extension field elements.
    type ExprEF: Algebra<Self::Expr> + Algebra<Self::EF>;

    /// Variable type over extension field elements.
    type VarEF: Into<Self::ExprEF> + Copy + Send + Sync;

    /// Assert that an extension field expression is zero.
    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>;

    /// Assert that two extension field expressions are equal.
    fn assert_eq_ext<I1, I2>(&mut self, x: I1, y: I2)
    where
        I1: Into<Self::ExprEF>,
        I2: Into<Self::ExprEF>,
    {
        self.assert_zero_ext(x.into() - y.into());
    }

    /// Assert that an extension field expression is equal to one.
    fn assert_one_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.assert_eq_ext(x, Self::ExprEF::ONE);
    }
}

/// Trait for builders supporting permutation arguments (e.g., for lookup constraints).
pub trait PermutationAirBuilder: ExtensionBuilder {
    /// Two-row window over the permutation trace columns.
    type MP: WindowAccess<Self::VarEF>;

    /// Randomness variable type used in permutation commitments.
    type RandomVar: Into<Self::ExprEF> + Copy;

    /// Value type for expected cumulated values used in global lookup arguments.
    type PermutationVar: Into<Self::ExprEF> + Clone;

    /// Return the current and next row slices of the permutation trace.
    fn permutation(&self) -> Self::MP;

    /// Return the list of randomness values for the permutation argument.
    fn permutation_randomness(&self) -> &[Self::RandomVar];

    /// Return the expected cumulated values for global lookup arguments.
    fn permutation_values(&self) -> &[Self::PermutationVar];
}

/// A wrapper around an [`AirBuilder`] that enforces constraints only when a
/// specified condition is met.
#[derive(Debug)]
pub struct FilteredAirBuilder<'a, AB: AirBuilder> {
    pub inner: &'a mut AB,
    condition: AB::Expr,
}

impl<AB: AirBuilder> FilteredAirBuilder<'_, AB> {
    pub fn condition(&self) -> AB::Expr {
        self.condition.clone()
    }
}

impl<AB: AirBuilder> AirBuilder for FilteredAirBuilder<'_, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type PreprocessedWindow = AB::PreprocessedWindow;
    type MainWindow = AB::MainWindow;
    type PublicVar = AB::PublicVar;

    fn main(&self) -> Self::MainWindow {
        self.inner.main()
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.inner.preprocessed()
    }

    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }

    fn is_transition(&self) -> Self::Expr {
        self.inner.is_transition()
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        self.inner.is_transition_window(size)
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.inner.assert_zero(self.condition() * x.into());
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.inner.public_values()
    }
}

impl<AB: PeriodicAirBuilder> PeriodicAirBuilder for FilteredAirBuilder<'_, AB> {
    type PeriodicVar = AB::PeriodicVar;

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.inner.periodic_values()
    }
}

impl<AB: ExtensionBuilder> ExtensionBuilder for FilteredAirBuilder<'_, AB> {
    type EF = AB::EF;
    type ExprEF = AB::ExprEF;
    type VarEF = AB::VarEF;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        let ext_x: Self::ExprEF = x.into();
        let condition: AB::Expr = self.condition();
        self.inner.assert_zero_ext(ext_x * condition);
    }
}

impl<AB: PermutationAirBuilder> PermutationAirBuilder for FilteredAirBuilder<'_, AB> {
    type MP = AB::MP;
    type RandomVar = AB::RandomVar;
    type PermutationVar = AB::PermutationVar;

    fn permutation(&self) -> Self::MP {
        self.inner.permutation()
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.inner.permutation_randomness()
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        self.inner.permutation_values()
    }
}

impl<AB: AirBuilderWithContext> AirBuilderWithContext for FilteredAirBuilder<'_, AB> {
    type EvalContext = AB::EvalContext;

    fn eval_context(&self) -> &Self::EvalContext {
        self.inner.eval_context()
    }
}
