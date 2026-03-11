//! Helpers for reusing an [`AirBuilder`] on a restricted set of trace columns.
//!
//! The uni-STARK builders often need to enforce constraints that refer to only a slice of the main
//! trace. [`SubSliced`] offers a cheap view over a subset of columns, and
//! [`SubAirBuilder`] wires that view into any [`AirBuilder`] implementation so a sub-air can be
//! evaluated independently without cloning trace data.

// Code inpsired from SP1 with additional modifications:
// https://github.com/succinctlabs/sp1/blob/main/crates/stark/src/air/sub_builder.rs

use core::ops::Range;

use lib_q_stark_air::{
    AirBuilder,
    BaseAir,
    WindowAccess,
};

/// A window wrapper that restricts access to a contiguous column range.
#[derive(Debug, Clone)]
pub struct SubSliced<W> {
    inner: W,
    range: Range<usize>,
}

impl<W> SubSliced<W> {
    /// Create a new sub-sliced window over the given column range.
    pub fn new(inner: W, range: Range<usize>) -> Self {
        Self { inner, range }
    }
}

impl<T, W: WindowAccess<T>> WindowAccess<T> for SubSliced<W> {
    fn current_slice(&self) -> &[T] {
        &self.inner.current_slice()[self.range.clone()]
    }
    fn next_slice(&self) -> &[T] {
        &self.inner.next_slice()[self.range.clone()]
    }
}

/// Evaluates a sub-AIR against a restricted slice of the parent trace.
///
/// This is useful whenever a standalone component AIR is embedded in a larger system but only owns
/// a few columns. `SubAirBuilder` reuses the parent builder for bookkeeping so witness generation
/// and constraint enforcement stay in sync.
pub struct SubAirBuilder<'a, AB: AirBuilder, SubAir: BaseAir<AB::F>, T> {
    /// Mutable reference to the parent builder.
    inner: &'a mut AB,

    /// Column range (in the parent trace) that the sub-AIR is allowed to see.
    column_range: Range<usize>,

    /// Marker for the sub-AIR and witness type.
    _phantom: core::marker::PhantomData<(SubAir, T)>,
}

impl<'a, AB: AirBuilder, SubAir: BaseAir<AB::F>, T> SubAirBuilder<'a, AB, SubAir, T> {
    /// Create a new [`SubAirBuilder`] exposing only `column_range` to the sub-AIR.
    ///
    /// The range must lie entirely inside the parent trace width.
    #[must_use]
    pub const fn new(inner: &'a mut AB, column_range: Range<usize>) -> Self {
        Self {
            inner,
            column_range,
            _phantom: core::marker::PhantomData,
        }
    }
}

/// Implements `AirBuilder` for `SubAirBuilder`.
impl<AB: AirBuilder, SubAir: BaseAir<AB::F>, F> AirBuilder for SubAirBuilder<'_, AB, SubAir, F> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type PreprocessedWindow = AB::PreprocessedWindow;
    type MainWindow = SubSliced<AB::MainWindow>;
    type PublicVar = AB::PublicVar;

    fn main(&self) -> Self::MainWindow {
        SubSliced::new(self.inner.main(), self.column_range.clone())
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.inner.preprocessed()
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.inner.public_values()
    }

    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        self.inner.is_transition_window(size)
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.inner.assert_zero(x.into());
    }
}
