use core::marker::PhantomData;
use core::ops::Range;

use lib_q_stark_air::{
    AirBuilder,
    BaseAir,
    WindowAccess,
};

/// A column-restricted view over a trace window.
///
/// Wraps an inner window and exposes only the columns within
/// the given range. Lets a sub-AIR see a contiguous subset
/// of the parent trace without copying data.
#[derive(Clone)]
pub struct SubSliced<W, T> {
    window: W,
    range: Range<usize>,
    _marker: PhantomData<T>,
}

impl<W: WindowAccess<T>, T> WindowAccess<T> for SubSliced<W, T> {
    #[inline]
    fn current_slice(&self) -> &[T] {
        &self.window.current_slice()[self.range.clone()]
    }

    #[inline]
    fn next_slice(&self) -> &[T] {
        &self.window.next_slice()[self.range.clone()]
    }
}

/// Evaluates a sub-AIR against a restricted slice of the parent trace.
pub struct SubAirBuilder<'a, AB: AirBuilder, SubAir: BaseAir<AB::F>, T> {
    inner: &'a mut AB,
    column_range: Range<usize>,
    _phantom: PhantomData<(SubAir, T)>,
}

impl<'a, AB: AirBuilder, SubAir: BaseAir<AB::F>, T> SubAirBuilder<'a, AB, SubAir, T> {
    #[must_use]
    pub const fn new(inner: &'a mut AB, column_range: Range<usize>) -> Self {
        Self {
            inner,
            column_range,
            _phantom: PhantomData,
        }
    }
}

impl<AB: AirBuilder, SubAir: BaseAir<AB::F>, F> AirBuilder for SubAirBuilder<'_, AB, SubAir, F> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type PreprocessedWindow = AB::PreprocessedWindow;
    type MainWindow = SubSliced<AB::MainWindow, AB::Var>;
    type PublicVar = AB::PublicVar;

    fn main(&self) -> Self::MainWindow {
        SubSliced {
            window: self.inner.main(),
            range: self.column_range.clone(),
            _marker: PhantomData,
        }
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

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        assert!(size <= 2, "only two-row windows are supported, got {size}");
        self.inner.is_transition()
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.inner.assert_zero(x.into());
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.inner.public_values()
    }
}
