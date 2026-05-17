//! Lookup gadget trait and trace builder for lookup argument generation.

use lib_q_stark_air::symbolic::SymbolicExpression;
use lib_q_stark_air::symbolic::expression::BaseLeaf;
use lib_q_stark_air::{
    AirBuilder,
    ExtensionBuilder,
    PermutationAirBuilder,
    RowWindow,
    WindowAccess,
};
use lib_q_stark_field::{
    ExtensionField,
    Field,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_matrix::stack::ViewPair;
use tracing::warn;

pub use crate::types::{
    Direction,
    Kind,
    Lookup,
    LookupData,
    LookupError,
    LookupEvaluator,
    LookupInput,
};

/// A trait for lookup argument gadgets.
pub trait LookupGadget: LookupEvaluator {
    /// Generates the permutation matrix for the lookup argument.
    fn generate_permutation<F: Field, EF: ExtensionField<F>>(
        &self,
        main: &RowMajorMatrix<F>,
        preprocessed: &Option<RowMajorMatrix<F>>,
        public_values: &[F],
        lookups: &[Lookup<F>],
        lookup_data: &mut [LookupData<EF>],
        permutation_challenges: &[EF],
    ) -> RowMajorMatrix<EF>;

    /// Evaluates the final cumulated value over all AIRs involved in the interaction.
    fn verify_global_final_value<EF: Field>(
        &self,
        all_expected_cumulated: &[EF],
    ) -> Result<(), LookupError>;

    /// Computes the polynomial degree of a lookup transition constraint.
    fn constraint_degree<F: Field>(&self, context: &Lookup<F>) -> usize;
}

/// A builder to generate lookup traces from the main trace, public values, and
/// permutation challenges.
pub struct LookupTraceBuilder<'a, F: Field, EF: ExtensionField<F>> {
    main: ViewPair<'a, F>,
    preprocessed: RowWindow<'a, F>,
    public_values: &'a [F],
    permutation_challenges: &'a [EF],
    height: usize,
    row: usize,
}

impl<'a, F: Field, EF: ExtensionField<F>> LookupTraceBuilder<'a, F, EF> {
    pub fn new(
        main: ViewPair<'a, F>,
        preprocessed: ViewPair<'a, F>,
        public_values: &'a [F],
        permutation_challenges: &'a [EF],
        height: usize,
        row: usize,
    ) -> Self {
        Self {
            main,
            preprocessed: RowWindow::from_two_rows(
                preprocessed.top.values,
                preprocessed.bottom.values,
            ),
            public_values,
            permutation_challenges,
            height,
            row,
        }
    }
}

impl<'a, F: Field, EF: ExtensionField<F>> AirBuilder for LookupTraceBuilder<'a, F, EF> {
    type F = F;
    type Expr = F;
    type Var = F;
    type PreprocessedWindow = RowWindow<'a, F>;
    type MainWindow = RowWindow<'a, F>;
    type PublicVar = F;

    #[inline]
    fn main(&self) -> Self::MainWindow {
        RowWindow::from_two_rows(self.main.top.values, self.main.bottom.values)
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed
    }

    #[inline]
    fn is_first_row(&self) -> Self::Expr {
        Self::F::from_bool(self.row == 0)
    }

    #[inline]
    fn is_last_row(&self) -> Self::Expr {
        Self::F::from_bool(self.row + 1 == self.height)
    }

    #[inline]
    fn is_transition_window(&self, size: usize) -> Self::Expr {
        assert!(size <= 2, "only two-row windows are supported, got {size}");
        Self::F::from_bool(self.row + 1 < self.height)
    }

    #[inline]
    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        assert!(x.into() == Self::F::ZERO);
    }

    #[inline]
    fn assert_zeros<const N: usize, I: Into<Self::Expr>>(&mut self, array: [I; N]) {
        for item in array {
            assert!(item.into() == Self::F::ZERO);
        }
    }

    #[inline]
    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

impl<'a, F: Field, EF: ExtensionField<F>> ExtensionBuilder for LookupTraceBuilder<'a, F, EF> {
    type EF = EF;
    type ExprEF = EF;
    type VarEF = EF;

    fn assert_zero_ext<I: Into<Self::ExprEF>>(&mut self, x: I) {
        assert!(x.into() == EF::ZERO);
    }
}

impl<'a, F: Field, EF: ExtensionField<F>> PermutationAirBuilder for LookupTraceBuilder<'a, F, EF> {
    type MP = RowWindow<'a, EF>;
    type RandomVar = EF;
    type PermutationVar = EF;

    fn permutation(&self) -> Self::MP {
        panic!("should not access the permutation matrix while building it");
    }

    fn permutation_randomness(&self) -> &[EF] {
        self.permutation_challenges
    }

    fn permutation_values(&self) -> &[EF] {
        &[]
    }
}

/// Evaluates a symbolic expression in the context of an AIR builder.
///
/// Converts `SymbolicExpression<F>` to the builder's expression type `AB::Expr`.
pub fn symbolic_to_expr<AB>(
    builder: &AB,
    expr: &SymbolicExpression<AB::F>,
) -> Result<AB::Expr, LookupError>
where
    AB: AirBuilder + PermutationAirBuilder,
{
    use lib_q_stark_air::symbolic::{
        BaseEntry,
        SymbolicExpr,
    };

    match expr {
        SymbolicExpr::Leaf(leaf) => match leaf {
            BaseLeaf::Variable(v) => match &v.entry {
                BaseEntry::Main { offset } => {
                    let main = builder.main();
                    match offset {
                        0 => main
                            .current(v.index)
                            .ok_or(LookupError::InvalidSymbolicVariable {
                                entry: "main",
                                offset: *offset,
                            })
                            .map(|e| e.into()),
                        1 => main
                            .next(v.index)
                            .ok_or(LookupError::InvalidSymbolicVariable {
                                entry: "main",
                                offset: *offset,
                            })
                            .map(|e| e.into()),
                        _ => Err(LookupError::InvalidSymbolicVariable {
                            entry: "main",
                            offset: *offset,
                        }),
                    }
                }
                BaseEntry::Periodic => Err(LookupError::UnsupportedPeriodicColumn),
                BaseEntry::Public => Ok(builder.public_values()[v.index].into()),
                BaseEntry::Preprocessed { offset } => {
                    let prep = builder.preprocessed();
                    match offset {
                        0 => prep
                            .current(v.index)
                            .ok_or(LookupError::InvalidSymbolicVariable {
                                entry: "preprocessed",
                                offset: *offset,
                            })
                            .map(|e| e.into()),
                        1 => prep
                            .next(v.index)
                            .ok_or(LookupError::InvalidSymbolicVariable {
                                entry: "preprocessed",
                                offset: *offset,
                            })
                            .map(|e| e.into()),
                        _ => Err(LookupError::InvalidSymbolicVariable {
                            entry: "preprocessed",
                            offset: *offset,
                        }),
                    }
                }
            },
            BaseLeaf::IsFirstRow => {
                warn!("IsFirstRow is not normalized");
                Ok(builder.is_first_row())
            }
            BaseLeaf::IsLastRow => {
                warn!("IsLastRow is not normalized");
                Ok(builder.is_last_row())
            }
            BaseLeaf::IsTransition => {
                warn!("IsTransition is not normalized");
                Ok(builder.is_transition_window(2))
            }
            BaseLeaf::Constant(c) => Ok(AB::Expr::from(*c)),
        },
        SymbolicExpr::Add { x, y, .. } => {
            Ok(symbolic_to_expr(builder, x)? + symbolic_to_expr(builder, y)?)
        }
        SymbolicExpr::Sub { x, y, .. } => {
            Ok(symbolic_to_expr(builder, x)? - symbolic_to_expr(builder, y)?)
        }
        SymbolicExpr::Neg { x, .. } => Ok(-symbolic_to_expr(builder, x)?),
        SymbolicExpr::Mul { x, y, .. } => {
            Ok(symbolic_to_expr(builder, x)? * symbolic_to_expr(builder, y)?)
        }
    }
}
