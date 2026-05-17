use lib_q_stark_field::{
    Algebra,
    ExtensionField,
    Field,
    InjectiveMonomial,
};

use crate::symbolic::variable::SymbolicVariable;
use crate::symbolic::{
    SymLeaf,
    SymbolicExpr,
};

/// Leaf nodes for base-field symbolic expressions.
///
/// These represent the atomic building blocks of AIR constraint expressions:
/// trace column references, selectors, and field constants.
#[derive(Clone, Debug)]
pub enum BaseLeaf<F> {
    /// A reference to a trace column or public input.
    Variable(SymbolicVariable<F>),

    /// Selector evaluating to a non-zero value only on the first row.
    IsFirstRow,

    /// Selector evaluating to a non-zero value only on the last row.
    IsLastRow,

    /// Selector evaluating to zero only on the last row.
    IsTransition,

    /// A constant field element.
    Constant(F),
}

/// A symbolic expression tree for base-field AIR constraints.
pub type SymbolicExpression<F> = SymbolicExpr<BaseLeaf<F>>;

impl<F: Field> SymLeaf for BaseLeaf<F> {
    type F = F;

    const ZERO: Self = Self::Constant(F::ZERO);
    const ONE: Self = Self::Constant(F::ONE);
    const TWO: Self = Self::Constant(F::TWO);
    const NEG_ONE: Self = Self::Constant(F::NEG_ONE);

    fn degree_multiple(&self) -> usize {
        match self {
            Self::Variable(v) => v.degree_multiple(),
            Self::IsFirstRow | Self::IsLastRow => 1,
            Self::IsTransition | Self::Constant(_) => 0,
        }
    }

    fn as_const(&self) -> Option<&F> {
        match self {
            Self::Constant(c) => Some(c),
            _ => None,
        }
    }

    fn from_const(c: F) -> Self {
        Self::Constant(c)
    }
}

impl<F: Field, EF: ExtensionField<F>> From<SymbolicVariable<F>> for SymbolicExpression<EF> {
    fn from(var: SymbolicVariable<F>) -> Self {
        Self::Leaf(BaseLeaf::Variable(SymbolicVariable::new(
            var.entry, var.index,
        )))
    }
}

impl<F: Field, EF: ExtensionField<F>> From<F> for SymbolicExpression<EF> {
    fn from(f: F) -> Self {
        Self::Leaf(BaseLeaf::Constant(f.into()))
    }
}

impl<F: Field> Algebra<F> for SymbolicExpression<F> {}

impl<F: Field> Algebra<SymbolicVariable<F>> for SymbolicExpression<F> {}

impl<F: Field + InjectiveMonomial<N>, const N: u64> InjectiveMonomial<N> for SymbolicExpression<F> {}
