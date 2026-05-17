//! Symbolic expression types for AIR constraint representation.

pub mod expression;
mod variable;

use alloc::sync::Arc;
use core::iter::{
    Product,
    Sum,
};
use core::ops;

pub use expression::{
    BaseLeaf,
    SymbolicExpression,
};
use lib_q_stark_field::{
    Field,
    PrimeCharacteristicRing,
};
pub use variable::{
    BaseEntry,
    SymbolicVariable,
};

/// Properties that leaf nodes must provide for the generic expression tree.
pub trait SymLeaf: Clone + core::fmt::Debug {
    type F: Field;

    const ZERO: Self;
    const ONE: Self;
    const TWO: Self;
    const NEG_ONE: Self;

    fn degree_multiple(&self) -> usize;
    fn as_const(&self) -> Option<&Self::F>;
    fn from_const(c: Self::F) -> Self;
}

/// A symbolic expression tree, generic over its leaf type `A`.
#[derive(Clone, Debug)]
pub enum SymbolicExpr<A> {
    Leaf(A),
    Add {
        x: Arc<Self>,
        y: Arc<Self>,
        degree_multiple: usize,
    },
    Sub {
        x: Arc<Self>,
        y: Arc<Self>,
        degree_multiple: usize,
    },
    Neg {
        x: Arc<Self>,
        degree_multiple: usize,
    },
    Mul {
        x: Arc<Self>,
        y: Arc<Self>,
        degree_multiple: usize,
    },
}

impl<A: SymLeaf> SymbolicExpr<A> {
    pub fn degree_multiple(&self) -> usize {
        match self {
            Self::Leaf(a) => a.degree_multiple(),
            Self::Add {
                degree_multiple, ..
            } |
            Self::Sub {
                degree_multiple, ..
            } |
            Self::Neg {
                degree_multiple, ..
            } |
            Self::Mul {
                degree_multiple, ..
            } => *degree_multiple,
        }
    }

    fn as_const(&self) -> Option<&A::F> {
        match self {
            Self::Leaf(a) => a.as_const(),
            _ => None,
        }
    }

    fn sym_add(self, rhs: Self) -> Self {
        if let (Some(&a), Some(&b)) = (self.as_const(), rhs.as_const()) {
            return Self::Leaf(A::from_const(a + b));
        }
        if self.as_const().is_some_and(|c| c.is_zero()) {
            return rhs;
        }
        if rhs.as_const().is_some_and(|c| c.is_zero()) {
            return self;
        }
        let dm = self.degree_multiple().max(rhs.degree_multiple());
        Self::Add {
            x: Arc::new(self),
            y: Arc::new(rhs),
            degree_multiple: dm,
        }
    }

    fn sym_sub(self, rhs: Self) -> Self {
        if let (Some(&a), Some(&b)) = (self.as_const(), rhs.as_const()) {
            return Self::Leaf(A::from_const(a - b));
        }
        if self.as_const().is_some_and(|c| c.is_zero()) {
            return rhs.sym_neg();
        }
        if rhs.as_const().is_some_and(|c| c.is_zero()) {
            return self;
        }
        let dm = self.degree_multiple().max(rhs.degree_multiple());
        Self::Sub {
            x: Arc::new(self),
            y: Arc::new(rhs),
            degree_multiple: dm,
        }
    }

    fn sym_neg(self) -> Self {
        if let Some(&c) = self.as_const() {
            return Self::Leaf(A::from_const(-c));
        }
        let dm = self.degree_multiple();
        Self::Neg {
            x: Arc::new(self),
            degree_multiple: dm,
        }
    }

    fn sym_mul(self, rhs: Self) -> Self {
        if let (Some(&a), Some(&b)) = (self.as_const(), rhs.as_const()) {
            return Self::Leaf(A::from_const(a * b));
        }
        if self.as_const().is_some_and(|c| c.is_zero()) ||
            rhs.as_const().is_some_and(|c| c.is_zero())
        {
            return Self::Leaf(A::from_const(A::F::ZERO));
        }
        if self.as_const().is_some_and(|c| c.is_one()) {
            return rhs;
        }
        if rhs.as_const().is_some_and(|c| c.is_one()) {
            return self;
        }
        let dm = self.degree_multiple() + rhs.degree_multiple();
        Self::Mul {
            x: Arc::new(self),
            y: Arc::new(rhs),
            degree_multiple: dm,
        }
    }
}

impl<A: SymLeaf> PrimeCharacteristicRing for SymbolicExpr<A> {
    type PrimeSubfield = <A::F as PrimeCharacteristicRing>::PrimeSubfield;

    const ZERO: Self = Self::Leaf(A::ZERO);
    const ONE: Self = Self::Leaf(A::ONE);
    const TWO: Self = Self::Leaf(A::TWO);
    const NEG_ONE: Self = Self::Leaf(A::NEG_ONE);

    #[inline]
    fn from_prime_subfield(f: Self::PrimeSubfield) -> Self {
        Self::Leaf(A::from_const(A::F::from_prime_subfield(f)))
    }
}

impl<A: SymLeaf> Default for SymbolicExpr<A> {
    fn default() -> Self {
        Self::ZERO
    }
}

impl<A: SymLeaf, T: Into<Self>> ops::Add<T> for SymbolicExpr<A> {
    type Output = Self;
    fn add(self, rhs: T) -> Self {
        self.sym_add(rhs.into())
    }
}

impl<A: SymLeaf, T: Into<Self>> ops::Sub<T> for SymbolicExpr<A> {
    type Output = Self;
    fn sub(self, rhs: T) -> Self {
        self.sym_sub(rhs.into())
    }
}

impl<A: SymLeaf> ops::Neg for SymbolicExpr<A> {
    type Output = Self;
    fn neg(self) -> Self {
        self.sym_neg()
    }
}

impl<A: SymLeaf, T: Into<Self>> ops::Mul<T> for SymbolicExpr<A> {
    type Output = Self;
    fn mul(self, rhs: T) -> Self {
        self.sym_mul(rhs.into())
    }
}

impl<A: SymLeaf, T: Into<Self>> ops::AddAssign<T> for SymbolicExpr<A> {
    fn add_assign(&mut self, rhs: T) {
        *self = self.clone() + rhs.into();
    }
}

impl<A: SymLeaf, T: Into<Self>> ops::SubAssign<T> for SymbolicExpr<A> {
    fn sub_assign(&mut self, rhs: T) {
        *self = self.clone() - rhs.into();
    }
}

impl<A: SymLeaf, T: Into<Self>> ops::MulAssign<T> for SymbolicExpr<A> {
    fn mul_assign(&mut self, rhs: T) {
        *self = self.clone() * rhs.into();
    }
}

impl<A: SymLeaf, T: Into<Self>> Sum<T> for SymbolicExpr<A> {
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.map(Into::into)
            .reduce(|a, b| a + b)
            .unwrap_or(Self::ZERO)
    }
}

impl<A: SymLeaf, T: Into<Self>> Product<T> for SymbolicExpr<A> {
    fn product<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.map(Into::into)
            .reduce(|a, b| a * b)
            .unwrap_or(Self::ONE)
    }
}

impl<F: Field, T: Into<SymbolicExpression<F>>> ops::Add<T> for SymbolicVariable<F> {
    type Output = SymbolicExpression<F>;
    fn add(self, rhs: T) -> Self::Output {
        Self::Output::from(self) + rhs.into()
    }
}

impl<F: Field, T: Into<SymbolicExpression<F>>> ops::Sub<T> for SymbolicVariable<F> {
    type Output = SymbolicExpression<F>;
    fn sub(self, rhs: T) -> Self::Output {
        Self::Output::from(self) - rhs.into()
    }
}

impl<F: Field, T: Into<SymbolicExpression<F>>> ops::Mul<T> for SymbolicVariable<F> {
    type Output = SymbolicExpression<F>;
    fn mul(self, rhs: T) -> Self::Output {
        Self::Output::from(self) * rhs.into()
    }
}
