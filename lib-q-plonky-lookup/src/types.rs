//! Core lookup types and traits.
//!
//! These types define the data structures for lookup arguments in STARKs.

use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Neg;

use lib_q_stark_air::symbolic::SymbolicExpression;
use lib_q_stark_air::{
    Air,
    PermutationAirBuilder,
};
use lib_q_stark_field::Field;
use serde::{
    Deserialize,
    Serialize,
};

/// Defines errors that can occur during lookup verification or evaluation.
#[derive(Debug)]
pub enum LookupError {
    /// Error indicating that the global cumulative sum is incorrect.
    GlobalCumulativeMismatch(Option<String>),
    /// Global lookups are not supported in local evaluation.
    GlobalInLocalEval,
    /// Duplicate auxiliary column index across lookups.
    DuplicateAuxColumn(usize),
    /// Invalid symbolic variable (e.g. offset not 0 or 1).
    InvalidSymbolicVariable { entry: &'static str, offset: usize },
    /// Periodic columns are not supported in lookup resolution.
    UnsupportedPeriodicColumn,
}

/// Specifies whether a lookup is local to an AIR or part of a global interaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// A lookup where all entries are contained within a single AIR.
    Local,
    /// A lookup that spans multiple AIRs, identified by a unique interaction name.
    Global(String),
}

/// Indicates the direction of data flow in a global lookup.
#[derive(Clone, Copy)]
pub enum Direction {
    /// Indicates that elements are being sent (contributed) to the lookup.
    Send,
    /// Indicates that elements are being received (removed) from the lookup.
    Receive,
}

impl Direction {
    pub fn multiplicity<T: Neg<Output = T>>(&self, mult: T) -> T {
        match self {
            Self::Send => -mult,
            Self::Receive => mult,
        }
    }
}

/// Data required for global lookup arguments in a multi-STARK proof.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LookupData<F> {
    /// Name of the global lookup interaction.
    pub name: String,
    /// Index of the auxiliary column.
    pub aux_idx: usize,
    /// Expected cumulated value for a global lookup argument.
    pub expected_cumulated: F,
}

/// A type alias for a lookup input tuple.
///
/// Contains:
/// - a vector of symbolic expressions representing the elements,
/// - a symbolic expression representing the multiplicity,
/// - a direction indicating send or receive.
pub type LookupInput<F> = (Vec<SymbolicExpression<F>>, SymbolicExpression<F>, Direction);

/// A structure that holds the lookup data necessary to generate lookup contexts.
#[derive(Clone, Debug)]
pub struct Lookup<F: Field> {
    /// Type of lookup: local or global.
    pub kind: Kind,
    /// Elements being read. Each `Vec<SymbolicExpression<F>>` represents a tuple
    /// of elements bundled together for one lookup.
    pub element_exprs: Vec<Vec<SymbolicExpression<F>>>,
    /// Multiplicities for the elements.
    pub multiplicities_exprs: Vec<SymbolicExpression<F>>,
    /// The column index in the permutation trace for this lookup's running sum.
    pub columns: Vec<usize>,
}

impl<F: Field> Lookup<F> {
    pub const fn new(
        kind: Kind,
        element_exprs: Vec<Vec<SymbolicExpression<F>>>,
        multiplicities_exprs: Vec<SymbolicExpression<F>>,
        columns: Vec<usize>,
    ) -> Self {
        Self {
            kind,
            element_exprs,
            multiplicities_exprs,
            columns,
        }
    }
}

/// Trait for evaluating lookup constraints.
pub trait LookupEvaluator {
    /// Returns the number of auxiliary columns needed by this lookup protocol.
    fn num_aux_cols(&self) -> usize;

    /// Returns the number of challenges for each lookup argument.
    fn num_challenges(&self) -> usize;

    /// Evaluates a local lookup argument.
    fn eval_local_lookup<AB>(
        &self,
        builder: &mut AB,
        context: &Lookup<AB::F>,
    ) -> Result<(), LookupError>
    where
        AB: PermutationAirBuilder;

    /// Evaluates a global lookup update with an expected cumulated value.
    fn eval_global_update<AB>(
        &self,
        builder: &mut AB,
        context: &Lookup<AB::F>,
        expected_cumulated: AB::ExprEF,
    ) -> Result<(), LookupError>
    where
        AB: PermutationAirBuilder;

    /// Evaluates the lookup constraints for all provided contexts.
    fn eval_lookups<AB>(
        &self,
        builder: &mut AB,
        contexts: &[Lookup<AB::F>],
    ) -> Result<(), LookupError>
    where
        AB: PermutationAirBuilder,
    {
        let mut pv_idx = 0;
        for context in contexts.iter() {
            match &context.kind {
                Kind::Local => {
                    self.eval_local_lookup(builder, context)?;
                }
                Kind::Global(_) => {
                    let expected = builder.permutation_values()[pv_idx].clone();
                    pv_idx += 1;
                    self.eval_global_update(builder, context, expected.into())?;
                }
            }
        }
        if pv_idx != builder.permutation_values().len() {
            return Err(LookupError::GlobalCumulativeMismatch(Some(
                "permutation values count mismatch".into(),
            )));
        }
        Ok(())
    }
}

/// Extension trait for AIRs that use lookups.
pub trait LookupAir<F: Field> {
    /// Allocate auxiliary columns for a new lookup and return their indices.
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        Vec::new()
    }

    /// Return all lookups registered by this AIR.
    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        Vec::new()
    }

    /// Register a lookup to be used in this AIR.
    fn register_lookup(&mut self, kind: Kind, lookup_inputs: &[LookupInput<F>]) -> Lookup<F> {
        let (element_exprs, multiplicities_exprs) = lookup_inputs
            .iter()
            .map(|(elems, mult, dir)| {
                let multiplicity = dir.multiplicity(mult.clone());
                (elems.clone(), multiplicity)
            })
            .unzip();

        Lookup {
            kind,
            element_exprs,
            multiplicities_exprs,
            columns: self.add_lookup_columns(),
        }
    }
}

/// Extension of [`Air`] that adds lookup constraint evaluation.
///
/// Blanket-implemented for every type that implements [`Air`].
pub trait AirWithLookups<AB: PermutationAirBuilder>: Air<AB> {
    /// Evaluate both AIR constraints and lookup constraints.
    fn eval_with_lookups(
        &self,
        builder: &mut AB,
        lookups: &[Lookup<AB::F>],
        lookup_evaluator: &impl LookupEvaluator,
    ) -> Result<(), LookupError> {
        self.eval(builder);

        if !lookups.is_empty() {
            lookup_evaluator.eval_lookups(builder, lookups)?;
        }
        Ok(())
    }
}

impl<AB: PermutationAirBuilder, A: Air<AB>> AirWithLookups<AB> for A {}
