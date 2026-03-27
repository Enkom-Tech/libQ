//! Debug-only constraint checker for batch STARK.
//!
//! When built with `debug_assertions`, this module provides a constraint checker
//! that walks the trace row-by-row, evaluates all AIR and lookup constraints,
//! and panics with detailed violation information on the first failing row.

#![cfg(debug_assertions)]

use alloc::vec;
use alloc::vec::Vec;
use core::ops::Deref;

use lib_q_plonky_lookup::AirWithLookups;
use lib_q_plonky_lookup::lookup_traits::{
    Lookup,
    LookupGadget,
};
use lib_q_stark_air::{
    AirBuilder,
    ExtensionBuilder,
    PermutationAirBuilder,
    RowWindow,
};
use lib_q_stark_field::{
    ExtensionField,
    Field,
};
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;

/// A single constraint violation recorded during debug evaluation.
#[derive(Debug, Clone)]
pub struct ConstraintFailure {
    /// Zero-based index of the trace row where the violation occurred.
    pub row: usize,
    /// Zero-based index of the constraint (in evaluation order) that was violated.
    pub constraint: usize,
}

/// Debug constraint builder that evaluates an AIR over concrete field values,
/// records every violation instead of panicking immediately, and supports
/// permutation/lookup arguments.
#[derive(Debug)]
pub struct DebugConstraintBuilder<'a, F: Field, EF: ExtensionField<F>> {
    row_index: usize,
    constraint_index: usize,
    failures: Vec<ConstraintFailure>,
    main: RowWindow<'a, F>,
    preprocessed: RowWindow<'a, F>,
    public_values: &'a [F],
    is_first_row: F,
    is_last_row: F,
    is_transition: F,
    permutation: Option<RowWindow<'a, EF>>,
    permutation_challenges: &'a [EF],
    permutation_values: &'a [EF],
}

impl<'a, F: Field, EF: ExtensionField<F>> DebugConstraintBuilder<'a, F, EF> {
    /// Build a constraint checker without permutation data (AIR-only).
    pub fn new(
        row_index: usize,
        main: RowWindow<'a, F>,
        preprocessed: RowWindow<'a, F>,
        public_values: &'a [F],
        is_first_row: F,
        is_last_row: F,
        is_transition: F,
    ) -> Self {
        Self {
            row_index,
            constraint_index: 0,
            failures: Vec::new(),
            main,
            preprocessed,
            public_values,
            is_first_row,
            is_last_row,
            is_transition,
            permutation: None,
            permutation_challenges: &[],
            permutation_values: &[],
        }
    }

    /// Build a constraint checker with permutation data (for lookups).
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_permutation(
        row_index: usize,
        main: RowWindow<'a, F>,
        preprocessed: RowWindow<'a, F>,
        public_values: &'a [F],
        is_first_row: F,
        is_last_row: F,
        is_transition: F,
        permutation: RowWindow<'a, EF>,
        permutation_challenges: &'a [EF],
        permutation_values: &'a [EF],
    ) -> Self {
        Self {
            row_index,
            constraint_index: 0,
            failures: Vec::new(),
            main,
            preprocessed,
            public_values,
            is_first_row,
            is_last_row,
            is_transition,
            permutation: Some(permutation),
            permutation_challenges,
            permutation_values,
        }
    }

    pub const fn has_failures(&self) -> bool {
        !self.failures.is_empty()
    }

    pub fn failures(&self) -> &[ConstraintFailure] {
        &self.failures
    }
}

impl<'a, F: Field, EF: ExtensionField<F>> AirBuilder for DebugConstraintBuilder<'a, F, EF> {
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
        if x.into() != F::ZERO {
            self.failures.push(ConstraintFailure {
                row: self.row_index,
                constraint: self.constraint_index,
            });
        }
        self.constraint_index += 1;
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

impl<F: Field, EF: ExtensionField<F>> ExtensionBuilder for DebugConstraintBuilder<'_, F, EF> {
    type EF = EF;
    type ExprEF = EF;
    type VarEF = EF;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        if x.into() != EF::ZERO {
            self.failures.push(ConstraintFailure {
                row: self.row_index,
                constraint: self.constraint_index,
            });
        }
        self.constraint_index += 1;
    }
}

impl<'a, F: Field, EF: ExtensionField<F>> PermutationAirBuilder
    for DebugConstraintBuilder<'a, F, EF>
{
    type MP = RowWindow<'a, EF>;
    type RandomVar = EF;
    type PermutationVar = EF;

    fn permutation(&self) -> Self::MP {
        self.permutation
            .expect("permutation() called on a builder created without permutation data; use new_with_permutation()")
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.permutation_challenges
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        self.permutation_values
    }
}

/// Type alias for lookup constraint checking inputs.
#[allow(unused)]
type LookupConstraintsInputs<'a, F, LG> = (&'a [Lookup<F>], &'a LG);

/// Runs constraint checks using the given AIR and trace matrices.
///
/// Iterates over every row in `main`, provides current and next row (with wraparound)
/// to the AIR, injects public values, and when lookups are present uses the
/// permutation matrix and challenges. Collects all constraint failures for the
/// first failing row, then panics with a summary of violated constraint indices.
///
/// Only compiled when `debug_assertions` is enabled.
#[allow(unused)]
#[allow(clippy::too_many_arguments)]
pub fn check_constraints<F, EF, A, LG>(
    air: &A,
    main: &RowMajorMatrix<F>,
    preprocessed: Option<&RowMajorMatrix<F>>,
    permutation: &RowMajorMatrix<EF>,
    permutation_challenges: &[EF],
    permutation_values: &[EF],
    public_values: &[F],
    lookups: &[Lookup<F>],
    lookup_gadget: &LG,
) where
    F: Field,
    EF: ExtensionField<F>,
    A: for<'b> AirWithLookups<DebugConstraintBuilder<'b, F, EF>>,
    LG: LookupGadget,
{
    let height = main.height();

    for row_index in 0..height {
        let row_index_next = (row_index + 1) % height;

        let main_local_guard = main.row_slice(row_index).expect("row_index in bounds");
        let main_next_guard = main.row_slice(row_index_next).expect("next row in bounds");
        let main_window = RowWindow::from_two_rows(&main_local_guard, &main_next_guard);

        let prep_row0;
        let prep_row1;
        let preprocessed_window = match preprocessed {
            Some(prep) => {
                let a = prep.row_slice(row_index).expect("row_index in bounds");
                let b = prep.row_slice(row_index_next).expect("next row in bounds");
                prep_row0 = a.deref().to_vec();
                prep_row1 = b.deref().to_vec();
                RowWindow::from_two_rows(&prep_row0, &prep_row1)
            }
            None => {
                prep_row0 = vec![];
                prep_row1 = vec![];
                RowWindow::from_two_rows(&prep_row0, &prep_row1)
            }
        };

        let perm_row0;
        let perm_row1;
        let permutation_window = if permutation.height() > 0 {
            let a = permutation
                .row_slice(row_index)
                .expect("row_index in bounds");
            let b = permutation
                .row_slice(row_index_next)
                .expect("next row in bounds");
            perm_row0 = a.deref().to_vec();
            perm_row1 = b.deref().to_vec();
            RowWindow::from_two_rows(&perm_row0, &perm_row1)
        } else {
            perm_row0 = vec![];
            perm_row1 = vec![];
            RowWindow::from_two_rows(&perm_row0, &perm_row1)
        };

        let mut builder = if lookups.is_empty() {
            DebugConstraintBuilder::new(
                row_index,
                main_window,
                preprocessed_window,
                public_values,
                F::from_bool(row_index == 0),
                F::from_bool(row_index == height - 1),
                F::from_bool(row_index != height - 1),
            )
        } else {
            DebugConstraintBuilder::new_with_permutation(
                row_index,
                main_window,
                preprocessed_window,
                public_values,
                F::from_bool(row_index == 0),
                F::from_bool(row_index == height - 1),
                F::from_bool(row_index != height - 1),
                permutation_window,
                permutation_challenges,
                permutation_values,
            )
        };

        let _ = air.eval_with_lookups(&mut builder, lookups, lookup_gadget);

        if builder.has_failures() {
            let indices: Vec<usize> = builder.failures().iter().map(|f| f.constraint).collect();
            panic!(
                "constraints not satisfied on row {row_index}: \
                 failed constraint indices = {indices:?}"
            );
        }
    }
}
