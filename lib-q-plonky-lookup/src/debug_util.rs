//! Debug helpers to inspect lookup witnesses.
//!
//! They recompute every lookup tuple from the raw traces and assert that the
//! resulting multiset is balanced (total multiplicity 0). Any mismatch will
//! be reported with its location.

use alloc::collections::BTreeMap;
use alloc::string::{
    String,
    ToString,
};
use alloc::vec::Vec;
use alloc::{
    format,
    vec,
};

use lib_q_stark_air::{
    AirBuilder,
    PermutationAirBuilder,
    RowWindow,
};
use lib_q_stark_field::Field;
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::{
    RowMajorMatrix,
    RowMajorMatrixView,
};
use lib_q_stark_matrix::stack::VerticalPair;

use crate::lookup_traits::{
    Kind,
    Lookup,
    symbolic_to_expr,
};

/// All inputs required to replay lookup evaluations for one AIR instance.
pub struct LookupDebugInstance<'a, F: Field> {
    pub main_trace: &'a RowMajorMatrix<F>,
    pub preprocessed_trace: &'a Option<RowMajorMatrix<F>>,
    pub public_values: &'a [F],
    pub lookups: &'a [Lookup<F>],
    pub permutation_challenges: &'a [F],
}

/// Location information used in debug messages.
#[allow(unused)]
#[derive(Clone, Debug)]
struct Location {
    instance: usize,
    lookup: usize,
    row: usize,
}

/// Accumulates tuples and their multiplicities, tracking where each was seen.
#[derive(Default)]
struct MultiSet<F: Field> {
    entries: BTreeMap<Vec<String>, (F, Vec<Location>)>,
}

impl<F: Field> MultiSet<F> {
    fn add(&mut self, key: Vec<F>, multiplicity: F, location: Location) {
        if multiplicity.is_zero() {
            return;
        }

        let string_key: Vec<String> = key.iter().map(|v| v.to_string()).collect();

        self.entries
            .entry(string_key)
            .and_modify(|(total, locations)| {
                *total += multiplicity;
                locations.push(location.clone());
            })
            .or_insert_with(|| (multiplicity, vec![location]));
    }

    fn assert_empty(&self, label: &str) {
        for (key, (total, locations)) in &self.entries {
            if !total.is_zero() {
                panic!(
                    "Lookup mismatch ({label}): tuple {:?} has net multiplicity {:?}. Locations: {:?}",
                    key, total, locations
                );
            }
        }
    }
}

/// Recompute all lookup tuples/multiplicities from the traces and assert that
/// every lookup represents a balanced multiset equality.
///
/// - Local lookups are checked independently per instance.
/// - Global lookups are grouped by interaction name; every tuple's total
///   multiplicity across all participants must be zero.
pub fn check_lookups<F: Field>(instances: &[LookupDebugInstance<'_, F>]) {
    for (instance_idx, instance) in instances.iter().enumerate() {
        for (lookup_idx, lookup) in instance.lookups.iter().enumerate() {
            if matches!(lookup.kind, Kind::Local) {
                let mut multiset = MultiSet::default();
                accumulate_lookup(instance_idx, lookup_idx, instance, lookup, &mut multiset);
                multiset.assert_empty(&format!(
                    "instance {instance_idx} local lookup {lookup_idx}"
                ));
            }
        }
    }

    let mut global_sets: Vec<(String, MultiSet<F>)> = Vec::new();
    let mut global_index: BTreeMap<String, usize> = BTreeMap::new();

    for (instance_idx, instance) in instances.iter().enumerate() {
        for (lookup_idx, lookup) in instance.lookups.iter().enumerate() {
            if let Kind::Global(name) = &lookup.kind {
                let idx = *global_index.entry(name.clone()).or_insert_with(|| {
                    global_sets.push((name.clone(), MultiSet::default()));
                    global_sets.len() - 1
                });

                accumulate_lookup(
                    instance_idx,
                    lookup_idx,
                    instance,
                    lookup,
                    &mut global_sets[idx].1,
                );
            }
        }
    }

    for (name, multiset) in global_sets {
        multiset.assert_empty(&format!("global lookup '{name}'"));
    }
}

fn accumulate_lookup<F: Field>(
    instance_idx: usize,
    lookup_idx: usize,
    instance: &LookupDebugInstance<'_, F>,
    lookup: &Lookup<F>,
    multiset: &mut MultiSet<F>,
) {
    let height = instance.main_trace.height();

    for row in 0..height {
        let local_main = instance.main_trace.row_slice(row).unwrap();
        let next_main = instance.main_trace.row_slice((row + 1) % height).unwrap();
        let main_rows = VerticalPair::new(
            RowMajorMatrixView::new_row(&*local_main),
            RowMajorMatrixView::new_row(&*next_main),
        );

        let preprocessed_rows_data = instance.preprocessed_trace.as_ref().map(|prep| {
            (
                prep.row_slice(row).unwrap(),
                prep.row_slice((row + 1) % height).unwrap(),
            )
        });
        let preprocessed_rows = match preprocessed_rows_data.as_ref() {
            Some((prep_local, prep_next)) => VerticalPair::new(
                RowMajorMatrixView::new_row(&**prep_local),
                RowMajorMatrixView::new_row(&**prep_next),
            ),
            None => VerticalPair::new(
                RowMajorMatrixView::new(&[], 0),
                RowMajorMatrixView::new(&[], 0),
            ),
        };

        let builder = MiniLookupBuilder {
            main: main_rows,
            preprocessed: RowWindow::from_two_rows(
                preprocessed_rows.top.values,
                preprocessed_rows.bottom.values,
            ),
            public_values: instance.public_values,
            permutation_challenges: instance.permutation_challenges,
            row,
            height,
        };

        for (tuple_idx, elements) in lookup.element_exprs.iter().enumerate() {
            let key = elements
                .iter()
                .map(|expr| symbolic_to_expr(&builder, expr).expect("symbolic resolution"))
                .collect::<Vec<_>>();

            let multiplicity = symbolic_to_expr(&builder, &lookup.multiplicities_exprs[tuple_idx])
                .expect("symbolic resolution");

            multiset.add(
                key,
                multiplicity,
                Location {
                    instance: instance_idx,
                    lookup: lookup_idx,
                    row,
                },
            );
        }
    }
}

struct MiniLookupBuilder<'a, F: Field> {
    main: VerticalPair<RowMajorMatrixView<'a, F>, RowMajorMatrixView<'a, F>>,
    preprocessed: RowWindow<'a, F>,
    public_values: &'a [F],
    permutation_challenges: &'a [F],
    row: usize,
    height: usize,
}

impl<'a, F: Field> AirBuilder for MiniLookupBuilder<'a, F> {
    type F = F;
    type Expr = F;
    type Var = F;
    type PreprocessedWindow = RowWindow<'a, F>;
    type MainWindow = RowWindow<'a, F>;
    type PublicVar = F;

    fn main(&self) -> Self::MainWindow {
        RowWindow::from_two_rows(self.main.top.values, self.main.bottom.values)
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed
    }

    fn is_first_row(&self) -> Self::Expr {
        F::from_bool(self.row == 0)
    }

    fn is_last_row(&self) -> Self::Expr {
        F::from_bool(self.row + 1 == self.height)
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        assert!(size <= 2, "only two-row windows are supported, got {size}");
        F::from_bool(self.row + 1 < self.height)
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, _x: I) {}

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

impl<F: Field> lib_q_stark_air::ExtensionBuilder for MiniLookupBuilder<'_, F> {
    type EF = F;
    type ExprEF = F;
    type VarEF = F;

    fn assert_zero_ext<I: Into<Self::ExprEF>>(&mut self, _x: I) {}
}

impl<'a, F: Field> PermutationAirBuilder for MiniLookupBuilder<'a, F> {
    type MP = RowWindow<'a, F>;
    type RandomVar = F;
    type PermutationVar = F;

    fn permutation(&self) -> Self::MP {
        RowWindow::from_two_rows(&[], &[])
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.permutation_challenges
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        &[]
    }
}
