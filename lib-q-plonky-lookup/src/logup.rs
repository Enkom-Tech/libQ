//! Core LogUp Implementation
//!
//! ## Mathematical Foundation
//!
//! LogUp transforms the standard lookup equation:
//! ```text
//! ∏(α - a_i)^(m_i) = ∏(α - b_j)^(m'_j)
//! ```
//!
//! Into an equivalent sum-based form using logarithmic derivatives:
//! ```text
//! ∑(m_i/(α - a_i)) = ∑(m'_j/(α - b_j))
//! ```
//!
//! Where:
//! - `α` is a random challenge
//! - `m_i, m'_j` are multiplicities (how many times each element appears)
//! - The transformation eliminates expensive exponentiation operations

use alloc::vec;
use alloc::vec::Vec;

use lib_q_stark_air::{
    ExtensionBuilder,
    PermutationAirBuilder,
    WindowAccess,
};
use lib_q_stark_field::{
    ExtensionField,
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::{
    RowMajorMatrix,
    RowMajorMatrixView,
};
use lib_q_stark_matrix::stack::VerticalPair;
use tracing::instrument;

use crate::lookup_traits::{
    Kind,
    Lookup,
    LookupData,
    LookupGadget,
    LookupTraceBuilder,
    symbolic_to_expr,
};
use crate::types::{
    LookupError,
    LookupEvaluator,
};

/// Core LogUp gadget implementing lookup arguments via logarithmic derivatives.
///
/// Uses a running sum auxiliary column `s` that accumulates:
/// ```text
/// s[i+1] = s[i] + ∑(m_a/(α - a)) - ∑(m_b/(α - b))
/// ```
///
/// Constraints:
/// - **Initial**: `s[0] = 0`
/// - **Transition**: `s[i+1] = s[i] + contribution[i]`
/// - **Final**: `s[n-1] + contribution[n-1] = 0`
#[derive(Debug, Clone, Default)]
pub struct LogUpGadget;

impl LogUpGadget {
    pub const fn new() -> Self {
        Self {}
    }

    /// Computes the combined elements for each tuple using the challenge `beta`:
    /// `combined_elements[i] = ∑elements[i][n-j] * β^j`
    fn combine_elements<AB, E>(
        &self,
        elements: &[Vec<E>],
        alpha: &AB::ExprEF,
        beta: &AB::ExprEF,
    ) -> Vec<AB::ExprEF>
    where
        AB: PermutationAirBuilder,
        E: Into<AB::ExprEF> + Clone,
    {
        elements
            .iter()
            .map(|elts| {
                let combined_elt = elts.iter().fold(AB::ExprEF::ZERO, |acc, elt| {
                    elt.clone().into() + acc * beta.clone()
                });
                alpha.clone() - combined_elt
            })
            .collect()
    }

    /// Computes the numerator and denominator of the fraction:
    /// `∑(m_i / (α - combined_elements[i]))`
    pub(crate) fn compute_combined_sum_terms<AB, E, M>(
        &self,
        elements: &[Vec<E>],
        multiplicities: &[M],
        alpha: &AB::ExprEF,
        beta: &AB::ExprEF,
    ) -> (AB::ExprEF, AB::ExprEF)
    where
        AB: PermutationAirBuilder,
        E: Into<AB::ExprEF> + Clone,
        M: Into<AB::ExprEF> + Clone,
    {
        if elements.is_empty() {
            return (AB::ExprEF::ZERO, AB::ExprEF::ONE);
        }

        let n = elements.len();

        let terms = self.combine_elements::<AB, E>(elements, alpha, beta);

        // Build prefix products: pref[i] = ∏_{j=0}^{i-1}(α - e_j)
        let mut pref = Vec::with_capacity(n + 1);
        pref.push(AB::ExprEF::ONE);
        for t in &terms {
            pref.push(pref.last().unwrap().clone() * t.clone());
        }

        // Build suffix products: suff[i] = ∏_{j=i}^{n-1}(α - e_j)
        let mut suff = vec![AB::ExprEF::ONE; n + 1];
        for i in (0..n).rev() {
            suff[i] = suff[i + 1].clone() * terms[i].clone();
        }

        let common_denominator = pref[n].clone();

        // Numerator: ∑(m_i * ∏_{j≠i}(α - e_j))
        let numerator = (0..n).fold(AB::ExprEF::ZERO, |acc, i| {
            acc + multiplicities[i].clone().into() * pref[i].clone() * suff[i + 1].clone()
        });

        (numerator, common_denominator)
    }

    /// Evaluates the transition and boundary constraints for a lookup argument.
    fn eval_update<AB>(
        &self,
        builder: &mut AB,
        context: &Lookup<AB::F>,
        opt_expected_cumulated: Option<AB::ExprEF>,
    ) -> Result<(), LookupError>
    where
        AB: PermutationAirBuilder,
    {
        let Lookup {
            kind,
            element_exprs,
            multiplicities_exprs,
            columns,
        } = context;

        assert!(
            element_exprs.len() == multiplicities_exprs.len(),
            "Mismatched lengths: elements and multiplicities must have same length"
        );
        assert_eq!(
            columns.len(),
            self.num_aux_cols(),
            "There is exactly one auxiliary column for LogUp"
        );
        let column = columns[0];

        let elements = element_exprs
            .iter()
            .map(|exprs| {
                exprs
                    .iter()
                    .map(|expr| symbolic_to_expr(builder, expr).map(|e| e.into()))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        let multiplicities = multiplicities_exprs
            .iter()
            .map(|expr| symbolic_to_expr(builder, expr).map(|e| e.into()))
            .collect::<Result<Vec<_>, _>>()?;

        let permutation = builder.permutation();

        let permutation_challenges = builder.permutation_randomness();

        assert!(
            permutation_challenges.len() >= self.num_challenges() * (column + 1),
            "Insufficient permutation challenges"
        );

        let alpha = permutation_challenges[self.num_challenges() * column];
        let beta = permutation_challenges[self.num_challenges() * column + 1];

        assert!(
            permutation.current_slice().len() > column,
            "Permutation trace has insufficient width"
        );

        let s_local = permutation.current(column).unwrap().into();
        let s_next = permutation.next(column).unwrap().into();

        builder.when_first_row().assert_zero_ext(s_local.clone());

        let (numerator, common_denominator) = self
            .compute_combined_sum_terms::<AB, AB::ExprEF, AB::ExprEF>(
                &elements,
                &multiplicities,
                &alpha.into(),
                &beta.into(),
            );

        if let Some(expected_cumulated) = opt_expected_cumulated {
            assert!(
                matches!(kind, Kind::Global(_)),
                "Expected cumulated value provided for a non-global lookup"
            );

            builder.when_transition().assert_zero_ext(
                (s_next - s_local.clone()) * common_denominator.clone() - numerator.clone(),
            );

            let final_val = (expected_cumulated - s_local) * common_denominator - numerator;
            builder.when_last_row().assert_zero_ext(final_val);
        } else {
            assert!(
                matches!(kind, Kind::Local),
                "No expected cumulated value provided for a global lookup"
            );

            builder.assert_zero_ext((s_next - s_local) * common_denominator - numerator);
        }
        Ok(())
    }
}

impl LookupEvaluator for LogUpGadget {
    fn num_aux_cols(&self) -> usize {
        1
    }

    fn num_challenges(&self) -> usize {
        2
    }

    fn eval_local_lookup<AB>(
        &self,
        builder: &mut AB,
        context: &Lookup<AB::F>,
    ) -> Result<(), LookupError>
    where
        AB: PermutationAirBuilder,
    {
        if let Kind::Global(_) = context.kind {
            return Err(LookupError::GlobalInLocalEval);
        }

        self.eval_update(builder, context, None)
    }

    fn eval_global_update<AB>(
        &self,
        builder: &mut AB,
        context: &Lookup<AB::F>,
        expected_cumulated: AB::ExprEF,
    ) -> Result<(), LookupError>
    where
        AB: PermutationAirBuilder,
    {
        self.eval_update(builder, context, Some(expected_cumulated))
    }
}

impl LookupGadget for LogUpGadget {
    fn verify_global_final_value<EF: Field>(
        &self,
        all_expected_cumulative: &[EF],
    ) -> Result<(), LookupError> {
        let total = all_expected_cumulative.iter().cloned().sum::<EF>();

        if !total.is_zero() {
            return Err(LookupError::GlobalCumulativeMismatch(None));
        }

        Ok(())
    }

    fn constraint_degree<F: Field>(&self, context: &Lookup<F>) -> usize {
        assert!(context.multiplicities_exprs.len() == context.element_exprs.len());

        let n = context.multiplicities_exprs.len();

        let mut degs = Vec::with_capacity(n);
        let mut deg_sum = 0;
        for elems in &context.element_exprs {
            let deg = elems
                .iter()
                .map(|elt| elt.degree_multiple())
                .max()
                .unwrap_or(0);
            degs.push(deg);
            deg_sum += deg;
        }

        let deg_denom_constr = 1 + deg_sum;

        let multiplicities = &context.multiplicities_exprs;
        let deg_num = (0..n)
            .map(|i| multiplicities[i].degree_multiple() + deg_sum - degs[i])
            .max()
            .unwrap_or(0);

        deg_denom_constr.max(deg_num)
    }

    #[instrument(name = "generate lookup permutation", skip_all, level = "debug")]
    fn generate_permutation<F: Field, EF: ExtensionField<F>>(
        &self,
        main: &RowMajorMatrix<F>,
        preprocessed: &Option<RowMajorMatrix<F>>,
        public_values: &[F],
        lookups: &[Lookup<F>],
        lookup_data: &mut [LookupData<EF>],
        permutation_challenges: &[EF],
    ) -> RowMajorMatrix<EF> {
        let height = main.height();
        let width = self.num_aux_cols() * lookups.len();

        debug_assert_eq!(
            permutation_challenges.len(),
            lookups.len() * self.num_challenges(),
            "perm challenge count must be per-lookup"
        );

        #[cfg(debug_assertions)]
        {
            use alloc::collections::btree_set::BTreeSet;

            let mut seen = BTreeSet::new();
            for ctx in lookups {
                let a = ctx.columns[0];
                if !seen.insert(a) {
                    panic!("duplicate aux column index {a} across lookups");
                }
            }
        }

        // 1. PRE-COMPUTE DENOMINATORS
        let denoms_per_row: usize = lookups.iter().map(|l| l.element_exprs.len()).sum();
        let mut lookup_denom_offsets = Vec::with_capacity(lookups.len() + 1);
        lookup_denom_offsets.push(0);
        for l in lookups.iter() {
            lookup_denom_offsets
                .push(lookup_denom_offsets.last().copied().unwrap() + l.element_exprs.len());
        }
        let num_lookups = lookups.len();

        let mut all_denominators = vec![EF::ZERO; height * denoms_per_row];
        let mut all_multiplicities = vec![F::ZERO; height * denoms_per_row];

        for (i, (denom_row, mult_row)) in all_denominators
            .chunks_mut(denoms_per_row)
            .zip(all_multiplicities.chunks_mut(denoms_per_row))
            .enumerate()
        {
            let local_main_row = main.row_slice(i).unwrap();
            let next_main_row = main.row_slice((i + 1) % height).unwrap();
            let main_rows = VerticalPair::new(
                RowMajorMatrixView::new_row(&local_main_row),
                RowMajorMatrixView::new_row(&next_main_row),
            );
            let preprocessed_rows_data = preprocessed.as_ref().map(|prep| {
                (
                    prep.row_slice(i).unwrap(),
                    prep.row_slice((i + 1) % height).unwrap(),
                )
            });
            let preprocessed_rows = match preprocessed_rows_data.as_ref() {
                Some((local_preprocessed_row, next_preprocessed_row)) => VerticalPair::new(
                    RowMajorMatrixView::new_row(local_preprocessed_row),
                    RowMajorMatrixView::new_row(next_preprocessed_row),
                ),
                None => VerticalPair::new(
                    RowMajorMatrixView::new(&[], 0),
                    RowMajorMatrixView::new(&[], 0),
                ),
            };

            let row_builder: LookupTraceBuilder<'_, F, EF> = LookupTraceBuilder::new(
                main_rows,
                preprocessed_rows,
                public_values,
                permutation_challenges,
                height,
                i,
            );

            let mut offset = 0;
            for context in lookups.iter() {
                let alpha = permutation_challenges[self.num_challenges() * context.columns[0]];
                let beta = permutation_challenges[self.num_challenges() * context.columns[0] + 1];

                for (j, elts) in context.element_exprs.iter().enumerate() {
                    let combined_elt = elts.iter().fold(EF::ZERO, |acc, e| {
                        acc * beta + symbolic_to_expr(&row_builder, e).expect("symbolic resolution")
                    });
                    denom_row[offset] = alpha - combined_elt;
                    mult_row[offset] =
                        symbolic_to_expr(&row_builder, &context.multiplicities_exprs[j])
                            .expect("symbolic resolution");
                    offset += 1;
                }
            }
        }

        debug_assert_eq!(all_denominators.len(), height * denoms_per_row);

        // 2. BATCH INVERSION
        let all_inverses = lib_q_stark_field::batch_multiplicative_inverse(&all_denominators);

        // 3. BUILD TRACE
        let mut row_sums = EF::zero_vec(height * num_lookups);
        for (i, row_sums_i) in row_sums.chunks_mut(num_lookups).enumerate() {
            let inv_base = i * denoms_per_row;
            for (lookup_idx, _context) in lookups.iter().enumerate() {
                let start = lookup_denom_offsets[lookup_idx];
                let end = lookup_denom_offsets[lookup_idx + 1];
                let sum = (start..end)
                    .map(|k| all_inverses[inv_base + k] * all_multiplicities[inv_base + k])
                    .sum();
                row_sums_i[lookup_idx] = sum;
            }
        }

        let mut aux_trace = EF::zero_vec(height * width);

        // Build prefix sums sequentially for each lookup column.
        let mut prefix = EF::zero_vec(height);

        for (lookup_idx, context) in lookups.iter().enumerate() {
            let aux_idx = context.columns[0];

            for (i, val) in prefix.iter_mut().enumerate() {
                *val = row_sums[i * num_lookups + lookup_idx];
            }

            // Inclusive prefix sum.
            for i in 1..height {
                let prev = prefix[i - 1];
                prefix[i] += prev;
            }

            // Convert to exclusive prefix sum in the aux trace.
            // Row 0 is already zero from initialization.
            for i in 1..height {
                aux_trace[i * width + aux_idx] = prefix[i - 1];
            }

            if matches!(context.kind, Kind::Global(_)) {
                let permutation_counter = lookups[..=lookup_idx]
                    .iter()
                    .filter(|l| matches!(l.kind, Kind::Global(_)))
                    .count() -
                    1;
                lookup_data[permutation_counter].expected_cumulated = prefix[height - 1];
            }
        }

        RowMajorMatrix::new(aux_trace, width)
    }
}
