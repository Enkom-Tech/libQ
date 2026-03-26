//! This module provides optimized routines for computing **batched multilinear equality polynomials**
//! over the Boolean hypercube `{0,1}^n`.
//!
//! The equality polynomial `eq(x, z)` evaluates to 1 if `x == z`, and 0 otherwise.
//! It is defined as:
//!
//! ```text
//! eq(x, z) = \prod_{i=0}^{n-1} (x_i * z_i + (1 - x_i)(1 - z_i))
//! ```
//!
//! These values are computed over all `x in {0,1}^n` efficiently using a recursive strategy.
//! The key relation used is:
//!
//! ```text
//! eq((0, x), z) = (1 - z_0) * eq(x, z[1:])
//! eq((1, x), z) = z_0 * eq(x, z[1:])
//! ```
//!
//! Which allows us to reuse the common factor `eq(x, z[1:])`.
//!
//! ## Batched Evaluation
//!
//! The batched methods (`eval_eq_batch`, `eval_eq_base_batch`) are designed to efficiently compute
//! linear combinations of multiple equality polynomial evaluations. Instead of computing each
//! equality polynomial individually and then summing the results, these functions leverage linearity
//! to perform the summation within the recursive evaluation process.
//!
//! The batched variants compute a linear combination of equality tables in one pass:
//!
//! ```text
//! W(x) = \sum_i gamma_i * eq(x, z_i)  ,  x in {0,1}^n .
//! ```
//!
//! ### Mathematical Foundation:
//! The batched algorithm exploits the recursive structure by updating entire vectors of scalars:
//!
//! At each variable z_j, the scalar vector gamma = (gamma_0, gamma_1, ..., gamma_{m-1}) splits into:
//! - gamma_0 = gamma * (1 - z_j) for the x_j = 0 branch
//! - gamma_1 = gamma * z_j for the x_j = 1 branch
//!
//! Where * denotes element-wise (Hadamard) product.
//!
//! ## `INITIALIZED` flag
//!
//! Each function accepts a `const INITIALIZED: bool` flag to control how output is written:
//!
//! - If `INITIALIZED = false`: the result is **written** into the output buffer.
//! - If `INITIALIZED = true`: the result is **added** to the output buffer.
//!
//! The output buffer must always be of length `2^n` for `n` variables.

use alloc::vec;
use alloc::vec::Vec;

use lib_q_stark_field::{
    Algebra,
    ExtensionField,
    Field,
    PackedFieldExtension,
    PackedValue,
    PrimeCharacteristicRing,
    dot_product,
};
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::{
    RowMajorMatrix,
    RowMajorMatrixView,
};
use lib_q_stark_rayon::prelude::*;
use lib_q_stark_util::log2_strict_usize;

/// Computes the batched multilinear equality polynomial `\sum_i gamma_i * eq(x, z_i)` over all
/// `x in {0,1}^n` for multiple points `z_i in EF^n` with weights `gamma_i in EF`.
///
/// This evaluates multiple equality tables simultaneously by pushing the linear combination
/// through the recursion.
///
/// # Mathematical statement
/// Given:
/// - evaluation points `z_0, z_1, ..., z_{m-1} in F^n`,
/// - weights `gamma_0, gamma_1, ..., gamma_{m-1} in EF`, this computes, for all `x in {0,1}^n`:
/// ```text
/// W(x) = \sum_i gamma_i * eq(x, z_i).
/// ```
///
/// # Arguments
/// - `evals`: Matrix where each column is one point `z_i`.
///     - height = number of variables `n`,
///     - width = number of points `m`
/// - `out`: Output buffer of size `2^n` storing `W(x)` in big-endian `x` order
/// - `scalars`: Weights `[ gamma_0, gamma_1, ..., gamma_{m-1} ]`
///
/// # Panics
/// Panics in debug builds if `evals.width() != scalars.len()` or if the output buffer size is incorrect.
#[inline]
pub fn eval_eq_batch<F, EF, const INITIALIZED: bool>(
    evals: RowMajorMatrixView<'_, EF>,
    out: &mut [EF],
    scalars: &[EF],
) where
    F: Field,
    EF: ExtensionField<F>,
{
    eval_eq_batch_common::<F, EF, EF, ExtFieldEvaluator<F, EF>, INITIALIZED>(evals, out, scalars);
}

/// Computes the batched multilinear equality polynomial `\sum_i gamma_i * eq(x, z_i)` over all
/// `x in {0,1}^n` for multiple points `z_i in F^n` with weights `gamma_i in EF`.
///
/// This evaluates multiple equality tables simultaneously by pushing the linear combination
/// through the recursion.
///
/// # Mathematical statement
/// Given:
/// - evaluation points `z_0, z_1, ..., z_{m-1} in EF^n`,
/// - weights `gamma_0, gamma_1, ..., gamma_{m-1} in EF`, this computes, for all `x in {0,1}^n`:
/// ```text
/// W(x) = \sum_i gamma_i * eq(x, z_i).
/// ```
///
/// # Arguments
/// - `evals`: Matrix where each column is one point `z_i`.
///     - height = number of variables `n`,
///     - width = number of points `m`
/// - `out`: Output buffer of size `2^n` storing `W(x)` in big-endian `x` order
/// - `scalars`: Weights `[ gamma_0, gamma_1, ..., gamma_{m-1} ]`
///
/// # Panics
/// Panics in debug builds if `evals.width() != scalars.len()` or if the output buffer size is incorrect.
#[inline]
pub fn eval_eq_base_batch<F, EF, const INITIALIZED: bool>(
    evals: RowMajorMatrixView<'_, F>,
    out: &mut [EF],
    scalars: &[EF],
) where
    F: Field,
    EF: ExtensionField<F>,
{
    eval_eq_batch_common::<F, F, EF, BaseFieldEvaluator<F, EF>, INITIALIZED>(evals, out, scalars);
}

/// Fills the `buffer` with evaluations of the equality polynomial for multiple points simultaneously.
///
/// This is the batched operation that operates on matrices where each column
/// represents a different evaluation point. The function expands a matrix of partial equality
/// polynomial evaluations across multiple variables.
///
/// Given a buffer with `2^k` rows (where each column holds partial products for a specific point
/// after `k` variables have been processed), this function processes the evaluation points
/// for the remaining variables to complete the equality polynomial computation.
#[inline(always)]
fn fill_buffer_batch<F, A>(evals: RowMajorMatrixView<'_, F>, buffer: &mut RowMajorMatrix<A>)
where
    F: Field,
    A: Algebra<F> + Send + Sync + Clone,
{
    for (ind, eval_row) in evals.row_slices().rev().enumerate() {
        let stride = 1 << ind;
        let width = buffer.width();

        for idx in 0..stride {
            for (col, &eval_point) in eval_row.iter().enumerate().take(width) {
                let val = buffer.values[idx * width + col].clone();

                let scaled_val = val.clone() * eval_point;
                let new_val = val - scaled_val.clone();

                buffer.values[idx * width + col] = new_val;
                buffer.values[(idx + stride) * width + col] = scaled_val;
            }
        }
    }
}

/// Computes the batched scaled multilinear equality polynomial over `{0,1}` for multiple points.
///
/// We compute:
/// ```text
/// eq_sum(0) = sum_i scalars[i] * (1 - evals[0][i])
/// eq_sum(1) = sum_i scalars[i] * evals[0][i]
/// ```
#[inline(always)]
fn eval_eq_1_batch<F, FP>(evals: RowMajorMatrixView<'_, F>, scalars: &[FP]) -> [FP; 2]
where
    F: Field,
    FP: Algebra<F>,
{
    debug_assert_eq!(evals.height(), 1);
    debug_assert_eq!(evals.width(), scalars.len());

    let sum: FP = scalars.iter().cloned().sum();

    let eq_1_sum: FP = dot_product(scalars.iter().cloned(), evals.values.iter().copied());

    let eq_0_sum = sum - eq_1_sum.clone();

    [eq_0_sum, eq_1_sum]
}

/// Computes the batched scaled multilinear equality polynomial over `{0,1}^2` for multiple points.
///
/// This is the batched version that efficiently handles the two-variable case
/// across multiple evaluation points simultaneously.
#[inline(always)]
fn eval_eq_2_batch<F, FP>(
    evals: RowMajorMatrixView<'_, F>,
    scalars: &[FP],
    workspace: &mut [FP],
) -> [FP; 4]
where
    F: Field,
    FP: Algebra<F> + Field,
{
    debug_assert_eq!(evals.height(), 2);
    debug_assert_eq!(evals.width(), scalars.len());

    let (first_row, second_row) = evals.split_rows(1);
    let num_points = evals.width();

    let (eq_0s, remaining) = workspace.split_at_mut(num_points);
    let eq_1s = &mut remaining[..num_points];

    for i in 0..num_points {
        let s = scalars[i];
        let z = first_row.values[i];
        let s1 = s * z;
        eq_1s[i] = s1;
        eq_0s[i] = s - s1;
    }

    let [eq_00, eq_01] = eval_eq_1_batch(second_row, eq_0s);
    let [eq_10, eq_11] = eval_eq_1_batch(second_row, eq_1s);

    [eq_00, eq_01, eq_10, eq_11]
}

/// Computes the batched scaled multilinear equality polynomial over `{0,1}^3` for multiple points.
///
/// This is the batched version that efficiently handles the three-variable case
/// across multiple evaluation points simultaneously.
#[inline(always)]
fn eval_eq_3_batch<F, FP>(
    evals: RowMajorMatrixView<'_, F>,
    scalars: &[FP],
    workspace: &mut [FP],
) -> [FP; 8]
where
    F: Field,
    FP: Algebra<F> + Field,
{
    debug_assert_eq!(evals.height(), 3);
    debug_assert_eq!(evals.width(), scalars.len());

    let (first_row, remainder) = evals.split_rows(1);
    let num_points = evals.width();

    let (eq_0s, next_workspace) = workspace.split_at_mut(num_points);
    let (eq_1s, next_workspace) = next_workspace.split_at_mut(num_points);

    for i in 0..num_points {
        let s = scalars[i];
        let z = first_row.values[i];
        let s1 = s * z;
        eq_1s[i] = s1;
        eq_0s[i] = s - s1;
    }

    let (ws0, remaining) = next_workspace.split_at_mut(2 * num_points);
    let ws1 = &mut remaining[..2 * num_points];

    let [eq_000, eq_001, eq_010, eq_011] = eval_eq_2_batch(remainder, eq_0s, ws0);
    let [eq_100, eq_101, eq_110, eq_111] = eval_eq_2_batch(remainder, eq_1s, ws1);

    [
        eq_000, eq_001, eq_010, eq_011, eq_100, eq_101, eq_110, eq_111,
    ]
}

/// A trait which allows us to define similar but subtly different evaluation strategies depending
/// on the incoming field types.
trait EqualityEvaluator {
    type InputField;
    type OutputField;
    type PackedField: Algebra<Self::InputField> + Copy + Send + Sync;

    fn init_packed_batch(
        evals: RowMajorMatrixView<'_, Self::InputField>,
        scalars: &[Self::OutputField],
    ) -> Vec<Self::PackedField>;

    fn process_chunk_batch<const INITIALIZED: bool>(
        evals: RowMajorMatrixView<'_, Self::InputField>,
        out_chunk: &mut [Self::OutputField],
        buffer_vals: &[Self::PackedField],
        scalars: &[Self::OutputField],
    );

    fn accumulate_packed_batch<const INITIALIZED: bool>(
        out: &mut [Self::OutputField],
        final_packed_evals: &[Self::PackedField],
        scalars: &[Self::OutputField],
    );
}

/// Evaluation strategy for the extension field case.
///
/// We initialise with `scalar` instead of `1` as this reduces the total
/// number of multiplications we need to do.
struct ExtFieldEvaluator<F, EF>(core::marker::PhantomData<(F, EF)>);

/// Evaluation strategy for the base field case.
///
/// We stay in the base field for as long as possible to simplify instructions and
/// reduce the amount of data transferred between cores. In particular this means we
/// hold off on scaling by `scalar` until the very end.
struct BaseFieldEvaluator<F, EF>(core::marker::PhantomData<(F, EF)>);

impl<F: Field, EF: ExtensionField<F>> EqualityEvaluator for ExtFieldEvaluator<F, EF> {
    type InputField = EF;
    type OutputField = EF;
    type PackedField = EF::ExtensionPacking;

    fn init_packed_batch(
        evals: RowMajorMatrixView<'_, Self::InputField>,
        scalars: &[Self::OutputField],
    ) -> Vec<Self::PackedField> {
        packed_eq_poly_batch(evals, scalars)
    }

    fn process_chunk_batch<const INITIALIZED: bool>(
        evals: RowMajorMatrixView<'_, Self::InputField>,
        out_chunk: &mut [Self::OutputField],
        buffer_vals: &[Self::PackedField],
        scalars: &[Self::OutputField],
    ) {
        let num_vars = evals.height();
        let num_points = evals.width();
        let workspace_len = (2 * (num_vars + 1) * num_points).max(8 * num_points);
        let mut workspace = Self::PackedField::zero_vec(workspace_len);
        eval_eq_packed_batch::<F, EF, EF, Self, INITIALIZED>(
            evals,
            out_chunk,
            buffer_vals,
            scalars,
            &mut workspace,
        );
    }

    fn accumulate_packed_batch<const INITIALIZED: bool>(
        out: &mut [Self::OutputField],
        final_packed_evals: &[Self::PackedField],
        _scalars: &[Self::OutputField],
    ) {
        if final_packed_evals.is_empty() {
            if !INITIALIZED {
                out.fill(Self::OutputField::ZERO);
            }
            return;
        }

        let packed_sum: Self::PackedField = final_packed_evals.iter().copied().sum();

        let unpacked_iter = Self::PackedField::to_ext_iter([packed_sum]);

        if INITIALIZED {
            out.iter_mut()
                .zip(unpacked_iter)
                .for_each(|(out_val, unpacked_val)| *out_val += unpacked_val);
        } else {
            out.iter_mut()
                .zip(unpacked_iter)
                .for_each(|(out_val, unpacked_val)| *out_val = unpacked_val);
        }
    }
}

impl<F: Field, EF: ExtensionField<F>> EqualityEvaluator for BaseFieldEvaluator<F, EF> {
    type InputField = F;
    type OutputField = EF;
    type PackedField = F::Packing;

    fn init_packed_batch(
        evals: RowMajorMatrixView<'_, Self::InputField>,
        _scalars: &[Self::OutputField],
    ) -> Vec<Self::PackedField> {
        packed_eq_poly_batch(evals, &vec![F::ONE; evals.width()])
    }

    fn process_chunk_batch<const INITIALIZED: bool>(
        evals: RowMajorMatrixView<'_, Self::InputField>,
        out_chunk: &mut [Self::OutputField],
        buffer_vals: &[Self::PackedField],
        scalars: &[Self::OutputField],
    ) {
        let num_vars = evals.height();
        let num_points = evals.width();

        let workspace_len = (2 * (num_vars + 1) * num_points).max(8 * num_points);
        let mut workspace = Self::PackedField::zero_vec(workspace_len);
        eval_eq_packed_batch::<F, F, EF, Self, INITIALIZED>(
            evals,
            out_chunk,
            buffer_vals,
            scalars,
            &mut workspace,
        );
    }

    fn accumulate_packed_batch<const INITIALIZED: bool>(
        out: &mut [Self::OutputField],
        final_packed_evals: &[Self::PackedField],
        scalars: &[Self::OutputField],
    ) {
        debug_assert_eq!(out.len(), F::Packing::WIDTH);
        debug_assert_eq!(final_packed_evals.len(), scalars.len());

        if scalars.is_empty() {
            if !INITIALIZED {
                out.fill(Self::OutputField::ZERO);
            }
            return;
        }

        for (k, out_val) in out.iter_mut().enumerate() {
            let dot_product = scalars
                .iter()
                .zip(final_packed_evals)
                .map(|(&scalar, packed_eval)| scalar * packed_eval.as_slice()[k])
                .sum::<Self::OutputField>();

            if INITIALIZED {
                *out_val += dot_product;
            } else {
                *out_val = dot_product;
            }
        }
    }
}

/// Computes the batched multilinear equality polynomial `sum_i gamma_i * eq(x, z_i)` over all
/// `x in {0,1}^n` for multiple points `z_i in IF^n` and corresponding scalars `gamma_i in EF`.
///
/// This is the core batched evaluation function that leverages the linearity of summation
/// to efficiently compute multiple equality polynomial evaluations simultaneously.
#[inline]
fn eval_eq_batch_common<F, IF, EF, E, const INITIALIZED: bool>(
    evals: RowMajorMatrixView<'_, IF>,
    out: &mut [EF],
    scalars: &[EF],
) where
    F: Field,
    IF: Field,
    EF: ExtensionField<F> + ExtensionField<IF>,
    E: EqualityEvaluator<InputField = IF, OutputField = EF>,
{
    if evals.width() == 0 {
        debug_assert!(scalars.is_empty());
        return;
    }

    let num_vars = evals.height();
    debug_assert_eq!(evals.width(), scalars.len());
    debug_assert_eq!(out.len(), 1 << num_vars);

    let packing_width = F::Packing::WIDTH;
    let num_threads = current_num_threads().next_power_of_two();
    let log_num_threads = log2_strict_usize(num_threads);

    if num_vars <= packing_width + 1 + log_num_threads {
        let mut workspace = EF::zero_vec((2 * evals.width() * num_vars).max(1));
        eval_eq_batch_basic::<F, IF, EF, INITIALIZED>(evals, scalars, out, &mut workspace);
    } else {
        let log_packing_width = log2_strict_usize(packing_width);
        let eval_len_min_packing = num_vars - log_packing_width;

        let mut parallel_buffer = RowMajorMatrix::new(
            E::PackedField::zero_vec(num_threads * evals.width()),
            evals.width(),
        );

        let out_chunk_size = out.len() >> log_num_threads;

        let (front_rows, packed_rows) = evals.split_rows(eval_len_min_packing);
        let init_packings = E::init_packed_batch(packed_rows, scalars);
        parallel_buffer.row_mut(0).copy_from_slice(&init_packings);

        let (buffer_rows, middle_rows) = front_rows.split_rows(log_num_threads);

        fill_buffer_batch(buffer_rows, &mut parallel_buffer);

        out.par_chunks_exact_mut(out_chunk_size)
            .zip(parallel_buffer.par_row_slices())
            .for_each(|(out_chunk, buffer_row)| {
                E::process_chunk_batch::<INITIALIZED>(middle_rows, out_chunk, buffer_row, scalars);
            });
    }
}

/// Computes the batched equality polynomial evaluations via a recursive algorithm.
///
/// This function directly implements the batched recursive strategy, updating the entire
/// vector of scalars at each recursive step. It serves as the basic implementation for
/// smaller problem sizes where parallelism and SIMD overhead is not warranted.
#[inline]
fn eval_eq_batch_basic<F, IF, EF, const INITIALIZED: bool>(
    evals: RowMajorMatrixView<'_, IF>,
    scalars: &[EF],
    out: &mut [EF],
    workspace: &mut [EF],
) where
    F: Field,
    IF: Field,
    EF: ExtensionField<F> + Algebra<IF>,
{
    let num_vars = evals.height();
    let num_points = evals.width();
    debug_assert_eq!(out.len(), 1 << num_vars);

    match num_vars {
        0 => {
            let sum: EF = scalars.iter().copied().sum();
            if INITIALIZED {
                out[0] += sum;
            } else {
                out[0] = sum;
            }
        }
        1 => {
            let eq_evaluations = eval_eq_1_batch(evals, scalars);
            add_or_set::<_, INITIALIZED>(out, &eq_evaluations);
        }
        2 => {
            let eq_evaluations = eval_eq_2_batch(evals, scalars, workspace);
            add_or_set::<_, INITIALIZED>(out, &eq_evaluations);
        }
        3 => {
            let eq_evaluations = eval_eq_3_batch(evals, scalars, workspace);
            add_or_set::<_, INITIALIZED>(out, &eq_evaluations);
        }
        _ => {
            let (low, high) = out.split_at_mut(out.len() / 2);
            let (first_row, remainder) = evals.split_rows(1);

            let (s0_buffer, next_workspace) = workspace.split_at_mut(num_points);
            let (s1_buffer, next_workspace) = next_workspace.split_at_mut(num_points);

            for i in 0..num_points {
                let s = scalars[i];
                let z = first_row.values[i];
                let s1 = s * z;
                s1_buffer[i] = s1;
                s0_buffer[i] = s - s1;
            }

            eval_eq_batch_basic::<F, IF, EF, INITIALIZED>(
                remainder,
                s0_buffer,
                low,
                next_workspace,
            );
            eval_eq_batch_basic::<F, IF, EF, INITIALIZED>(
                remainder,
                s1_buffer,
                high,
                next_workspace,
            );
        }
    }
}

/// Computes the batched equality polynomial evaluation using packed values and parallelism.
///
/// This is the batched version that processes multiple evaluation points
/// simultaneously within each parallel thread. It operates on packed scalar values for
/// improved SIMD performance while maintaining the recursive batched structure.
#[inline]
fn eval_eq_packed_batch<F, IF, EF, E, const INITIALIZED: bool>(
    eval_points: RowMajorMatrixView<'_, IF>,
    out: &mut [EF],
    eq_evals: &[E::PackedField],
    scalars: &[EF],
    workspace: &mut [E::PackedField],
) where
    F: Field,
    IF: Field,
    EF: ExtensionField<F>,
    E: EqualityEvaluator<InputField = IF, OutputField = EF>,
{
    let num_vars = eval_points.height();
    let num_points = eval_points.width();
    debug_assert_eq!(out.len(), F::Packing::WIDTH << num_vars);

    match num_vars {
        0 => {
            E::accumulate_packed_batch::<INITIALIZED>(out, eq_evals, scalars);
        }
        1 => {
            let first_row = eval_points;

            let (s0_buffer, s1_buffer) = workspace.split_at_mut(num_points);
            for i in 0..num_points {
                let z_0 = first_row.values[i];
                let eq_eval = eq_evals[i];
                let s1 = eq_eval * z_0;
                let s0 = eq_eval - s1;
                s0_buffer[i] = s0;
                s1_buffer[i] = s1;
            }

            let (low, high) = out.split_at_mut(out.len() / 2);
            E::accumulate_packed_batch::<INITIALIZED>(low, s0_buffer, scalars);
            E::accumulate_packed_batch::<INITIALIZED>(high, s1_buffer, scalars);
        }
        2 => {
            debug_assert!(workspace.len() >= 4 * num_points);
            let (first_row, second_row) = eval_points.split_rows(1);

            let (s00_buffer, rest) = workspace.split_at_mut(num_points);
            let (s01_buffer, rest) = rest.split_at_mut(num_points);
            let (s10_buffer, s11_buffer) = rest.split_at_mut(num_points);

            for i in 0..num_points {
                let eq_eval = eq_evals[i];
                let z_0 = first_row.values[i];
                let z_1 = second_row.values[i];

                let s1 = eq_eval * z_0;
                let s0 = eq_eval - s1;

                let s01 = s0 * z_1;
                let s11 = s1 * z_1;
                s00_buffer[i] = s0 - s01;
                s01_buffer[i] = s01;
                s10_buffer[i] = s1 - s11;
                s11_buffer[i] = s11;
            }

            let quarter = out.len() / 4;
            let (out_00, rest) = out.split_at_mut(quarter);
            let (out_01, rest) = rest.split_at_mut(quarter);
            let (out_10, out_11) = rest.split_at_mut(quarter);

            E::accumulate_packed_batch::<INITIALIZED>(out_00, s00_buffer, scalars);
            E::accumulate_packed_batch::<INITIALIZED>(out_01, s01_buffer, scalars);
            E::accumulate_packed_batch::<INITIALIZED>(out_10, s10_buffer, scalars);
            E::accumulate_packed_batch::<INITIALIZED>(out_11, s11_buffer, scalars);
        }
        3 => {
            debug_assert!(
                workspace.len() >= 8 * num_points,
                "Workspace for n=3 unrolled case must be >= 8 * num_points, but was only {}",
                workspace.len()
            );

            let (first_row, remainder) = eval_points.split_rows(1);
            let (second_row, third_row) = remainder.split_rows(1);

            let (s000_buffer, rest) = workspace.split_at_mut(num_points);
            let (s001_buffer, rest) = rest.split_at_mut(num_points);
            let (s010_buffer, rest) = rest.split_at_mut(num_points);
            let (s011_buffer, rest) = rest.split_at_mut(num_points);
            let (s100_buffer, rest) = rest.split_at_mut(num_points);
            let (s101_buffer, rest) = rest.split_at_mut(num_points);
            let (s110_buffer, s111_buffer) = rest.split_at_mut(num_points);

            for i in 0..num_points {
                let eq_eval = eq_evals[i];
                let z_0 = first_row.values[i];
                let z_1 = second_row.values[i];
                let z_2 = third_row.values[i];

                let s1 = eq_eval * z_0;
                let s0 = eq_eval - s1;

                let s01 = s0 * z_1;
                let s11 = s1 * z_1;
                let s00 = s0 - s01;
                let s10 = s1 - s11;

                let s001 = s00 * z_2;
                let s011 = s01 * z_2;
                let s101 = s10 * z_2;
                let s111 = s11 * z_2;
                s000_buffer[i] = s00 - s001;
                s001_buffer[i] = s001;
                s010_buffer[i] = s01 - s011;
                s011_buffer[i] = s011;
                s100_buffer[i] = s10 - s101;
                s101_buffer[i] = s101;
                s110_buffer[i] = s11 - s111;
                s111_buffer[i] = s111;
            }

            let eighth = out.len() / 8;
            let (out_000, rest) = out.split_at_mut(eighth);
            let (out_001, rest) = rest.split_at_mut(eighth);
            let (out_010, rest) = rest.split_at_mut(eighth);
            let (out_011, rest) = rest.split_at_mut(eighth);
            let (out_100, rest) = rest.split_at_mut(eighth);
            let (out_101, rest) = rest.split_at_mut(eighth);
            let (out_110, out_111) = rest.split_at_mut(eighth);

            E::accumulate_packed_batch::<INITIALIZED>(out_000, s000_buffer, scalars);
            E::accumulate_packed_batch::<INITIALIZED>(out_001, s001_buffer, scalars);
            E::accumulate_packed_batch::<INITIALIZED>(out_010, s010_buffer, scalars);
            E::accumulate_packed_batch::<INITIALIZED>(out_011, s011_buffer, scalars);
            E::accumulate_packed_batch::<INITIALIZED>(out_100, s100_buffer, scalars);
            E::accumulate_packed_batch::<INITIALIZED>(out_101, s101_buffer, scalars);
            E::accumulate_packed_batch::<INITIALIZED>(out_110, s110_buffer, scalars);
            E::accumulate_packed_batch::<INITIALIZED>(out_111, s111_buffer, scalars);
        }
        _ => {
            let (low, high) = out.split_at_mut(out.len() / 2);
            let (first_row, remainder) = eval_points.split_rows(1);

            let (s0_buffer, rest_workspace) = workspace.split_at_mut(num_points);
            let (s1_buffer, next_workspace) = rest_workspace.split_at_mut(num_points);

            for i in 0..num_points {
                let z_0 = first_row.values[i];
                let eq_eval = eq_evals[i];
                let s1 = eq_eval * z_0;
                let s0 = eq_eval - s1;
                s0_buffer[i] = s0;
                s1_buffer[i] = s1;
            }

            eval_eq_packed_batch::<F, IF, EF, E, INITIALIZED>(
                remainder,
                low,
                s0_buffer,
                scalars,
                next_workspace,
            );
            eval_eq_packed_batch::<F, IF, EF, E, INITIALIZED>(
                remainder,
                high,
                s1_buffer,
                scalars,
                next_workspace,
            );
        }
    }
}

/// Computes batched small equality polynomial evaluations and packs the results into packed vectors.
///
/// Handles multiple evaluation points simultaneously during the packing phase of parallel
/// evaluation. Processes the bottom log_packing_width variables for all points in the batch
/// and returns packed results.
#[inline(always)]
fn packed_eq_poly_batch<F, EF>(
    evals: RowMajorMatrixView<'_, EF>,
    scalars: &[EF],
) -> Vec<EF::ExtensionPacking>
where
    F: Field,
    EF: ExtensionField<F>,
{
    debug_assert_eq!(F::Packing::WIDTH, 1 << evals.height());
    debug_assert_eq!(evals.width(), scalars.len());

    let mut buffer = RowMajorMatrix::new(
        EF::zero_vec((1 << evals.height()) * evals.width()),
        evals.width(),
    );

    buffer.row_mut(0).copy_from_slice(scalars);

    fill_buffer_batch(evals, &mut buffer);

    (0..evals.width())
        .map(|col_idx| {
            let column: Vec<EF> = (0..(1 << evals.height()))
                .map(|row_idx| buffer.values[row_idx * buffer.width() + col_idx])
                .collect();
            EF::ExtensionPacking::from_ext_slice(&column)
        })
        .collect()
}

/// Adds or sets the equality polynomial evaluations in the output buffer.
///
/// If the output buffer is already initialized, it adds the evaluations otherwise
/// it copies the evaluations into the buffer directly.
#[inline]
fn add_or_set<F: Field, const INITIALIZED: bool>(out: &mut [F], evaluations: &[F]) {
    debug_assert_eq!(out.len(), evaluations.len());
    if INITIALIZED {
        F::add_slices(out, evaluations);
    } else {
        out.copy_from_slice(evaluations);
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_field::integers::QuotientMap;
    use lib_q_stark_field::{
        ExtensionField,
        Field,
    };
    use lib_q_stark_matrix::dense::RowMajorMatrixView;

    use super::*;

    type F = lib_q_stark_mersenne31::Mersenne31;
    type EF = Complex<F>;

    /// Naive equality polynomial evaluation for extension field points (for testing).
    fn eval_eq_naive<F, EF, const INITIALIZED: bool>(eval_point: &[EF], out: &mut [EF], scalar: EF)
    where
        F: Field,
        EF: ExtensionField<F>,
    {
        let num_vars = eval_point.len();
        assert_eq!(out.len(), 1 << num_vars);
        for (x, o) in out.iter_mut().enumerate().take(1 << num_vars) {
            let mut eq_val = scalar;
            for (i, &z_i) in eval_point.iter().enumerate().rev() {
                let x_i = (x >> (num_vars - 1 - i)) & 1;
                if x_i == 1 {
                    eq_val *= z_i;
                } else {
                    eq_val *= EF::ONE - z_i;
                }
            }
            if INITIALIZED {
                *o += eq_val;
            } else {
                *o = eq_val;
            }
        }
    }

    /// Naive equality polynomial for base field points (for testing).
    fn eval_eq_base_naive<F, EF, const INITIALIZED: bool>(
        eval_point: &[F],
        out: &mut [EF],
        scalar: EF,
    ) where
        F: Field,
        EF: ExtensionField<F>,
    {
        let point_ext: Vec<EF> = eval_point.iter().map(|&x| EF::from(x)).collect();
        eval_eq_naive::<F, EF, INITIALIZED>(&point_ext, out, scalar);
    }

    #[test]
    fn test_eval_eq_batch_functionality() {
        // 2 variables, 3 points. Matrix: rows = variables, cols = points.
        // Point 1: (1, 0), Point 2: (0, 1), Point 3: (1, 1)
        let evals_data: Vec<F> = vec![
            F::from_int(1),
            F::from_int(0),
            F::from_int(1),
            F::from_int(0),
            F::from_int(1),
            F::from_int(1),
        ];
        let evals = RowMajorMatrixView::new(&evals_data, 3);
        let scalars: Vec<F> = vec![F::from_int(2), F::from_int(3), F::from_int(5)];

        let mut output_batch = F::zero_vec(4);
        eval_eq_batch::<F, F, false>(evals, &mut output_batch, &scalars);

        let mut expected = F::zero_vec(4);
        let points: [Vec<F>; 3] = [
            vec![F::from_int(1), F::from_int(0)],
            vec![F::from_int(0), F::from_int(1)],
            vec![F::from_int(1), F::from_int(1)],
        ];
        for (point, &scalar) in points.iter().zip(scalars.iter()) {
            let mut temp = F::zero_vec(4);
            eval_eq_naive::<F, F, false>(point.as_slice(), &mut temp, scalar);
            F::add_slices(&mut expected, &temp);
        }
        assert_eq!(
            output_batch, expected,
            "eval_eq_batch should match naive sum"
        );
    }

    #[test]
    fn test_eval_eq_base_batch_functionality() {
        // Base field batch: 2 variables, 2 points. Point 1: (1, 0), Point 2: (0, 1)
        let evals_data: Vec<F> = vec![
            F::from_int(1),
            F::from_int(0),
            F::from_int(0),
            F::from_int(1),
        ];
        let evals = RowMajorMatrixView::new(&evals_data, 2);
        let scalars: Vec<EF> = vec![EF::from(F::from_int(2)), EF::from(F::from_int(3))];

        let mut output_batch = EF::zero_vec(4);
        eval_eq_base_batch::<F, EF, false>(evals, &mut output_batch, &scalars);

        let mut expected = EF::zero_vec(4);
        let points: [Vec<F>; 2] = [
            vec![F::from_int(1), F::from_int(0)],
            vec![F::from_int(0), F::from_int(1)],
        ];
        for (point, &scalar) in points.iter().zip(scalars.iter()) {
            let mut temp = EF::zero_vec(4);
            eval_eq_base_naive::<F, EF, false>(point, &mut temp, scalar);
            EF::add_slices(&mut expected, &temp);
        }
        assert_eq!(output_batch, expected);
    }

    #[test]
    fn test_eval_eq_batch_initialized_adds() {
        // 1 variable, 1 point: evals is 1 row x 1 col (height=1), out len = 2^1 = 2
        let evals_data: Vec<F> = vec![F::from_int(0)];
        let evals = RowMajorMatrixView::new(&evals_data, 1);
        let scalars: Vec<F> = vec![F::from_int(1)];

        let mut out = F::zero_vec(2);
        eval_eq_batch::<F, F, false>(evals, &mut out, &scalars);
        let first: Vec<F> = out.to_vec();

        eval_eq_batch::<F, F, true>(evals, &mut out, &scalars);
        for (a, b) in out.iter().zip(first.iter()) {
            assert_eq!(*a, *b + *b, "INITIALIZED=true should add");
        }
    }
}
