use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;

use itertools::Itertools;
use lib_q_stark_air::{
    Air,
    RowWindow,
};
use lib_q_stark_challenger::{
    CanObserve,
    FieldChallenger,
};
use lib_q_stark_commit::{
    Pcs,
    PolynomialSpace,
};
use lib_q_stark_field::{
    BasedVectorSpace,
    PackedValue,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::{
    RowMajorMatrix,
    RowMajorMatrixView,
};
use lib_q_stark_util::log2_strict_usize;
use tracing::{
    debug_span,
    info_span,
    instrument,
};

use crate::symbolic::{
    get_constraint_layout,
    get_log_num_quotient_chunks,
    get_symbolic_constraints,
};
use crate::{
    AirLayout,
    Commitments,
    Domain,
    OpenedValues,
    PackedVal,
    PreprocessedProverData,
    Proof,
    ProverConstraintFolder,
    StarkGenericConfig,
    SymbolicAirBuilder,
    Val,
};

/// DoS limits for prover input validation.
const MAX_TRACE_HEIGHT: usize = 1 << 24;
const MAX_TRACE_WIDTH: usize = 1 << 16;
const MAX_PUBLIC_VALUES: usize = 1 << 16;

/// Errors that can occur during STARK proof generation.
#[derive(Debug)]
pub enum ProverError {
    /// AIR defines preprocessed columns but no PreprocessedProverData was provided.
    MissingPreprocessedData { width: usize },
    /// PreprocessedProverData degree_bits does not match trace degree_bits.
    PreprocessedDegreeMismatch { expected: usize, actual: usize },
    /// ZK is enabled but PCS did not return randomization commitment.
    MissingRandomizationCommitment,
    /// Domain does not support next_point operation.
    NextPointUnavailable,
    /// Trace height exceeds DoS limit.
    TraceTooLarge { height: usize, max: usize },
    /// Trace width exceeds DoS limit.
    TraceTooWide { width: usize, max: usize },
    /// Public values count exceeds DoS limit.
    TooManyPublicValues { count: usize, max: usize },
}

#[cfg(debug_assertions)]
#[instrument(skip_all)]
pub fn prove<SC, A>(
    config: &SC,
    air: &A,
    trace: RowMajorMatrix<Val<SC>>,
    public_values: &[Val<SC>],
) -> Result<Proof<SC>, ProverError>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<crate::check_constraints::DebugConstraintBuilder<'a, Val<SC>>>,
{
    prove_with_preprocessed::<SC, A>(config, air, trace, public_values, None)
}

#[cfg(not(debug_assertions))]
#[instrument(skip_all)]
pub fn prove<SC, A>(
    config: &SC,
    air: &A,
    trace: RowMajorMatrix<Val<SC>>,
    public_values: &[Val<SC>],
) -> Result<Proof<SC>, ProverError>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<ProverConstraintFolder<'a, SC>>,
{
    prove_with_preprocessed::<SC, A>(config, air, trace, public_values, None)
}

/// Prove a STARK with optional preprocessed columns.
///
/// For zeroization of sensitive trace data, wrap the trace in a type that zeroizes on drop
/// before calling this function. When using `lib-q-stark`, use `lib_q_stark::secret::SecretWitness`:
///
/// ```text
/// use lib_q_stark::secret::SecretWitness;
/// let secret_trace = SecretWitness::new(trace);
/// let proof = prove_with_preprocessed(config, air, secret_trace.trace(), public_values, None);
/// ```
#[cfg(debug_assertions)]
#[instrument(skip_all)]
pub fn prove_with_preprocessed<SC, A>(
    config: &SC,
    air: &A,
    trace: RowMajorMatrix<Val<SC>>,
    public_values: &[Val<SC>],
    preprocessed: Option<&PreprocessedProverData<SC>>,
) -> Result<Proof<SC>, ProverError>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<crate::check_constraints::DebugConstraintBuilder<'a, Val<SC>>>,
{
    crate::check_constraints::check_constraints(air, &trace, public_values);
    prove_inner::<SC, A>(config, air, trace, public_values, preprocessed)
}

/// Prove a STARK with optional preprocessed columns.
///
/// For zeroization of sensitive trace data, wrap the trace in a type that zeroizes on drop
/// before calling. When using `lib-q-stark`, use [`lib_q_stark::secret::SecretWitness`].
#[cfg(not(debug_assertions))]
#[instrument(skip_all)]
pub fn prove_with_preprocessed<SC, A>(
    config: &SC,
    air: &A,
    trace: RowMajorMatrix<Val<SC>>,
    public_values: &[Val<SC>],
    preprocessed: Option<&PreprocessedProverData<SC>>,
) -> Result<Proof<SC>, ProverError>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<ProverConstraintFolder<'a, SC>>,
{
    prove_inner::<SC, A>(config, air, trace, public_values, preprocessed)
}

fn prove_inner<SC, A>(
    config: &SC,
    air: &A,
    trace: RowMajorMatrix<Val<SC>>,
    public_values: &[Val<SC>],
    preprocessed: Option<&PreprocessedProverData<SC>>,
) -> Result<Proof<SC>, ProverError>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<ProverConstraintFolder<'a, SC>>,
{
    if trace.height() > MAX_TRACE_HEIGHT {
        return Err(ProverError::TraceTooLarge {
            height: trace.height(),
            max: MAX_TRACE_HEIGHT,
        });
    }
    if trace.width() > MAX_TRACE_WIDTH {
        return Err(ProverError::TraceTooWide {
            width: trace.width(),
            max: MAX_TRACE_WIDTH,
        });
    }
    if public_values.len() > MAX_PUBLIC_VALUES {
        return Err(ProverError::TooManyPublicValues {
            count: public_values.len(),
            max: MAX_PUBLIC_VALUES,
        });
    }

    let degree = trace.height();
    let log_degree = log2_strict_usize(degree);
    let log_ext_degree = log_degree + config.is_zk();

    let preprocessed_width = preprocessed.map_or_else(
        || {
            if let Some(preprocessed_trace) = air.preprocessed_trace() {
                let width = preprocessed_trace.width();
                if width > 0 {
                    return Err(ProverError::MissingPreprocessedData { width });
                }
            }
            Ok(0)
        },
        |pp| {
            if pp.degree_bits != log_ext_degree {
                return Err(ProverError::PreprocessedDegreeMismatch {
                    expected: log_ext_degree,
                    actual: pp.degree_bits,
                });
            }
            Ok(pp.width)
        },
    )?;

    let layout = AirLayout {
        preprocessed_width,
        main_width: air.width(),
        num_public_values: air.num_public_values(),
    };

    debug_assert!(
        air.num_constraints()
            .is_none_or(|n| { n == get_symbolic_constraints(air, layout).len() }),
        "num_constraints() hint mismatch",
    );

    let log_num_quotient_chunks =
        get_log_num_quotient_chunks::<Val<SC>, A>(air, layout, config.is_zk());
    let num_quotient_chunks = 1 << (log_num_quotient_chunks + config.is_zk());

    let pcs = config.pcs();
    let mut challenger = config.initialise_challenger();

    let trace_domain = pcs.natural_domain_for_degree(degree);
    let ext_trace_domain = pcs.natural_domain_for_degree(degree * (config.is_zk() + 1));

    let (trace_commit, trace_data) =
        info_span!("commit to trace data").in_scope(|| pcs.commit([(ext_trace_domain, trace)]));

    let (preprocessed_commit, preprocessed_data_ref) = preprocessed
        .map(|pp| (pp.commitment.clone(), &pp.prover_data))
        .unzip();

    challenger.observe(Val::<SC>::from_usize(log_ext_degree));
    challenger.observe(Val::<SC>::from_usize(log_degree));
    challenger.observe(Val::<SC>::from_usize(preprocessed_width));

    challenger.observe(trace_commit.clone());
    if let Some(ref c) = preprocessed_commit {
        challenger.observe(c.clone());
    }
    challenger.observe_slice(public_values);

    let alpha: SC::Challenge = challenger.sample_algebra_element();

    let quotient_domain =
        ext_trace_domain.create_disjoint_domain(1 << (log_ext_degree + log_num_quotient_chunks));

    let trace_on_quotient_domain = pcs.get_evaluations_on_domain(&trace_data, 0, quotient_domain);
    let preprocessed_on_quotient_domain =
        preprocessed_data_ref.map(|data| pcs.get_evaluations_on_domain(data, 0, quotient_domain));

    let quotient_values = quotient_values(
        air,
        public_values,
        layout,
        trace_domain,
        quotient_domain,
        &trace_on_quotient_domain,
        preprocessed_on_quotient_domain.as_ref(),
        alpha,
    );

    let quotient_flat = RowMajorMatrix::new_col(quotient_values).flatten_to_base();

    let (quotient_commit, quotient_data) = info_span!("commit to quotient poly chunks")
        .in_scope(|| pcs.commit_quotient(quotient_domain, quotient_flat, num_quotient_chunks));
    challenger.observe(quotient_commit.clone());

    let (opt_r_commit, opt_r_data) = if SC::Pcs::ZK {
        let (r_commit, r_data) = pcs
            .get_opt_randomization_poly_commitment(core::iter::once(ext_trace_domain))
            .ok_or(ProverError::MissingRandomizationCommitment)?;
        (Some(r_commit), Some(r_data))
    } else {
        (None, None)
    };

    let commitments = Commitments {
        trace: trace_commit,
        quotient_chunks: quotient_commit,
        random: opt_r_commit.clone(),
    };

    if let Some(r_commit) = opt_r_commit {
        challenger.observe(r_commit);
    }

    let zeta: SC::Challenge = challenger.sample_algebra_element();
    let zeta_next = trace_domain
        .next_point(zeta)
        .ok_or(ProverError::NextPointUnavailable)?;

    let main_next = !air.main_next_row_columns().is_empty();
    let pre_next = !air.preprocessed_next_row_columns().is_empty();

    let round0 = opt_r_data.as_ref().map(|r_data| (r_data, vec![vec![zeta]]));
    let trace_points = if main_next {
        vec![vec![zeta, zeta_next]]
    } else {
        vec![vec![zeta]]
    };
    let round1 = (&trace_data, trace_points);
    let round2 = (&quotient_data, vec![vec![zeta]; num_quotient_chunks]);
    let pre_points = if pre_next {
        vec![vec![zeta, zeta_next]]
    } else {
        vec![vec![zeta]]
    };
    let round3 = preprocessed_data_ref.map(|data| (data, pre_points));

    let rounds = round0
        .into_iter()
        .chain([round1, round2])
        .chain(round3)
        .collect();

    let (opened_values, opening_proof) =
        info_span!("open").in_scope(|| pcs.open(rounds, &mut challenger));

    let trace_idx = SC::Pcs::TRACE_IDX;
    let quotient_idx = SC::Pcs::QUOTIENT_IDX;
    let is_random = opt_r_data.is_some();

    let trace_local = opened_values[trace_idx][0][0].clone();
    let trace_next = if main_next {
        Some(opened_values[trace_idx][0][1].clone())
    } else {
        None
    };
    let quotient_chunks = opened_values[quotient_idx]
        .iter()
        .map(|v| v[0].clone())
        .collect_vec();
    let random = if is_random {
        Some(opened_values[0][0][0].clone())
    } else {
        None
    };
    let (preprocessed_local, preprocessed_next) = if preprocessed_width > 0 {
        let local = Some(opened_values[SC::Pcs::PREPROCESSED_TRACE_IDX][0][0].clone());
        let next = if pre_next {
            Some(opened_values[SC::Pcs::PREPROCESSED_TRACE_IDX][0][1].clone())
        } else {
            None
        };
        (local, next)
    } else {
        (None, None)
    };

    let opened_values = OpenedValues {
        trace_local,
        trace_next,
        preprocessed_local,
        preprocessed_next,
        quotient_chunks,
        random,
    };
    Ok(Proof {
        commitments,
        opened_values,
        opening_proof,
        degree_bits: log_ext_degree,
    })
}

#[instrument(skip_all, level = "debug")]
#[allow(clippy::too_many_arguments)]
pub fn quotient_values<SC, A, Mat>(
    air: &A,
    public_values: &[Val<SC>],
    layout: AirLayout,
    trace_domain: Domain<SC>,
    quotient_domain: Domain<SC>,
    trace_on_quotient_domain: &Mat,
    preprocessed_on_quotient_domain: Option<&Mat>,
    alpha: SC::Challenge,
) -> Vec<SC::Challenge>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<ProverConstraintFolder<'a, SC>>,
    Mat: Matrix<Val<SC>> + Sync,
{
    let quotient_size = quotient_domain.size();
    let width = trace_on_quotient_domain.width();
    let mut sels = debug_span!("compute selectors")
        .in_scope(|| trace_domain.selectors_on_coset(quotient_domain));

    let qdb = log2_strict_usize(quotient_domain.size()) - log2_strict_usize(trace_domain.size());
    let next_step = 1 << qdb;

    for _ in quotient_size..PackedVal::<SC>::WIDTH {
        sels.is_first_row.push(Val::<SC>::default());
        sels.is_last_row.push(Val::<SC>::default());
        sels.is_transition.push(Val::<SC>::default());
        sels.inv_vanishing.push(Val::<SC>::default());
    }

    let constraint_layout = get_constraint_layout(air, layout);
    let (base_alpha_powers, ext_alpha_powers) = constraint_layout.decompose_alpha(alpha);

    (0..quotient_size)
        .step_by(PackedVal::<SC>::WIDTH)
        .flat_map(|i_start| {
            let i_range = i_start..i_start + PackedVal::<SC>::WIDTH;

            let is_first_row = *PackedVal::<SC>::from_slice(&sels.is_first_row[i_range.clone()]);
            let is_last_row = *PackedVal::<SC>::from_slice(&sels.is_last_row[i_range.clone()]);
            let is_transition = *PackedVal::<SC>::from_slice(&sels.is_transition[i_range.clone()]);
            let inv_vanishing = *PackedVal::<SC>::from_slice(&sels.inv_vanishing[i_range]);

            let main = RowMajorMatrix::new(
                trace_on_quotient_domain.vertically_packed_row_pair(i_start, next_step),
                width,
            );

            let preprocessed = preprocessed_on_quotient_domain.map(|preprocessed| {
                let preprocessed_width = preprocessed.width();
                RowMajorMatrix::new(
                    preprocessed.vertically_packed_row_pair(i_start, next_step),
                    preprocessed_width,
                )
            });

            let preprocessed_view = preprocessed
                .as_ref()
                .map_or_else(|| RowMajorMatrixView::new(&[], 0), |m| m.as_view());
            let preprocessed_window = RowWindow::from_view(&preprocessed_view);

            let mut folder = ProverConstraintFolder {
                main: main.as_view(),
                preprocessed: preprocessed_view,
                preprocessed_window,
                public_values,
                is_first_row,
                is_last_row,
                is_transition,
                base_alpha_powers: &base_alpha_powers,
                ext_alpha_powers: &ext_alpha_powers,
                base_constraints: Vec::with_capacity(constraint_layout.base_indices.len()),
                ext_constraints: Vec::with_capacity(constraint_layout.ext_indices.len()),
                constraint_index: 0,
                constraint_count: constraint_layout.total_constraints(),
            };
            air.eval(&mut folder);

            let quotient = folder.finalize_constraints() * inv_vanishing;

            (0..min(quotient_size, PackedVal::<SC>::WIDTH)).map(move |idx_in_packing| {
                SC::Challenge::from_basis_coefficients_fn(|d| {
                    quotient.as_basis_coefficients_slice()[d].as_slice()[idx_in_packing]
                })
            })
        })
        .collect()
}
