use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

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
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::dense::RowMajorMatrixView;
use lib_q_stark_matrix::stack::VerticalPair;
use tracing::instrument;

use crate::config::PcsError;
use crate::symbolic::get_log_num_quotient_chunks;
use crate::{
    AirLayout,
    Domain,
    PreprocessedVerifierKey,
    Proof,
    StarkGenericConfig,
    SymbolicAirBuilder,
    Val,
    VerifierConstraintFolder,
};

/// Recomposes the quotient polynomial from its chunks evaluated at a point.
pub fn recompose_quotient_from_chunks<SC, PcsErr>(
    quotient_chunks_domains: &[Domain<SC>],
    quotient_chunks: &[Vec<SC::Challenge>],
    zeta: SC::Challenge,
) -> Result<SC::Challenge, VerificationError<PcsErr>>
where
    SC: StarkGenericConfig,
    PcsErr: core::fmt::Debug,
{
    let zps = quotient_chunks_domains
        .iter()
        .enumerate()
        .map(|(i, domain)| {
            quotient_chunks_domains
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, other_domain)| {
                    other_domain.vanishing_poly_at_point(zeta) *
                        other_domain
                            .vanishing_poly_at_point(domain.first_point())
                            .inverse()
                })
                .product::<SC::Challenge>()
        })
        .collect_vec();

    quotient_chunks
        .iter()
        .enumerate()
        .map(|(ch_i, ch)| {
            ch.iter()
                .enumerate()
                .map(|(e_i, &c)| {
                    SC::Challenge::ith_basis_element(e_i)
                        .ok_or(VerificationError::InvalidBasisIndex(e_i))
                        .map(|b| b * c)
                })
                .sum::<Result<SC::Challenge, _>>()
                .map(|s| zps[ch_i] * s)
        })
        .sum::<Result<SC::Challenge, _>>()
}

/// Verifies that the folded constraints match the quotient polynomial at zeta.
#[allow(clippy::too_many_arguments)]
pub fn verify_constraints<SC, A, PcsErr>(
    air: &A,
    trace_local: &[SC::Challenge],
    trace_next: &[SC::Challenge],
    preprocessed_local: Option<&[SC::Challenge]>,
    preprocessed_next: Option<&[SC::Challenge]>,
    public_values: &[Val<SC>],
    trace_domain: Domain<SC>,
    zeta: SC::Challenge,
    alpha: SC::Challenge,
    quotient: SC::Challenge,
) -> Result<(), VerificationError<PcsErr>>
where
    SC: StarkGenericConfig,
    A: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    PcsErr: core::fmt::Debug,
{
    let sels = trace_domain.selectors_at_point(zeta);

    let main = VerticalPair::new(
        RowMajorMatrixView::new_row(trace_local),
        RowMajorMatrixView::new_row(trace_next),
    );

    let preprocessed = match (preprocessed_local, preprocessed_next) {
        (Some(local), Some(next)) => VerticalPair::new(
            RowMajorMatrixView::new_row(local),
            RowMajorMatrixView::new_row(next),
        ),
        _ => VerticalPair::new(
            RowMajorMatrixView::new(&[], 0),
            RowMajorMatrixView::new(&[], 0),
        ),
    };

    let preprocessed_window =
        RowWindow::from_two_rows(preprocessed.top.values, preprocessed.bottom.values);
    let mut folder = VerifierConstraintFolder {
        main,
        preprocessed,
        preprocessed_window,
        public_values,
        is_first_row: sels.is_first_row,
        is_last_row: sels.is_last_row,
        is_transition: sels.is_transition,
        alpha,
        accumulator: SC::Challenge::ZERO,
    };
    air.eval(&mut folder);
    let folded_constraints = folder.accumulator;

    if folded_constraints * sels.inv_vanishing != quotient {
        return Err(VerificationError::OodEvaluationMismatch { index: None });
    }

    Ok(())
}

#[allow(clippy::type_complexity)]
fn process_preprocessed_trace<SC, A>(
    air: &A,
    opened_values: &crate::proof::OpenedValues<SC::Challenge>,
    preprocessed_vk: Option<&PreprocessedVerifierKey<SC>>,
) -> Result<
    (
        usize,
        Option<<SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>,
    ),
    VerificationError<PcsError<SC>>,
>
where
    SC: StarkGenericConfig,
    A: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    let preprocessed_width = preprocessed_vk
        .map(|vk| vk.width)
        .or_else(|| air.preprocessed_trace().as_ref().map(|m| m.width))
        .unwrap_or(0);

    let preprocessed_local_len = opened_values
        .preprocessed_local
        .as_ref()
        .map_or(0, |v| v.len());
    let preprocessed_next_len = opened_values
        .preprocessed_next
        .as_ref()
        .map_or(0, |v| v.len());
    let expected_next_len = if !air.preprocessed_next_row_columns().is_empty() {
        preprocessed_width
    } else {
        0
    };
    if preprocessed_width != preprocessed_local_len || expected_next_len != preprocessed_next_len {
        return Err(VerificationError::InvalidProofShape);
    }

    match (preprocessed_width, preprocessed_vk) {
        (0, None) => Ok((0, None)),
        (w, Some(vk)) if w == vk.width => Ok((w, Some(vk.commitment.clone()))),
        _ => Err(VerificationError::InvalidProofShape),
    }
}

#[instrument(skip_all)]
pub fn verify<SC, A>(
    config: &SC,
    air: &A,
    proof: &Proof<SC>,
    public_values: &[Val<SC>],
) -> Result<(), VerificationError<PcsError<SC>>>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    verify_with_preprocessed(config, air, proof, public_values, None)
}

#[instrument(skip_all)]
pub fn verify_with_preprocessed<SC, A>(
    config: &SC,
    air: &A,
    proof: &Proof<SC>,
    public_values: &[Val<SC>],
    preprocessed_vk: Option<&PreprocessedVerifierKey<SC>>,
) -> Result<(), VerificationError<PcsError<SC>>>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    let Proof {
        commitments,
        opened_values,
        opening_proof,
        degree_bits,
    } = proof;

    if *degree_bits > MAX_DEGREE_BITS {
        return Err(VerificationError::ProofTooLarge);
    }
    // Reject before any subtraction/shift by the zk offset would underflow/panic.
    if *degree_bits < config.is_zk() {
        return Err(VerificationError::InvalidProofShape);
    }
    if opened_values.quotient_chunks.len() > MAX_PROOF_QUOTIENT_CHUNKS {
        return Err(VerificationError::ProofTooLarge);
    }

    let pcs = config.pcs();
    let degree = 1 << degree_bits;
    let trace_domain = pcs.natural_domain_for_degree(degree);
    let (preprocessed_width, preprocessed_commit) =
        process_preprocessed_trace::<SC, A>(air, opened_values, preprocessed_vk)?;

    if let Some(vk) = preprocessed_vk &&
        preprocessed_width > 0 &&
        vk.degree_bits != *degree_bits
    {
        return Err(VerificationError::InvalidProofShape);
    }

    let layout = AirLayout {
        preprocessed_width,
        main_width: air.width(),
        num_public_values: air.num_public_values(),
    };
    let log_num_quotient_chunks =
        get_log_num_quotient_chunks::<Val<SC>, A>(air, layout, config.is_zk());
    let num_quotient_chunks = 1 << (log_num_quotient_chunks + config.is_zk());
    let mut challenger = config.initialise_challenger();
    let init_trace_domain = pcs.natural_domain_for_degree(degree >> (config.is_zk()));

    let quotient_domain =
        trace_domain.create_disjoint_domain(1 << (degree_bits + log_num_quotient_chunks));
    let quotient_chunks_domains = quotient_domain.split_domains(num_quotient_chunks);

    let randomized_quotient_chunks_domains = quotient_chunks_domains
        .iter()
        .map(|domain| pcs.natural_domain_for_degree(domain.size() << (config.is_zk())))
        .collect_vec();

    if (opened_values.random.is_some() != SC::Pcs::ZK) ||
        (commitments.random.is_some() != SC::Pcs::ZK)
    {
        return Err(VerificationError::RandomizationError);
    }

    let air_width = <A as lib_q_stark_air::BaseAir<Val<SC>>>::width(air);
    let main_next = !air.main_next_row_columns().is_empty();
    let pre_next = !air.preprocessed_next_row_columns().is_empty();
    let trace_next_ok = if main_next {
        opened_values
            .trace_next
            .as_ref()
            .is_some_and(|v| v.len() == air_width)
    } else {
        opened_values.trace_next.is_none()
    };
    let valid_shape = opened_values.trace_local.len() == air_width &&
        trace_next_ok &&
        opened_values.quotient_chunks.len() == num_quotient_chunks &&
        opened_values
            .quotient_chunks
            .iter()
            .all(|qc| qc.len() == SC::Challenge::DIMENSION) &&
        opened_values
            .random
            .as_ref()
            .is_none_or(|r_comm| r_comm.len() == SC::Challenge::DIMENSION);
    if !valid_shape {
        return Err(VerificationError::InvalidProofShape);
    }

    challenger.observe(Val::<SC>::from_usize(proof.degree_bits));
    challenger.observe(Val::<SC>::from_usize(proof.degree_bits - config.is_zk()));
    challenger.observe(Val::<SC>::from_usize(preprocessed_width));

    // Public values are untrusted: validate their count against the AIR's declared
    // number before they are observed or folded into the constraints.
    if public_values.len() != air.num_public_values() {
        return Err(VerificationError::InvalidProofShape);
    }

    challenger.observe(commitments.trace.clone());
    if let Some(ref c) = preprocessed_commit {
        challenger.observe(c.clone());
    }
    challenger.observe_slice(public_values);

    let alpha = challenger.sample_algebra_element();
    challenger.observe(commitments.quotient_chunks.clone());

    if let Some(r_commit) = commitments.random.clone() {
        challenger.observe(r_commit);
    }

    let zeta = challenger.sample_algebra_element();
    let zeta_next = init_trace_domain
        .next_point(zeta)
        .ok_or(VerificationError::NextPointUnavailable)?;

    let mut coms_to_verify = if let Some(random_commit) = &commitments.random {
        let random_values = opened_values
            .random
            .as_ref()
            .ok_or(VerificationError::RandomizationError)?;
        vec![(
            random_commit.clone(),
            vec![(trace_domain, vec![(zeta, random_values.clone())])],
        )]
    } else {
        vec![]
    };
    let trace_round = {
        let mut trace_points = vec![(zeta, opened_values.trace_local.clone())];
        if main_next {
            trace_points.push((
                zeta_next,
                opened_values
                    .trace_next
                    .clone()
                    .ok_or(VerificationError::InvalidProofShape)?,
            ));
        }
        (
            commitments.trace.clone(),
            vec![(trace_domain, trace_points)],
        )
    };
    coms_to_verify.push(trace_round);
    coms_to_verify.push((
        commitments.quotient_chunks.clone(),
        randomized_quotient_chunks_domains
            .iter()
            .zip(&opened_values.quotient_chunks)
            .map(|(domain, values)| (*domain, vec![(zeta, values.clone())]))
            .collect_vec(),
    ));

    if preprocessed_width > 0 {
        let preprocessed_local = opened_values
            .preprocessed_local
            .clone()
            .ok_or(VerificationError::InvalidProofShape)?;
        let mut pre_points = vec![(zeta, preprocessed_local)];
        if pre_next {
            let preprocessed_next = opened_values
                .preprocessed_next
                .clone()
                .ok_or(VerificationError::InvalidProofShape)?;
            pre_points.push((zeta_next, preprocessed_next));
        }
        let commit = preprocessed_commit.ok_or(VerificationError::InvalidProofShape)?;
        coms_to_verify.push((commit, vec![(trace_domain, pre_points)]));
    }

    pcs.verify(coms_to_verify, opening_proof, &mut challenger)
        .map_err(VerificationError::InvalidOpeningArgument)?;

    let quotient = recompose_quotient_from_chunks::<SC, PcsError<SC>>(
        &quotient_chunks_domains,
        &opened_values.quotient_chunks,
        zeta,
    )?;

    let zeros;
    let trace_next_slice = match &opened_values.trace_next {
        Some(v) => v.as_slice(),
        None => {
            zeros = vec![SC::Challenge::ZERO; air_width];
            &zeros
        }
    };
    let pre_next_zeros;
    let preprocessed_next_for_verify = match &opened_values.preprocessed_next {
        Some(v) => Some(v.as_slice()),
        None if preprocessed_width > 0 => {
            pre_next_zeros = vec![SC::Challenge::ZERO; preprocessed_width];
            Some(pre_next_zeros.as_slice())
        }
        None => None,
    };
    verify_constraints::<SC, A, PcsError<SC>>(
        air,
        &opened_values.trace_local,
        trace_next_slice,
        opened_values.preprocessed_local.as_deref(),
        preprocessed_next_for_verify,
        public_values,
        init_trace_domain,
        zeta,
        alpha,
        quotient,
    )?;

    Ok(())
}

/// DoS limits for verifier input validation.
const MAX_DEGREE_BITS: usize = 24;
const MAX_PROOF_QUOTIENT_CHUNKS: usize = 256;

#[derive(Debug)]
pub enum VerificationError<PcsErr>
where
    PcsErr: core::fmt::Debug,
{
    InvalidProofShape,
    InvalidOpeningArgument(PcsErr),
    OodEvaluationMismatch {
        index: Option<usize>,
    },
    RandomizationError,
    NextPointUnavailable,
    LookupError(String),
    /// Basis element index out of range for the challenge extension.
    InvalidBasisIndex(usize),
    /// Proof size exceeds DoS limit (degree_bits or quotient_chunks).
    ProofTooLarge,
}

impl<PcsErr: core::fmt::Debug> core::fmt::Display for VerificationError<PcsErr> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidProofShape => write!(f, "invalid proof shape"),
            Self::InvalidOpeningArgument(e) => write!(f, "invalid opening argument: {e:?}"),
            Self::OodEvaluationMismatch { index } => {
                write!(f, "out-of-domain evaluation mismatch")?;
                if let Some(i) = index {
                    write!(f, " at index {i}")?;
                }
                Ok(())
            }
            Self::RandomizationError => write!(
                f,
                "randomization error: FRI batch randomization does not match ZK setting"
            ),
            Self::NextPointUnavailable => write!(
                f,
                "next point unavailable: domain does not support computing the next point algebraically"
            ),
            Self::LookupError(msg) => write!(f, "lookup error: {msg}"),
            Self::InvalidBasisIndex(i) => write!(f, "invalid basis index: {i}"),
            Self::ProofTooLarge => write!(f, "proof too large: exceeds DoS limit"),
        }
    }
}
