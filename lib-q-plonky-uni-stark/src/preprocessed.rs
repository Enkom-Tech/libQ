use lib_q_stark_air::Air;
use lib_q_stark_commit::Pcs;
use lib_q_stark_matrix::Matrix;
use tracing::debug_span;

use crate::{
    ProverConstraintFolder,
    StarkGenericConfig,
    SymbolicAirBuilder,
    Val,
};

/// Prover-side reusable data for preprocessed columns.
///
/// Allows committing to the preprocessed trace once per [`Air`]/degree and reusing
/// the commitment and [`Pcs`] prover data across many proofs.
pub struct PreprocessedProverData<SC: StarkGenericConfig> {
    pub width: usize,
    pub degree_bits: usize,
    pub commitment: <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
    pub prover_data: <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::ProverData,
}

/// Verifier-side reusable data for preprocessed columns.
///
/// Allows committing to the preprocessed trace once per [`Air`]/degree and reusing
/// the commitment across many verifications.
#[derive(Clone)]
pub struct PreprocessedVerifierKey<SC: StarkGenericConfig> {
    pub width: usize,
    pub degree_bits: usize,
    pub commitment: <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
}

/// Set up and commit the preprocessed trace for a given [`Air`] and degree.
///
/// Returns `None` if the [`Air`] does not define any preprocessed columns.
pub fn setup_preprocessed<SC, A>(
    config: &SC,
    air: &A,
    degree_bits: usize,
) -> Option<(PreprocessedProverData<SC>, PreprocessedVerifierKey<SC>)>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<ProverConstraintFolder<'a, SC>>,
{
    let pcs = config.pcs();
    let is_zk = config.is_zk();

    let init_degree = 1 << degree_bits;
    let degree = 1 << (degree_bits + is_zk);

    let preprocessed = air.preprocessed_trace()?;

    let width = preprocessed.width();
    if width == 0 {
        return None;
    }

    assert_eq!(
        preprocessed.height(),
        init_degree,
        "preprocessed trace height must equal trace degree"
    );

    let trace_domain = pcs.natural_domain_for_degree(degree);
    let (commitment, prover_data) = debug_span!("commit to preprocessed trace")
        .in_scope(|| pcs.commit([(trace_domain, preprocessed)]));

    let degree_bits = degree_bits + is_zk;
    let prover_data = PreprocessedProverData {
        width,
        degree_bits,
        commitment: commitment.clone(),
        prover_data,
    };
    let vk = PreprocessedVerifierKey {
        width,
        degree_bits,
        commitment,
    };
    Some((prover_data, vk))
}
