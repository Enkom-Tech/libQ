use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use lib_q_plonky_lookup::lookup_traits::{
    Kind,
    Lookup,
    LookupGadget,
};
use lib_q_stark_challenger::FieldChallenger;
use lib_q_stark_commit::Pcs;

use crate::config::{
    Challenge,
    Commitment,
    StarkGenericConfig as SGC,
    Val,
};

#[derive(Clone)]
pub struct PreprocessedInstanceMeta {
    pub matrix_index: usize,
    pub width: usize,
    pub degree_bits: usize,
}

pub struct GlobalPreprocessed<SC: SGC> {
    pub commitment: Commitment<SC>,
    pub instances: Vec<Option<PreprocessedInstanceMeta>>,
    pub matrix_to_instance: Vec<usize>,
}

pub struct CommonData<SC: SGC> {
    pub preprocessed: Option<GlobalPreprocessed<SC>>,
    pub lookups: Vec<Vec<Lookup<Val<SC>>>>,
}

pub struct ProverOnlyData<SC: SGC> {
    pub preprocessed_prover_data:
        Option<<SC::Pcs as Pcs<Challenge<SC>, SC::Challenger>>::ProverData>,
}

pub struct ProverData<SC: SGC> {
    pub common: CommonData<SC>,
    pub prover_only: ProverOnlyData<SC>,
}

impl<SC: SGC> CommonData<SC> {
    pub const fn new(
        preprocessed: Option<GlobalPreprocessed<SC>>,
        lookups: Vec<Vec<Lookup<Val<SC>>>>,
    ) -> Self {
        Self {
            preprocessed,
            lookups,
        }
    }

    pub fn empty(num_instances: usize) -> Self {
        let lookups = vec![Vec::new(); num_instances];
        Self {
            preprocessed: None,
            lookups,
        }
    }
}

impl<SC: SGC> ProverOnlyData<SC> {
    pub const fn empty() -> Self {
        Self {
            preprocessed_prover_data: None,
        }
    }
}

impl<SC: SGC> ProverData<SC> {
    pub fn empty(num_instances: usize) -> Self {
        Self {
            common: CommonData::empty(num_instances),
            prover_only: ProverOnlyData::empty(),
        }
    }
}

pub fn get_perm_challenges<SC: SGC, LG: LookupGadget>(
    challenger: &mut SC::Challenger,
    all_lookups: &[Vec<Lookup<Val<SC>>>],
    lookup_gadget: &LG,
) -> Vec<Vec<SC::Challenge>> {
    let num_challenges_per_lookup = lookup_gadget.num_challenges();
    let mut global_perm_challenges: BTreeMap<&str, Vec<SC::Challenge>> = BTreeMap::new();

    all_lookups
        .iter()
        .map(|contexts| {
            let num_challenges = contexts.len() * num_challenges_per_lookup;
            let mut instance_challenges = Vec::with_capacity(num_challenges);

            for context in contexts {
                match &context.kind {
                    Kind::Global(name) => {
                        let challenges = global_perm_challenges
                            .entry(name.as_str())
                            .or_insert_with(|| {
                                (0..num_challenges_per_lookup)
                                    .map(|_| challenger.sample_algebra_element())
                                    .collect()
                            });
                        instance_challenges.extend_from_slice(challenges);
                    }
                    Kind::Local => {
                        instance_challenges.extend(
                            (0..num_challenges_per_lookup)
                                .map(|_| challenger.sample_algebra_element::<SC::Challenge>()),
                        );
                    }
                }
            }
            instance_challenges
        })
        .collect()
}
