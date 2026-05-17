use alloc::vec::Vec;

use lib_q_plonky_lookup::LookupData;
use lib_q_plonky_uni_stark::OpenedValues;
use serde::{
    Deserialize,
    Serialize,
};

use crate::config::{
    Challenge,
    Commitment,
    PcsProof,
    StarkGenericConfig,
};

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct BatchProof<SC: StarkGenericConfig> {
    pub commitments: BatchCommitments<Commitment<SC>>,
    pub opened_values: BatchOpenedValues<Challenge<SC>>,
    pub opening_proof: PcsProof<SC>,
    pub global_lookup_data: Vec<Vec<LookupData<Challenge<SC>>>>,
    pub degree_bits: Vec<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchCommitments<Com> {
    pub main: Com,
    pub permutation: Option<Com>,
    pub quotient_chunks: Com,
    pub random: Option<Com>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenedValuesWithLookups<Challenge> {
    pub base_opened_values: OpenedValues<Challenge>,
    pub permutation_local: Vec<Challenge>,
    pub permutation_next: Vec<Challenge>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchOpenedValues<Challenge> {
    pub instances: Vec<OpenedValuesWithLookups<Challenge>>,
}
