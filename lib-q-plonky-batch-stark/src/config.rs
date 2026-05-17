pub use lib_q_plonky_uni_stark::{
    Domain,
    PackedChallenge,
    PackedVal,
    PcsError,
    StarkGenericConfig,
    Val,
};
use lib_q_stark_challenger::FieldChallenger;
use lib_q_stark_commit::Pcs;
use lib_q_stark_field::{
    ExtensionField,
    PrimeCharacteristicRing,
};

pub type Challenge<SC> = <SC as StarkGenericConfig>::Challenge;

pub type Commitment<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Commitment;

pub type PcsProof<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Proof;

#[inline]
pub fn observe_instance_binding<SC: StarkGenericConfig>(
    ch: &mut SC::Challenger,
    log_ext_degree: usize,
    log_degree: usize,
    width: usize,
    n_quotient_chunks: usize,
) where
    Challenge<SC>: ExtensionField<Val<SC>>,
{
    ch.observe_base_as_algebra_element::<Challenge<SC>>(Val::<SC>::from_usize(log_ext_degree));
    ch.observe_base_as_algebra_element::<Challenge<SC>>(Val::<SC>::from_usize(log_degree));
    ch.observe_base_as_algebra_element::<Challenge<SC>>(Val::<SC>::from_usize(width));
    ch.observe_base_as_algebra_element::<Challenge<SC>>(Val::<SC>::from_usize(n_quotient_chunks));
}
