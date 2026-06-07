use lib_q_threshold_sig::{
    Round1Commitment,
    Round1State,
    Round2Partial,
    SecretShare,
    ThresholdSigProfileV1,
    keygen_shares,
    setup,
    sign_round1,
    sign_round2,
};

pub const THRESHOLD: u8 = 3;
pub const PARTIES: u8 = 5;

pub fn deterministic_rng(seed: u8) -> lib_q_random::LibQRng {
    lib_q_random::new_deterministic_rng([seed; 32])
}

pub fn deterministic_keygen(
    seed: u8,
) -> (
    ThresholdSigProfileV1,
    lib_q_threshold_sig::KeygenSharesOutput,
) {
    let profile = setup();
    let mut rng = deterministic_rng(seed);
    let keygen = keygen_shares(&profile, THRESHOLD, PARTIES, &mut rng).expect("keygen");
    (profile, keygen)
}

pub fn select_signers(shares: &[SecretShare]) -> Vec<SecretShare> {
    shares
        .iter()
        .take(usize::from(THRESHOLD))
        .cloned()
        .collect()
}

pub fn build_round_states(
    profile: &ThresholdSigProfileV1,
    shares: &[SecretShare],
    message: &[u8],
    rng: &mut lib_q_random::LibQRng,
) -> Vec<Round1State> {
    shares
        .iter()
        .map(|share| sign_round1(profile, share, message, rng).expect("round1"))
        .collect()
}

pub fn build_partials(
    profile: &ThresholdSigProfileV1,
    public_key: &lib_q_threshold_sig::ThresholdSigPublicKey,
    shares: &[SecretShare],
    states: &[Round1State],
    commitments: &[Round1Commitment],
    message: &[u8],
) -> Vec<Round2Partial> {
    states
        .iter()
        .zip(shares.iter())
        .map(|(state, share)| {
            sign_round2(profile, public_key, message, share, state, commitments).expect("round2")
        })
        .collect()
}
