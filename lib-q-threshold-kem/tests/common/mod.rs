use lib_q_threshold_kem::{
    KeygenSharesOutput,
    ThresholdKemProfileV1,
    keygen_shares,
    setup,
};

pub const THRESHOLD: u8 = 32;
pub const PARTIES: u16 = 64;

pub fn deterministic_rng(seed: u8) -> lib_q_random::LibQRng {
    lib_q_random::new_deterministic_rng([seed; 32])
}

pub fn deterministic_keygen(seed: u8) -> (ThresholdKemProfileV1, KeygenSharesOutput) {
    let profile = setup();
    let mut rng = deterministic_rng(seed);
    let keygen = keygen_shares(&profile, THRESHOLD, PARTIES, &mut rng).expect("keygen");
    (profile, keygen)
}
